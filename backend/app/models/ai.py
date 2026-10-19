"""Grounded AI data structures, without LLM calls or text entailment logic."""

from __future__ import annotations

from typing import Annotated, Literal
from pydantic import Field, ValidationInfo, field_validator, model_validator

from app.utils.stable_id import normalize_propositions
from .base import (AlertID, AnalysisID, ChainEdgeID, ChainID, ClaimID, CorrelationID,
                   Digest, DomainModel, ExplanationID, IncidentID, Json, NodeID,
                   StrictModel, Text, ids)
from .enums import ClaimKind, ClaimSection, GroundingStatus


# §12.2's structured facts and accepted algorithm conclusions. Raw payloads,
# vendor free text, diagnostics and arbitrary paths are deliberately absent.
PROPOSITION_FIELDS = {
    "alert": {"alert_id", "timestamp", "source_type", "source_namespace", "sensor", "category", "severity",
              "entity_ids", "entity_occurrences", "relations"},
    "node": {"node_id", "incident_id", "alert_ids", "start_time", "end_time", "category", "severity",
             "entity_ids", "confidence", "reasons"},
    "chain_edge": {"edge_id", "incident_id", "source_node_id", "target_node_id", "relation_type", "confidence",
                   "direction_score", "alert_ids", "entity_ids", "correlation_edge_ids", "reasons", "score_breakdown"},
    "correlation_edge": {"edge_id", "source_alert_id", "target_alert_id", "score", "entity_ids", "reasons",
                         "score_breakdown", "support_pair"},
}
SUBJECT_IDS = {"alert": AlertID, "node": NodeID, "chain_edge": ChainEdgeID, "correlation_edge": CorrelationID}


class GroundedProposition(StrictModel):
    subject_type: Literal["alert", "node", "chain_edge", "correlation_edge"]
    subject_id: str
    field: Text
    value: Json

    @field_validator("value")
    @classmethod
    def canonical_snapshot_value(cls, value, info):
        if {"subject_type", "subject_id", "field"} <= info.data.keys():
            return normalize_propositions([{key: info.data[key] for key in ("subject_type", "subject_id", "field")} |
                                           {"value": value}])[0]["value"]
        return value

    @model_validator(mode="after")
    def whitelist(self, info: ValidationInfo):
        from pydantic import TypeAdapter
        TypeAdapter(SUBJECT_IDS[self.subject_type]).validate_python(self.subject_id, strict=True)
        if self.field not in PROPOSITION_FIELDS[self.subject_type]:
            raise ValueError("proposition field is outside the structured fact whitelist")
        if info.context and "subjects" in info.context:
            subjects = info.context["subjects"]
            subject = subjects.get((self.subject_type, self.subject_id))
            if subject is None:
                raise ValueError("proposition subject is absent from supplied snapshot")
            data = subject.model_dump(mode="json") if hasattr(subject, "model_dump") else subject
            # Canonical comparison respects JSON types (true is not 1) and declared
            # snapshot sets; it never sorts ordinary fact arrays.
            from app.utils.stable_id import canonical_json
            if self.field not in data or canonical_json(data[self.field]) != canonical_json(self.value):
                raise ValueError("proposition value differs from supplied snapshot field")
        return self


class AttackMapping(StrictModel):
    technique_id: Annotated[str, Field(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")]
    technique_name: Text
    tactic: Text | None = None
    catalog_version: Text
    rationale: Text


class AIClaim(DomainModel):
    claim_id: ClaimID
    kind: ClaimKind
    section: ClaimSection
    text: Text
    node_ids: ids(NodeID) = Field(default_factory=list)
    edge_ids: ids(ChainEdgeID) = Field(default_factory=list)
    alert_ids: ids(AlertID) = Field(default_factory=list)
    propositions: list[GroundedProposition] = Field(default_factory=list)
    attack_mapping: AttackMapping | None = None
    grounding_status: GroundingStatus = GroundingStatus.PENDING
    validation_errors: list[Text] = Field(default_factory=list)

    @field_validator("propositions")
    @classmethod
    def proposition_set(cls, values, info):
        normalized = normalize_propositions([v.model_dump(mode="json") for v in values])
        return [GroundedProposition.model_validate(v, context=info.context) for v in normalized]

    @model_validator(mode="after")
    def claim_contract(self):
        if self.kind == ClaimKind.FACT and (not self.alert_ids or not self.propositions):
            raise ValueError("fact requires nonempty alert references and propositions")
        if self.kind == ClaimKind.ATTACK_MAPPING:
            if self.attack_mapping is None or not self.alert_ids or not self.node_ids:
                raise ValueError("attack_mapping requires mapping, nodes and alerts")
        elif self.attack_mapping is not None:
            raise ValueError("attack_mapping is only allowed on attack_mapping kind")
        if self.kind == ClaimKind.INFERENCE and not (self.alert_ids or self.node_ids or self.edge_ids):
            raise ValueError("inference requires existing evidence references")
        if self.grounding_status == GroundingStatus.REJECTED and not self.validation_errors:
            raise ValueError("rejected claim requires validation_errors")
        for p in self.propositions:
            if p.subject_type == "alert" and p.subject_id not in self.alert_ids:
                raise ValueError("alert proposition lacks its alert reference")
            if p.subject_type == "node" and (p.subject_id not in self.node_ids or not self.alert_ids):
                raise ValueError("node proposition lacks node/alert references")
            if p.subject_type == "chain_edge" and (p.subject_id not in self.edge_ids or len(self.node_ids) < 2 or not self.alert_ids):
                raise ValueError("edge proposition lacks edge/endpoints/alert references")
            if p.subject_type == "correlation_edge" and (not self.edge_ids or len(self.node_ids) < 2 or not self.alert_ids):
                raise ValueError("correlation proposition requires chain-edge reference closure")
        return self


SECTION_ORDER = {value: index for index, value in enumerate((
    ClaimSection.SUMMARY, ClaimSection.ATTACK_PATH, ClaimSection.ATTACK_MAPPING,
    ClaimSection.RISK, ClaimSection.RECOMMENDATIONS,
))}


class AIExplanation(DomainModel):
    explanation_id: ExplanationID
    analysis_id: AnalysisID
    incident_id: IncidentID
    chain_id: ChainID
    input_digest: Digest
    provider: Text
    model: Text
    prompt_version: Text
    claims: Annotated[list[AIClaim], Field(min_length=1)]
    grounding_status: GroundingStatus = GroundingStatus.PENDING

    @field_validator("claims")
    @classmethod
    def sorted_claims(cls, values):
        from .base import sorted_objects
        unique = sorted_objects(values, "claim_id")
        return sorted(unique, key=lambda c: (SECTION_ORDER[c.section], c.claim_id))

    @model_validator(mode="after")
    def validation_state(self):
        if self.grounding_status == GroundingStatus.VALIDATED and any(
                c.grounding_status != GroundingStatus.VALIDATED for c in self.claims):
            raise ValueError("validated explanation requires every claim validated")
        return self

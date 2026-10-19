"""Strict code-specific Reason params and their canonical set semantics."""

from __future__ import annotations

from typing import Annotated, Literal
from pydantic import AfterValidator, Field, ValidationInfo, field_validator, model_validator

from app.utils.stable_id import id_for, normalize_params
from .alerts import EvidencePointers, require_relation_fields
from .base import (AlertID, EntityID, NodeID, NonNegative, Positive, PositiveInt,
                   ReasonID, Score, StrictModel, Text, check_evidence, ids, sorted_objects)
from .enums import (AlertRelationType, Category, EntityRole, EntityType, ReasonCode,
                    SourceIndependence, SourceType)


class TimeGapParams(StrictModel):
    gap_seconds: NonNegative
    half_life_seconds: Positive


class SharedEntityParams(StrictModel):
    entity_type: EntityType
    roles: Annotated[list[EntityRole], Field(min_length=1)]
    rarity: Score
    contribution: Score


class ExplicitRelationParams(StrictModel):
    relation_type: AlertRelationType
    raw_pointers: Annotated[EvidencePointers, Field(min_length=1)]

    @model_validator(mode="after")
    def structured(self, info: ValidationInfo):
        require_relation_fields(self.raw_pointers, info)
        return self


class BehaviorTransitionParams(StrictModel):
    from_category: Category
    to_category: Category
    compatibility: Score


class SourceComplementParams(StrictModel):
    source_types: Annotated[list[SourceType], Field(min_length=1)]
    sensor_names: list[Text]
    rule_id: Text
    source_independence: SourceIndependence
    raw_pointers: EvidencePointers
    independence_rule_ids: list[Text]

    @model_validator(mode="after")
    def confirmation_basis(self, info: ValidationInfo):
        if self.source_independence != SourceIndependence.UNKNOWN and not (self.raw_pointers or self.independence_rule_ids):
            raise ValueError("confirmed source independence requires field or configuration evidence")
        allowed_rules = None
        if info.context and "independence_rule_ids" in info.context:
            allowed_rules = set(info.context["independence_rule_ids"])
        elif info.context and "config_snapshot" in info.context:
            files = info.context["config_snapshot"].get("source", {}).get("independence_mapping_files", [])
            allowed_rules = {rule["id"] for mapping in files for rule in mapping["rules"]}
        if allowed_rules is not None:
            if set(self.independence_rule_ids) - allowed_rules:
                raise ValueError("independence rule is absent from the supplied configuration")
        return self


class ConflictParams(StrictModel):
    rule_id: Text
    penalty: Score


class DuplicateParams(StrictModel):
    rule_id: Text
    similarity: Score


class DirectionParams(StrictModel):
    rule_id: Text
    source_node_id: NodeID
    target_node_id: NodeID
    direction_score: Score

    @model_validator(mode="after")
    def distinct(self):
        if self.source_node_id == self.target_node_id:
            raise ValueError("direction cannot point to itself")
        return self


class ClusteringGuardParams(StrictModel):
    rule_id: Text
    decision: Literal["accept", "reject"]
    component_sizes: Annotated[list[PositiveInt], Field(min_length=1)]


class NodeBasisParams(StrictModel):
    rule_id: Text
    category: Category
    confidence: Score


PARAM_MODELS = {
    ReasonCode.TIME_GAP: TimeGapParams, ReasonCode.SHARED_ENTITY: SharedEntityParams,
    ReasonCode.EXPLICIT_RELATION: ExplicitRelationParams,
    ReasonCode.BEHAVIOR_TRANSITION: BehaviorTransitionParams,
    ReasonCode.SOURCE_COMPLEMENT: SourceComplementParams, ReasonCode.CONFLICT: ConflictParams,
    ReasonCode.DUPLICATE: DuplicateParams, ReasonCode.DIRECTION: DirectionParams,
    ReasonCode.CLUSTERING_GUARD: ClusteringGuardParams, ReasonCode.NODE_BASIS: NodeBasisParams,
}


class Reason(StrictModel):
    reason_id: ReasonID
    code: ReasonCode
    message: Text
    alert_ids: Annotated[ids(AlertID), Field(min_length=1)]
    entity_ids: ids(EntityID) = Field(default_factory=list)
    params: dict

    @field_validator("params")
    @classmethod
    def strict_params(cls, value, info: ValidationInfo):
        if "code" not in info.data:
            raise ValueError("valid reason code is required before params")
        code = info.data["code"]
        parsed = PARAM_MODELS[code].model_validate(value, context=info.context)
        return normalize_params(code.value, parsed.model_dump(mode="json"))

    @model_validator(mode="after")
    def references_and_identity(self, info: ValidationInfo):
        if "raw_pointers" in self.params:
            parsed = PARAM_MODELS[self.code].model_validate(self.params, context=info.context)
            check_evidence(parsed.raw_pointers, self.alert_ids, info)
        if self.code == ReasonCode.SHARED_ENTITY and not self.entity_ids:
            raise ValueError("shared_entity reason requires referenced entities")
        if self.reason_id != id_for("Reason", self):
            raise ValueError("reason_id does not match its v1 content identity")
        return self


def canonical_reasons(values):
    return sorted_objects(values, "reason_id")


Reasons = Annotated[list[Reason], AfterValidator(canonical_reasons)]

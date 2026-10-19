"""Dedupe, correlation, incident and chain representations with local closure checks."""

from __future__ import annotations

from typing import Annotated, Literal
from pydantic import Field, ValidationInfo, field_validator, model_validator, model_serializer

from .alerts import EvidencePointer, SupportPair
from .base import (AlertID, ChainEdgeID, ChainID, CorrelationID, DedupeID, DomainModel,
                   EntityID, IncidentID, NodeID, Score, Text, UTCDateTime,
                   check_evidence, check_interval, ids)
from .enums import CHAIN_RELATION_MAPPING, Category, ChainRelationType, IncidentStatus, ReasonCode, Severity
from .reasons import Reasons
from .scoring import ScoreBreakdown, check_source_reasons, check_source_snapshot, close
from .correlation_v5 import ScoreBreakdownV5
from .triage import SingleAlertTriage


def check_reason_refs(reasons, alert_ids, entity_ids, info):
    for reason in reasons:
        if set(reason.alert_ids) - set(alert_ids) or set(reason.entity_ids) - set(entity_ids):
            raise ValueError("reason references outside its owning object")
        pointers = [EvidencePointer.model_validate(p) for p in reason.params.get("raw_pointers", [])]
        check_evidence(pointers, alert_ids, info)


class DedupeGroup(DomainModel):
    group_id: DedupeID
    representative_alert_id: AlertID
    alert_ids: Annotated[ids(AlertID), Field(min_length=2)]
    duplicate_score: Score
    reasons: Annotated[Reasons, Field(min_length=1)]

    @model_validator(mode="after")
    def representative(self):
        if self.representative_alert_id != min(self.alert_ids):
            raise ValueError("representative must be the minimum member alert ID")
        for reason in self.reasons:
            if set(reason.alert_ids) - set(self.alert_ids):
                raise ValueError("dedupe reason references a nonmember alert")
        return self


class CorrelationEdge(DomainModel):
    edge_id: CorrelationID
    source_alert_id: AlertID
    target_alert_id: AlertID
    score: Score
    reasons: Annotated[Reasons, Field(min_length=1)]
    entity_ids: ids(EntityID) = Field(default_factory=list)
    score_breakdown: ScoreBreakdown | ScoreBreakdownV5
    support_pair: SupportPair

    @model_validator(mode="after")
    def edge_contract(self, info: ValidationInfo):
        if self.source_alert_id >= self.target_alert_id:
            raise ValueError("correlation endpoints must be distinct and lexicographically ordered")
        if not close(self.score, self.score_breakdown.final_score):
            raise ValueError("edge score differs from breakdown final_score")
        v2 = self.score_breakdown.evidence_v2
        if isinstance(self.score_breakdown,ScoreBreakdownV5):
            v5=self.score_breakdown
            if not v5.gate.passed or not v5.threshold_passed:
                raise ValueError('formal V5 edge requires passed gate and threshold')
            for feature in v5.features:
                if set(feature.entity_ids)-set(self.entity_ids):
                    raise ValueError('V5 feature entities outside edge')
                check_evidence(feature.provenance,self.support_pair.alert_ids(),info)
        if v2 is not None and (not v2.evidence_gate_passed or not v2.threshold_passed or v2.decision != "ACCEPT"):
            raise ValueError("formal v2 correlation edge requires sufficient accepted evidence")
        if self.score_breakdown.selected_correlation_edge_id is not None:
            raise ValueError("CorrelationEdge cannot select itself as a supporting correlation edge")
        codes = {r.code for r in self.reasons}
        if ReasonCode.TIME_GAP not in codes or not codes & {ReasonCode.SHARED_ENTITY, ReasonCode.EXPLICIT_RELATION}:
            raise ValueError("correlation requires time and actual non-time context evidence")
        check_reason_refs(self.reasons, self.support_pair.alert_ids(), self.entity_ids, info)
        if v2 is not None and v2.version in {"v3", "v4"}:
            for fact in v2.evidence:
                if fact.source_alert_ids is not None and set(fact.source_alert_ids) != self.support_pair.alert_ids():
                    raise ValueError('v3 fact source alerts differ from support pair')
                if set(fact.entity_ids) - set(self.entity_ids):
                    raise ValueError("v3 fact entities outside edge")
                check_evidence(fact.evidence_refs, self.support_pair.alert_ids(), info)
        if set().union(*(set(r.alert_ids) for r in self.reasons)) != self.support_pair.alert_ids():
            raise ValueError("correlation reasons must cover the complete support_pair")
        check_source_reasons(self.score_breakdown, self.reasons)
        check_source_snapshot(self.score_breakdown, self.reasons, self.support_pair, info)
        if info.context and "groups" in info.context:
            groups = info.context["groups"]
            if self.support_pair.alert_id_src not in groups.get(self.source_alert_id, [self.source_alert_id]):
                raise ValueError("support_pair src does not belong to the source fact group")
            if self.support_pair.alert_id_dst not in groups.get(self.target_alert_id, [self.target_alert_id]):
                raise ValueError("support_pair dst does not belong to the target fact group")
        return self


class Incident(DomainModel):
    incident_id: IncidentID
    start_time: UTCDateTime
    end_time: UTCDateTime
    severity: Severity
    alert_ids: Annotated[ids(AlertID), Field(min_length=1)]
    entity_ids: ids(EntityID) = Field(default_factory=list)
    correlation_edge_ids: ids(CorrelationID) = Field(default_factory=list)
    status: IncidentStatus = IncidentStatus.NEW
    summary: Text | None = None
    single_alert_triage: SingleAlertTriage | None = None

    @model_serializer(mode="wrap")
    def legacy_serialization(self, handler):
        data = handler(self)
        if self.single_alert_triage is None:
            data.pop("single_alert_triage", None)
        return data

    @model_validator(mode="after")
    def interval(self):
        check_interval(self.start_time, self.end_time)
        if self.single_alert_triage is not None and self.alert_ids != [self.single_alert_triage.alert_id]:
            raise ValueError("single alert triage requires exactly its owning singleton")
        return self


class ChainNode(DomainModel):
    node_id: NodeID
    incident_id: IncidentID
    alert_ids: Annotated[ids(AlertID), Field(min_length=1)]
    start_time: UTCDateTime
    end_time: UTCDateTime
    category: Category
    severity: Severity
    entity_ids: ids(EntityID) = Field(default_factory=list)
    confidence: Score
    reasons: Annotated[Reasons, Field(min_length=1)]

    @model_validator(mode="after")
    def node_contract(self, info: ValidationInfo):
        check_interval(self.start_time, self.end_time)
        if ReasonCode.NODE_BASIS not in {r.code for r in self.reasons}:
            raise ValueError("node requires node_basis")
        check_reason_refs(self.reasons, self.alert_ids, self.entity_ids, info)
        for reason in self.reasons:
            if reason.code == ReasonCode.NODE_BASIS and (reason.params["category"] != self.category.value or
                                                        not close(reason.params["confidence"], self.confidence)):
                raise ValueError("node_basis differs from node category/confidence")
        return self


class ChainEdge(DomainModel):
    edge_id: ChainEdgeID
    incident_id: IncidentID
    source_node_id: NodeID
    target_node_id: NodeID
    relation_type: ChainRelationType
    confidence: Score
    direction_score: Score
    alert_ids: Annotated[ids(AlertID), Field(min_length=2)]
    entity_ids: ids(EntityID) = Field(default_factory=list)
    correlation_edge_ids: Annotated[ids(CorrelationID), Field(min_length=1)]
    reasons: Annotated[Reasons, Field(min_length=1)]
    score_breakdown: ScoreBreakdown | ScoreBreakdownV5

    @model_validator(mode="after")
    def direction_contract(self, info: ValidationInfo):
        if self.source_node_id == self.target_node_id:
            raise ValueError("chain endpoints must differ")
        selected = self.score_breakdown.selected_correlation_edge_id
        if selected is None or selected not in self.correlation_edge_ids:
            raise ValueError("selected supporting correlation edge must be present")
        if not close(self.confidence, min(self.score_breakdown.final_score, self.direction_score)):
            raise ValueError("chain confidence differs from min(correlation, direction)")
        directions = [r for r in self.reasons if r.code == ReasonCode.DIRECTION]
        relations = [r for r in self.reasons if r.code == ReasonCode.EXPLICIT_RELATION]
        if not directions or not any(CHAIN_RELATION_MAPPING[r.params["relation_type"]] == self.relation_type for r in relations):
            raise ValueError("chain edge requires direction and the matching frozen explicit relation")
        for reason in directions:
            if (reason.params["source_node_id"] != self.source_node_id or
                    reason.params["target_node_id"] != self.target_node_id or
                    not close(reason.params["direction_score"], self.direction_score)):
                raise ValueError("direction reason differs from chain endpoints/score")
        check_reason_refs(self.reasons, self.alert_ids, self.entity_ids, info)
        check_source_reasons(self.score_breakdown, self.reasons)
        if info.context and "correlation_edges" in info.context:
            edges = info.context["correlation_edges"]
            if selected not in edges:
                raise ValueError("selected correlation edge absent from supplied snapshot")
            edge = edges[selected]
            if not isinstance(edge, CorrelationEdge):
                edge = CorrelationEdge.model_validate(edge, context=info.context)
            original = self.score_breakdown.model_dump(mode="json")
            original["selected_correlation_edge_id"] = None
            if original != edge.score_breakdown.model_dump(mode="json"):
                raise ValueError("chain breakdown differs from selected correlation breakdown")
            for reason in relations:
                check_evidence([EvidencePointer.model_validate(p) for p in reason.params["raw_pointers"]],
                               edge.support_pair.alert_ids(), info)
            check_source_snapshot(self.score_breakdown, self.reasons, edge.support_pair, info)
        return self


class AttackChain(DomainModel):
    chain_id: ChainID
    incident_id: IncidentID
    nodes: Annotated[list[ChainNode], Field(min_length=1)]
    edges: list[ChainEdge] = Field(default_factory=list)
    status: Literal["complete", "partial"]
    unresolved_correlation_edge_ids: ids(CorrelationID) = Field(default_factory=list)

    @field_validator("nodes", "edges")
    @classmethod
    def unique_sorted_objects(cls, values, info):
        key = "node_id" if info.field_name == "nodes" else "edge_id"
        identifiers = [getattr(v, key) for v in values]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("chain node/edge IDs must be unique")
        return sorted(values, key=lambda v: getattr(v, key))

    @model_validator(mode="after")
    def local_closure(self):
        nodes = {n.node_id: n for n in self.nodes}
        if any(n.incident_id != self.incident_id for n in self.nodes):
            raise ValueError("chain nodes belong to another Incident")
        for edge in self.edges:
            if edge.incident_id != self.incident_id or {edge.source_node_id, edge.target_node_id} - nodes.keys():
                raise ValueError("chain edge endpoints/Incident are not closed")
            endpoints = (nodes[edge.source_node_id], nodes[edge.target_node_id])
            if any(not set(n.alert_ids) & set(edge.alert_ids) for n in endpoints):
                raise ValueError("edge must have actual supporting alerts from both endpoint nodes")
            if set(edge.alert_ids) - set(endpoints[0].alert_ids + endpoints[1].alert_ids):
                raise ValueError("edge alert outside its endpoint nodes")
        # Cycle validation is a schema invariant, not cycle selection/rejection logic.
        outgoing = {key: [] for key in nodes}
        indegrees = dict.fromkeys(nodes, 0)
        for edge in self.edges:
            outgoing[edge.source_node_id].append(edge.target_node_id)
            indegrees[edge.target_node_id] += 1
        ready = [key for key, degree in indegrees.items() if degree == 0]
        visited = 0
        while ready:
            key = ready.pop()
            visited += 1
            for target in outgoing[key]:
                indegrees[target] -= 1
                if indegrees[target] == 0:
                    ready.append(target)
        if visited != len(nodes):
            raise ValueError("formal AttackChain must be a DAG")
        return self

"""Independent versioned contract; historical Stage/ChainEdge schemas unchanged."""
from typing import Annotated, Literal
from pydantic import Field, ValidationInfo, model_validator

from app.community.models import CommunityID
from app.models.alerts import EvidencePointer, canonical_pointers
from app.models.base import (AlertID, Digest, EntityID, Number, NonNegative, PositiveInt,
                             Score, StrictModel, Text, UTCDateTime, check_evidence, ids, id_type)
from app.stages.models import StageID
from app.utils.stable_id import content_digest

RelationType = Literal['STRONG_DIRECTED', 'STRONG_UNDIRECTED', 'WEAK_DIRECTED']
DirectionBasis = Literal['evidence_semantics', 'temporal_order', 'unresolved']
DIRECTION_BASES = {'STRONG_DIRECTED': 'evidence_semantics',
                   'STRONG_UNDIRECTED': 'unresolved', 'WEAK_DIRECTED': 'temporal_order'}


def stable(prefix, kind, identity):
    return prefix+'_'+content_digest(dict(id_version='v1', kind=kind, identity=identity))


class SemanticDirection(StrictModel):
    from_stage_id: StageID
    to_stage_id: StageID
    from_alert_id: AlertID
    to_alert_id: AlertID


class RelationEvidence(StrictModel):
    evidence_id: id_type('sre')
    evidence_type: Text
    evidence_strength: Score
    rank: PositiveInt
    strong: bool
    alert_ids: Annotated[ids(AlertID), Field(min_length=2, max_length=2)]
    entity_ids: ids(EntityID)
    identity_key: Text
    pointers: Annotated[list[EvidencePointer], Field(min_length=2)]
    semantic_direction: SemanticDirection | None
    reason: Text

    @model_validator(mode='after')
    def bound(self, info: ValidationInfo):
        object.__setattr__(self, 'pointers', canonical_pointers(self.pointers))
        if {p.alert_id for p in self.pointers} != set(self.alert_ids):
            raise ValueError('relation_evidence_requires_both_alerts')
        check_evidence(self.pointers, self.alert_ids, info)
        identity_only = self.evidence_type == 'same_instance'
        if identity_only and (not self.strong or self.semantic_direction is not None):
            raise ValueError('same_instance_requires_strong_undirected_evidence')
        if not identity_only and self.strong != (self.semantic_direction is not None):
            raise ValueError('strong_evidence_requires_semantic_direction')
        if self.semantic_direction and set(self.alert_ids) != {self.semantic_direction.from_alert_id, self.semantic_direction.to_alert_id}:
            raise ValueError('semantic_direction_outside_evidence')
        identity = dict(evidence_type=self.evidence_type, alert_ids=self.alert_ids,
                        identity_key=self.identity_key, pointers=[p.model_dump(mode='json') for p in self.pointers],
                        semantic_direction=self.semantic_direction.model_dump(mode='json') if self.semantic_direction else None)
        if self.evidence_id != stable('sre', 'StageRelationEvidence', identity):
            raise ValueError('evidence_identity_mismatch')
        return self


class TimeFacts(StrictModel):
    stage_a_start: UTCDateTime
    stage_a_end: UTCDateTime
    stage_b_start: UTCDateTime
    stage_b_end: UTCDateTime
    primary_alert_timestamps: dict[AlertID, UTCDateTime]
    semantic_gap_seconds: Number | None
    tolerance_seconds: NonNegative
    rule: Text


class RelationConfidence(StrictModel):
    evidence_strength: Score
    direction_reliability: Score = Field(description='Reliability under the relation direction_basis; for temporal_order this concerns display order only, not causal evidence.')
    time_consistency: Literal['consistent', 'within_tolerance', 'conflict', 'overlap']
    policy: Literal['primary_evidence_only_uncalibrated'] = 'primary_evidence_only_uncalibrated'
    reason: Text


class StageRelation(StrictModel):
    contract_version: Literal['stage-relations-v1'] = 'stage-relations-v1'
    relation_id: id_type('str')
    community_id: CommunityID
    stage_a_id: StageID
    stage_b_id: StageID
    from_stage_id: StageID | None = Field(description='Arrow source: evidence semantics for strong directed relations; earlier Stage for temporal_order; null when unresolved.')
    to_stage_id: StageID | None = Field(description='Arrow target: evidence semantics for strong directed relations; later Stage for temporal_order; null when unresolved.')
    relation_type: RelationType
    direction_reliable: bool = Field(description='Whether endpoints have a resolved direction under direction_basis; true does not by itself assert semantic or causal direction.')
    direction_basis: DirectionBasis = Field(description='evidence_semantics: valid primary strong evidence determines direction; temporal_order: observed earlier-to-later display order only, not causal or propagation evidence; unresolved: no reliable direction.')
    primary_evidence: RelationEvidence
    supporting_evidence: list[RelationEvidence]
    witness_alert_ids: ids(AlertID)
    evidence_type: Text
    evidence_strength: Score
    semantic_direction: SemanticDirection | None = Field(description='Original primary evidence direction, retained for diagnostics even when direction_basis is unresolved; null for weak relations.')
    observed_time_order: Literal['A_BEFORE_B', 'B_BEFORE_A', 'OVERLAP_OR_EQUAL']
    time_gap: NonNegative
    overlap: bool
    time_conflict: bool
    direction_conflict: bool
    time_facts: TimeFacts
    confidence: Score
    confidence_basis: RelationConfidence
    reason: Text

    @model_validator(mode='before')
    @classmethod
    def legacy_direction_basis(cls, data):
        # Read historical v1 snapshots without rewriting them. New exports
        # always carry the explicit basis; an explicitly supplied value is checked.
        if isinstance(data, dict) and 'direction_basis' not in data:
            kind = data.get('relation_type')
            if isinstance(kind, str) and kind in DIRECTION_BASES:
                return dict(data, direction_basis=DIRECTION_BASES[kind])
        return data

    @model_validator(mode='after')
    def closure(self, info: ValidationInfo):
        pair = [self.stage_a_id, self.stage_b_id]
        if pair != sorted(set(pair)):
            raise ValueError('canonical_distinct_stage_pair_required')
        identity = dict(community_id=self.community_id, stage_ids=pair)
        if self.relation_id != stable('str', 'StageRelation', identity):
            raise ValueError('relation_identity_mismatch')
        if self.direction_basis != DIRECTION_BASES[self.relation_type]:
            raise ValueError('direction_basis_must_match_relation_type')
        undirected = self.relation_type == 'STRONG_UNDIRECTED'
        if undirected:
            if self.direction_reliable or self.from_stage_id is not None or self.to_stage_id is not None:
                raise ValueError('undirected_relation_cannot_assert_direction')
            if not (self.time_conflict or self.direction_conflict or
                    (self.primary_evidence.strong and self.primary_evidence.semantic_direction is None)):
                raise ValueError('undirected_requires_unresolved_conflict')
        elif not self.direction_reliable or {self.from_stage_id, self.to_stage_id} != set(pair):
            raise ValueError('directed_relation_requires_valid_endpoints')
        if self.primary_evidence.strong != (self.relation_type != 'WEAK_DIRECTED'):
            raise ValueError('relation_strength_mismatch')
        if self.semantic_direction != self.primary_evidence.semantic_direction:
            raise ValueError('original_semantic_direction_must_be_retained')
        if self.relation_type == 'WEAK_DIRECTED':
            endpoints = {'A_BEFORE_B': (self.stage_a_id, self.stage_b_id),
                         'B_BEFORE_A': (self.stage_b_id, self.stage_a_id)}
            if (self.overlap or self.time_conflict or self.semantic_direction or
                    (self.from_stage_id, self.to_stage_id) != endpoints.get(self.observed_time_order)):
                raise ValueError('weak_relation_requires_unambiguous_observed_order')
        if self.relation_type == 'STRONG_DIRECTED' and (self.semantic_direction is None or self.time_conflict or self.direction_conflict or
                (self.from_stage_id, self.to_stage_id) != (self.semantic_direction.from_stage_id, self.semantic_direction.to_stage_id)):
            raise ValueError('strong_direction_must_follow_unconflicted_semantics')
        if (self.evidence_type, self.evidence_strength, self.confidence) != (
                self.primary_evidence.evidence_type, self.primary_evidence.evidence_strength, self.primary_evidence.evidence_strength):
            raise ValueError('confidence_and_type_must_come_from_primary_only')
        all_evidence = [self.primary_evidence, *self.supporting_evidence]
        if all_evidence != sorted(all_evidence, key=lambda e:(e.rank, -e.evidence_strength, e.evidence_id)):
            raise ValueError('primary_must_be_the_highest_ranked_single_evidence')
        expected_reliability = self.confidence if self.direction_reliable else 0.0
        if self.confidence_basis.evidence_strength != self.confidence or self.confidence_basis.direction_reliability != expected_reliability:
            raise ValueError('confidence_components_must_match_decision')
        if len({e.evidence_id for e in all_evidence}) != len(all_evidence):
            raise ValueError('duplicate_relation_evidence')
        if set(self.witness_alert_ids) != {aid for e in all_evidence for aid in e.alert_ids}:
            raise ValueError('witnesses_must_equal_actual_evidence_alerts')
        for e in all_evidence:
            check_evidence(e.pointers, e.alert_ids, info)
            if info.context and 'entities' in info.context and set(e.entity_ids) - set(info.context['entities']):
                raise ValueError('evidence_entity_reference_missing')
            if info.context and 'stages' in info.context:
                stages = [info.context['stages'][sid] for sid in pair]
                if any(s.community_id != self.community_id for s in stages):
                    raise ValueError('relation_crosses_community')
                if any(len(set(e.alert_ids) & set(s.alert_ids)) != 1 for s in stages):
                    raise ValueError('evidence_must_cross_stage_endpoints')
                if e.semantic_direction:
                    d = e.semantic_direction
                    if {d.from_stage_id, d.to_stage_id} != set(pair) or any(
                        aid not in info.context['stages'][sid].alert_ids for sid, aid in
                        ((d.from_stage_id, d.from_alert_id), (d.to_stage_id, d.to_alert_id))):
                        raise ValueError('semantic_alert_stage_binding_mismatch')
        if info.context and 'stages' in info.context and 'alerts' in info.context:
            from .time import time_facts
            from types import SimpleNamespace
            stages = info.context['stages']
            aa = info.context['alerts']
            order, gap, overlaps, conflict, consistency, facts = time_facts(
                stages[self.stage_a_id], stages[self.stage_b_id], self.primary_evidence, aa,
                SimpleNamespace(time_reversal_tolerance_seconds=self.time_facts.tolerance_seconds))
            if (self.observed_time_order,self.time_gap,self.overlap,self.time_conflict,self.time_facts) != (order,gap,overlaps,conflict,facts):
                raise ValueError('time_facts_must_recompute_from_bound_snapshot')
            if self.confidence_basis.time_consistency != consistency:
                raise ValueError('time_consistency_component_mismatch')
        return self


class StageRelationResult(StrictModel):
    contract_version: Literal['stage-relations-v1'] = 'stage-relations-v1'
    config_hash: Digest
    input_digest: Digest
    relations: list[StageRelation]
    diagnostics: list[dict]
    statistics: dict

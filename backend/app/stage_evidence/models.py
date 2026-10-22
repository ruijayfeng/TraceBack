"""Evidence-first Stage ⑧ contracts, independent of historical v1 relations."""
from collections import Counter
from typing import Literal

from pydantic import Field, ValidationInfo, model_validator

from app.models.alerts import EvidencePointer, canonical_pointers
from app.models.base import AlertID, Digest, StrictModel, Text, id_type
from app.stages.models import StageID
from app.utils.stable_id import content_digest
from .config import DIRECTIONAL, ASSOCIATIVE, SUPPORTING

Strength = Literal['DIRECTIONAL_STRONG', 'ASSOCIATIVE_STRONG', 'SUPPORTING_ONLY']
Direction = Literal['A_TO_B', 'B_TO_A', 'UNDIRECTED', 'NONE']
RelationType = Literal['DIRECTED_EDGE', 'UNDIRECTED_EDGE', 'NO_RELATION']


class CrossStageEvidence(StrictModel):
    evidence_id: id_type('cse')
    stage_a_id: StageID
    stage_b_id: StageID
    alert_a_id: AlertID
    alert_b_id: AlertID
    evidence_type: Text
    evidence_strength_class: Strength
    direction_claim: Direction
    raw_pointers: list[EvidencePointer] = Field(min_length=2)
    reason: Text
    temporal_check: dict
    conflict_status: list[Text]
    valid: bool
    metadata: dict

    @model_validator(mode='after')
    def closure(self, info: ValidationInfo):
        if self.stage_a_id >= self.stage_b_id or self.alert_a_id == self.alert_b_id:
            raise ValueError('distinct_canonical_cross_stage_witness_required')
        expected = ('DIRECTIONAL_STRONG' if self.evidence_type in DIRECTIONAL else
                    'ASSOCIATIVE_STRONG' if self.evidence_type in ASSOCIATIVE else
                    'SUPPORTING_ONLY' if self.evidence_type in SUPPORTING else None)
        if self.evidence_strength_class != expected:
            raise ValueError('evidence_strength_must_follow_semantics')
        allowed = {'A_TO_B', 'B_TO_A'} if expected == 'DIRECTIONAL_STRONG' else {'UNDIRECTED'} if expected == 'ASSOCIATIVE_STRONG' else {'NONE'}
        if self.direction_claim not in allowed:
            raise ValueError('direction_must_follow_evidence_semantics')
        object.__setattr__(self, 'raw_pointers', canonical_pointers(self.raw_pointers))
        if {p.alert_id for p in self.raw_pointers} != {self.alert_a_id, self.alert_b_id} or any(not p.pointer for p in self.raw_pointers):
            raise ValueError('raw_evidence_requires_both_witnesses')
        if self.valid != (not self.conflict_status):
            raise ValueError('invalid_witness_requires_conflict_diagnostics')
        identity = {k:v for k,v in self.model_dump(mode='json').items() if k != 'evidence_id'}
        if self.evidence_id != 'cse_' + content_digest(identity):
            raise ValueError('cross_stage_evidence_identity_mismatch')
        context = info.context or {}
        if 'alerts' in context:
            for p in self.raw_pointers:
                p.resolve(context['alerts'])
        if 'stages' in context:
            for sid, aid in ((self.stage_a_id,self.alert_a_id),(self.stage_b_id,self.alert_b_id)):
                if aid not in context['stages'][sid].alert_ids:
                    raise ValueError('witness_outside_stage')
        return self


class StageRelationDecision(StrictModel):
    candidate_id: id_type('scp')
    stage_a_id: StageID
    stage_b_id: StageID
    relation_type: RelationType
    direction_claim: Direction
    from_stage_id: StageID | None
    to_stage_id: StageID | None
    primary_evidence_id: id_type('cse') | None
    supporting_evidence_ids: list[id_type('cse')]
    invalid_evidence_ids: list[id_type('cse')]
    evidence_type_counts: dict[str,int]
    directional_evidence_count: int
    associative_evidence_count: int
    supporting_only_count: int
    conflicting_evidence_count: int
    diagnostics: list[Text]
    reason: Text

    @model_validator(mode='after')
    def direction(self):
        from app.stage_candidates.models import candidate_id
        if self.stage_a_id >= self.stage_b_id:
            raise ValueError('canonical_pair_required')
        if self.candidate_id != candidate_id(self.stage_a_id,self.stage_b_id):
            raise ValueError('candidate_decision_identity_mismatch')
        if self.relation_type == 'DIRECTED_EDGE':
            endpoints = {'A_TO_B':(self.stage_a_id,self.stage_b_id), 'B_TO_A':(self.stage_b_id,self.stage_a_id)}
            if (self.from_stage_id,self.to_stage_id) != endpoints.get(self.direction_claim) or not self.primary_evidence_id:
                raise ValueError('directed_decision_requires_semantic_endpoints_and_evidence')
        elif self.from_stage_id is not None or self.to_stage_id is not None or self.direction_claim != ('UNDIRECTED' if self.relation_type == 'UNDIRECTED_EDGE' else 'NONE'):
            raise ValueError('unresolved_decision_cannot_assert_direction')
        if self.relation_type == 'UNDIRECTED_EDGE' and not self.primary_evidence_id:
            raise ValueError('edge_requires_evidence')
        if self.relation_type == 'NO_RELATION' and not self.diagnostics:
            raise ValueError('no_relation_requires_diagnostics')
        return self


class CrossStageEvidenceResult(StrictModel):
    contract_version: Literal['stage-evidence-v1'] = 'stage-evidence-v1'
    config_hash: Digest
    input_digest: Digest
    decisions: list[StageRelationDecision]
    evidence: list[CrossStageEvidence]
    statistics: dict

    @model_validator(mode='after')
    def closed(self):
        ee = {e.evidence_id:e for e in self.evidence}
        if len(ee) != len(self.evidence) or len({d.candidate_id for d in self.decisions}) != len(self.decisions):
            raise ValueError('duplicate_evidence_or_candidate_decision')
        referenced = set()
        for d in self.decisions:
            refs = ([d.primary_evidence_id] if d.primary_evidence_id else []) + d.supporting_evidence_ids + d.invalid_evidence_ids
            if len(refs) != len(set(refs)) or set(refs) - ee.keys():
                raise ValueError('duplicate_or_dangling_evidence_reference')
            witnesses = [ee[eid] for eid in refs]
            if any((e.stage_a_id,e.stage_b_id) != (d.stage_a_id,d.stage_b_id) for e in witnesses):
                raise ValueError('decision_evidence_pair_mismatch')
            valid = [e for e in witnesses if e.valid]
            directions = {e.direction_claim for e in valid if e.evidence_strength_class == 'DIRECTIONAL_STRONG'}
            strong = [e for e in valid if e.evidence_strength_class != 'SUPPORTING_ONLY']
            expected = 'DIRECTED_EDGE' if len(directions) == 1 else 'UNDIRECTED_EDGE' if strong else 'NO_RELATION'
            if d.relation_type != expected or (expected == 'DIRECTED_EDGE' and d.direction_claim not in directions):
                raise ValueError('decision_must_aggregate_all_valid_evidence_semantics')
            if d.primary_evidence_id and (not ee[d.primary_evidence_id].valid or
                    (expected != 'NO_RELATION' and ee[d.primary_evidence_id] not in strong)):
                raise ValueError('primary_evidence_must_support_decision')
            if expected == 'DIRECTED_EDGE' and ee[d.primary_evidence_id].direction_claim != d.direction_claim:
                raise ValueError('directed_primary_must_assert_direction')
            if set(d.invalid_evidence_ids) != {e.evidence_id for e in witnesses if not e.valid}:
                raise ValueError('invalid_evidence_partition_mismatch')
            counts = Counter(e.evidence_type for e in witnesses)
            sizes = Counter(e.evidence_strength_class for e in valid)
            if d.evidence_type_counts != dict(counts) or (d.directional_evidence_count,d.associative_evidence_count,d.supporting_only_count) != tuple(sizes[k] for k in ('DIRECTIONAL_STRONG','ASSOCIATIVE_STRONG','SUPPORTING_ONLY')):
                raise ValueError('witness_summary_mismatch')
            if len(directions) > 1 and 'DIRECTION_CONFLICT' not in d.diagnostics:
                raise ValueError('direction_conflict_requires_diagnostic')
            if d.conflicting_evidence_count != sum(not e.valid for e in witnesses) + (len([e for e in valid if e.evidence_strength_class == 'DIRECTIONAL_STRONG']) if len(directions)>1 else 0):
                raise ValueError('conflicting_witness_summary_mismatch')
            referenced.update(refs)
        if referenced != ee.keys():
            raise ValueError('orphan_evidence')
        return self

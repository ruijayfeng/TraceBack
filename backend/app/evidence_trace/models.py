"""Read-only trace projections; existing domain contracts stay unchanged."""
from typing import Annotated, Literal

from pydantic import Field, model_validator

from app.models.alerts import EvidencePointer
from app.models.base import (AlertID, AnalysisID, Digest, StrictModel, Text,
                             UTCDateTime, ids, id_type)
from app.stage_relations.models import DirectionBasis, RelationEvidence, RelationType
from app.stages.models import Behavior, BehaviorAnnotation, Stage, StageID


class RawEvidenceRef(StrictModel):
    """Resolve within one snapshot, never against a file path or another alert."""
    analysis_id: AnalysisID
    alert_id: AlertID
    raw_fingerprint: Digest
    field: Literal['raw_alert'] = 'raw_alert'


class WitnessAlert(StrictModel):
    alert_id: AlertID
    source_type: Text
    timestamp: UTCDateTime
    alert_type: Text | None
    signature: Text | None
    behavior: Behavior
    raw_ref: RawEvidenceRef


class EvidenceTrace(StrictModel):
    contract_version: Literal['evidence-trace-v1'] = 'evidence-trace-v1'
    analysis_id: AnalysisID
    subject_type: Literal['STAGE', 'STRONG_DIRECTED_EDGE', 'STRONG_UNDIRECTED_EDGE', 'WEAK_DIRECTED_RELATION']
    subject_id: Text
    trace_type: Literal['stage_membership', 'relation_decision']
    witness_alert_ids: Annotated[ids(AlertID), Field(min_length=1)]
    witness_alerts: list[WitnessAlert]
    raw_evidence_refs: list[RawEvidenceRef]
    evidence_type: Text
    evidence_summary: Text
    direction_basis: DirectionBasis | None
    stage: Stage | None = None
    behaviors: list[BehaviorAnnotation] = Field(default_factory=list)
    stage_a_id: StageID | None = None
    stage_b_id: StageID | None = None
    source_stage_id: StageID | None = None
    target_stage_id: StageID | None = None
    relation_type: RelationType | None = None
    primary_evidence: RelationEvidence | None = None
    supporting_evidence: list[RelationEvidence] = Field(default_factory=list)
    winning_witness_alert_ids: ids(AlertID) = Field(default_factory=list)
    evidence_pointers: list[EvidencePointer]
    temporal_order_is_causal_evidence: Literal[False] = False

    @model_validator(mode='after')
    def closure(self):
        expected = self.witness_alert_ids
        if ([w.alert_id for w in self.witness_alerts] != expected or
                [r.alert_id for r in self.raw_evidence_refs] != expected or
                [w.raw_ref for w in self.witness_alerts] != self.raw_evidence_refs):
            raise ValueError('trace_witness_closure_mismatch')
        if any(r.analysis_id != self.analysis_id for r in self.raw_evidence_refs):
            raise ValueError('trace_crosses_snapshot')
        if any(p.alert_id not in expected for p in self.evidence_pointers):
            raise ValueError('trace_pointer_outside_witnesses')
        if self.subject_type == 'STAGE':
            if (self.trace_type != 'stage_membership' or self.stage is None or
                    self.subject_id != self.stage.stage_id or expected != self.stage.alert_ids or
                    [b.alert_id for b in self.behaviors] != expected or
                    self.direction_basis is not None or self.relation_type is not None or
                    self.primary_evidence is not None or self.supporting_evidence or
                    self.winning_witness_alert_ids or any(x is not None for x in
                    (self.stage_a_id, self.stage_b_id, self.source_stage_id, self.target_stage_id))):
                raise ValueError('invalid_stage_trace')
            if any((b.community_id, b.behavior) != (self.stage.community_id, self.stage.behavior) for b in self.behaviors):
                raise ValueError('stage_trace_behavior_mismatch')
        else:
            mapping = {'STRONG_DIRECTED': ('STRONG_DIRECTED_EDGE', 'evidence_semantics'),
                       'STRONG_UNDIRECTED': ('STRONG_UNDIRECTED_EDGE', 'unresolved'),
                       'WEAK_DIRECTED': ('WEAK_DIRECTED_RELATION', 'temporal_order')}
            if (self.trace_type != 'relation_decision' or self.primary_evidence is None or
                    mapping.get(self.relation_type) != (self.subject_type, self.direction_basis) or
                    self.stage is not None or self.behaviors or
                    self.stage_a_id is None or self.stage_b_id is None or self.stage_a_id == self.stage_b_id):
                raise ValueError('invalid_relation_trace')
            if self.winning_witness_alert_ids != self.primary_evidence.alert_ids:
                raise ValueError('winning_witness_mismatch')
            if self.evidence_type != self.primary_evidence.evidence_type or self.primary_evidence.strong != (self.relation_type != 'WEAK_DIRECTED'):
                raise ValueError('trace_primary_evidence_mismatch')
            if expected != sorted({a for e in [self.primary_evidence, *self.supporting_evidence] for a in e.alert_ids}):
                raise ValueError('relation_witness_closure_mismatch')
            if self.relation_type == 'STRONG_UNDIRECTED':
                if self.source_stage_id is not None or self.target_stage_id is not None:
                    raise ValueError('undirected_trace_cannot_assert_direction')
            elif {self.source_stage_id, self.target_stage_id} != {self.stage_a_id, self.stage_b_id}:
                raise ValueError('directed_trace_endpoint_mismatch')
            if self.relation_type == 'STRONG_DIRECTED' and (self.source_stage_id, self.target_stage_id) != (
                    self.primary_evidence.semantic_direction.from_stage_id, self.primary_evidence.semantic_direction.to_stage_id):
                raise ValueError('trace_direction_differs_from_winning_semantics')
        from app.models.alerts import canonical_pointers
        expected_pointers = ([p for b in self.behaviors for p in b.evidence] +
                             [p for b in self.stage.aggregation_basis for p in b.evidence] if self.stage else
                             [p for e in [self.primary_evidence, *self.supporting_evidence] for p in e.pointers])
        if self.evidence_pointers != canonical_pointers(expected_pointers):
            raise ValueError('trace_evidence_pointer_mismatch')
        return self


class ChainReference(StrictModel):
    """Caller-supplied references from an EXISTING chain, not a chain builder.

    No ID is generated, no path is selected, no relation is added or removed.
    An upstream exporter can project its existing chain into this input shape.
    """
    chain_id: Text
    stage_ids: Annotated[ids(StageID), Field(min_length=1)]
    relation_ids: ids(id_type('str'))


class ChainTrace(StrictModel):
    contract_version: Literal['evidence-trace-v1'] = 'evidence-trace-v1'
    analysis_id: AnalysisID
    chain: ChainReference
    stage_traces: list[EvidenceTrace]
    relation_traces: list[EvidenceTrace]

    @model_validator(mode='after')
    def closure(self):
        if ([t.subject_id for t in self.stage_traces] != self.chain.stage_ids or
                [t.subject_id for t in self.relation_traces] != self.chain.relation_ids):
            raise ValueError('chain_trace_reference_mismatch')
        if any(t.subject_type != 'STAGE' for t in self.stage_traces):
            raise ValueError('chain_requires_stage_traces')
        for trace in [*self.stage_traces, *self.relation_traces]:
            if trace.analysis_id != self.analysis_id:
                raise ValueError('chain_trace_crosses_snapshot')
        for trace in self.relation_traces:
            if trace.subject_type == 'STAGE' or {trace.stage_a_id, trace.stage_b_id} - set(self.chain.stage_ids):
                raise ValueError('chain_relation_endpoint_missing')
        return self

"""Closed graph references and existing Evidence Trace resolution. No algorithms."""
from copy import deepcopy

from app.evidence_trace import ChainReference, ChainTrace, EvidenceTrace
from app.stage_relations.models import StageRelation
from app.stages.models import Stage
from app.utils.stable_id import content_digest
from .models import TraceReference

SUBJECTS = {'STRONG_DIRECTED': 'STRONG_DIRECTED_EDGE', 'STRONG_UNDIRECTED': 'STRONG_UNDIRECTED_EDGE',
            'WEAK_DIRECTED': 'WEAK_DIRECTED_RELATION'}


def model_index(values, model, key):
    result = {}
    for value in values:
        value = model.model_validate(deepcopy(value))
        identity = getattr(value, key)
        if identity in result:
            raise ValueError('duplicate_stage_chain_input:' + identity)
        result[identity] = value
    return dict(sorted(result.items()))


class StageGraphSnapshot:
    """Copies existing objects; a resolver reads the original raw evidence only."""
    def __init__(self, stages, relations, evidence_traces, trace_index):
        self.source_analysis_id = trace_index.analysis_id
        self.trace_index = trace_index
        self.stages = model_index(stages, Stage, 'stage_id')
        self.relations = model_index(relations, StageRelation, 'relation_id')
        self.traces = model_index(evidence_traces, EvidenceTrace, 'subject_id')
        if set(self.traces) != set(self.stages) | set(self.relations):
            raise ValueError('existing_trace_coverage_mismatch')
        if set(self.stages) != set(trace_index.stage_ids) or set(self.relations) != set(trace_index.relation_ids):
            raise ValueError('existing_trace_resolver_coverage_mismatch')
        for sid, stage in self.stages.items():
            trace = self.traces[sid]
            if trace.subject_type != 'STAGE' or trace.stage != stage or trace != trace_index.stage_trace(sid):
                raise ValueError('existing_stage_trace_differs_from_source')
        for rid, relation in self.relations.items():
            if {relation.stage_a_id, relation.stage_b_id} - self.stages.keys():
                raise ValueError('dangling_stage_reference:' + rid)
            if any(self.stages[sid].community_id != relation.community_id
                   for sid in (relation.stage_a_id, relation.stage_b_id)):
                raise ValueError('relation_crosses_community')
            trace = self.traces[rid]
            if trace != trace_index.relation_trace(rid) or (
                    trace.subject_type, trace.stage_a_id, trace.stage_b_id, trace.source_stage_id, trace.target_stage_id,
                    trace.relation_type, trace.direction_basis, trace.primary_evidence, trace.supporting_evidence,
                    trace.witness_alert_ids, trace.evidence_summary, trace.evidence_type) != (
                    SUBJECTS[relation.relation_type], relation.stage_a_id, relation.stage_b_id,
                    relation.from_stage_id, relation.to_stage_id, relation.relation_type, relation.direction_basis,
                    relation.primary_evidence, relation.supporting_evidence, relation.witness_alert_ids,
                    relation.reason, relation.evidence_type):
                raise ValueError('existing_relation_trace_differs_from_source')
        for trace in self.traces.values():
            self.resolve_trace(TraceReference(analysis_id=trace.analysis_id,
                subject_type=trace.subject_type, subject_id=trace.subject_id))
        self.input_digest = content_digest(dict(source_analysis_id=self.source_analysis_id,
            stages=[s.model_dump(mode='json') for s in self.stages.values()],
            relations=[r.model_dump(mode='json') for r in self.relations.values()],
            traces=[t.model_dump(mode='json') for t in self.traces.values()]))

    def resolve_trace(self, ref):
        ref = TraceReference.model_validate(ref)
        trace = self.traces.get(ref.subject_id)
        if ref.analysis_id != self.source_analysis_id or trace is None or trace.subject_type != ref.subject_type:
            raise ValueError('dangling_evidence_reference:' + ref.subject_id)
        for raw in trace.raw_evidence_refs:
            self.trace_index.raw_evidence(raw)
        for pointer in trace.evidence_pointers:
            self.trace_index.resolve_evidence(pointer)
        return trace.model_copy(deep=True)

    def references(self, stage_ids, relation_ids):
        return sorted([TraceReference(analysis_id=self.source_analysis_id, subject_type=self.traces[sid].subject_type,
                                      subject_id=sid) for sid in [*stage_ids, *relation_ids]],
                      key=lambda ref:(ref.subject_type, ref.subject_id))

    def chain_trace(self, chain):
        """Compose the existing ChainTrace model without altering its module."""
        expected = self.references(chain.stage_ids, chain.relation_ids)
        if chain.evidence_refs != expected or chain.source_analysis_id != self.source_analysis_id:
            raise ValueError('chain_evidence_reference_mismatch')
        by_id = {ref.subject_id:self.resolve_trace(ref) for ref in chain.evidence_refs}
        return ChainTrace(analysis_id=self.source_analysis_id,
            chain=ChainReference(chain_id=chain.chain_id, stage_ids=chain.stage_ids, relation_ids=chain.relation_ids),
            stage_traces=[by_id[sid] for sid in chain.stage_ids],
            relation_traces=[by_id[rid] for rid in chain.relation_ids])

    def chain_graph(self, chain):
        """Return existing Stage/Relation objects; no replacement edge schema."""
        return dict(stages=[self.stages[sid].model_copy(deep=True) for sid in chain.stage_ids],
                    relations=[self.relations[rid].model_copy(deep=True) for rid in chain.relation_ids])

"""Observe existing decisions. No scoring, clustering, direction or chain calls."""
from copy import deepcopy

from app.models import CanonicalAlert
from app.models.alerts import canonical_pointers
from app.models.base import resolve_pointer
from app.stage_relations.models import StageRelation
from app.stages.models import BehaviorAnnotation, Stage
from .models import ChainReference, ChainTrace, EvidenceTrace, RawEvidenceRef, WitnessAlert


def _index(values, model, key):
    result = {}
    for value in values:
        value = model.model_validate(deepcopy(value))
        identity = getattr(value, key)
        if identity in result:
            raise ValueError('duplicate_trace_input_id:' + identity)
        result[identity] = value
    return dict(sorted(result.items()))


class EvidenceTraceIndex:
    def __init__(self, analysis_id, alerts, stages, behaviors, relations, chains=()):
        # Validate the snapshot identity even when every supplied collection is empty.
        from pydantic import TypeAdapter
        from app.models.base import AnalysisID
        self.analysis_id = TypeAdapter(AnalysisID).validate_python(analysis_id, strict=True)
        self._alerts = _index(alerts, CanonicalAlert, 'alert_id')
        self._stages = _index(stages, Stage, 'stage_id')
        self._behaviors = _index(behaviors, BehaviorAnnotation, 'alert_id')
        self._relations = _index(relations, StageRelation, 'relation_id')
        self._chains = _index(chains, ChainReference, 'chain_id')
        self._validate_closure()

    def _pointer(self, pointer, allowed):
        if pointer.alert_id not in allowed or pointer.alert_id not in self._alerts:
            raise ValueError('dangling_evidence_alert:' + pointer.alert_id)
        pointer.resolve(self._alerts)

    def _validate_closure(self):
        covered = [aid for stage in self._stages.values() for aid in stage.alert_ids]
        if sorted(covered) != sorted(self._alerts) or sorted(covered) != sorted(self._behaviors):
            raise ValueError('stage_behavior_alert_partition_mismatch')
        for stage in self._stages.values():
            Stage.model_validate(stage, context={'alerts': self._alerts})
            for aid in stage.alert_ids:
                behavior = self._behaviors[aid]
                if (behavior.community_id, behavior.behavior) != (stage.community_id, stage.behavior):
                    raise ValueError('stage_behavior_binding_mismatch')
                for pointer in behavior.evidence:
                    self._pointer(pointer, [aid])
            for basis in stage.aggregation_basis:
                for pointer in basis.evidence:
                    self._pointer(pointer, basis.alert_ids)
        for alert in self._alerts.values():
            for provenance in alert.field_provenance.values():
                resolve_pointer(alert.raw_alert, provenance.raw_pointer)
        for relation in self._relations.values():
            if {relation.stage_a_id, relation.stage_b_id} - self._stages.keys():
                raise ValueError('dangling_relation_stage:' + relation.relation_id)
            pair = [self._stages[sid] for sid in (relation.stage_a_id, relation.stage_b_id)]
            if any(s.community_id != relation.community_id for s in pair):
                raise ValueError('relation_community_mismatch')
            for evidence in [relation.primary_evidence, *relation.supporting_evidence]:
                if any(len(set(evidence.alert_ids) & set(s.alert_ids)) != 1 for s in pair):
                    raise ValueError('witness_alert_stage_binding_mismatch')
                for pointer in evidence.pointers:
                    self._pointer(pointer, evidence.alert_ids)
                direction = evidence.semantic_direction
                if direction and ({direction.from_stage_id, direction.to_stage_id} != {s.stage_id for s in pair} or
                        direction.from_alert_id not in self._stages[direction.from_stage_id].alert_ids or
                        direction.to_alert_id not in self._stages[direction.to_stage_id].alert_ids):
                    raise ValueError('semantic_witness_binding_mismatch')
        for chain in self._chains.values():
            self._check_chain(chain)

    def _check_chain(self, chain):
        if set(chain.stage_ids) - self._stages.keys() or set(chain.relation_ids) - self._relations.keys():
            raise ValueError('dangling_chain_reference:' + chain.chain_id)
        if len({self._stages[sid].community_id for sid in chain.stage_ids}) != 1:
            raise ValueError('chain_crosses_communities')
        for rid in chain.relation_ids:
            relation = self._relations[rid]
            if {relation.stage_a_id, relation.stage_b_id} - set(chain.stage_ids):
                raise ValueError('chain_relation_endpoint_missing')

    def _ref(self, aid):
        alert = self._alerts[aid]
        return RawEvidenceRef(analysis_id=self.analysis_id, alert_id=aid, raw_fingerprint=alert.raw_fingerprint)

    def _witnesses(self, aids):
        return [WitnessAlert(alert_id=aid, source_type=self._alerts[aid].source_type.value,
            timestamp=self._alerts[aid].timestamp, alert_type=self._alerts[aid].alert_type,
            signature=self._alerts[aid].signature, behavior=self._behaviors[aid].behavior,
            raw_ref=self._ref(aid)) for aid in aids]

    def raw_evidence(self, ref):
        ref = RawEvidenceRef.model_validate(ref)
        if ref.analysis_id != self.analysis_id or ref.alert_id not in self._alerts:
            raise ValueError('raw_evidence_snapshot_or_alert_missing')
        if ref != self._ref(ref.alert_id):
            raise ValueError('raw_evidence_fingerprint_mismatch')
        return deepcopy(self._alerts[ref.alert_id].raw_evidence)

    def resolve_evidence(self, pointer):
        from app.models.alerts import EvidencePointer
        pointer = EvidencePointer.model_validate(pointer)
        return deepcopy(pointer.resolve(self._alerts))

    def stage_trace(self, stage_id):
        stage = self._stages[stage_id]
        annotations = [self._behaviors[aid] for aid in stage.alert_ids]
        pointers = canonical_pointers([p for b in annotations for p in b.evidence] +
                                      [p for b in stage.aggregation_basis for p in b.evidence])
        return EvidenceTrace(analysis_id=self.analysis_id, subject_type='STAGE', subject_id=stage_id,
            trace_type='stage_membership', witness_alert_ids=stage.alert_ids,
            witness_alerts=self._witnesses(stage.alert_ids), raw_evidence_refs=[self._ref(a) for a in stage.alert_ids],
            evidence_type='existing_stage_membership', evidence_summary=stage.evidence_summary,
            direction_basis=None, stage=stage.model_copy(deep=True),
            behaviors=deepcopy(annotations), evidence_pointers=pointers)

    def relation_trace(self, relation_id):
        relation = self._relations[relation_id]
        subject = {'STRONG_DIRECTED': 'STRONG_DIRECTED_EDGE', 'STRONG_UNDIRECTED': 'STRONG_UNDIRECTED_EDGE',
                   'WEAK_DIRECTED': 'WEAK_DIRECTED_RELATION'}[relation.relation_type]
        evidence = [relation.primary_evidence, *relation.supporting_evidence]
        return EvidenceTrace(analysis_id=self.analysis_id, subject_type=subject, subject_id=relation_id,
            trace_type='relation_decision', witness_alert_ids=relation.witness_alert_ids,
            witness_alerts=self._witnesses(relation.witness_alert_ids),
            raw_evidence_refs=[self._ref(a) for a in relation.witness_alert_ids],
            evidence_type=relation.evidence_type, evidence_summary=relation.reason,
            direction_basis=relation.direction_basis, stage_a_id=relation.stage_a_id, stage_b_id=relation.stage_b_id,
            source_stage_id=relation.from_stage_id, target_stage_id=relation.to_stage_id,
            relation_type=relation.relation_type, primary_evidence=deepcopy(relation.primary_evidence),
            supporting_evidence=deepcopy(relation.supporting_evidence),
            winning_witness_alert_ids=relation.primary_evidence.alert_ids,
            evidence_pointers=canonical_pointers([p for e in evidence for p in e.pointers]))

    def chain_trace(self, chain_id):
        chain = self._chains[chain_id]
        return ChainTrace(analysis_id=self.analysis_id, chain=chain.model_copy(deep=True),
            stage_traces=[self.stage_trace(sid) for sid in chain.stage_ids],
            relation_traces=[self.relation_trace(rid) for rid in chain.relation_ids])

    def validate(self):
        """Exhaustively resolve every trace and raw record, without algorithm replay."""
        pointer_count = 0
        for trace in [*(self.stage_trace(s) for s in self._stages),
                      *(self.relation_trace(r) for r in self._relations)]:
            for ref in trace.raw_evidence_refs:
                self.raw_evidence(ref)
            for pointer in trace.evidence_pointers:
                self.resolve_evidence(pointer)
                pointer_count += 1
        for cid in self._chains:
            self.chain_trace(cid)
        return dict(stage_count=len(self._stages), relation_count=len(self._relations),
            chain_count=len(self._chains), alert_count=len(self._alerts),
            evidence_pointers_resolved=pointer_count, dangling_reference_count=0)

    @property
    def stage_ids(self):
        return tuple(self._stages)

    @property
    def relation_ids(self):
        return tuple(self._relations)

    @property
    def chain_ids(self):
        return tuple(self._chains)

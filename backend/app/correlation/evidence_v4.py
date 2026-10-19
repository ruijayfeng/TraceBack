"""Conservative role informativeness and explicit flow context for v4."""
from .evidence_v3 import EvidenceV3Evaluator


class EvidenceV4Evaluator(EvidenceV3Evaluator):
    def __init__(self, scorer):
        super().__init__(scorer)
        self.policy = scorer.algorithm.score.evidence_v4

    def detector_different(self, a, b):
        return a.source_namespace == b.source_namespace and any(
            getattr(a, f) is not None and getattr(b, f) is not None and getattr(a, f) != getattr(b, f)
            for f in self.policy.primary_detector_fields)

    def metadata_support(self, metadata):
        selected = [d for d in metadata if d['dimension'].removeprefix('semantic.') in self.policy.metadata_support_fields]
        return (any(d['state'].startswith('AVAILABLE') for d in selected),
                max((d['strength'] for d in selected), default=0.) * self.repair.metadata_cap)

    def network(self, a, b):
        observable, strength, ids, reason = super().network(a, b)
        if not strength:
            return observable, strength, ids, reason
        src, dst = sorted((a, b), key=lambda x: (self.scorer.index.times[x.alert_id], x.alert_id))
        if src.category.value == 'unknown' or dst.category.value == 'unknown':
            return False, 0., [], 'network_behavior_context_unavailable'
        compatible = src.category != dst.category and self.scorer.behavior_value(src, dst) >= self.repair.network_behavior_minimum
        if not compatible:
            return True, 0., [], 'network_behavior_context_incompatible'
        return observable, strength, ids, reason

    def evaluate(self, a, b, values, features, relations, refused, source_state, hard):
        idx = self.scorer.index
        adjusted = []
        for feature in features:
            eid = feature['entity_id']
            if feature['type'] == 'IP' and idx.roles[a.alert_id][eid] == {'dst_ip'} and idx.roles[b.alert_id][eid] == {'dst_ip'}:
                feature = {**feature, 'role_factor': feature['role_factor'] * self.policy.destination_only_ip_factor}
            adjusted.append(feature)
        raw, score, audit = super().evaluate(a, b, values, adjusted, relations, refused, source_state, hard)
        audit['version'] = 'v4'
        return raw, score, audit

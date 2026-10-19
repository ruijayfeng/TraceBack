"""Observe every scored candidate; no values flow back to production."""

from array import array
from collections import Counter, defaultdict
import heapq
import math

from app.services.bounded_diagnostics import BoundedDiagnostics, ColumnarStream, dumps

from .common import FAMILIES, distribution, pair_source, ratio, source


class FrozenBudgetBlocked(RuntimeError):
    pass


def attribution(member, config):
    ev = member['evidence']['evidence_v2']
    aw, tw = ev['available_weight'], ev['total_configured_weight']
    coefficient = ev['quality_factor']/aw if aw else 0
    coefficient += ev['mass_factor']/tw if tw else 0
    families = {k: coefficient*ev['family_weights'][k]*v for k, v in ev['family_strengths'].items()}
    penalties = {k: -getattr(config.algorithm.score.weights, k)*member['values'][k] for k in ('conflict', 'duplicate')}
    error = abs(math.fsum((*families.values(), *penalties.values()))-member['raw_total'])
    if error > .00001:
        raise ValueError('v3_effective_attribution_mismatch')
    return {'effective_family_contributions': families, 'penalties': penalties,
        'legacy_contributions': member['contributions'], 'recomputed_raw_total': math.fsum((*families.values(), *penalties.values())),
        'note': 'legacy seven-term contributions are audit values, not the v3 final score formula'}


def missing_dimensions(ev):
    return {state: [d['dimension'] for d in ev['dimensions'] if d['state'] == state]
        for state in ('NOT_APPLICABLE', 'UNAVAILABLE', 'AVAILABLE_MISMATCH')} | {
        'PRESENT_BUT_WEAK': [d['dimension'] for d in ev['dimensions'] if d['state'] == 'AVAILABLE_MATCH'
                            and d['strength'] < .6],
        'suppressed_to_avoid_double_counting': ev['suppressed_dimensions']}


def rank_sample(heap, payload, n=30):
    """Highest score first, lexical pair ascending for ties, independent of order."""
    pair = tuple(payload['decision']['support_key'])
    item = (payload['member']['score'], tuple(-ord(c) for c in '\0'.join(pair)), pair, payload)
    if len(heap) < n:
        heapq.heappush(heap, item)
    elif item[:3] > heap[0][:3]:
        heapq.heapreplace(heap, item)


def sample_rows(heap):
    return [v[3] for v in sorted(heap, key=lambda v: (-v[0], v[2]))]


class Observer(BoundedDiagnostics):
    def __init__(self, directory, handle, config):
        super().__init__(directory, handle)
        self.config = config
        self.scores = array('d')
        self.valid_scores = array('d')
        self.family_candidates, self.family_edges = Counter(), Counter()
        self.continuity_candidates, self.continuity_edges = Counter(), Counter()
        self.dim_states, self.rejected_states = Counter(), Counter()
        self.family_strengths = defaultdict(lambda: [0, 0., 0])
        self.source_pairs, self.role_pairs = Counter(), Counter()
        self.participation, self.edge_participation = Counter(), Counter()
        self.coverage_bins = Counter()
        self.candidate_taxonomy = Counter()
        self.top_rejected, self.near, self.accepted, self.strata = [], [], [], {}
        self.candidate_summary = None
        self.audit_errors = []
        self.compact = ColumnarStream(directory/'task_c_candidate_index',
            'source_id VARCHAR, target_id VARCHAR, member_a VARCHAR, member_b VARCHAR, score DOUBLE, decision VARCHAR, evidence_decision VARCHAR, gate_reason VARCHAR, shared_count BIGINT, primary_count BIGINT')

    def prepare_candidates(self, index, candidates):
        self.index = index
        self.candidate_summary = {'potential_pair_stats': candidates.potential_pair_stats,
            'admitted_candidate_count': candidates.admitted_count, 'scheduled_candidate_count': len(candidates.pairs),
            'resource_truncated_count': candidates.resource_truncated_count,
            'policy_pruned_count': candidates.policy_pruned_count,
            'candidate_admission_stats': candidates.candidate_admission_stats}
        if candidates.candidate_truncated:
            # Task C requires complete cross-dataset evaluation. Scoring the
            # retained budget cannot recover omitted candidates; do not publish
            # a partial formal graph as a completed dataset comparison.
            raise FrozenBudgetBlocked('frozen_max_candidate_pairs_resource_truncation')
        return super().prepare_candidates(index, candidates)

    def __call__(self, row):
        if row.get('stage') == 'correlation_decision' and self.best:
            chosen = (self.valid_best or self.best)[1]
            self.observe(self.current, chosen, row)
        super().__call__(row)

    def observe(self, candidate, member, decision):
        ev = member['evidence']['evidence_v2']
        self.scores.append(member['score'])
        if decision['score'] is not None:
            self.valid_scores.append(decision['score'])
        a, b = (self.index.alerts[i] for i in member['support_pair'])
        sp = pair_source(a, b)
        accepted = decision['decision'] == 'accept'
        self.source_pairs[(sp, decision['decision'])] += 1
        for src in {source(a), source(b)}:
            self.participation[src] += 1
            self.edge_participation[src] += int(accepted)
        host = lambda x: bool(x.host or x.process or x.account)
        network = lambda x: bool(x.src_ip and x.dst_ip)
        self.role_pairs[('Host ↔ Network' if host(a) and network(b) or host(b) and network(a)
                         else 'other', decision['decision'])] += 1
        for family in set(ev['evidence_families']):
            self.family_candidates[family] += 1
            self.family_edges[family] += int(accepted)
        matching = {d['dimension'] for d in ev['dimensions']
                    if d['state'] == 'AVAILABLE_MATCH' and d['strength'] > 0}
        continuity = {
            'entity_continuity': any(d.startswith('entity.') for d in matching),
            'network_continuity': ev['network_continuity_valid'],
            'session_continuity': 'entity.SESSION' in matching,
            'process_continuity': 'entity.PROCESS' in matching,
            'account_continuity': 'entity.ACCOUNT' in matching,
            'resource_continuity': bool(matching & {'entity.FILE', 'entity.COMMAND', 'entity.DOMAIN', 'entity.URL'}),
            'temporal_evidence': 'TEMPORAL' in ev['evidence_families'],
            'relation_evidence': bool(ev['relation_support']),
        }
        for name, observed in continuity.items():
            self.continuity_candidates[name] += int(observed)
            self.continuity_edges[name] += int(observed and accepted)
        for dimension in ev['dimensions']:
            key = (dimension['dimension'], dimension['state'])
            self.dim_states[key] += 1
            if not accepted:
                self.rejected_states[key] += 1
        for family, strength in ev['family_strengths'].items():
            row = self.family_strengths[family]
            row[0] += 1
            row[1] += strength
            row[2] += int(strength > 0)
        shared = set(a.entity_ids) & set(b.entity_ids)
        hot = any(f['hot'] for f in ev['entity_reliability'])
        thin = any(d['state'] in ('NOT_APPLICABLE', 'UNAVAILABLE') and d['dimension'].startswith('entity.')
                   for d in ev['dimensions'])
        annotations = {
            'F1': thin and not accepted, 'F2': not shared and not accepted,
            'F3': hot and not accepted, 'F5': ev['network_diagnostic'] == 'network_fields_unavailable' and not accepted,
            'F6': not a.host or not b.host, 'F9': not ev['evidence_gate_passed'] and not accepted,
            'F10': accepted and not ev['relation_support'],
            'F11': .5 <= member['score'] < .65 and not accepted,
            'F13': hot and not ev['primary_evidence'] and not accepted,
            'F14': ev['metadata_dominated'] and not accepted,
            'F15': source(a) != source(b) and not shared and not accepted}
        for code, triggered in annotations.items():
            self.candidate_taxonomy[code] += int(triggered)
        availability = sum(d['state'].startswith('AVAILABLE') for d in ev['dimensions'] if d['dimension'].startswith('entity.'))
        self.coverage_bins[(availability, decision['decision'], ev['decision'])] += 1
        self.compact.add((*decision['support_key'], *member['support_pair'], member['score'],
            decision['decision'], ev['decision'], ev['gate_reason'], len(shared), len(ev['primary_evidence'])))
        payload = {'candidate': candidate, 'member': member, 'decision': decision}
        if not accepted:
            rank_sample(self.top_rejected, payload)
            if .5 <= member['score'] < .65:
                rank_sample(self.near, payload)
        else:
            rank_sample(self.accepted, payload)
            if (not ev['primary_evidence'] or ev['duplicate_observation_risk'] or ev['metadata_dominated']
                    or member['score'] < self.config.algorithm.score.correlation_threshold):
                self.audit_errors.append({'type': 'formal_edge_violates_v3_admission', 'payload': payload})
        for key in (sp, ev['gate_reason'], ev['network_diagnostic']):
            h = self.strata.setdefault(key, [])
            rank_sample(h, payload, 3)

    def finish_observation(self):
        self.compact.close()
        def rows(counter):
            return [{'dimension': k[0], 'state': k[1], 'count': v} for k, v in sorted(counter.items())]
        n, e = len(self.scores), self.counts.get('accept', 0)
        samples = {'near_threshold': sample_rows(self.near), 'top_rejected': sample_rows(self.top_rejected),
                   'top_admitted': sample_rows(self.accepted),
                   'stratified': {k: sample_rows(v) for k, v in sorted(self.strata.items())}}
        return {'scores': {'all_scored_candidates': distribution(self.scores),
            'valid_winning_candidates': distribution(self.valid_scores),
            'score_population': 'highest valid member score; highest observed rejected member score when no member is valid',
            'note': 'numeric score >=0.65 is insufficient without evidence gate and hard guards'},
            'evidence': {'candidate_count': n, 'edge_count': e,
                'candidate_evidence_distribution': {f: {'count': self.family_candidates[f], 'rate': ratio(self.family_candidates[f], n)} for f in FAMILIES},
                'formal_edge_evidence_distribution': {f: {'count': self.family_edges[f], 'rate': ratio(self.family_edges[f], e)} for f in FAMILIES},
                'candidate_continuity_observations': {k: {'count': v, 'rate': ratio(v, n)} for k, v in sorted(self.continuity_candidates.items())},
                'formal_edge_continuity_observations': {k: {'count': v, 'rate': ratio(v, e)} for k, v in sorted(self.continuity_edges.items())},
                'continuity_note': 'views of existing positive matching dimensions/verified relations, not additional scoring families or independent evidence; process matching alone is not an attested process-instance propagation',
                'dimension_states_all_candidates': rows(self.dim_states), 'dimension_states_rejected': rows(self.rejected_states),
                'strengths': {k: {'count': v[0], 'mean': ratio(v[1], v[0]), 'nonzero': v[2]} for k, v in sorted(self.family_strengths.items())},
                'availability_vs_admission': [{'available_entity_dimensions': k[0], 'decision': k[1],
                    'evidence_decision': k[2], 'count': v} for k, v in sorted(self.coverage_bins.items())],
                'missing_semantics': {'NOT_APPLICABLE': 'both sides absent OR suppressed dependence; inspect suppressed_dimensions',
                    'UNAVAILABLE': 'one side missing / prerequisite unobserved', 'AVAILABLE_MISMATCH': 'both observed but not matched',
                    'AVAILABLE_MATCH': 'observed matching dimension; a weak match need not meet primary evidence guard'}},
            'source_pairs': [{'source_pair': k[0], 'decision': k[1], 'count': v} for k, v in sorted(self.source_pairs.items())],
            'host_network_pairs': [{'combination': k[0], 'decision': k[1], 'count': v} for k, v in sorted(self.role_pairs.items())],
            'source_candidate_participation': dict(self.participation), 'source_edge_participation': dict(self.edge_participation),
            'candidate_taxonomy': dict(self.candidate_taxonomy), 'samples': samples,
            'implementation_defect_candidates': self.audit_errors}

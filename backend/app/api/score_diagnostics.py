"""Read-only, offline score audit. No production writes or algorithm overrides.

The workbench only reads a separately generated receipt. Expensive diagnostics
are never run by a GET request, nor passed to AI grounding.
"""
from collections import Counter
import heapq
import json
import math
from pathlib import Path

COMPONENTS = ('time', 'entity', 'relation', 'behavior', 'source', 'conflict', 'duplicate')
LABELS = dict(time='时间证据', entity='共享实体证据', relation='显式传播关系',
              behavior='行为兼容', source='独立来源互补', conflict='冲突惩罚', duplicate='疑似重复惩罚')
IMPLEMENTATION_PATHS = ('backend/app/api/score_diagnostics.py', 'outputs/task09_1/run_diagnostics.py',
                        'backend/app/correlation/scoring.py', 'backend/app/correlation/candidates.py')
# Pinned, archived v0 implementations keep historical receipts verifiable after
# the authorized upgrade. Arbitrary receipt paths/digests never select archives.
V0_ARCHIVES = {
    'backend/app/api/score_diagnostics.py': ('4e9e0bfeae628c11ed691a6aec96f8d17f438dbcc7743c37e0c4dde5c20a7efc', 'outputs/correlation_v2/baseline_code/score_diagnostics.py'),
    'backend/app/correlation/scoring.py': ('d50822f28141ff99b020be81d0ca7f75839a368fbf4e22259ae577de37c5d8f6', 'outputs/correlation_v2/baseline_code/backend/app/correlation/scoring.py'),
    'backend/app/correlation/candidates.py': ('850d663ab5b58b6ce41736628b037fdc6a6ab4da1e21377af2e78790e332fa55', 'outputs/correlation_v2/baseline_code/backend/app/correlation/candidates.py'),
}


def component_bounds(config):
    """Supremum under fixed config, independent of finite dataset frequency.

    Two alerts expose at most two IPs and two process refs, one of every other
    type. Rarity tends to 1 as N grows; hence this is a supremum, not a claimed
    attainable score/probability. These are score-model component bounds;
    mapping activation gates are applied separately to the joint bound.
    """
    e = config.algorithm.entity
    counts = {k: min(e.max_contributors_per_type, 2 if k in {'IP', 'PROCESS'} else 1) for k in e.weights}
    entity = 1 - math.prod((1 - min(1, w)) ** counts[k] for k, w in e.weights.items())
    a = config.algorithm
    return dict(time=1.0, entity=entity, relation=max(a.relation.scores.values()),
                behavior=max(a.behavior.same_category, a.behavior.unknown_category,
                             a.behavior.unlisted_transition, *(r.score for r in a.behavior.transitions)),
                source=max(a.source.same_type_independent_score,
                           a.source.different_type_confirmed_independent_unlisted_score,
                           *(r.score for r in a.source.complement_rules)),
                conflict=1.0, duplicate=1.0)


def theoretical_config_details(config):
    """Joint scoring supremum, including frozen normalization output gates.

    Parent-child R=1 requires a shared process↔parent role bridge. For two
    shared process instances, both roles cross, so each uses other_role, not
    same_role. The alternative non-lineage relation can use all same-role
    entities. Neutral penalties can coexist by distinct ports/native rule IDs.
    Rarity tends to one; no finite dataset is claimed to attain the supremum.
    """
    bounds = component_bounds(config)
    a, e = config.algorithm, config.algorithm.entity
    mappings = config.mapping_files['normalization.category_mapping_files']
    categories = {str(m.default) for m in mappings} | {str(r.output) for m in mappings for r in m.rules}
    if categories:
        transitions={(r.from_category,r.to_category):r.score for r in a.behavior.transitions}
        bmax=max(a.behavior.unknown_category if 'unknown' in (x,y) else a.behavior.same_category if x==y
                 else transitions.get((x,y),a.behavior.unlisted_transition) for x in categories for y in categories)
    else:
        bmax=bounds['behavior']
    counts = {k:min(e.max_contributors_per_type,2 if k in {'IP','PROCESS'} else 1) for k in e.weights}
    other_complement=math.prod((1-min(1,w))**counts[k] for k,w in e.weights.items() if k!='PROCESS')
    lineage_entity=1-other_complement*(1-min(1,e.weights['PROCESS']*e.role_factors.other_role))**counts['PROCESS']
    relation_without_lineage=max(v for k,v in a.relation.scores.items() if k!='parent_child_process')
    branches=dict(parent_child_process=a.score.weights.entity*lineage_entity+a.score.weights.relation*a.relation.scores['parent_child_process'],
                  other_verified_relation=a.score.weights.entity*bounds['entity']+a.score.weights.relation*relation_without_lineage)
    source_max=bounds['source'] if any(m.rules for m in config.mapping_files['source.independence_mapping_files']) else 0.0
    shared=a.score.weights.time*bounds['time']+a.score.weights.behavior*bmax+a.score.weights.source*source_max
    return dict(max=min(1,shared+max(branches.values())),normalization_categories=sorted(categories),
        normalization_behavior_max=bmax,activated_source_max=source_max,lineage_joint_entity_supremum=lineage_entity,joint_branches=branches,
        scorer_only_optimistic_bound=min(1,sum(getattr(a.score.weights,k)*bounds[k] for k in COMPONENTS[:5])),
        kind='joint_supremum_with_fixed_category_source_mapping_gates_and_process_role_coexistence')


def theoretical_config_max(config):
    return theoretical_config_details(config)['max']


class ScoreAudit:
    def __init__(self, config, top_n=20, pair_sources=None):
        self.config, self.top_n = config, top_n
        self.threshold = config.algorithm.score.correlation_threshold
        self.bounds = component_bounds(config)
        self.count = self.member_count = self.passed = 0
        self.maxima = dict.fromkeys(COMPONENTS, 0.0)
        self.triggered, self.at_max, self.combo = Counter(), Counter(), Counter()
        self.combo_max, self.top = {}, []
        self.type_hits, self.type_max, self.type_counts = Counter(), Counter(), Counter()
        self.source_states, self.guards = Counter(), Counter()
        self.pending = []
        self.all_member_max = 0.0
        self.pair_sources = pair_sources or {}
        self.cross_source_count = 0

    def member(self, row):
        self.member_count += 1
        if abs(sum(row['contributions'].values()) - row['raw_total']) > 1e-12:
            raise ValueError('score_decomposition_mismatch')
        if abs(max(0, min(1, row['raw_total'])) - row['score']) > 1e-12:
            raise ValueError('score_clamp_mismatch')
        self.all_member_max = max(self.all_member_max, row['score'])
        self.pending.append(row)

    def decision(self, row):
        self.count += 1
        self.passed += row['decision'] == 'accept'
        valid = [m for m in self.pending if m['valid']]
        for m in self.pending:
            if m['support_key'] != row['support_key']:
                raise ValueError('noncontiguous_member_diagnostics')
            self.guards.update(m['rejection_codes'])
        selected = next((m for m in valid if m['support_pair'] == row['support_pair']), None)
        if selected is not None:
            if selected['score'] != row['score'] or selected['score'] != max(m['score'] for m in valid):
                raise ValueError('candidate_winner_mismatch')
            self.observe(selected)
        elif row['score'] is not None:
            raise ValueError('missing_candidate_winner')
        self.pending.clear()

    def observe(self, row):
        vals = row['values']
        for k, v in vals.items():
            self.maxima[k] = max(self.maxima[k], v)
            self.triggered[k] += v > 0
            self.at_max[k] += math.isclose(v, self.bounds[k], abs_tol=1e-12)
        self.source_states[row['source_independence']] += 1
        features = row['evidence']['entity_features']
        types = sorted({f['type'] for f in features})
        for kind in types:
            xs = [f['x'] for f in features if f['type'] == kind]
            self.type_hits[kind] += 1
            self.type_max[kind] = max(self.type_max[kind], 1 - math.prod(1 - x for x in xs))
        key = tuple([k.upper() for k in COMPONENTS[:5] if vals[k] > 0 and k != 'entity'] + types)
        if self.pair_sources and len({self.pair_sources[a] for a in row['support_pair']}) > 1:
            self.cross_source_count += 1
            key += ('CROSS_SOURCE',)
        self.combo[key] += 1
        self.combo_max[key] = max(self.combo_max.get(key, 0), row['score'])
        # Heap root is the least desirable result; equal scores prefer lower IDs.
        token = (row['score'], tuple(-ord(c) for c in '|'.join(row['support_key'])), row)
        if len(self.top) < self.top_n:
            heapq.heappush(self.top, token)
        elif token[:2] > self.top[0][:2]:
            heapq.heapreplace(self.top, token)

    def result(self):
        top = [r[2] for r in sorted(self.top, key=lambda r: (-r[0], r[2]['support_key']))]
        observed = top[0]['score'] if top else None
        weights = self.config.algorithm.score.weights
        return dict(threshold=self.threshold, theoretical_config_max=theoretical_config_max(self.config),
            theoretical_max_kind=theoretical_config_details(self.config)['kind'],
            theoretical_config_proof=theoretical_config_details(self.config),
            algebraic_positive_weight_ceiling=sum(getattr(weights, k) for k in COMPONENTS[:5]),
            observed_max=observed, highest_member_score=self.all_member_max,
            threshold_gap=max(0, self.threshold - observed) if observed is not None else None,
            scored_candidate_count=self.count, verified_member_pair_count=self.member_count,
            cross_source_candidate_count=self.cross_source_count,
            passed_threshold_count=self.passed, top_candidates=top,
            feature_reachability=[dict(component=k, label=LABELS[k], weight=getattr(weights, k),
                configured_max=self.bounds[k], configured_max_contribution=getattr(weights, k)*self.bounds[k]*(-1 if k in COMPONENTS[5:] else 1),
                observed_max=self.maxima[k], observed_max_contribution=getattr(weights, k)*self.maxima[k]*(-1 if k in COMPONENTS[5:] else 1),
                candidates_triggered=self.triggered[k], candidates_reaching_max=self.at_max[k],
                missing_evidence_count=self.count-self.triggered[k]) for k in COMPONENTS],
            entity_reachability=[dict(type=k, configured_type_weight=w,
                observed_max=self.type_max[k], candidates_triggered=self.type_hits[k])
                for k, w in self.config.algorithm.entity.weights.items()],
            evidence_co_occurrence=[dict(features=list(k), count=v, max_score=self.combo_max[k])
                for k, v in sorted(self.combo.items(), key=lambda kv: (-self.combo_max[kv[0]], -kv[1], kv[0]))],
            source_independence_counts=dict(self.source_states), rejection_codes=dict(self.guards))


def stream_diagnostics(path, config, progress=None, pair_sources=None):
    audit = ScoreAudit(config, pair_sources=pair_sources)
    with Path(path).open(encoding='utf-8') as f:
        for line in f:
            # Avoid parsing large admission records irrelevant to score auditing.
            if '"member_score"' not in line and '"correlation_decision"' not in line:
                continue
            row = json.loads(line)
            if row['stage'] == 'member_score':
                audit.member(row)
            elif row['stage'] == 'correlation_decision':
                audit.decision(row)
                if progress and audit.count % 100000 == 0:
                    progress(audit.count)
    if audit.pending:
        raise ValueError('unfinished_candidate_diagnostics')
    return audit.result()


def read_score_diagnostic(q, analysis_id):
    """Only same-analysis receipts with verified snapshot/config/source hashes."""
    store = q.ready(analysis_id)
    detail = q.analysis(analysis_id)
    if detail.get('config_version') in {'v2', 'v3'}:
        if not detail.get('correlation_v2'):
            return dict(status='unavailable', analysis_id=analysis_id, conclusion='此 v2 分析尚未发布完整评分诊断。')
        from app.services.queries import QueryError
        try:
            summary = detail['correlation_v2']
            expected = f'outputs/analyses/{analysis_id}/correlation_v2_scores.json'
            if summary['report_ref'] != expected:
                raise ValueError('v2_report_scope_mismatch')
            q.verify(q.root / expected, summary['sha256'])
            data = json.loads((q.root / expected).read_text(encoding='utf-8'))
            if (data['analysis_id'] != analysis_id or data['config_hash'] != detail['config_hash'] or
                    data['dataset_digest'] != detail['dataset_digest']):
                raise ValueError('v2_report_binding_mismatch')
            maximum = data['score_distribution']['MAX']
            threshold = detail['config_snapshot']['algorithm']['score']['correlation_threshold']
            count = detail['counts']['scored_candidate_count']
            return dict(status='available', version=detail['config_version'], analysis_id=analysis_id,
                conclusion=f"{detail['config_version']} 已核验 {count} 个候选；通过证据门槛 {data['gate_passed_candidate_count']} 个，正式关联边 {detail['counts']['correlation_edge_count']} 条。无显式传播证据的关联不生成因果边。",
                threshold=threshold, observed_max=maximum,
                threshold_gap=max(0, threshold-maximum) if maximum is not None else None,
                scored_candidate_count=count,
                passed_threshold_count=data['score_cutoffs'].get(str(threshold)), evidence_v2=data)
        except (KeyError, ValueError, OSError) as exc:
            raise QueryError(409, 'score_diagnostic_integrity_error') from exc
    path = q.root / 'outputs/task09_1' / analysis_id / 'score_diagnostics.json'
    if not path.is_file():
        return dict(status='unavailable', analysis_id=analysis_id, conclusion='此冻结快照尚未生成关联评分诊断。')
    from app.services.queries import QueryError
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if data['analysis_id'] != analysis_id or data['config_hash'] != detail['config_hash']:
            raise ValueError('scope_mismatch')
        q.verify(store.details / 'manifest.json', data['snapshot_manifest_sha256'])
        if set(data['diagnostic_implementation_hashes']) != set(IMPLEMENTATION_PATHS):
            raise ValueError('implementation_scope_mismatch')
        for name, digest in data['diagnostic_implementation_hashes'].items():
            from app.services.storage import file_digest
            archive = V0_ARCHIVES.get(name)
            if (detail.get('config_version') == 'v0' and archive and digest == archive[0] and
                    file_digest(q.root / name) != digest):
                q.verify(q.root / archive[1], digest)
            else:
                q.verify(q.root / name, digest)
        # QueryService checks all domain table digests; score file is bound to
        # the manifest's immutable diagnostics digest at generation time.
        manifest = json.loads((store.details / 'manifest.json').read_text(encoding='utf-8'))
        if data['diagnostics_sha256'] != manifest['diagnostics_digest']:
            raise ValueError('diagnostic_digest_mismatch')
        return {**data, 'status': 'available'}
    except (KeyError, ValueError, OSError) as exc:
        raise QueryError(409, 'score_diagnostic_integrity_error') from exc

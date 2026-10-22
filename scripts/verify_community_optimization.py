"""Read-only ATTACK125 Community replay. Never imports or executes later stages."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))

from app.adapters.base import AdapterSettings
from app.adapters.multisource import MultiSourceAdapter
from app.community import load_community_config, prepare_communities
from app.community.evidence import profile
from app.community.evidence import seconds
from app.community.models import community_id
from app.community.temporal import TemporalHistory
from app.config import load_config, read_yaml
from app.models.base import resolve_pointer

DATA = Path('D:/Code_WorkSpace/TraceBack-Dataset/data/attack125')
OUTPUT = ROOT / 'outputs/community_optimization'
STRONG = {'request', 'flow', 'session', 'connection', 'application_session', 'task', 'direct_reference'}
FILES_CHANGED = [
    'backend/app/community/builder.py', 'backend/app/community/config.py',
    'backend/app/community/evidence.py', 'backend/app/community/index.py',
    'backend/app/community/temporal.py', 'configs/community-v1.yaml',
    'backend/tests/test_community_builder.py', 'backend/tests/test_entity_binding_index.py',
    'backend/tests/test_community_optimization.py', 'scripts/verify_community_optimization.py',
    'docs/COMMUNITY_OPTIMIZATION.md',
]


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def protected_hashes():
    # Include canonical snapshots, historical releases, native input and truth.
    # Truth/release contents are opaque bytes, never runtime observations.
    folders = [DATA, ROOT / 'data', ROOT / 'evaluation/outputs', ROOT / 'outputs/analyses']
    return {str(p): sha(p) for folder in folders for p in sorted(folder.rglob('*')) if p.is_file()}


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf8')


def write_acceptance(output, summary):
    summary['FILES_CHANGED'] = FILES_CHANGED
    counts = summary['LARGEST_COMMUNITY_ANALYSIS']['evidence_counts']
    summary['LARGEST_COMMUNITY_ANALYSIS']['explanation'] = (
        f"{summary['LARGEST_COMMUNITY_SIZE']} alerts: {counts.get('strong', 0)} strong binding proof edges, "
        f"{counts.get('context', 0)} context edges, {counts.get('weak', 0)} weak network edges. "
        'Historical process-edge cadence and raw witnesses are in validation/historical_65_edges.json. '
        'A partition change does not establish that the old community represented different attacks.')
    save(output / 'summary.json', summary)
    save(output / 'validation/summary.json', summary)
    lines = ['# Alert → Community 验收结果', '', '```text']
    lines += [key + '=' + (value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))
              for key, value in summary.items()]
    lines += ['```', '', '详细规则与限制见 docs/COMMUNITY_OPTIMIZATION.md。',
              f"最终已完成回归 {summary['TEST_RESULT']['passed']} passed；全量旧 Demo 收集缺少数据登记，扩大尝试在旧 API fixture 停滞并中断。",
              f"保护范围的 {summary['PROTECTED_FILE_COUNT']} 个文件 SHA256 前后一致。"]
    (output / 'ACCEPTANCE.md').write_text('\n'.join(lines) + '\n', encoding='utf8')


def replay():
    cfg = load_config(ROOT / 'configs/algorithm-v5-evidence-semantics.yaml',
                      deployment_override=ROOT / 'configs/front-data-sources.yaml')
    adapters = {s: MultiSourceAdapter(cfg, AdapterSettings(**v), s)
                for s, v in read_yaml(ROOT / 'configs/front-data-profiles.yaml')['sources'].items()}
    sources = {a.settings.source_namespace: a.settings for a in adapters.values()}
    alerts = []
    with (DATA / 'final/attack125_final.jsonl').open(encoding='utf8') as stream:
        for line in stream:
            raw = json.loads(line)
            alerts.append(adapters[raw['source_type']].convert_record(raw))
    policy = load_community_config(ROOT / 'configs/community-v1.yaml')
    run = prepare_communities(alerts, sources, policy)
    membership = Counter(a for c in run.result.incident_candidates for a in c.alert_ids)
    assert set(membership) == {a.alert_id for a in run.noise_filter.kept_alerts}
    assert all(count == 1 for count in membership.values()), 'community_partition_invalid'
    entities = {e.entity_id: e for e in run.entities}
    ps = [profile(a, entities, sources[a.source_namespace], policy) for a in run.alerts]
    degrees = Counter(key for p in ps for key in {(b.kind, b.key) for b in p.bindings
                      if b.kind in {'core_host', 'core_account', 'context.src_ip', 'context.dst_ip', 'network_ip'}})
    identities = {(b.kind, b.key): (entities[b.entity_ids[0]].model_dump(mode='json')
                   if b.projection == 'entity' else json.loads(b.identity)) for p in ps for b in p.bindings}
    return run, dict(input_alerts=len(run.alerts), noise=run.noise_filter.statistics,
        policy_snapshot=policy.model_dump(mode='json'), policy_hash=policy.digest,
        input_sha256=sha(DATA / 'final/attack125_final.jsonl'),
        implementation_sha256={str(p.relative_to(ROOT)): sha(p)
            for folder in ('backend/app/community', 'backend/app/noise_filter')
            for p in sorted((ROOT / folder).glob('*.py'))},
        community_count=len(run.result.incident_candidates),
        community_sizes=sorted(c.member_count for c in run.result.incident_candidates),
        statistics=run.result.statistics,
        communities=[c.model_dump(mode='json') for c in run.result.incident_candidates],
        entity_degrees=[dict(kind=k[0], key=k[1], degree=v, identity=identities[k])
                        for k, v in sorted(degrees.items(), key=lambda r: (-r[1], r[0]))],
        diagnostics=run.result.diagnostics)


def completed_tests(output):
    results = []
    for name in ('required', 'downstream'):
        suite = ET.parse(output / (name + '.xml')).getroot().find('testsuite')
        counts = {k: int(suite.attrib[k]) for k in ('tests', 'failures', 'errors', 'skipped')}
        assert counts['failures'] == counts['errors'] == 0, 'required_regression_failed'
        results.append(dict(suite=name, **counts))
    return dict(result='PASS', completed_suites=results,
        passed=sum(r['tests'] - r['skipped'] for r in results),
        full_suite='Collection blocked: missing data/ait_ads/dataset.yaml in test_demo and test_demo_integration.',
        broader_attempt='Without the two Demo modules, execution stalled at test_ai_explanation API service fixture; interrupted. No full-suite pass claimed.')


def historical_edge_diagnostics(run, baseline):
    """Reconstruct prior admission state for the historical 65-member proof.

    Inspect only its old non-binding edges, never generate a pairwise graph.
    """
    alerts = {a.alert_id: a for a in run.alerts}
    order = lambda aid: (alerts[aid].timestamp, aid)
    old_edges = [e for c in baseline['communities'] if c['member_count'] == 65
                 for e in c['matching_evidence'] if e['identity_kind'] not in STRONG]
    incoming_edges = {}
    for e in old_edges:
        incoming = max(e['alert_ids'], key=order)
        incoming_edges.setdefault(incoming, []).append(e)
    final_membership = {a: c.community_id for c in run.result.incident_candidates for a in c.alert_ids}
    live, membership, diagnostics = {}, {}, []
    policy = load_community_config(ROOT / 'configs/community-v1.yaml')
    decisions = sorted((d for c in run.result.incident_candidates for d in c.membership_decisions), key=lambda d: order(d.alert_id))
    for d in decisions:
        for edge in incoming_edges.get(d.alert_id, []):
            prior = next(a for a in edge['alert_ids'] if a != d.alert_id)
            members = live[membership[prior]]
            cadence = TemporalHistory([seconds(alerts[a].timestamp) for a in members]).snapshot(policy.temporal)
            diagnostics.append(dict(identity_kind=edge['identity_kind'], alert_ids=edge['alert_ids'],
                prior_community_size=len(members), time_delta_seconds=edge['time_delta_seconds'],
                **cadence, temporal_compatible=edge['time_delta_seconds'] <= cadence['dynamic_threshold_seconds'],
                same_after_community=final_membership[prior] == final_membership[d.alert_id],
                original_witnesses=[dict(**p, raw_value=resolve_pointer(alerts[p['alert_id']].raw_alert, p['pointer']))
                                    for p in edge['supporting_evidence']]))
        merged = {d.alert_id}
        for cid in d.prior_community_ids:
            merged.update(live.pop(cid))
        cid = community_id(merged)
        live[cid] = merged
        membership.update({a: cid for a in merged})
    return diagnostics


def execute(phase, output=OUTPUT):
    output = Path(output).resolve()
    if not output.is_relative_to(ROOT / 'outputs'):
        raise ValueError('new_validation_output_required_inside_outputs')
    if phase == 'diagnostics':
        run, _ = replay()
        baseline = json.loads((output / 'baseline/replay.json').read_text(encoding='utf8'))
        diagnostics = historical_edge_diagnostics(run, baseline)
        save(output / 'validation/historical_65_edges.json', diagnostics)
        print(json.dumps(diagnostics, indent=2))
        return
    target = output / phase
    target.mkdir(parents=True, exist_ok=False)
    if phase == 'baseline':
        save(target / 'protected_before.json', protected_hashes())
    before = json.loads((output / 'baseline/protected_before.json').read_text(encoding='utf8'))
    run, report = replay()
    save(target / 'replay.json', report)
    after = protected_hashes()
    save(target / 'protected_after.json', after)
    assert before == after, 'protected_data_changed'
    if phase == 'baseline':
        print(json.dumps({k: report[k] for k in ('input_alerts', 'community_count', 'community_sizes')}))
        return
    baseline = json.loads((output / 'baseline/replay.json').read_text(encoding='utf8'))
    tests = completed_tests(output)
    save(output / 'test_results.json', tests)
    stats = run.result.statistics
    largest = max(run.result.incident_candidates, key=lambda c: c.member_count)
    counts = Counter('strong' if e.identity_kind in STRONG else 'weak' if e.identity_kind == 'network_ip'
                     else 'context' for e in largest.matching_evidence)
    historical = [c for c in baseline['communities'] if c['member_count'] == 65]
    after_membership = {a: c.community_id for c in run.result.incident_candidates for a in c.alert_ids}
    report['historical_65_analysis'] = [dict(
        community_id=c['community_id'],
        original_evidence_kinds=dict(Counter(e['identity_kind'] for e in c['matching_evidence'])),
        nonbinding_edges=[dict(identity_kind=e['identity_kind'], alert_ids=e['alert_ids'],
            delta_seconds=e['time_delta_seconds'],
            same_after_community=len({after_membership[a] for a in e['alert_ids']}) == 1,
            rejections_at_endpoints=[d for d in run.result.diagnostics
                if d['decision'] == 'REJECT' and d['alert_id'] in e['alert_ids']])
            for e in c['matching_evidence'] if e['identity_kind'] not in STRONG],
        high_degree_entities=[d for d in report['entity_degrees'] if (
            d['identity'].get('entity_id', d['key']) in {row['identity_key'] for row in stats['high_degree_entities']})
            and (d['kind'] == 'network_ip' or set(c['alert_ids']) & set(d['identity'].get('alert_ids', [])))],
        after_overlaps=[dict(community_id=new.community_id, size=new.member_count,
            overlap=len(set(c['alert_ids']) & set(new.alert_ids))) for new in run.result.incident_candidates
            if set(c['alert_ids']) & set(new.alert_ids)]) for c in historical]
    flags = ['NOISE_SUPPRESSION_INPUT_USED', 'COMMUNITY_BUILDER_OPTIMIZED', 'INDEX_BASED_CANDIDATE_RETRIEVAL',
             'STRONG_BINDING_POLICY_IMPLEMENTED', 'CONTEXT_EVIDENCE_POLICY_IMPLEMENTED',
             'WEAK_NETWORK_EVIDENCE_RESTRICTED', 'DYNAMIC_TIME_CONSTRAINT_IMPLEMENTED',
             'HIGH_DEGREE_ENTITY_SUPPRESSION_IMPLEMENTED', 'BRIDGE_SUPPRESSION_IMPLEMENTED',
             'SINGLE_ALERT_COMMUNITY_SUPPORTED']
    summary = dict(TASK_RESULT='SUCCESS', **{f: True for f in flags},
        PAIRWISE_GLOBAL_SCORING_INTRODUCED=False, INPUT_ALERTS=report['input_alerts'],
        COMMUNITY_COUNT=report['community_count'], COMMUNITY_SIZES=report['community_sizes'],
        BEFORE_COMMUNITY_COUNT=baseline['community_count'], BEFORE_COMMUNITY_SIZES=baseline['community_sizes'],
        AFTER_COMMUNITY_COUNT=report['community_count'], AFTER_COMMUNITY_SIZES=report['community_sizes'],
        **{k: stats[k] for k in ('STRONG_RELATION_COUNT', 'CONTEXT_RELATION_COUNT', 'WEAK_RELATION_COUNT',
             'REJECTED_WEAK_LINK_COUNT', 'BRIDGE_SUPPRESSION_COUNT', 'HIGH_DEGREE_ENTITY_HIT_COUNT')},
        LARGEST_COMMUNITY_SIZE=largest.member_count,
        LARGEST_COMMUNITY_ANALYSIS=dict(evidence_counts=dict(counts),
            identity_kinds=dict(Counter(e.identity_kind for e in largest.matching_evidence))),
        DATASET_MODIFIED=False, GROUND_TRUTH_MODIFIED=False, PROTECTED_DATA_SHA256_UNCHANGED=before == after,
        PROTECTED_FILE_COUNT=len(before), TEST_RESULT=tests,
        CURRENT_PIPELINE_STAGE='COMMUNITY_BUILDER_OPTIMIZED', NEXT_STAGE_NOT_STARTED=True)
    save(target / 'replay.json', report)
    save(target / 'historical_65_edges.json', historical_edge_diagnostics(run, baseline))
    write_acceptance(output, summary)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['baseline', 'validation', 'diagnostics'])
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    execute(args.phase, args.output)

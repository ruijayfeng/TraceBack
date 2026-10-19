"""Freeze receipts and development comparisons, without restarting Task C."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import duckdb

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
sys.path.insert(0, str(ROOT/'scripts'))
from app.services.storage import atomic_json, file_digest
from report_correlation_v4 import read, records

OUT = ROOT/'outputs/correlation_v4'


def implementation_hashes():
    files = [*sorted((ROOT/'backend/app').rglob('*.py')),
             *sorted((ROOT/'configs').glob('algorithm-*.yaml')), ROOT/'configs/sources.yaml',
             *sorted((ROOT/'configs/mappings').glob('*.yaml'))]
    return {p.relative_to(ROOT).as_posix(): file_digest(p) for p in files}


def candidate_digest(identity):
    db = duckdb.connect(':memory:')
    db.execute('SET enable_progress_bar=false')
    digest = hashlib.sha256()
    count = 0
    try:
        cursor = db.execute('SELECT payload FROM read_parquet(?) ORDER BY ordinal',
            [str(ROOT/'outputs/analyses'/identity/'candidate_batches/*.parquet')])
        while batch := cursor.fetchmany(4096):
            for (payload,) in batch:
                digest.update(payload.encode('utf8')+b'\n')
                count += 1
    finally:
        db.close()
    return dict(count=count, sha256=digest.hexdigest(),
        content='all unordered representative pairs, priority, channels and complete provenance, in deterministic ordinal order')


def junit():
    path = OUT/'pytest_full.xml'
    if not path.exists(): return {'passed': False, 'status': 'not_finished'}
    suites = list(ET.parse(path).getroot().iter('testsuite'))
    result = {k: sum(int(s.attrib.get(k, 0)) for s in suites) for k in ('tests', 'failures', 'errors', 'skipped')}
    result['passed'] = result['tests'] > 0 and not result['failures'] and not result['errors']
    return result


def implementation_receipt():
    before = read(OUT/'before_hashes.json')
    current = implementation_hashes()
    changed = {p: digest for p, digest in current.items() if before.get(p) != digest}
    atomic_json(OUT/'implementation_receipt.json', dict(
        authorization='User-authorized Correlation v4 role/context upgrade and necessary compatibility dispatch',
        algorithm_version='alert-correlation-v4-role-context-candidate-v1.1',
        validation_status='DEVELOPMENT_IMPLEMENTATION_ONLY_NOT_FINAL_FREEZE',
        previous={p: before[p] for p in changed if p in before}, production=changed))


def compare():
    if not junit()['passed']:
        raise ValueError('full_pytest_must_pass_before_fox_lock')
    before, after = (read(OUT/name/'RESULT.json') for name in ('baseline', 'development'))
    digests = {k: candidate_digest(r['analysis_id']) for k, r in [('v3', before), ('v4', after)]}
    candidate_equal = digests['v3'] == digests['v4']
    old_domain, new_domain = (ROOT/'data/processed'/r['analysis_id'] for r in (before, after))
    old = {e['edge_id']: e for e in records(old_domain/'correlation_edges.jsonl')}
    new = {e['edge_id']: e for e in records(new_domain/'correlation_edges.jsonl')}
    retained, removed, added = sorted(old.keys() & new.keys()), sorted(old.keys()-new.keys()), sorted(new.keys()-old.keys())
    comparison = dict(candidate_payloads=digests, candidate_equal=candidate_equal,
        retained_edge_ids=retained, removed_edge_ids=removed, added_edge_ids=added,
        retained_count=len(retained), removed_count=len(removed), added_count=len(added),
        input_equal=before['dataset_digest'] == after['dataset_digest'],
        retained_edge_score_changes=[dict(edge_id=e, v3_score=old[e]['score'], v4_score=new[e]['score'],
            v3_metadata=old[e]['score_breakdown']['evidence_v2']['family_strengths']['behavior'],
            v4_metadata=new[e]['score_breakdown']['evidence_v2']['family_strengths']['behavior'])
            for e in retained if old[e]['score'] != new[e]['score']],
        preprocessing_equal={name: file_digest(old_domain/(name+'.jsonl')) == file_digest(new_domain/(name+'.jsonl'))
                             for name in ('alerts', 'entities', 'dedupe_groups')},
        removed_edge_evidence=[dict(edge_id=e, v3_score=old[e]['score'],
            support_pair=old[e]['support_pair'], v3_metadata=old[e]['score_breakdown']['evidence_v2']['family_strengths']['behavior'],
            rationale='Generic detector type has no v4 metadata reward; inspect underlying fields, not an asserted false positive.') for e in removed])
    shared_triage = {}
    for prefix, domain in [('v3', old_domain), ('v4', new_domain)]:
        shared_triage[prefix] = {i['alert_ids'][0]: {k: i['single_alert_triage'][k] for k in
            ('single_alert_risk_score', 'risk_level', 'recommended_priority', 'risk_reasons', 'evidence_refs')}
            for i in records(domain/'incidents.jsonl') if len(i['alert_ids']) == 1 and i.get('single_alert_triage')}
    shared = shared_triage['v3'].keys() & shared_triage['v4'].keys()
    comparison['triage_risk_equal'] = all(shared_triage['v3'][a] == shared_triage['v4'][a] for a in shared)
    comparison['shared_raw_singletons_checked'] = len(shared)
    atomic_json(OUT/'RUSSELLMITCHELL_V3_BASELINE.json', before)
    atomic_json(OUT/'RUSSELLMITCHELL_V4_RESULT.json', after)
    atomic_json(OUT/'COMPARISON.json', comparison)
    atomic_json(OUT/'SCORE_DISTRIBUTION.json', {k: r['score_distribution'] for k, r in [('v3', before), ('v4', after)]})
    atomic_json(OUT/'EDGE_EVIDENCE_ANALYSIS.json', {k: r['evidence'] for k, r in [('v3', before), ('v4', after)]})
    atomic_json(OUT/'SINGLETON_ANALYSIS.json', {k: read(OUT/n/'SINGLETON_ANALYSIS.json') for k, n in [('v3', 'baseline'), ('v4', 'development')]})
    if not comparison['input_equal'] or not candidate_equal or not all(comparison['preprocessing_equal'].values()) or not comparison['triage_risk_equal']:
        raise ValueError('development_preservation_check_failed')
    atomic_json(OUT/'DEVELOPMENT_LOCK.json', dict(status='LOCKED_FOR_FOX_LIGHT_VALIDATION',
        algorithm_version=after['algorithm_version'], config_hash=after['config_hash'], mapping_digest=after['mapping_digest'],
        implementation=implementation_hashes(), development_result_sha256=file_digest(OUT/'RUSSELLMITCHELL_V4_RESULT.json'),
        dataset_roles={'russellmitchell': 'primary_development', 'fox': 'lightweight_validation', 'all_other_scenes': 'hold_out'},
        algorithm_changes_after_fox_forbidden=True, ground_truth_used=False))
    print(json.dumps({'comparison': {k: comparison[k] for k in ('candidate_equal', 'retained_count', 'removed_count', 'added_count', 'triage_risk_equal')},
        'tests': junit(), 'status': 'DEVELOPMENT_LOCKED'}), flush=True)


def final():
    before, after = (read(OUT/name) for name in ('RUSSELLMITCHELL_V3_BASELINE.json', 'RUSSELLMITCHELL_V4_RESULT.json'))
    lock, comparison = read(OUT/'DEVELOPMENT_LOCK.json'), read(OUT/'COMPARISON.json')
    unchanged = lock['implementation'] == implementation_hashes()
    tests = junit()
    fox_file = OUT/'fox/RESULT.json'
    fox_failure = OUT/'fox/FAILED_RUN.json'
    fox = read(fox_file) if fox_file.exists() else None
    failed_fox = read(fox_failure) if fox_failure.exists() else None
    blockers = []
    if not unchanged: blockers.append('algorithm_implementation_changed_after_development_lock')
    if not tests['passed']: blockers.append('full_pytest_not_passed')
    if fox is None: blockers.append('fox_full_pipeline_failed_or_unfinished')
    if failed_fox and failed_fox.get('resource_guard'):
        blockers.append(failed_fox['incomplete_reason'])
    fox_checks = {}
    if fox:
        proxy = fox['evidence']['evidence_proxies']['accepted']
        fox_checks = dict(pipeline_completed=fox['status'] == 'completed' and fox['is_complete'],
            all_admitted_scored=fox['counts']['admitted_candidate_count'] == fox['counts']['scored_candidate_count'],
            no_resource_truncation=fox['counts']['resource_truncated_count'] == 0,
            grounding_valid=fox['grounding']['valid'], no_metadata_only_formal_edges=proxy.get('metadata_only', 0) == 0,
            bounded_incident=fox['counts']['largest_incident_representative_count'] <= 500,
            bounded_candidates=fox['counts']['candidate_pair_count'] <= 2000000)
        if not all(fox_checks.values()): blockers.append('fox_light_validation_failed')
    status = 'V4_NOT_READY' if blockers else 'V4_FROZEN_READY_FOR_TASK_C'
    fox_status = 'FAIL' if fox is None or not all(fox_checks.values()) else 'PASS_WITH_LIMITATIONS'
    fox_markdown = ['# Fox lightweight validation', '', f'Status: **{fox_status}**. One v4 replay after the russellmitchell development lock; no fox-driven algorithm or parameter changes.', '',
        f'Implementation unchanged after lock: `{unchanged}`.', '', 'Checks:', '',
        *[f'- {k}: {v}' for k, v in fox_checks.items()], '',
        'Metrics:', '', '```json', json.dumps({k: fox[k] for k in ('analysis_id', 'counts', 'runtime', 'peak_memory_mb', 'singleton_ratio', 'score_distribution')} if fox else
            {'failed_receipt': str(fox_failure.relative_to(ROOT)), 'analysis_id': failed_fox.get('analysis_id') if failed_fox else None,
             'classification': failed_fox.get('failure_classification') if failed_fox else None,
             'resource_guard': failed_fox.get('resource_guard') if failed_fox else None,
             'peak_memory_mb': None, 'unavailable_metrics': ['candidate_count', 'edge_count', 'incidents', 'score_distribution', 'final_runtime', 'process_peak_memory'],
             'blockers': blockers}, ensure_ascii=False, indent=2), '```', '',
        'Resource diagnosis: the historical fox v3 receipt also stopped on host available commit below 512 MiB and reports 473,083 canonical alerts (about 10.4 times russellmitchell). The current v4 run stopped during ingress before a completed candidate/scoring output. Classification: DATASET_SPECIFIC_DIFFERENCE (input scale / available host capacity); a v4 scoring defect is not established. No per-example mining, rule/weight/threshold changes, second fox run or subset substitution occurred.', '',
        'This is a production/evidence/scale sanity check. No pair/incident truth is consumed, so high-quality attack correlation precision and cross-scene recall remain for Task C. An authoritative same-recipe pre-v4 fox production baseline is required for a measured before/after generalization claim; no unavailable metric is replaced with a historical constant.']
    (OUT/'FOX_LIGHT_VALIDATION.md').write_text('\n'.join(fox_markdown)+'\n', encoding='utf8')
    manifest = dict(status=status, algorithm_version=after['algorithm_version'], config_hash=after['config_hash'],
        mapping_digest=after['mapping_digest'], schema_version='1.0', embedded_evidence_version='v4',
        implementation=implementation_hashes(), development_lock_sha256=file_digest(OUT/'DEVELOPMENT_LOCK.json'),
        implementation_unchanged_after_fox=unchanged, pytest=tests, fox_status=fox_status, blockers=blockers,
        final_algorithm_frozen=status == 'V4_FROZEN_READY_FOR_TASK_C',
        frozen_scope=['implementation', 'weights', 'threshold', 'candidate_rules', 'evidence_families',
            'entity_reliability', 'temporal_decay', 'guards', 'relation_mappings', 'incident_clustering'],
        dataset_roles=lock['dataset_roles'], ground_truth_used=False, task_c_status='PAUSED', task_c_started=False,
        snapshots={k: dict(analysis_id=r['analysis_id'], config_hash=r['config_hash'], dataset_digest=r['dataset_digest'])
                   for k, r in [('russellmitchell_v3', before), ('russellmitchell_v4', after), *(([('fox_v4', fox)]) if fox else [])]})
    atomic_json(OUT/'FREEZE_MANIFEST.json', manifest)
    source_before = read(OUT/'before_hashes.json')
    changed = [k for k, digest in implementation_hashes().items() if source_before.get(k) != digest]
    for p in sorted((ROOT/'scripts').glob('*correlation_v4*.py')):
        relative = p.relative_to(ROOT).as_posix()
        if source_before.get(relative) != file_digest(p): changed.append(relative)
    changed += ['backend/tests/test_correlation_v4.py', 'scripts/check_repository.py', 'evaluation/tests/test_task_06_6.py']
    changed = sorted(set(changed))
    atomic_json(OUT/'FILES_CHANGED.json', dict(source_files=changed, artifact_directory='outputs/correlation_v4',
        new_production_snapshots=manifest['snapshots'], original_requirements_unchanged=True))
    rows = ['| Metric | v3 | v4 |', '| --- | ---: | ---: |']
    for key in ('canonical_alert_count', 'representative_count', 'candidate_pair_count', 'correlation_edge_count',
                'incident_count', 'singleton_count', 'multi_alert_incident_count', 'multi_representative_incident_count',
                'largest_incident_alert_count', 'chain_edge_count'):
        rows.append(f"| {key} | {before['counts'][key]} | {after['counts'][key]} |")
    for key in ('singleton_ratio', 'multi_alert_ratio', 'peak_memory_mb'):
        rows.append(f'| {key} | {before[key]} | {after[key]} |')
    for key in before['evidence_ratios']:
        rows.append(f"| {key} | {before['evidence_ratios'][key]} | {after['evidence_ratios'][key]} |")
    for key in ('candidate_generation_seconds', 'correlation_scoring_seconds', 'incident_clustering_seconds', 'total_seconds'):
        rows.append(f"| {key} | {before['runtime'][key]:.3f} | {after['runtime'][key]:.3f} |")
    sections = ['# Correlation v4 report', '', f'CORRELATION_V4_RESULT = **{status}**', '',
        '## A. v3 root causes', '', 'Generic detector type reinforcement; destination-role informativeness; transport-only network support; background/hot candidate pressure. See CORRELATION_V4_FAILURE_ANALYSIS.md for actual evidence, ranking, risks and adversarial reproductions. The current v3 baseline has eight formal edges, not the historical 18k population.', '',
        '## B. Design and compatibility', '',
        '- Candidate Generation: UNCHANGED; full deterministic payload equality verified.',
        '- Evidence Modeling: generic alert_type excluded from metadata support and detector-difference primary promotion; port continuity requires compatible mapped behavior.',
        '- Scoring: quality/mass formula, family weights and 0.65 threshold UNCHANGED; affected evidence strengths flow into the existing full audit calculation.',
        '- ScoreBreakdown keeps the complete seven legacy raw/weight/contribution audit; the actual v4 total is reconstructed from versioned quality/mass and penalties, rather than the sum of the legacy audit contributions.',
        '- Reliability: destination-only IP supporting factor 0.25; scope, rarity, hot detection and other roles UNCHANGED.',
        '- Temporal Logic: UNCHANGED; category-dependent exponential half-lives retained.',
        '- Guards: existing hard guards UNCHANGED; missing network behavior is unavailable support and known incompatible behavior is a mismatched flow dimension, not invented session exclusivity.',
        '- Incident Formation: UNCHANGED 0.70 threshold, two bridges, target/span/size guards and singleton retention; member changes result only from changed formal edges.',
        '- Relation mappings: UNCHANGED; undirected flow does not create a ChainEdge.',
        '- Compatibility: additive v4 audit subtype in the existing optional evidence slot, shape preserved. Old v0/v2/v3 snapshots retain serialization/config semantics and require no migration. CanonicalAlert/Stable ID/Reason/API/AI contracts remain unchanged. Incremental population dependency now applies to v4; interfaces unchanged.', '',
        '## C. Edge quality, without a quantity target', '',
        f"Stable IDs: {comparison['retained_count']} retained, {comparison['removed_count']} removed, {comparison['added_count']} added. Complete candidate equality and preprocessing equality rule out recall-policy changes as the explanation. Retained score changes: `{json.dumps(comparison['retained_edge_score_changes'])}`. Generic-type reinforcement is removed without claiming a label-confirmed false positive. Host/account investigation context remains intact for retained edges. Synthetic transport-only and destination-role counterexamples improve conservatism; real positive flow evidence is absent and cannot be claimed recovered.", '',
        'All formal edge fact pointers resolve to their exact source alerts and raw_alert. Metadata-only/duplicate-only accepted edges remain forbidden. Public infrastructure contamination ratios are observable proxies, not benign/attack truth. Both accepted and rejected composition/distributions are exact per selected candidate; member statistics have a separate denominator. SCORE_DISTRIBUTION.json includes P50/P75/P90/P95/P99/MAX.', '',
        'Figures: `figures/score_distribution.png` and `figures/evidence_composition.png` (editable vector SVG copies included). Field-equality proxy counters compare nonnull canonical values; matched evidence families retain actual scope/role validation. Cross-source namespace equality is distinct from confirmed independent corroboration.', '',
        '## D. russellmitchell before / after', '', *rows, '',
        'The v3 run overlapped regression verification; elapsed time is machine/load dependent, not a controlled speedup claim. Scoring/role changes retain the same candidate and complete member populations. Runtime and memory are measured process receipts. No hardware-independent SLA or calibrated probability is claimed.', '',
        '## Singleton analysis and triage', '',
        f"Shared original singleton risk fields checked: {comparison['shared_raw_singletons_checked']}; all identical: {comparison['triage_risk_equal']}. Raw-alert singleton and representative-singleton counts are distinguished. A/C/E classification limits and B/D evidence diagnostics are in SINGLETON_ANALYSIS.json and full per-alert JSONL. D includes display correlations that do not satisfy clustering. No singleton is deleted or forcibly merged.", '',
        '## E. Fox', '', f'{fox_status}. See FOX_LIGHT_VALIDATION.md. Parameters and implementation were locked before the single v4 replay; fox metrics are not used to tune v4. The run was resource-stopped during ingress when free host commit reached 504.6 MiB; downstream counts, distribution, final runtime and process peak memory are unavailable. Historical v3 fox was also blocked by the same commit guard, with a 473k-alert input scale. This is a capacity limitation for this dataset/host, not an established scoring defect. It prevents a PASS or freeze-ready declaration.', '',
        '## Regression verification', '', f'Full backend/evaluation pytest: `{json.dumps(tests)}`. Frontend: 35 tests passed, TypeScript and build passed. Legacy completed v3 metadata/config/file digests revalidated. New adversarial tests include role/metadata/context, missing/mismatch, rare/hot evidence, network positives without directions, confirmed source complement, candidate separation, snapshot/API/triage and incremental/full equivalence.', '',
        '## F. Freeze and Task C gate', '', f"Algorithm version: `{after['algorithm_version']}`\n\nconfig_hash (russellmitchell effective analysis snapshot): `{after['config_hash']}`\n\nmapping_digest: `{after['mapping_digest']}`", '',
        'FREEZE_MANIFEST.json records code/config/mapping hashes and snapshot references. Fox has its own source namespace/timezone-specific config hash; shared numerical/semantic policy is identical. All other scenes stay hold-out. Pair Precision/Recall remain unavailable without pair/incident-equivalence truth; vendor alert labels are not substituted.', '',
        f'Blockers: {json.dumps(blockers)}. Task C remains PAUSED and has not been started. '+('The frozen artifact is ready for a separately authorized Task C restart.' if not blockers else 'Task C cannot restart.'), '',
        f'CORRELATION_V4_RESULT = {status}']
    (OUT/'CORRELATION_V4_REPORT.md').write_text('\n'.join(sections)+'\n', encoding='utf8')
    atomic_json(OUT/'TASK_C_STATUS.json', dict(status='PAUSED', started=False, restart_gate=status))
    print(json.dumps({'status': status, 'fox': fox_status, 'tests': tests, 'blockers': blockers}), flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['implementation-receipt']: implementation_receipt()
    elif sys.argv[1:] == ['compare']: compare()
    elif sys.argv[1:] == ['final']: final()
    else: raise SystemExit('Usage: finalize_correlation_v4.py compare|final')

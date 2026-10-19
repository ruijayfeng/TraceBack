"""Read-only Task B dependency audit, NOT an incremental pipeline or benchmark.

Synthetic counterexamples invoke the unchanged production algorithms. Real
checks read only the frozen snapshot and recompute its selected support pairs.
No labels, source mappings, frozen snapshots, or production files are modified.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))

from app.adapters.base import AdapterSettings
from app.config import load_config
from app.correlation.candidates import generate_candidates
from app.correlation.edges import peak_memory_mb, run_correlation
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.dedup.grouping import deduplicate
from app.entities.extraction import extract_entities
from app.incidents.clustering import cluster_incidents
from app.incidents.triage import triage_singletons
from app.models import CanonicalAlert, CorrelationEdge, DedupeGroup, Entity
from app.services.storage import restore_config


def synthetic_inputs(hot=False):
    # Existing test helper only constructs marked synthetic CanonicalAlerts;
    # it supplies no scoring, candidate, dedupe, or clustering implementation.
    sys.path.insert(0, str(ROOT / 'backend/tests'))
    from test_correlation_score import alert
    if hot:
        base = [alert(f'hot-{i}', i, host='synthetic-shared-host', rule_id=f'hot-{i}') for i in range(100)]
        base += [alert(f'noise-{i}', 86400+i, rule_id=f'noise-{i}', severity='high') for i in range(900)]
    else:
        # Fixed timestamps, not threshold/weight tuning. This pair witnesses
        # a discontinuity at the existing 0.70 controlled clustering boundary.
        base = [alert('a', host='h', account='u', rule_id='a'),
                alert('b', 14.366120, host='h', account='u', rule_id='b')]
        base += [alert(f'noise{i}', 86400+i, rule_id=f'noise{i}', severity='high') for i in range(998)]
    return base, [alert('delta', 172800, rule_id='delta')]


def fixture_full(alerts, cfg):
    started = time.perf_counter()
    settings = {a.source_namespace: AdapterSettings(a.source_namespace, 'synthetic', 'synthetic') for a in alerts}
    dedupe = deduplicate(alerts, cfg, settings)
    extracted = extract_entities(alerts, settings)
    result = run_correlation(extracted.alerts, dedupe.groups, extracted.entities, cfg, settings)
    index = AlertIndex(extracted.alerts, dedupe.groups, extracted.entities)
    scorer = CorrelationScorer(index, cfg, settings, result.record.config_hash)
    incidents = cluster_incidents(index, result.edges, scorer).incidents
    incidents = triage_singletons(incidents, index, cfg, result.summary, search_complete=True)
    return index, result, incidents, time.perf_counter()-started


def synthetic_audit(cfg):
    base, delta = synthetic_inputs()
    old, a, ai, at = fixture_full(base, cfg)
    new, b, bi, bt = fixture_full(base+delta, cfg)
    delta_id = delta[0].alert_id
    assert not new.alerts[delta_id].entity_ids
    assert all(delta_id not in p.support_key for p in b.candidates.pairs)
    assert len(a.edges) == len(b.edges) == 1
    assert a.edges[0].edge_id == b.edges[0].edge_id
    historical_ids = {base[0].alert_id, base[1].alert_id}
    before = [i.alert_ids for i in ai if historical_ids.intersection(i.alert_ids)]
    after = [i.alert_ids for i in bi if historical_ids.intersection(i.alert_ids)]
    settings = {item.source_namespace: AdapterSettings(item.source_namespace, 'synthetic', 'synthetic') for item in base}
    sca = CorrelationScorer(old, cfg, settings)
    scb = CorrelationScorer(new, cfg, sca.settings)
    pair = sorted(historical_ids)
    pa, pb = sca.score_pair(*pair), scb.score_pair(*pair)
    assert pa.score < cfg.algorithm.clustering.edge_threshold <= pb.score
    tri_before = {i.incident_id: i for i in ai if i.single_alert_triage is not None}
    tri_after = {i.incident_id: i for i in bi if i.single_alert_triage is not None}
    common = sorted(tri_before.keys() & tri_after.keys())
    changed_tri = sum(tri_before[i].canonical_json() != tri_after[i].canonical_json() for i in common)
    witness = common[0]
    hot_base, hot_delta = synthetic_inputs(hot=True)
    hot_runs = []
    for aa in (hot_base, hot_base+hot_delta):
        settings = {'synthetic': AdapterSettings('synthetic', 'synthetic', 'synthetic')}
        groups = deduplicate(aa, cfg, settings).groups
        extracted = extract_entities(aa, settings)
        idx = AlertIndex(extracted.alerts, groups, extracted.entities)
        sc = CorrelationScorer(idx, cfg, settings)
        candidates = generate_candidates(idx, cfg, sc)
        eid = next(e for e in idx.entities if idx.entities[e].value == 'synthetic-shared-host')
        hot_runs.append(dict(N=idx.N, df=idx.df[eid], hot=sc.evidence_evaluator.hot(eid),
            candidate_count=len(candidates.pairs), pairs={p.support_key for p in candidates.pairs}))
    x, y = hot_runs
    def stats(idx, result, runtime):
        return dict(mode='full_fixture_correlation_and_incident', representatives=idx.N,
            candidates=len(result.candidates.pairs), scoring_count=result.summary['scored_candidate_count'],
            edges=len(result.edges), total_seconds=runtime)
    return dict(
        population_dependency=dict(base_N=old.N, combined_N=new.N, delta_candidate_count=0,
            delta_shared_entity_count=0, canonical_history_unchanged=all(old.alerts[i] == new.alerts[i] for i in old.alerts),
            dedupe_group_counts=[sum(len(g)>1 for g in old.groups.values()),sum(len(g)>1 for g in new.groups.values())],
            representative_ids_preserved=set(old.representatives) <= set(new.representatives),
            edge_id=a.edges[0].edge_id, base_unrounded_score=pa.score, combined_unrounded_score=pb.score,
            base_formal_score=a.edges[0].score, combined_formal_score=b.edges[0].score,
            base_historical_memberships=before, combined_historical_memberships=after,
            primary_gate_passed=[pa.valid, pb.valid], correlation_threshold=cfg.algorithm.score.correlation_threshold,
            clustering_threshold=cfg.algorithm.clustering.edge_threshold,
            append_only_preserve_history_equivalence='FAIL',
            note='Two FULL fixture executions prove that preserving this unrelated historical Incident is incorrect.'),
        triage_dependency=dict(common_unrelated_singletons=len(common), changed_incident_payloads=changed_tri,
            example_incident_id=witness,
            base=tri_before[witness].single_alert_triage.model_dump(mode='json'),
            combined=tri_after[witness].single_alert_triage.model_dump(mode='json')),
        hot_dependency=dict(base={k:v for k,v in x.items() if k!='pairs'},
            combined={k:v for k,v in y.items() if k!='pairs'},
            historical_candidates_added=len(y['pairs']-x['pairs']),
            historical_candidates_removed=len(x['pairs']-y['pairs']),
            delta_candidate_count=sum(hot_delta[0].alert_id in p for p in y['pairs']),
            note='Unchanged df=100 changes hot status solely because N changes.'),
        fixture_full_stats=[stats(old,a,at),stats(new,b,bt)],
        peak_memory_mb=peak_memory_mb())


def real_support_audit(snapshot):
    """Population sensitivity, not a Base/Delta Full Rebuild equivalence run."""
    import duckdb
    domain = ROOT/'data/processed'/snapshot
    details = ROOT/'outputs/analyses'/snapshot
    run = json.loads((domain/'run.json').read_text(encoding='utf-8'))
    cfg = restore_config(run['config_snapshot']['algorithm'])
    settings = {k: AdapterSettings(**v) for k,v in run['config_snapshot']['sources'].items()}
    frequency = json.loads((details/'frequency_snapshot.json').read_text(encoding='utf-8'))
    edges = [CorrelationEdge.model_validate_json(line) for line in (domain/'correlation_edges.jsonl').read_text(encoding='utf-8').splitlines()]
    reps = sorted({i for e in edges for i in (e.source_alert_id, e.target_alert_id)})
    db = duckdb.connect(str(domain/'domain.duckdb'), read_only=True)
    try:
        groups = [DedupeGroup.model_validate_json(row[0]) for row in db.execute(
            "SELECT payload FROM dedupe_groups WHERE json_extract_string(payload, '$.representative_alert_id') IN (SELECT unnest(?))", [reps]).fetchall()]
        ids = sorted(set(reps) | {i for g in groups for i in g.alert_ids})
        alerts = [CanonicalAlert.model_validate_json(r[0]) for r in db.execute(
            'SELECT payload FROM alerts WHERE object_id IN (SELECT unnest(?))', [ids]).fetchall()]
        eids = sorted({e for a in alerts for e in a.entity_ids})
        entities = []
        for row in db.execute('SELECT payload FROM entities WHERE object_id IN (SELECT unnest(?))', [eids]).fetchall():
            data = json.loads(row[0]); data['alert_ids'] = sorted(set(data['alert_ids']) & set(ids))
            entities.append(Entity.model_validate(data))
    finally:
        db.close()
    idx = AlertIndex(alerts, groups, entities)
    idx.N = frequency['N']
    idx.df.update({r['entity_id']:r['df'] for r in frequency['entities'] if r['entity_id'] in eids})
    base_N = idx.N
    rows = []
    for count in (0,1,10,100,1000):
        idx.N = base_N+count
        scorer = CorrelationScorer(idx, cfg, settings, run['config_hash'])
        values = []
        for edge in edges:
            p = scorer.score_pair(edge.support_pair.alert_id_src, edge.support_pair.alert_id_dst)
            breakdown = scorer.breakdown(p)
            if count == 0:
                assert breakdown.canonical_json() == edge.score_breakdown.canonical_json(), edge.edge_id
            values.append(dict(edge_id=edge.edge_id, frozen_score=edge.score, recomputed_score=breakdown.final_score,
                unrounded_score=p.score, valid=p.valid,
                score_changed=breakdown.final_score != edge.score,
                evidence_changed=breakdown.evidence_v2 != edge.score_breakdown.evidence_v2))
        rows.append(dict(counterfactual_new_representatives=count, N=idx.N,
            scored_selected_support_pairs=len(edges), changed_formal_scores=sum(v['score_changed'] for v in values),
            changed_evidence=sum(v['evidence_changed'] for v in values), edges=values))
    return dict(status='selected_support_population_sensitivity_verified', analysis_id=snapshot,
        historical_counts=run['counts'], historical_runtime=run['runtime'], historical_peak_memory_mb=run['metrics']['peak_memory_mb'],
        config_hash=run['config_hash'], dataset_digest=run['dataset_digest'],
        config_threshold=cfg.algorithm.score.correlation_threshold, loaded_alert_count=len(alerts),
        loaded_entity_count=len(entities), samples=rows,
        limitation='Not an incremental benchmark, not a full candidate replay; selected support winners are NOT reselected for hypothetical larger inputs.')


def frozen_hashes():
    paths = [ROOT/'AGENTS.md', *sorted((ROOT/'docs').glob('*.md')),
             *sorted((ROOT/'backend/app').rglob('*.py')), *sorted((ROOT/'configs').rglob('*.yaml'))]
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', default='ana_c9d63511744137fb6fb34fce4d17a60796a62dfbb2291456cecf59c3b1d631fd')
    parser.add_argument('--output', type=Path, default=ROOT/'outputs/incremental_correlation')
    args = parser.parse_args()
    before = frozen_hashes()
    args.output.mkdir(parents=True, exist_ok=True)
    report = dict(audit_kind='frozen_dependency_counterexamples', production_incremental_implemented=False,
        synthetic=synthetic_audit(load_config(ROOT/'configs/algorithm-v3.yaml')),
        real_selected_support_sensitivity=real_support_audit(args.snapshot))
    (args.output/'dependency_audit.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    after = frozen_hashes()
    integrity = dict(frozen_file_count=len(before), all_unchanged=before==after, hashes=after,
        incremental_state_created=False, snapshot_opened_read_only=True)
    (args.output/'state_integrity.json').write_text(json.dumps(integrity,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    unavailable = dict(status='not_run_blocked', reason='Complete frequency dependency closure requires scope clarification; production incremental path unimplemented.')
    def save(name, value):
        (args.output/name).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    save('benchmark.json', {**unavailable, 'historical_full_snapshot':args.snapshot,
        'requested_batches':[dict(new_alert_count=n, full_candidates=None, incremental_candidates=None,
            full_scoring_count=None, incremental_scoring_count=None, full_runtime_seconds=None,
            incremental_runtime_seconds=None, full_peak_memory_mb=None, incremental_peak_memory_mb=None)
            for n in (1,10,100,1000)], 'historical_full_measurements':dict(
                candidates=report['real_selected_support_sensitivity']['historical_counts']['candidate_pair_count'],
                runtime=report['real_selected_support_sensitivity']['historical_runtime']['total_seconds'],
                peak_memory_mb=report['real_selected_support_sensitivity']['historical_peak_memory_mb'])})
    save('equivalence.json', {**unavailable, 'FULL_INCREMENTAL_EQUIVALENCE':None,
        'append_only_preserve_unrelated_history_counterexample':'FAIL',
        'production_incremental_path_executed':False,
        'synthetic_full_vs_full_dependency':report['synthetic']['population_dependency'],
        'missing_acceptance':['incremental_normalization','incremental_dedupe','representative_mutation',
            'entity_index_mutation','candidate_lookup','edge_mutation','incident_local_update',
            'batch_1_10_100_1000','threshold_boundary','empty_batch','idempotency','restart','crash_safety',
            'real_base_delta_full_incremental_equivalence']})
    save('incremental_run_stats.json', {**unavailable,'mode':'incremental','actual_run_count':0,
        'incoming_alerts':None,'candidate_pairs_examined':None,'candidate_pairs_scored':None,
        'edges_inserted':None,'edges_updated':None,'incidents_created':None,'incidents_updated':None,
        'total_time':None,'peak_memory':None})
    save('full_run_stats.json', {'historical_full_snapshot':args.snapshot,
        'historical_counts':report['real_selected_support_sensitivity']['historical_counts'],
        'historical_runtime':report['real_selected_support_sensitivity']['historical_runtime'],
        'historical_peak_memory_mb':report['real_selected_support_sensitivity']['historical_peak_memory_mb'],
        'new_fixture_full_stats':report['synthetic']['fixture_full_stats'],
        'new_real_full_rebuild_executed':False})
    save('candidate_reduction.json', {**unavailable,'candidate_reduction_ratio':None,
        'incremental_candidate_count':None,'incremental_scoring_count':None,
        'historical_hot_transition_counterexample':report['synthetic']['hot_dependency']})
    print(json.dumps(dict(audit=report['audit_kind'], frozen_files_unchanged=before==after,
        historical_membership_changed=report['synthetic']['population_dependency']['append_only_preserve_history_equivalence']),indent=2))


if __name__ == '__main__':
    main()

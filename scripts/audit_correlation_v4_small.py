"""Predeclared read-only coverage/evidence audit of one completed snapshot."""
import argparse
from collections import Counter
from itertools import combinations
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
from app.adapters import AdapterSettings
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.services.bounded_diagnostics import DiskCandidates
from app.services.storage import SnapshotStore, atomic_json, restore_config
from demo_support import truth_guard

OUTPUT = ROOT/'outputs/correlation_v4_small'


def development_compare():
    """Compare the same real member facts under the two development recipes."""
    import duckdb
    baseline = OUTPUT/'baseline_v3_verified'
    dev = OUTPUT/'dev_v4'
    before = json.loads((baseline/'RESULT.json').read_text(encoding='utf8'))
    after = json.loads((dev/'RESULT.json').read_text(encoding='utf8'))
    assert before['dataset_digest'] == after['dataset_digest']
    store = SnapshotStore(dev, after['correlation_analysis_id'])
    record, _, _ = store.read_metadata()
    index = AlertIndex(*(list(store.read_records(k)) for k in ('alerts','dedupe_groups','entities')))
    cfg = restore_config(record.config_snapshot['algorithm'])
    settings = {k:AdapterSettings(**v) for k,v in record.config_snapshot['sources'].items()}
    scorer = CorrelationScorer(index,cfg,settings,record.config_hash)
    old_store = SnapshotStore(baseline,before['correlation_analysis_id'])
    db = duckdb.connect(':memory:')
    counts, examples, seen = Counter(), [], set()
    try:
        cursor = db.execute('SELECT payload FROM read_parquet(?)', [str(old_store.details/'candidate_samples/*.parquet')])
        while rows := cursor.fetchmany(128):
            for (payload,) in rows:
                sample = json.loads(payload)
                old = sample['member']
                key = tuple(old['support_pair'])
                if key in seen:
                    continue
                seen.add(key)
                new = scorer.score_pair(*key)
                old_ev, new_ev = old['evidence']['evidence_v2'], new.diagnostics['evidence_v2']
                metadata_removed = old_ev['family_strengths']['behavior']>0 and new_ev['family_strengths']['behavior']==0
                destination_discounted = any(
                    row['role_factor'] < previous['role_factor'] for row in new_ev['entity_reliability']
                    for previous in old_ev['entity_reliability'] if row['entity_id']==previous['entity_id'])
                counts['member_pairs_compared'] += 1
                counts['generic_metadata_support_removed'] += int(metadata_removed)
                counts['destination_context_discounted'] += int(destination_discounted)
                counts['score_decreased'] += int(new.score<old['score'])
                counts['score_increased'] += int(new.score>old['score'])
                if (metadata_removed or destination_discounted) and len(examples)<20:
                    examples.append({'support_pair':list(key),'v3_score':old['score'],'v4_score':new.score,
                        'generic_metadata_removed':metadata_removed,'destination_context_discounted':destination_discounted,
                        'v3_evidence':old_ev,'v4_evidence':new_ev,
                        'alerts':[index.alerts[a].model_dump(mode='json') for a in key]})
    finally:
        db.close()
    out = {'same_input_digest':before['dataset_digest'], 'observed_sample_changes':dict(counts),
        'samples_are_bounded_diagnostic_population_not_random':True,'changed_real_pairs':examples,
        'dev_v3':before,'dev_v4':after,'quality_improvement':bool(counts['generic_metadata_support_removed'] or counts['destination_context_discounted']),
        'no_precision_recall_claim':True}
    atomic_json(OUTPUT/'DEVELOPMENT_COMPARISON.json',out)
    print(json.dumps({'development_comparison':dict(counts),'quality_improvement':out['quality_improvement']}),flush=True)
    return out


def audit(tag, limit=256):
    dest = OUTPUT/tag
    # An evidence audit is diagnostic, never a second formal correlation run.
    # Validation audit also consumes its own marker before any inspection.
    with (dest/'EVIDENCE_AUDIT_STARTED.json').open('x', encoding='utf8') as f:
        json.dump({'omitted_pair_limit':limit, 'algorithm_unchanged':True}, f)
    result = json.loads((dest/'RESULT.json').read_text(encoding='utf8'))
    with truth_guard(ROOT):
        store = SnapshotStore(dest, result['correlation_analysis_id'])
        record, frequency, manifest = store.read_metadata()
        cfg = restore_config(record.config_snapshot['algorithm'])
        settings = {k:AdapterSettings(**v) for k,v in record.config_snapshot['sources'].items()}
        index = AlertIndex(*(list(store.read_records(k)) for k in ('alerts','dedupe_groups','entities')))
        assert index.frequency_snapshot() == frequency
        scorer = CorrelationScorer(index, cfg, settings, record.config_hash)
        ev = scorer.evidence_evaluator
        candidates = {p.support_key for p in DiskCandidates(store.details/'candidate_batches', result['candidate_pair_count'])}
        primary_possible, type_counts = set(), Counter()
        for eid, entity in index.entities.items():
            kind = entity.type.value
            # Superset of eligible primary entity facts: role, descriptor,
            # detector distinction and action specificity are checked by the
            # full scorer below. No hot entity alone or plain IP is primary.
            if kind not in {'HOST','ACCOUNT','SESSION','PROCESS','URL','FILE','COMMAND'} or ev.hot(eid):
                continue
            if ev.repair.reliability_floor+(1-ev.repair.reliability_floor)*ev.rarity(eid) < ev.repair.primary_minimum_reliability:
                continue
            if kind == 'PROCESS' and not scorer.is_instance(eid):
                continue
            if kind == 'SESSION' and not any(settings[index.alerts[a].source_namespace].session_scope for a in entity.alert_ids):
                continue
            reps = sorted({index.owner[a] for a in entity.alert_ids})
            for pair in combinations(reps, 2):
                if not any(abs(index.times[a]-index.times[b]) <= cfg.algorithm.candidate.max_window_seconds*1e6
                           for a in index.groups[pair[0]] for b in index.groups[pair[1]]):
                    continue
                primary_possible.add(pair)
                type_counts[kind] += 1
        relation_count = sum(len(a.relations) for a in index.alerts.values())
        # Explicit propagation uses related scoped entities across the groups.
        for alert in index.alerts.values():
            for relation in alert.relations:
                members = set(index.entities[relation.source_entity_id].alert_ids) | set(index.entities[relation.target_entity_id].alert_ids)
                reps = sorted({index.owner[a] for a in members})
                primary_possible.update(combinations(reps, 2))
        network_checked = 0
        # Behavior eligibility is fixed before validation. Ordered endpoint
        # bridges with compatible known categories are a superset of v4 flows.
        for eid, entity in index.entities.items():
            if entity.type.value != 'IP' or ev.hot(eid):
                continue
            left = [a for a in entity.alert_ids if 'dst_ip' in index.roles[a][eid]]
            right = [a for a in entity.alert_ids if 'src_ip' in index.roles[a][eid]]
            for a in left:
                for b in right:
                    x, y = index.alerts[a], index.alerts[b]
                    if x.category.value == 'unknown' or y.category.value == 'unknown' or x.category==y.category:
                        continue
                    if index.times[a] >= index.times[b] or index.times[b]-index.times[a] > cfg.algorithm.candidate.max_window_seconds*1e6:
                        continue
                    if scorer.behavior_value(x,y) < ev.repair.network_behavior_minimum:
                        continue
                    pair = tuple(sorted((index.owner[a],index.owner[b])))
                    if pair[0] != pair[1]:
                        primary_possible.add(pair)
                        network_checked += 1
        omitted = sorted(primary_possible-candidates)
        counter, samples, apparent_missed = Counter(), [], []
        for pair in omitted[:limit]:
            winners = []
            best = None
            for a in index.groups[pair[0]]:
                for b in index.groups[pair[1]]:
                    scored = scorer.score_pair(a,b)
                    key = (-scored.score,index.alerts[a].timestamp,index.alerts[b].timestamp,a,b)
                    if best is None or key < best[0]:
                        best = (key,scored)
                    if scored.valid and scored.score >= cfg.algorithm.score.correlation_threshold:
                        winners.append((key,scored))
            selected = min(winners,key=lambda row:row[0])[1] if winners else best[1]
            counter[selected.diagnostics['evidence_v2']['gate_reason']] += 1
            sample = {'support_key':list(pair), 'support_pair':[selected.source_member_id,selected.target_member_id],
                'score':selected.score,'valid':selected.valid,'rejection_codes':list(selected.rejection_codes),
                'evidence':selected.diagnostics['evidence_v2']}
            if winners:
                apparent_missed.append(sample)
            if len(samples)<20:
                samples.append(sample)
        bounded = json.loads((store.details/'bounded_diagnostics.json').read_text(encoding='utf8'))
        report = {'role':result['role'], 'formal_pipeline_runs':1, 'read_only_counterfactual_audit':True,
            'primary_entity_superset_pair_count':len(primary_possible), 'primary_entity_type_pair_counts':dict(type_counts),
            'attested_relation_count':relation_count,'network_behavior_eligible_member_pair_count':network_checked,
            'omitted_primary_superset_pair_count':len(omitted), 'omitted_pairs_scored':min(limit,len(omitted)),
            'omitted_audit_exhaustive_for_primary_superset':len(omitted)<=limit,
            'omitted_reasons':dict(counter), 'apparent_missed_formal_pairs':apparent_missed, 'omitted_samples':samples,
            'candidate_evidence_family_usage':bounded['candidate_evidence_family_statistics'],
            'evidence_audit':result['evidence_audit'], 'accepted_sample_count':len(json.loads((dest/'top_accepted_pairs.json').read_text(encoding='utf8'))),
            'rejected_sample_count':len(json.loads((dest/'top_rejected_pairs.json').read_text(encoding='utf8'))),
            'limitations':['This is observed-field coverage, not Ground Truth recall or calibrated attack precision.',
                'Primary superset does not create new relations or claim two alerts confirm an attack.']}
        atomic_json(dest/'EVIDENCE_QUALITY_AUDIT.json', report)
        print(json.dumps({k:report[k] for k in ('role','primary_entity_superset_pair_count','omitted_primary_superset_pair_count',
            'omitted_pairs_scored','omitted_audit_exhaustive_for_primary_superset','apparent_missed_formal_pairs')}), flush=True)
        return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--omitted-pair-limit', type=int, default=256)
    args = parser.parse_args()
    if args.tag not in {'baseline_v3_verified','dev_v4','validation'} or not 1<=args.omitted_pair_limit<=10000:
        raise ValueError('invalid_audit_request')
    audit(args.tag,args.omitted_pair_limit)

"""Production evidence diagnostics; never opens evaluation or hold-out inputs."""
from collections import Counter
from bisect import bisect_left, bisect_right
import argparse
import json
from pathlib import Path
import sys
import duckdb

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
from app.models.base import resolve_pointer
from app.services.storage import atomic_json, file_digest


def read(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def records(path):
    with Path(path).open(encoding='utf8') as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def lightweight(receipt, destination, domain, details):
    """Fox only: aggregate sanity metrics, no raw-alert/failure sample mining."""
    owner = {}
    for group in records(domain/'dedupe_groups.jsonl'):
        owner.update({a: group['representative_alert_id'] for a in group['alert_ids']})
    counts = Counter()
    for incident in records(domain/'incidents.jsonl'):
        n = len(incident['alert_ids'])
        reps = len({owner.get(a, a) for a in incident['alert_ids']})
        counts['singleton_count'] += int(n == 1)
        counts['representative_singleton_count'] += int(reps == 1)
        counts['multi_alert_incident_count'] += int(n > 1)
        counts['multi_representative_incident_count'] += int(reps > 1)
        counts['largest_incident_alert_count'] = max(counts['largest_incident_alert_count'], n)
        counts['largest_incident_representative_count'] = max(counts['largest_incident_representative_count'], reps)
    exact = read(details/'development_audit.json')
    stats = {**receipt, 'counts': {**receipt['counts'], **dict(counts)},
        'singleton_ratio': counts['singleton_count']/receipt['counts']['incident_count'],
        'multi_alert_ratio': counts['multi_alert_incident_count']/receipt['counts']['incident_count'],
        'score_distribution': exact['score_distribution'], 'evidence': exact,
        'validation_scope': 'aggregate production/evidence/resource sanity only; no failure mining or labels'}
    stats['evidence_ratios'] = evidence_ratios(exact)
    atomic_json(destination/'RESULT.json', stats)
    print(json.dumps({'analysis_id': receipt['analysis_id'], 'status': 'fox_aggregate_only', 'counts': stats['counts']}), flush=True)
    return stats


def evidence_ratios(exact):
    accepted = exact['evidence_proxies']['accepted']
    n = accepted.get('count', 0)
    return {name: accepted.get(field, 0)/n if n else None for name, field in (
        ('high_frequency_entity_edge_ratio', 'high_frequency_entity'), ('cross_source_namespace_edge_ratio', 'cross_source'),
        ('same_rule_id_field_edge_ratio', 'same_rule_id'), ('metadata_only_edge_ratio', 'metadata_only'),
        ('confirmed_source_corroboration_edge_ratio', 'confirmed_corroboration'))}


def analyze(receipt, destination):
    receipt = read(receipt)
    domain = ROOT/'data/processed'/receipt['analysis_id']
    details = ROOT/'outputs/analyses'/receipt['analysis_id']
    run = read(domain/'run.json')
    if run.get('dataset_metadata', {}).get('scene_id') not in {'russellmitchell', 'fox'}:
        raise ValueError('development_split_violation')
    destination = Path(destination)
    if not destination.resolve().is_relative_to((ROOT/'outputs/correlation_v4').resolve()):
        raise ValueError('development_output_scope')
    destination.mkdir(parents=True, exist_ok=True)
    if run['dataset_metadata']['scene_id'] == 'fox':
        return lightweight(receipt, destination, domain, details)
    alerts = {a['alert_id']: a for a in records(domain/'alerts.jsonl')}
    entities = {e['entity_id']: e for e in records(domain/'entities.jsonl')}
    edges = list(records(domain/'correlation_edges.jsonl'))
    incidents = list(records(domain/'incidents.jsonl'))
    groups = list(records(domain/'dedupe_groups.jsonl'))
    owner = {a: a for a in alerts}
    for group in groups:
        owner.update({a: group['representative_alert_id'] for a in group['alert_ids']})
    rep_sizes = [len({owner[a] for a in i['alert_ids']}) for i in incidents]
    bounded = read(details/'bounded_diagnostics.json')
    exact = read(details/'development_audit.json') if (details/'development_audit.json').exists() else None
    if exact:
        bounds = (0, .1, .2, .3, .4, .5, .6, .65, .7, .8, .9, 1)
        buckets = [f'[{a:.2f},{b:.2f})' for a, b in zip(bounds, bounds[1:])]+['{1.00}']
        for population in exact['score_distribution'].values():
            population['histogram'] = {b: population['histogram'].get(b, 0) for b in buckets}
        if exact.get('proxy_semantics') != 'selected-candidate-v2':
            for name, population in exact['evidence_proxies'].items():
                population['no_primary'] = population.pop('metadata_only')
                # The initial observer recorded no-primary under the broad old
                # label. Formal-edge primary validation proves zero accepted
                # metadata-only edges; rejected pure metadata-only is unknown.
                population['metadata_only'] = 0 if name == 'accepted' else None
            exact['proxy_semantics'] = 'v3_no_primary_exact_rejected_pure_metadata_only_not_collected'
    distribution = read(details/'candidate_distribution.json')
    per_rep = {r['alert_id']: r for r in distribution.get('top_20', [])}
    algorithm = run['config_snapshot']['algorithm']
    postings = {}
    for eid, entity in entities.items():
        rows = sorted((alerts[a]['timestamp'], a) for a in entity['alert_ids'])
        postings[eid] = ([t for t, _ in rows], rows)
    overrides = {(o['from_category'], o['to_category']): o['window_seconds']
                 for o in algorithm['candidate']['behavior_window_overrides']}
    from datetime import datetime, timedelta
    def indexed_context(aid):
        """Prove an entity-indexed eligible neighbor, without any top-K scoring."""
        a = alerts[aid]
        stamp = datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00'))
        radius = timedelta(seconds=algorithm['candidate']['max_window_seconds'])
        lo = (stamp-radius).isoformat(timespec='microseconds').replace('+00:00', 'Z')
        hi = (stamp+radius).isoformat(timespec='microseconds').replace('+00:00', 'Z')
        for eid in a['entity_ids']:
            times, rows = postings[eid]
            kind = entities[eid]['type']
            for _, other in rows[bisect_left(times, lo):bisect_right(times, hi)]:
                if owner[aid] == owner[other]: continue
                b = alerts[other]
                early, late = sorted((a, b), key=lambda x: (x['timestamp'], x['alert_id']))
                window = algorithm['candidate']['entity_windows_seconds'][kind]
                if kind in algorithm['candidate']['behavior_override_channels']:
                    window = overrides.get((early['category'], late['category']), window)
                    if a['timestamp'] == b['timestamp']:
                        window = max(window, overrides.get((late['category'], early['category']), window))
                gap = abs((stamp-datetime.fromisoformat(b['timestamp'].replace('Z', '+00:00'))).total_seconds())
                if gap <= window: return True
        return False
    singletons, singleton_counts = [], Counter()
    for incident in incidents:
        if len(incident['alert_ids']) != 1:
            continue
        aid = incident['alert_ids'][0]
        alert = alerts[aid]
        triage = incident.get('single_alert_triage', {})
        indexed = per_rep.get(aid, {})
        non_time = sum(v for k, v in indexed.get('candidate_sources', {}).items() if k != 'time_only')
        if not triage.get('candidate_count', 0) and not non_time:
            non_time = int(indexed_context(aid))
        if triage.get('gate_passed_count', 0):
            category = 'D_evidence_exists_score_or_clustering_insufficient'
        elif not triage.get('candidate_count', 0) and non_time:
            category = 'C_indexed_context_not_admitted'
        elif not triage.get('candidate_count', 0) and alert['entity_ids'] and alert['category'] != 'unknown':
            category = 'A_observed_standalone_provisional'
        else:
            category = 'B_evidence_poor'
        singleton_counts[category] += 1
        singletons.append(dict(alert_id=aid, classification=category, candidate_count=triage.get('candidate_count', 0),
            gate_passed_count=triage.get('gate_passed_count', 0), formal_edge_count=triage.get('formal_edge_count', 0),
            indexed_non_time_count=non_time, search_complete=triage.get('search_complete'),
            category=alert['category'], entity_count=len(alert['entity_ids']),
            rejection_counts=triage.get('rejection_counts', {})))
    singletons.sort(key=lambda x: x['alert_id'])
    singleton = dict(raw_singleton_count=len(singletons), counts={k: singleton_counts[k] for k in (
        'A_observed_standalone_provisional', 'B_evidence_poor', 'C_indexed_context_not_admitted',
        'D_evidence_exists_score_or_clustering_insufficient', 'E_confirmed_adapter_or_extraction_defect')},
        denominator='Incidents containing exactly one original alert',
        representative_singleton_incidents=sum(n == 1 for n in rep_sizes),
        limitations=['A is observed standalone, genuine standalone cannot be established without incident truth.',
            'C is observable admission-policy loss, not proof that a positive correlation was missed.',
            'D includes accepted display edges that do not pass clustering threshold/guards.',
            'E=0 confirmed defects does not establish complete extraction; unknown categories and sparse raw inputs require source review.'],
        unknown_category_count=sum(s['category'] == 'unknown' for s in singletons),
        no_entity_count=sum(s['entity_count'] == 0 for s in singletons))
    atomic_json(destination/'SINGLETON_ANALYSIS.json', singleton)
    with (destination/'singleton_details.jsonl').open('w', encoding='utf8') as handle:
        for row in singletons:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True)+'\n')
    stats = {**receipt, 'counts': {**receipt['counts'],
        'singleton_count': len(singletons), 'representative_singleton_count': sum(n == 1 for n in rep_sizes),
        'multi_alert_incident_count': sum(len(i['alert_ids']) > 1 for i in incidents),
        'multi_representative_incident_count': sum(n > 1 for n in rep_sizes),
        'largest_incident_alert_count': max((len(i['alert_ids']) for i in incidents), default=0),
        'largest_incident_representative_count': max(rep_sizes, default=0)},
        'singleton_ratio': len(singletons)/len(incidents) if incidents else None,
        'multi_alert_ratio': sum(len(i['alert_ids']) > 1 for i in incidents)/len(incidents) if incidents else None,
        'score_distribution': exact['score_distribution'] if exact else {'status': 'preview_histogram_only', 'histograms': bounded['score_histogram']},
        'evidence': exact if exact else {'status': 'preview', 'family_statistics': bounded['candidate_evidence_family_statistics']},
        'candidate_diagnostics': {k: bounded[k] for k in ('counts', 'candidate_gate_statistics', 'network_statistics', 'flow_role_statistics')},
        'triage_formula': 'UNCHANGED', 'pair_precision': None, 'pair_recall': None,
        'evaluation_capability': 'No incident/pair equivalence truth is used in development; vendor rule names do not establish attacks.'}
    if exact:
        stats['evidence_ratios'] = evidence_ratios(exact)
    atomic_json(destination/'RESULT.json', stats)
    atomic_json(destination/'SCORE_DISTRIBUTION.json', stats['score_distribution'])
    atomic_json(destination/'EDGE_EVIDENCE_ANALYSIS.json', stats['evidence'])
    categories = {k: [] for k in ('top_high_score', 'threshold_near', 'large_incident', 'high_frequency_entity',
        'same_signature', 'cross_source', 'low_information', 'evidence_rich')}
    membership = {a: i for i in incidents for a in i['alert_ids']}
    trace_count = 0
    for edge in sorted(edges, key=lambda e: (-e['score'], e['edge_id'])):
        ev = edge['score_breakdown']['evidence_v2']
        aa = [alerts[x] for x in edge['support_pair'].values()]
        for fact in ev['evidence']:
            for pointer in fact['evidence_refs']:
                resolve_pointer(alerts[pointer['alert_id']]['raw_alert'], pointer['pointer'])
                trace_count += 1
        row = dict(edge=edge, alerts=aa, entities=[entities[e] for e in edge['entity_ids']],
            incident_id=membership[edge['source_alert_id']]['incident_id'], disposition='formal_correlation_not_confirmed_attack')
        include = ['top_high_score', 'evidence_rich']
        if .60 <= edge['score'] < .70: include.append('threshold_near')
        if len(membership[edge['source_alert_id']]['alert_ids']) > 1: include.append('large_incident')
        if any(f['hot'] for f in ev['entity_reliability']): include.append('high_frequency_entity')
        if aa[0]['signature'] and aa[0]['signature'] == aa[1]['signature']: include.append('same_signature')
        if aa[0]['source_namespace'] != aa[1]['source_namespace']: include.append('cross_source')
        if not ev['relation_support'] and not ev['network_continuity_valid']: include.append('low_information')
        for category in include:
            if len(categories[category]) < 5: categories[category].append(row)
    rejected = []
    db = duckdb.connect(':memory:')
    try:
        parts = list((details/'candidate_samples').glob('*.parquet'))
        if parts:
            cursor = db.execute("SELECT payload FROM read_parquet(?) ORDER BY "
                "json_extract_string(payload, '$.candidate.support_key[0]'), "
                "json_extract_string(payload, '$.candidate.support_key[1]')", [str(details/'candidate_samples/*.parquet')])
            while batch := cursor.fetchmany(256):
                for (payload,) in batch:
                    sample = json.loads(payload)
                    ev = sample['member']['evidence']['evidence_v2']
                    aa = [alerts[a] for a in sample['member']['support_pair']]
                    include = []
                    if any(f['hot'] for f in ev['entity_reliability']): include.append('high_frequency_entity')
                    if aa[0]['signature'] and aa[0]['signature'] == aa[1]['signature']: include.append('same_signature')
                    if aa[0]['source_namespace'] != aa[1]['source_namespace']: include.append('cross_source')
                    if ev['metadata_dominated']: include.append('low_information')
                    if .60 <= sample['member']['score'] < .70: include.append('threshold_near')
                    for category in include:
                        if len(categories[category]) < 5:
                            categories[category].append(dict(sample=sample, alerts=aa, disposition='rejected_candidate'))
                    if len(rejected) < 5: rejected.append(dict(sample=sample, alerts=aa))
    finally:
        db.close()
    (destination/'samples').mkdir(exist_ok=True)
    for name, rows in categories.items():
        atomic_json(destination/'samples'/f'{name}.json', {'count': len(rows), 'samples': rows,
            'population_note': 'deterministic examples; rejected examples supplement empty formal-edge strata; empty strata remain empty'})
    atomic_json(destination/'samples'/'rejected.json', rejected)
    atomic_json(destination/'TRACEABILITY.json', dict(formal_edges=len(edges), checked_evidence_pointers=trace_count,
        evidence_pointer_resolution='PASS', raw_alert_chain='PASS', ground_truth_used=False))
    print(json.dumps({'analysis_id': receipt['analysis_id'], 'counts': stats['counts'], 'destination': str(destination)}), flush=True)
    return stats


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    analyze(ROOT/args.receipt, ROOT/args.destination)

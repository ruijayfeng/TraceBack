"""Offline labels, pointer audits and evidence-grounded failure cases."""

from bisect import bisect_left
from collections import Counter, defaultdict
import gzip
import json
from pathlib import Path

import duckdb

from app.models.base import resolve_pointer
from app.services.bounded_diagnostics import sql_literal
from .common import FAMILIES, pair_source, ratio, source
from .observer import attribution, missing_dimensions


def ingress_observation_coverage(directory, config):
    """Inventory stored native/wrapped event fields, independently of labels.

    Reuse only already declared frozen pointer paths for observational coverage;
    never send these alternate paths back into the production configuration.
    """
    path = Path(directory)/'canonical_ingress.jsonl.gz'
    if not path.exists():
        return {'status': 'unavailable', 'reason': 'no_frozen_ingress'}
    events = config.algorithm.duplicate.observation.event_pointers
    paths = {field: sorted({p for product in ('wazuh', 'suricata') for p in events.get(product, {}).get(field, [])})
             for field in ('flow_id', 'protocol')}
    population, flow, protocol, misses, full_tuple_misses = Counter(), Counter(), Counter(), Counter(), Counter()
    samples = []
    def find(raw, pointers):
        for pointer in pointers:
            try:
                value = resolve_pointer(raw, pointer)
            except ValueError:
                continue
            if type(value) in (str, int) and str(value).strip():
                return pointer, value
        return None, None
    with gzip.open(path, 'rt', encoding='utf-8') as handle:
        for line in handle:
            a = json.loads(line)
            src = a['source_type']
            population[src] += 1
            flow_path, flow_value = find(a['raw_alert'], paths['flow_id'])
            protocol_path, protocol_value = find(a['raw_alert'], paths['protocol'])
            configured_path, _ = find(a['raw_alert'], events.get(src, {}).get('flow_id', []))
            flow[src] += int(flow_path is not None)
            protocol[src] += int(protocol_path is not None)
            missed = flow_path is not None and configured_path is None
            misses[src] += int(missed)
            complete = missed and protocol_path is not None and all(a.get(k) is not None for k in ('src_ip', 'dst_ip', 'src_port', 'dst_port'))
            full_tuple_misses[src] += int(complete)
            if complete and len(samples) < 3:
                samples.append({'canonical_alert': a, 'observed_flow_pointer': flow_path,
                    'observed_protocol_pointer': protocol_path, 'flow_value': flow_value, 'protocol_value': protocol_value})
    total = sum(population.values())
    return {'status': 'available_full_ingress', 'canonical_alert_count': total,
        'raw_embedded_flow_presence_count': sum(flow.values()), 'raw_embedded_flow_presence_rate': ratio(sum(flow.values()), total),
        'by_source': {s: {'canonical_alert_count': n, 'raw_embedded_flow_presence_count': flow[s],
            'raw_embedded_flow_presence_rate': ratio(flow[s], n), 'raw_embedded_protocol_presence_count': protocol[s],
            'configured_flow_pointer_miss_count': misses[s], 'complete_tuple_pointer_miss_count': full_tuple_misses[s]}
            for s, n in sorted(population.items())},
        'configured_flow_pointer_miss_count': sum(misses.values()), 'complete_tuple_pointer_miss_count': sum(full_tuple_misses.values()),
        'observational_pointer_paths': paths, 'samples': samples,
        'limitation': 'Stored field presence is separate from the paths actually used by frozen v3. No config changes or new FLOW Entity.'}


def reproduce_observation_pointer_gap(sample, config, settings, config_hash):
    """One real canonical input, unchanged production observation machinery.

    No synthetic second alert, scoring population, label, or partial formal
    graph is created. The result only tests whether existing raw fields are read.
    """
    from app.models import CanonicalAlert
    from app.entities.extraction import extract_entities
    from app.correlation.index import AlertIndex
    from app.correlation.scoring import CorrelationScorer
    a = CanonicalAlert.model_validate(sample['canonical_alert'])
    extracted = extract_entities([a], settings)
    index = AlertIndex(extracted.alerts, [], extracted.entities)
    scorer = CorrelationScorer(index, config, settings, config_hash)
    observed = scorer.duplicate.observation.identities[a.alert_id]
    confirmed = a.source_type.value == 'suricata' and observed.event_fingerprint is None and observed.protocol is None
    return {'alert_id': a.alert_id, 'source_type': a.source_type.value, 'source_namespace': a.source_namespace,
        'configured_event_pointers': config.algorithm.duplicate.observation.event_pointers.get(a.source_type.value, {}),
        'raw_evidence_pointers': [{'alert_id': a.alert_id, 'pointer': sample[k], 'side': 'src'}
                                 for k in ('observed_flow_pointer', 'observed_protocol_pointer')],
        'raw_flow_present': resolve_pointer(a.raw_alert, sample['observed_flow_pointer']) == sample['flow_value'],
        'raw_protocol_present': resolve_pointer(a.raw_alert, sample['observed_protocol_pointer']) == sample['protocol_value'],
        'complete_canonical_endpoint_tuple': all(getattr(a, k) is not None for k in ('src_ip', 'dst_ip', 'src_port', 'dst_port')),
        'observed_event_fingerprint': observed.event_fingerprint, 'observed_protocol': observed.protocol,
        'confirmed_envelope_pointer_mismatch': confirmed, 'diagnosis': 'IMPLEMENTATION_DEFECT' if confirmed else 'UNRESOLVED',
        'defect_scope': 'existing frozen observation config and supported Adapter envelope integration',
        'impact': 'existing network continuity requires an event fingerprint and protocol; wrapped context is unread. Actual edge/missed-pair impact requires completed full populations.',
        'production_modified': False, 'ground_truth_used': False}


def describe(alert, entities):
    fields = ('alert_id', 'timestamp', 'source_type', 'source_namespace', 'sensor', 'rule_id',
        'signature', 'category', 'severity', 'host', 'account', 'session', 'src_ip', 'dst_ip',
        'src_port', 'dst_port', 'process', 'parent_process', 'file', 'command', 'domain', 'url')
    return {k: alert.get(k) for k in fields} | {'entities': [entities[e] for e in alert.get('entity_ids', [])],
        'entity_roles': alert.get('entity_occurrences', []), 'field_provenance': alert['field_provenance']}


def load_objects(directory, sampled_ids):
    """Keep raw payloads only for sampled pointers; entities support all profiles."""
    alerts, entities = {}, {}
    with gzip.open(directory/'entities.jsonl.gz', 'rt', encoding='utf-8') as handle:
        for line in handle:
            entity = json.loads(line)
            entities[entity['entity_id']] = {k: entity[k] for k in ('entity_id', 'type', 'scope', 'value')}
    with gzip.open(directory/'alerts.jsonl.gz', 'rt', encoding='utf-8') as handle:
        for line in handle:
            alert = json.loads(line)
            if alert['alert_id'] not in sampled_ids:
                alert.pop('raw_alert', None)
            alerts[alert['alert_id']] = alert
    owner = {a: a for a in alerts}
    groups = []
    with gzip.open(directory/'dedupe_groups.jsonl.gz', 'rt', encoding='utf-8') as handle:
        for line in handle:
            group = json.loads(line)
            groups.append(group)
            for a in group['alert_ids']:
                owner[a] = group['representative_alert_id']
    return alerts, entities, owner, groups


def audit_case(payload, alerts, entities, config):
    member, decision = payload['member'], payload['decision']
    a, b = (alerts[i] for i in member['support_pair'])
    ev = member['evidence']['evidence_v2']
    shared = sorted(set(a['entity_ids']) & set(b['entity_ids']))
    pointers = { (p['alert_id'], p['pointer'], p['side']): p for f in ev['evidence'] for p in f['evidence_refs'] }
    pointer_errors = []
    for key, ref in sorted(pointers.items()):
        try:
            resolve_pointer(alerts[ref['alert_id']]['raw_alert'], ref['pointer'])
        except (ValueError, KeyError) as exc:
            pointer_errors.append({'reference': ref, 'error': str(exc)})
    fact_keys = [f['fact_key'] for f in ev['evidence']]
    repeated_facts = len(fact_keys) != len(set(fact_keys))
    hot = [f['entity_id'] for f in ev['entity_reliability'] if f['hot']]
    local = any(x['src_ip'] and x['src_ip'] == x['dst_ip'] for x in (a, b))
    flags = []
    if repeated_facts:
        flags.append('DUPLICATE_FACT_KEY')
    if pointer_errors:
        flags.append('UNRESOLVABLE_EVIDENCE_POINTER')
    if not ev['primary_evidence']:
        flags.append('NO_PRIMARY_EVIDENCE')
    if ev['duplicate_observation_risk']:
        flags.append('DUPLICATE_OBSERVATION_RISK')
    if ev['metadata_dominated']:
        flags.append('METADATA_DOMINATED')
    if hot:
        flags.append('COMMON_ENTITY_PRESENT_REVIEW_DISCRIMINATIVE_SUPPORT')
    if local:
        flags.append('LOCAL_ENDPOINT_PRESENT_REVIEW_NETWORK_SUPPORT')
    if ev['network_continuity_valid'] and local:
        flags.append('INVALID_LOCALHOST_NETWORK_CONTINUITY')
    defect_flags = {'DUPLICATE_FACT_KEY', 'UNRESOLVABLE_EVIDENCE_POINTER', 'INVALID_LOCALHOST_NETWORK_CONTINUITY'}
    if decision['decision'] == 'accept':
        defect_flags |= {'NO_PRIMARY_EVIDENCE', 'DUPLICATE_OBSERVATION_RISK', 'METADATA_DOMINATED'}
    suspicious = bool(defect_flags & set(flags))
    explanation = (f"独立主证据 {len(ev['primary_evidence'])} 项；可用权重 {ev['available_weight']:.6f}，"
        f"归一质量 {ev['normalized_quality']:.6f}，证据质量总量 {ev['evidence_mass']:.6f}。"
        f"v3 gate={ev['gate_reason']}，decision={ev['decision']}；最终未舍入分 {member['score']:.9f}。"
        "规则/类别/签名合并为一项 metadata 支撑；阈值合格也须通过独立证据及 guard。")
    return {'support_key': decision['support_key'], 'support_pair': member['support_pair'],
        'alert_A': describe(a, entities), 'alert_B': describe(b, entities), 'source_pair': pair_source(a, b),
        'timestamp_delta_seconds': member['evidence']['gap_seconds'], 'shared_entities': [entities[e] for e in shared],
        'evidence_families': ev['evidence_families'], 'evidence_facts': ev['evidence'],
        'entity_reliability': ev['entity_reliability'], 'individual_score_contribution': attribution(member, config),
        'missing_evidence': missing_dimensions(ev), 'final_score': member['score'],
        'threshold_passed': member['score'] >= .65, 'evidence_gate_passed': ev['evidence_gate_passed'],
        'rejection_reason': None if decision['decision'] == 'accept' else {'rule_id': decision['rule_id'],
            'codes': member['rejection_codes'], 'gate_reason': ev['gate_reason'], 'evidence_decision': ev['decision']},
        'raw_evidence_pointers': [pointers[k] for k in sorted(pointers)], 'pointer_errors': pointer_errors,
        'network_diagnostic': ev['network_diagnostic'], 'network_continuity_valid': ev['network_continuity_valid'],
        'flags': flags, 'suspicious_edge': suspicious, 'why_this_score': explanation}


def offline_windows(gt, scene, alerts, owner, edges):
    """Outside-window means unlabelled; never automatically background/benign."""
    from app.correlation.index import event_microseconds
    selected = [r for r in gt['records'] if r['scene_id'] == scene]
    alert_windows = defaultdict(set)
    window_counts = []
    ordered = sorted((event_microseconds(a['timestamp']), aid) for aid, a in alerts.items())
    times = [t for t, aid in ordered]
    for number, row in enumerate(selected):
        start = event_microseconds(row['start_time'])
        end = event_microseconds(row['end_time'])
        lo, hi = bisect_left(times, start), bisect_left(times, end)
        ids = [aid for _, aid in ordered[lo:hi]]
        window_counts.append({'index': number, 'attack_label': row['attack_label'], 'start_time': row['start_time'],
            'end_time': row['end_time'], 'alert_count': len(ids), 'representative_count': len({owner[a] for a in ids})})
        for aid in ids:
            alert_windows[aid].add(number)
    temporal_flags = []
    for edge in edges:
        a, b = edge['support_pair']['alert_id_src'], edge['support_pair']['alert_id_dst']
        wa, wb = alert_windows.get(a, set()), alert_windows.get(b, set())
        if wa and wb and not wa & wb:
            temporal_flags.append({'edge_id': edge['edge_id'], 'classification': 'Potential False Correlation',
                'temporal_flag': 'disjoint_selected_attack_windows', 'window_A': sorted(wa), 'window_B': sorted(wb),
                'support_pair': edge['support_pair'],
                'limitation': 'disjoint window labels are review prompts, not pairwise ground truth or proof of semantic incompatibility'})
        elif bool(wa) != bool(wb):
            temporal_flags.append({'edge_id': edge['edge_id'], 'classification': 'WINDOW_BOUNDARY_REVIEW',
                'temporal_flag': 'window_overlap_vs_unlabelled', 'support_pair': edge['support_pair'],
                'limitation': 'unlabelled endpoint is not confirmed background; no false-positive assertion'})
    return {'status': 'available' if selected else 'unavailable', 'window_count': len(selected), 'windows': window_counts,
        'temporally_overlapping_alert_count': len(alert_windows), 'temporal_overlap_fraction': ratio(len(alert_windows), len(alerts)),
        'outside_window_alert_count': len(alerts)-len(alert_windows), 'alert_or_pair_quality_evaluation_coverage': 0.0,
        'pairwise_precision': None, 'pairwise_recall': None, 'pairwise_metric_status': 'unavailable',
        'potential_false_correlations': temporal_flags,
        'limitations': gt['limitations'] + ['Different labels/scenarios are never passed into production; scenario namespaces are independently declared.']}, alert_windows


def ingress_window_coverage(directory, gt, scene):
    """Offline temporal label alignment even when scoring did not complete.

    No pairwise outcome, identity, or production input is inferred from labels.
    Read the full frozen ingress stream with constant-memory timestamp counts.
    """
    from app.correlation.index import event_microseconds
    selected = [r for r in gt['records'] if r['scene_id'] == scene]
    path = Path(directory)/'canonical_ingress.jsonl.gz'
    if not selected or not path.exists():
        return {'status': 'unavailable', 'reason': 'no_scene_windows_or_frozen_ingress',
                'alert_or_pair_quality_evaluation_coverage': 0.0}
    intervals = [(event_microseconds(r['start_time']), event_microseconds(r['end_time'])) for r in selected]
    counts = [0]*len(intervals)
    population = overlap = 0
    with gzip.open(path, 'rt', encoding='utf-8') as handle:
        for line in handle:
            stamp = event_microseconds(json.loads(line)['timestamp'])
            population += 1
            matched = False
            for i, (start, end) in enumerate(intervals):
                if start <= stamp < end:
                    counts[i] += 1
                    matched = True
            overlap += int(matched)
    return {'status': 'available_temporal_metadata_only', 'canonical_alert_count': population,
        'temporally_overlapping_alert_count': overlap, 'temporal_overlap_fraction': ratio(overlap, population),
        'outside_window_unlabelled_alert_count': population-overlap,
        'alert_or_pair_quality_evaluation_coverage': 0.0,
        'windows': [{**r, 'alert_count': n} for r, n in zip(selected, counts)],
        'limitation': 'Temporal overlap is not attack confirmation or a pairwise outcome; outside-window alerts are unlabelled.'}


def missed_cases(directory, alerts, entities, owner, windows, edges, config, max_cases=50):
    """Deterministic, evidence-constrained screen; counts are sampled, not recall.

    Same HOST/IP or time alone is excluded. A candidate must share an account,
    scoped session, concrete resource, or full process instance, inside the
    frozen entity window, and have another observed context dimension. Only
    nearest pairs per (window, entity) are screened; this is not a full oracle.
    """
    from datetime import datetime
    postings = defaultdict(list)
    for aid, numbers in windows.items():
        for eid in alerts[aid]['entity_ids']:
            entity = entities[eid]
            if entity['type'] not in {'ACCOUNT', 'SESSION', 'PROCESS', 'FILE', 'COMMAND', 'URL'}:
                continue
            if entity['type'] == 'PROCESS' and not any(alerts[aid].get(k) and alerts[aid][k].get('start_time') is not None
                and alerts[aid][k].get('pid') is not None for k in ('process', 'parent_process')):
                continue
            for number in numbers:
                postings[(number, eid)].append(aid)
    options = {}
    deduped, fragmented = [], []
    for (window, eid), ids in sorted(postings.items()):
        ids.sort(key=lambda a: (alerts[a]['timestamp'], a))
        for a, b in zip(ids, ids[1:]):
            if owner[a] == owner[b]:
                if len(deduped) < 10:
                    deduped.append({'alert_ids': [a, b], 'reason': 'DEDUPE_EFFECT', 'fact_group': owner[a],
                        'limitation': 'retention in the same group is not demonstrated information loss'})
                continue
            shared = set(alerts[a]['entity_ids']) & set(alerts[b]['entity_ids'])
            kinds = {entities[e]['type'] for e in shared}
            if len(kinds) < 2:
                continue
            gap = abs((datetime.fromisoformat(alerts[a]['timestamp'].replace('Z', '+00:00'))-
                       datetime.fromisoformat(alerts[b]['timestamp'].replace('Z', '+00:00'))).total_seconds())
            limit = config.algorithm.candidate.entity_windows_seconds[entities[eid]['type']]
            early, late = sorted((alerts[a], alerts[b]), key=lambda x: (x['timestamp'], x['alert_id']))
            if entities[eid]['type'] in config.algorithm.candidate.behavior_override_channels:
                overrides = {(r.from_category, r.to_category): r.window_seconds for r in config.algorithm.candidate.behavior_window_overrides}
                limit = overrides.get((early['category'], late['category']), limit)
            if gap > limit:
                if len(fragmented) < 10:
                    fragmented.append({'alert_ids': [a, b], 'window_index': window,
                        'reason': 'TEMPORAL_GAP', 'timestamp_delta_seconds': gap, 'effective_window_seconds': limit,
                        'shared_entities': [entities[e] for e in sorted(shared)]})
                continue
            pair = tuple(sorted((owner[a], owner[b])))
            options.setdefault(pair, {'support_key': list(pair), 'alert_ids': [a, b], 'window_index': window,
                'timestamp_delta_seconds': gap, 'shared_entities': [entities[e] for e in sorted(shared)],
                'sources': [alerts[a]['source_type'], alerts[b]['source_type']],
                'assessment': 'missed_correlation_candidate_for_review; factual continuity screen, not established GT pair'})
            if len(options) >= max_cases:
                break
        if len(options) >= max_cases:
            break
    formal_pairs = {tuple(sorted((e['source_alert_id'], e['target_alert_id']))) for e in edges}
    unresolved = {k: v for k, v in options.items() if k not in formal_pairs}
    found = {}
    if unresolved:
        db = duckdb.connect()
        try:
            db.execute('SET threads=1')
            db.execute('CREATE TABLE wanted(source_id VARCHAR,target_id VARCHAR)')
            db.execute('INSERT INTO wanted VALUES '+','.join('('+sql_literal(a)+','+sql_literal(b)+')' for a, b in unresolved))
            path = str(directory/'task_c_candidate_index/*.parquet')
            for a, b, score, decision, evidence_decision, gate_reason in db.execute(
                'SELECT c.source_id,c.target_id,c.score,c.decision,c.evidence_decision,c.gate_reason FROM read_parquet('
                +sql_literal(path)+') c JOIN wanted w ON c.source_id=w.source_id AND c.target_id=w.target_id').fetchall():
                found[(a, b)] = {'score': score, 'decision': decision, 'evidence_decision': evidence_decision, 'gate_reason': gate_reason}
        finally:
            db.close()
    cases = []
    for pair, row in sorted(unresolved.items()):
        match = found.get(pair)
        row['candidate_decision'] = match
        row['failure_reason'] = ('NO_CANDIDATE' if match is None else 'SCORE_BELOW_THRESHOLD' if match['evidence_decision'] == 'REJECT_LOW_SCORE'
            else 'EVIDENCE_GUARD_REJECTION' if match['evidence_decision'] in {'REJECT_GUARD', 'REJECT_INSUFFICIENT_EVIDENCE'} else 'UNKNOWN')
        cases.append(row)
    return {'status': 'available_bounded_review', 'screened_pair_count': len(options), 'case_count': len(cases),
        'reason_counts': dict(Counter(c['failure_reason'] for c in cases)), 'cases': cases, 'dedupe_examples': deduped,
        'temporal_fragmentation_examples': fragmented,
        'limits': {'maximum_pairs': max_cases, 'nearest_pair_only': True},
        'limitations': ['Same attack window alone is never a missed-pair criterion.',
            'Sampled continuity cases do not establish pairwise recall; source scopes and public-resource semantics require human review.',
            'NO_CANDIDATE can arise from frozen local Top-K; it is not automatically an implementation defect.']}


def diagnose_scene(directory, result, gt, config):
    samples = result['samples']
    payloads = samples['top_rejected'] + samples['near_threshold'] + samples['top_admitted']
    payloads += [p for rows in samples['stratified'].values() for p in rows]
    ids = {a for p in payloads for a in p['member']['support_pair']}
    alerts, entities, owner, groups = load_objects(directory, ids)
    audit = lambda p: audit_case(p, alerts, entities, config)
    near = {'selection': 'exact highest-scoring rejected candidates, score in [0.50,0.65); separate top rejects may be above threshold but gate-rejected',
        'near_threshold_count_population': result['candidate_taxonomy'].get('F11', 0),
        'cases': [audit(p) for p in samples['near_threshold']], 'top_rejected': [audit(p) for p in samples['top_rejected']],
        'stratified': {k: [audit(p) for p in v] for k, v in samples['stratified'].items()}}
    with gzip.open(directory/'correlation_edges.jsonl.gz', 'rt', encoding='utf-8') as handle:
        edges = [json.loads(line) for line in handle]
    edge_audit = {'selection': 'top 30 admitted plus source/evidence strata; all accepted decisions also checked by Observer',
        'population_count': len(edges), 'cases': [audit(p) for p in samples['top_admitted']],
        'all_edge_invariant_defects': result['implementation_defect_candidates']}
    labels, windows = offline_windows(gt, result['dataset'], alerts, owner, edges)
    edge_audit['offline_window_review'] = labels
    missed = missed_cases(directory, alerts, entities, owner, windows, edges, config)
    return near, edge_audit, missed

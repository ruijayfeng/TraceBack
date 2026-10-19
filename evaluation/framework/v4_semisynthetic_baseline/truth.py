"""Sidecar-only GT adapter. Must verify a sealed blind run before any truth read."""
from collections import Counter
from datetime import datetime
import hashlib
import json

from .artifacts import require_sealed
from .common import BASE, INPUT, OUT, read, save, sha
from .metrics import pair_key, chain_metrics


def field(raw, path):
    for key in path.split('.'):
        if not isinstance(raw, dict) or key not in raw:
            return None
        raw = raw[key]
    return raw


def load(alerts):
    sealed = require_sealed()
    marker = OUT / 'evaluation_started.json'
    if not marker.exists():
        save(marker, {'blind_manifest_sha256': sha(OUT / 'blind_run_manifest.json'),
            'order': 'complete sealed prediction -> semantic GT load', 'production_replay_forbidden_from_here': True})
    if read(marker)['blind_manifest_sha256'] != sha(OUT / 'blind_run_manifest.json'):
        raise ValueError('blind_manifest_changed_since_first_truth_read')
    gt = read(BASE / 'attack_scenarios/ground_truth.json')
    provenance = read(BASE / 'final/provenance.json')['records']
    manifest = read(BASE / 'final/traceback_demo_v1_manifest.json')
    for key, p in [('ground_truth_sha256', BASE / 'attack_scenarios/ground_truth.json'),
                   ('provenance_sha256', BASE / 'final/provenance.json'), ('final_file_sha256', INPUT)]:
        if sha(p) != manifest[key]:
            raise ValueError('dataset_declared_hash_mismatch:' + key)
    if (len(gt['nodes']), len(gt['edges']), len(gt['hard_negatives'])) != (7, 6, 30):
        raise ValueError('unexpected_GT_counts')
    line_map = {r['final_line']: r['alert_id'] for r in read(OUT / 'blind/input_line_map.json')}
    if len(provenance) != 10051 or set(r['final_line'] for r in provenance) != set(line_map):
        raise ValueError('provenance_does_not_cover_exact_input')
    raw_lines = INPUT.read_bytes().splitlines()
    ids, metadata = {}, {}
    for row in provenance:
        line = row['final_line']
        if hashlib.sha256(raw_lines[line - 1]).hexdigest() != row['line_sha256']:
            raise ValueError('provenance_line_hash_mismatch')
        aid = line_map[line]
        if aid not in alerts or row['source_namespace'] != alerts[aid]['source_namespace']:
            raise ValueError('provenance_canonical_mapping_mismatch')
        if row['alert_id'] in ids:
            raise ValueError('duplicate_external_alert_ID')
        ids[row['alert_id']] = aid
        metadata[aid] = row
    counts = Counter(r['label'] for r in provenance)
    if counts != {'unlabeled_background': 10000, 'attack_progression': 21, 'not_related': 30}:
        raise ValueError('unexpected_label_populations')
    nodes = {n['node_id']: n for n in gt['nodes']}
    members = {n: {ids[x] for x in row['alert_ids']} for n, row in nodes.items()}
    attack_ids = set().union(*members.values())
    hard_ids = {ids[r['alert_id']] for r in gt['hard_negatives']}
    if len(attack_ids) != 21 or len(hard_ids) != 30 or attack_ids & hard_ids:
        raise ValueError('invalid_or_overlapping_attack_hard_negative_membership')
    if any(metadata[x]['label'] != 'attack_progression' for x in attack_ids):
        raise ValueError('GT_membership_provenance_label_conflict')
    witnesses, validation = {}, []
    for edge in gt['edges']:
        e = edge['edge_id']
        a, b = (ids[edge['witness_alert_ids'][s]] for s in ('from', 'to'))
        if a not in members[edge['from']] or b not in members[edge['to']]:
            raise ValueError('GT_witness_outside_node')
        if a == b:
            raise ValueError('GT_witness_collapsed_to_same_alert')
        witnesses[e] = {pair_key(a, b)}
        raw_a, raw_b = alerts[a]['raw_alert'], alerts[b]['raw_alert']
        actual_delta = (datetime.fromisoformat(alerts[b]['timestamp'].replace('Z', '+00:00')) -
                        datetime.fromisoformat(alerts[a]['timestamp'].replace('Z', '+00:00'))).total_seconds()
        if actual_delta != edge['time_delta_seconds']:
            raise ValueError('GT_witness_time_delta_mismatch')
        for eq in edge['equality_witnesses']:
            if field(raw_a, eq['from_field']) != eq['value'] or field(raw_b, eq['to_field']) != eq['value']:
                raise ValueError('GT_equality_witness_not_in_input')
        for side, path in edge['missing_field_witnesses']:
            if field(raw_a if side == 'from' else raw_b, path) is not None:
                raise ValueError('GT_missing_field_witness_is_present')
        validation.append({'edge_id': e, 'canonical_witness': [a, b],
                           'time_delta_seconds_verified': actual_delta,
                           'equalities_verified': len(edge['equality_witnesses']),
                           'missing_fields_verified': len(edge['missing_field_witnesses'])})
    negatives = set()
    for pair in gt['negative_pairs']:
        if pair['label'] != 'not_related' or not pair['symmetric']:
            raise ValueError('unsupported_GT_negative_policy')
        negatives.add(pair_key(ids[pair['from_alert_id']], ids[pair['to_alert_id']]))
    if len(negatives) != 630 or negatives != {pair_key(a, b) for a in hard_ids for b in attack_ids}:
        raise ValueError('explicit_negative_pairs_not_30_by_21')
    if set().union(*witnesses.values()) & negatives:
        raise ValueError('positive_negative_conflict')
    graph = chain_metrics(set(nodes), [(e['from'], e['to']) for e in gt['edges']])
    if graph['longest_path_edges'] != 6 or graph['connected_components'] != 1:
        raise ValueError('GT_is_not_seven_node_six_edge_progression')
    save(OUT / 'dataset_validation.json', {'status': 'PASS', 'raw_count': sealed['raw_alert_count'],
        'gt_nodes': 7, 'gt_edges': 6, 'longest_gt_path_edges': 6,
        'labels': dict(counts), 'synthetic_attack_alerts': 21, 'hard_negative_alerts': 30,
        'explicit_positive_pairs': sum(map(len, witnesses.values())), 'explicit_negative_pairs': len(negatives),
        'all_input_line_hashes_verified': True, 'all_GT_references_mapped': True,
        'edge_field_validation': validation, 'gt_sha256': sha(BASE / 'attack_scenarios/ground_truth.json'),
        'evaluation_policy': gt['evaluation_policy'],
        'ordering_note': 'Manifest counts checked before run; actual GT references/edges checked only after sealed blind completion.'})
    return {'gt': gt, 'ids': ids, 'metadata': metadata, 'nodes': nodes, 'members': members,
            'attack_ids': attack_ids, 'hard_ids': hard_ids,
            'background_ids': {a for a, m in metadata.items() if m['label'] == 'unlabeled_background'},
            'witnesses': witnesses, 'negative_pairs': negatives}

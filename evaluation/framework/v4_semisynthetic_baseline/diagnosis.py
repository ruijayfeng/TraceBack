"""Explanations derived solely from saved observations and frozen equations."""
from datetime import datetime
import math


def stamp(alert):
    return datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00')).timestamp()


def candidate_absence(a, b, entities, owners, algorithm):
    if owners[a['alert_id']] == owners[b['alert_id']]:
        return {'reason': 'SAME_DEDUPE_FACT_GROUP', 'eligible_channels': []}
    cfg = algorithm['candidate']
    common = sorted(set(a['entity_ids']) & set(b['entity_ids']))
    early, late = sorted((a, b), key=lambda x: (x['timestamp'], x['alert_id']))
    gap = abs(stamp(a) - stamp(b))
    overrides = {(r['from_category'], r['to_category']): r['window_seconds']
                 for r in cfg['behavior_window_overrides']}
    channels, rejected = [], []
    for eid in common:
        channel = entities[eid]['type']
        window = cfg['entity_windows_seconds'].get(channel, cfg['default_window_seconds'])
        if channel in cfg['behavior_override_channels']:
            window = overrides.get((early['category'], late['category']), window)
            if gap == 0:
                window = max(window, overrides.get((late['category'], early['category']), window))
        item = {'channel': channel, 'entity_id': eid, 'gap_seconds': gap, 'effective_window_seconds': window}
        (channels if gap <= window else rejected).append(item)
    if not a['entity_ids'] and not b['entity_ids'] and a['source_namespace'] == b['source_namespace']:
        for name in algorithm['score']['evidence_v2']['semantic_candidate_fields']:
            if a[name] is not None and a[name] == b[name] and (name != 'category' or a[name] != 'unknown'):
                item = {'channel': 'semantic', 'field': name, 'gap_seconds': gap,
                        'effective_window_seconds': algorithm['score']['evidence_v2']['semantic_candidate_window_seconds']}
                (channels if gap <= item['effective_window_seconds'] else rejected).append(item)
    # This is a local eligibility explanation, never a replay or nomination.
    return {'reason': 'POLICY_PRUNED_ELIGIBLE_PAIR' if channels else 'OUTSIDE_ALL_SHARED_CHANNEL_WINDOWS'
            if rejected else 'NO_SHARED_SCOPED_ENTITY_OR_ENTITY_FREE_SEMANTIC_KEY',
        'eligible_channels': channels, 'outside_window_channels': rejected,
        'shared_entity_ids': common, 'gap_seconds': gap,
        'source_namespaces': [a['source_namespace'], b['source_namespace']],
        'explicit_relation_count': len(a['relations']) + len(b['relations']),
        'note': 'Static saved-field audit; no candidate/scoring function rerun. Local Top-K is inferred only when eligibility is proven and the sealed candidate set omits the pair.'}


def decomposition(row, algorithm):
    if row is None:
        return {'status': 'not_applicable', 'reason': 'no_candidate_witness_was_scored',
                'final_score': None, 'families': None}
    audit = row['evidence']['evidence_v2']
    qf, mf = audit['quality_factor'], audit['mass_factor']
    aw, tw = audit['available_weight'], audit['total_configured_weight']
    families = {}
    for family, weight in audit['family_weights'].items():
        dims = [d for d in audit['dimensions'] if d['family'] == family]
        available = any(d['state'].startswith('AVAILABLE') for d in dims)
        mass = weight * audit['family_strengths'][family] if available else 0.
        families[family] = {'weight': weight, 'strength': audit['family_strengths'][family],
            'observable': available, 'weighted_evidence_mass': mass,
            'quality_score_contribution': qf * mass / aw if aw else 0.,
            'mass_score_contribution': mf * mass / tw if tw else 0., 'dimensions': dims}
    penalties = {k: -algorithm['score']['weights'][k] * row['values'][k] for k in ('conflict', 'duplicate')}
    computed = math.fsum(v['quality_score_contribution'] + v['mass_score_contribution'] for v in families.values()) + math.fsum(penalties.values())
    if abs(computed - row['raw_total']) > 1e-10:
        raise ValueError('v4_evidence_decomposition_does_not_recompute')
    # Algebraic diagnostic only; no synthetic evidence, candidate, or score replay.
    # Hold all non-temporal fields and availability fixed and let T approach 1.
    delta = audit['family_weights']['time'] * (1 - audit['family_strengths']['time'])
    temporal_ceiling = min(1., max(0., row['raw_total'] + delta * (qf / aw + mf / tw)))
    return {'status': 'available', 'support_pair': row['support_pair'], 'families': families,
        'actual_evidence_families': audit['evidence_families'], 'raw_evidence_mass': audit['matched_weight'],
        'available_weight': aw, 'total_configured_weight': tw,
        'normalized_quality': audit['normalized_quality'], 'evidence_mass': audit['evidence_mass'],
        'quality_factor': qf, 'mass_factor': mf, 'penalties': penalties,
        'raw_total': row['raw_total'], 'final_score': row['score'], 'recomputed_raw_total': computed,
        'gate_passed': audit['evidence_gate_passed'], 'gate_reason': audit['gate_reason'],
        'primary_evidence': audit['primary_evidence'], 'network_diagnostic': audit['network_diagnostic'],
        'legacy_seven_component_values': row['values'],
        'legacy_contributions': row['contributions'],
        'legacy_note': 'These seven signed contributions are retained audit values, not the v4 final score formula.',
        'frozen_non_temporal_evidence_score_ceiling': temporal_ceiling,
        'ceiling_definition': 'Algebra only: actual availability, entity reliability, metadata, topology and penalties fixed; only temporal strength allowed to reach 1. Not a production rerun or attainable evidence claim.',
        'missingness_semantics': 'UNAVAILABLE/NOT_APPLICABLE excluded from quality denominator; total configured weight remains the mass denominator. Missing families get no mass credit. AVAILABLE_MISMATCH remains in the family/quality denominator.'}


def get(raw, *path):
    for key in path:
        if not isinstance(raw, dict) or key not in raw:
            return None
        raw = raw[key]
    return raw


def observation(alert):
    raw = alert['raw_alert']
    raw_hints = {
        'host': get(raw, 'data', 'host') or get(raw, 'data', 'hostname') or get(raw, 'predecoder', 'hostname'),
        'account': get(raw, 'data', 'dstuser') or get(raw, 'data', 'srcuser') or get(raw, 'data', 'user') or get(raw, 'data', 'audit', 'auid'),
        'session': get(raw, 'data', 'session') or get(raw, 'data', 'audit', 'session'),
        'process': get(raw, 'data', 'process') or get(raw, 'data', 'audit'),
        'parent_process': get(raw, 'data', 'parent_process') or get(raw, 'data', 'audit', 'parent_exe'),
        'url': get(raw, 'http', 'url') or get(raw, 'data', 'http', 'url'),
        'domain': get(raw, 'http', 'hostname') or get(raw, 'tls', 'sni'),
        'file': get(raw, 'data', 'file'), 'command': get(raw, 'data', 'command') or get(raw, 'data', 'audit', 'command')}
    fields = {}
    for name, hint in raw_hints.items():
        fields[name] = {'canonical_present': alert.get(name) is not None,
            'raw_present_at_known_path': hint is not None,
            'status': 'OBSERVED' if alert.get(name) is not None else 'RAW_ONLY_UNMAPPED'
                      if hint is not None else 'UNOBSERVABLE_IN_THIS_ALERT'}
    process = alert.get('process') or {}
    return {'alert_id': alert['alert_id'], 'source_namespace': alert['source_namespace'],
        'fields': fields, 'canonical_category': alert['category'],
        'vendor_semantic_present': bool(alert['rule_id'] or alert['signature']),
        'category_status': 'OBSERVED' if alert['category'] != 'unknown' else 'VENDOR_SEMANTICS_UNMAPPED',
        'process_instance_observable': bool(alert['host'] and process.get('pid') is not None and process.get('start_time')),
        'agent_name': get(raw, 'agent', 'name'), 'agent_ip': get(raw, 'agent', 'ip'),
        'agent_note': 'Present agent identity is retained raw, but frozen adapter does not assert it is the execution/target host. No alias/host reinterpretation was added.'}


def capability(row, alerts):
    observations = [observation(a) for a in alerts]
    dimensions = []
    if row:
        for dim in row['evidence']['evidence_v2']['dimensions']:
            state = dim['state']
            dimensions.append({**dim, 'capability_status': 'OBSERVED_MATCH' if state == 'AVAILABLE_MATCH' else
                'ABSENT_BUT_OBSERVABLE' if state == 'AVAILABLE_MISMATCH' else
                'UNOBSERVABLE_BY_SOURCE' if state == 'UNAVAILABLE' else 'NOT_APPLICABLE',
                'interpretation': 'UNOBSERVABLE_BY_SOURCE here means unavailable to this frozen pair input/adapter, not that the vendor can never emit the field.'})
    return {'observations': observations, 'dimensions': dimensions,
            'scope': 'actual saved source records and frozen adapter/config; no global vendor capability claims',
            'raw_only_fields_are_not_automatically_safe_to_promote': True,
            'unobservable_is_not_negative_evidence': True}


def equality_projection(edge, source, target):
    """Trace GT-declared raw joins to already saved canonical provenance only."""
    result = []
    entity_fields = {'src_ip', 'dst_ip', 'host', 'account', 'session', 'process',
                     'parent_process', 'url', 'domain', 'file', 'command'}
    def projection(alert, path):
        pointer = '/' + '/'.join(x.replace('~', '~0').replace('/', '~1') for x in path.split('.'))
        retained = sorted(name for name, provenance in alert['field_provenance'].items()
            if provenance['raw_pointer'] == pointer and alert.get(name) is not None)
        return {'raw_field': path, 'canonical_fields': retained,
                'canonical_entity_fields': sorted(set(retained) & entity_fields),
                'status': 'PROJECTED_ENTITY_FIELD' if set(retained) & entity_fields else
                          'RETAINED_AS_NON_ENTITY_METADATA' if retained else 'RAW_ONLY_UNMAPPED'}
    for eq in edge['equality_witnesses']:
        result.append({'source': projection(source, eq['from_field']),
                       'target': projection(target, eq['to_field']),
                       'raw_equality_verified': True})
    return result

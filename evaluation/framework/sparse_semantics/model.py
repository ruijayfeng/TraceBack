"""Evaluation-only incident evidence projection. No production schema or scorer registration.

project binds structured facts; score receives only evidence classes/numbers/states.
Missing observations have no negative compatibility contribution. No label access.
"""
import math
import json
from evaluation.framework.anchor_semantics.model import observed, compare, timestamp, SUPPORTED, CONTRADICTED


def project(env, bindings, a, b, entities, behavior, policy):
    channels = {}
    audit = []
    def add(name, value, weight, refs=(), basis=None):
        item = dict(channel=name, support=value, weight=weight)
        previous = channels.get(name)
        if previous is None or (value*weight, value, weight) > (previous['support']*previous['weight'], previous['support'], previous['weight']):
            channels[name] = item
        audit.append(dict(**item, evidence_refs=list(refs), basis=basis))
    values = {}; refs = {}
    for key, paths in policy['paths'].items():
        av, ar = observed(a, paths); bv, br = observed(b, paths)
        values[key] = (av, bv); refs[key] = ar+br
    local = []
    for key in ['request', 'epoch', 'scope', 'process_start']:
        if compare(*values[key]) == CONTRADICTED:
            # A process start only conflicts with same-process identity on the same host/PID.
            if key == 'process_start' and not (a.get('host') and a.get('host') == b.get('host')
                and a.get('process') and b.get('process') and a['process'].get('pid') == b['process'].get('pid')):
                continue
            local.append(dict(kind=key, **policy['contradiction_matrix'][key], evidence_refs=refs[key]))
    contextual_invalid = any(x['kind'] in {'epoch','scope'} for x in local)
    shared_kinds = {x['type'] for x in bindings}
    request_scoped = False
    for binding in bindings:
        if binding['type']=='SESSION':
            try: request_scoped |= json.loads(binding['scope']).get('identity_kind') in {'request','transaction','operation'}
            except (KeyError,ValueError,TypeError,AttributeError): pass
    task = bool(request_scoped and compare(*values['request']) == SUPPORTED
                and not contextual_invalid)
    exact_process = False
    for binding in bindings:
        if binding['type'] != 'PROCESS' or binding.get('parent_only'): continue
        try:
            value = json.loads(entities[binding['entity_id']]['value'])
            exact_process |= bool(value.get('host') and value.get('pid') is not None and value.get('start_time'))
            if value.get('start_time') and any(timestamp(x['timestamp'])<timestamp(value['start_time']) for x in (a,b)):
                local.append(dict(kind='temporal',**policy['contradiction_matrix']['temporal'],evidence_refs=[]))
        except (KeyError,ValueError,TypeError,AttributeError):
            pass
    for f in sorted(env['features'], key=lambda f: f['name']):
        if f['state'] != 'OBSERVED_SUPPORT': continue
        if f['role'] == 'direct':
            add('direct',f['strength'],policy['direct_weight'],basis=f['name']); continue
        if f['family'] != 'entity': continue
        kind = f['name'].removeprefix('entity.')
        if kind in {'SESSION','PROCESS'} and (contextual_invalid or f['hot']): continue
        channel = 'actor' if kind == 'ACCOUNT' else 'content' if kind in {'COMMAND','FILE'} else 'context'
        value = f['strength'] * (policy['parent_factor'] if f.get('parent_only') else 1.)
        add(channel,value,f['reliability'],basis=f['name'])
    # Canonical category observations remain unknown if either side has no mapping.
    # Feature-stress callers may explicitly supply an observed scalar witness.
    observed_behavior = behavior is not None
    behavior_support = behavior if observed_behavior else None
    operations = []
    for i in range(2):
        operation_classes=set()
        for path in policy['paths']['operation']:
            native, native_refs=observed((a,b)[i],[path])
            if native in policy['operation_classes']:
                operation_classes.add(policy['operation_classes'][native]);refs['operation'].extend(native_refs)
        observation = values['observation'][i]
        operations.append(next(iter(operation_classes)) if len(operation_classes)==1 else
                          policy['operation_classes'].get(observation) if not operation_classes else None)
    operation_pair = all(operations) and any(sorted(operations) == sorted(pair)
                                          for pair in policy['compatible_operations'])
    behavior_refs = refs['operation']+refs['observation']
    if operation_pair:
        observed_behavior = True; behavior_support = max(behavior_support or 0.,1.)
    if observed_behavior:
        add('behavior',behavior_support,policy['behavior_weight'],behavior_refs,basis='observed_behavior')
    # Research-only, direction-free compound witnesses. No ChainRelation is created.
    asset_bridge = any(f['state']=='OBSERVED_SUPPORT' and f['name'] in {'entity.HOST','entity.IP'}
                       for f in env['features'])
    target_bridge = bool((a.get('host') and a.get('host')==b.get('host')) or
        (a.get('dst_ip') and a.get('dst_ip')==b.get('dst_ip') and a.get('dst_port') is not None and a.get('dst_port')==b.get('dst_port')))
    object_bridge = (compare(*values['application']) == SUPPORTED and target_bridge
        and any(values['object_out'][i] is not None and values['object_out'][i] == values['object_in'][1-i]
                for i in range(2)))
    endpoints = []
    endpoint_refs = []
    for i, alert in enumerate((a,b)):
        native_auth = all(values[k][i] is not None for k in ['auth_src','auth_sport','auth_dst','auth_dport'])
        if native_auth:
            endpoints.append(tuple(values[k][i] for k in ['auth_src','auth_sport','auth_dst','auth_dport']))
            endpoint_refs.extend(r for k in ['auth_src','auth_sport','auth_dst','auth_dport'] for r in refs[k] if r['alert_id']==alert['alert_id'])
        else:
            endpoints.append(tuple(alert.get(k) for k in ['src_ip','src_port','dst_ip','dst_port']))
            for k in ['src_ip','src_port','dst_ip','dst_port']:
                pointer=alert.get('field_provenance',{}).get(k,{}).get('raw_pointer')
                if pointer: endpoint_refs.append(dict(alert_id=alert['alert_id'],pointer=pointer,side='shared'))
    endpoint_match = (all(v is not None for row in endpoints for v in row) and endpoints[0] == endpoints[1]
                      and compare(*values['protocol']) != CONTRADICTED)
    qualifies = {k:all(operations) and any(sorted(operations)==sorted(pair) for pair in pairs)
                 for k,pairs in policy['qualified_operation_pairs'].items()}
    network_bridge = bool('SESSION' in shared_kinds and endpoint_match and qualifies['network_context'] and not contextual_invalid)
    execution_bridge = bool(exact_process and qualifies['execution_context'] and asset_bridge)
    auth_bridge = bool('SESSION' in shared_kinds and qualifies['authentication_context'] and asset_bridge
                       and any(f['name']=='entity.ACCOUNT' and f['state']=='OBSERVED_SUPPORT' for f in env['features'])
                       and not contextual_invalid)
    qualified = bool(object_bridge or network_bridge or execution_bridge or auth_bridge)
    if qualified:
        add('qualified_context',1.,policy['qualified_context_weight'],
            refs['object_out']+refs['object_in']+refs['application']+behavior_refs+endpoint_refs,
            basis=dict(object_handoff=object_bridge,network_context=network_bridge,
                       execution_context=execution_bridge,authentication_context=auth_bridge))
    if task and asset_bridge:
        add('task',1.,policy['task_weight'],refs['request'],basis='scoped_request_with_asset')
    hard = bool(env['gate'].get('hard_contradiction'))
    incident = ([dict(kind='original_hard_guard',strength=1.,**policy['contradiction_matrix']['original_hard_guard'])]
                if hard else [])
    temporal = max((f['strength'] for f in env['features'] if f['family']=='time' and f['state']=='OBSERVED_SUPPORT'),default=0.)
    numeric = dict(channels=sorted(channels.values(),key=lambda x:x['channel']),
        incident_conflict=1. if hard else 0.,legacy_unscoped_penalty=env['conflict_penalty'],duplicate_penalty=env['duplicate_penalty'],
        valid=env['valid'],hard_guard=hard,duplicate_observation=bool(env['gate'].get('duplicate_observation')),
        original_gate=bool(env['gate'].get('passed')),temporal=temporal,
        discriminating_context=bool(qualified or 'task' in channels or 'direct' in channels))
    taxonomy = ('DIRECT_RELATION_ANCHOR' if 'direct' in channels else 'TASK_SCOPED_ANCHOR' if 'task' in channels
                else 'CONTEXT_ANCHOR' if shared_kinds & {'SESSION','PROCESS'} else 'IDENTITY_ONLY')
    return numeric,dict(anchor_category=taxonomy,local_contradictions=local,incident_contradictions=incident,
        behavior_observed=observed_behavior,behavior_support=behavior_support,behavior_conflict=None,
        behavior_state='OBSERVED_SUPPORT' if observed_behavior and behavior_support else 'OBSERVED_NEUTRAL' if observed_behavior else 'UNKNOWN',
        evidence=audit,original_observations=env['features'],
        granularity=dict(DIRECT_RELATION='SUPPORTED' if 'direct' in channels else 'UNKNOWN',
                        TASK_RELATION='SUPPORTED' if 'task' in channels else 'CONTRADICTED' if any(x['scope']=='TASK_CONTRADICTION' for x in local) else 'UNKNOWN',
                        INCIDENT_CONTEXT_RELATION='CONTRADICTED' if hard else 'OBSERVED_CONTEXT' if channels else 'UNKNOWN'))


def score(projection, policy, threshold):
    """Observed-only compatibility; bounded support mass; no UNKNOWN multiplier."""
    channels = {}
    for item in projection['channels']:
        if item['channel'] not in policy['dimensions'] or not all(math.isfinite(item[k]) and 0<=item[k]<=2 for k in ['support','weight']):
            raise ValueError('invalid_observed_channel')
        value=item['support']*item['weight']
        channels[item['channel']]=max(channels.get(item['channel'],0.),value)
    positive = sum(channels[k] for k in sorted(channels))
    negative = projection['incident_conflict']
    compatibility = positive/(positive+negative) if positive+negative else None
    observed = len(channels); missing = len(policy['dimensions'])-observed
    confidence = positive/(positive+policy['confidence_scale']) if positive else 0.
    completeness = observed/len(policy['dimensions'])
    saturated = -math.expm1(-positive/policy['mass_scale'])
    raw = min(compatibility or 0.,saturated)
    independent = len(channels) >= policy['minimum_groups']
    if not independent and not {'direct','task'} & channels.keys(): raw=min(raw,policy['weak_ceiling'])
    temporal=policy['time_floor']+(1-policy['time_floor'])*projection['temporal']
    total = max(0.,min(1.,raw*temporal-negative-projection['legacy_unscoped_penalty']-projection['duplicate_penalty']))
    gate = bool(projection['valid'] and projection['original_gate'] and not projection['hard_guard']
                and not projection['duplicate_observation'] and channels)
    if not gate: total=0.
    binary = gate and total>=threshold
    ambiguous = binary and not projection['discriminating_context']
    decision = 'AMBIGUOUS' if ambiguous else 'ADMIT' if binary else 'REJECT'
    return dict(score=total,gate=gate,binary_admit=binary,decision=decision,
        decision_reason='AMBIGUOUS_LOW_OBSERVABILITY' if ambiguous else 'SUPPORTED_INCIDENT_CONTEXT' if binary else 'INSUFFICIENT_SUPPORT_OR_GUARD',
        semantic_compatibility=compatibility,evidence_confidence=confidence,evidence_completeness=completeness,
        support_strength=positive,contradiction_strength=negative,observed_evidence_mass=float(observed),
        unobserved_evidence_mass=float(missing),channels=channels,saturated_support=saturated,
        temporal_factor=temporal,legacy_unscoped_penalty=projection['legacy_unscoped_penalty'],duplicate_penalty=projection['duplicate_penalty'])

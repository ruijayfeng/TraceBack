"""Separate identity, role compatibility, observed behavior and bound operations."""
from app.correlation.separation_direction.evidence import behavior, bridges, value
from app.correlation.separation_direction.direction import decide as previous_direction


def direction(a, b, index, settings, policy, *, hard=False, relations=()):
    result = previous_direction(a, b, index, policy, hard=hard, explicit_relations=relations)
    # A flow ID has no global identity. The legacy flow pathway is retained
    # only within one source instance. Cross-source flow scope is unobserved.
    if a.source_namespace != b.source_namespace:
        for key in ('forward_evidence', 'reverse_evidence'):
            if any(c['channel'] == 'bound_flow_receive' for c in result[key]):
                result[key] = [c for c in result[key] if c['channel'] not in
                               {'bound_flow_receive', 'destination_observed_host'}]
        f, r = [policy['direction_support'] if len({c['channel'] for c in result[k]}) >= 2 else 0.
                for k in ('forward_evidence', 'reverse_evidence')]
        if f != result['forward_support'] or r != result['reverse_support']:
            # Re-evaluate the remaining explicit/account pathways without
            # pretending that missing flow scope is a contradictory observation.
            result.update(forward_support=f, reverse_support=r, contradiction=bool(hard or f and r),
                          direction_confidence=0., status='AMBIGUOUS_DIRECTION', source_alert_id=None,
                          target_alert_id=None, rejection_reason='flow_scope_unobservable',
                          direction_reason='flow_scope_unobservable')
            if not hard and bool(f) != bool(r) and max(f, r) >= policy['direction_threshold']:
                src, dst = (a, b) if f else (b, a)
                if (index.times[src.alert_id]-index.times[dst.alert_id])/1e6 <= policy['clock_skew_seconds']:
                    result.update(status='DERIVED_VERIFIED_DIRECTION', source_alert_id=src.alert_id,
                                  target_alert_id=dst.alert_id, direction_confidence=max(f, r),
                                  rejection_reason=None, direction_reason='two_consistent_operation_role_channels')
    return result


def hierarchy(a, b, index, policy, directional, rarity_parameters):
    """L0/L1/L2 are observations/compatibility, never operation proof by themselves."""
    shared = bridges(a, b, index)
    ca, cb = behavior(a, policy), behavior(b, policy)
    roles = []
    for m in shared:
        l, r = set(m['source_roles']), set(m['target_roles'])
        rule = None
        if m['kind'] == 'ACCOUNT':
            if 'target_account' in l and 'authenticated_account' in r:
                rule = 'target_account_to_authenticated_actor'
            elif 'authenticated_account' in l and 'audit_account' in r:
                rule = 'authenticated_actor_to_execution_actor'
        elif m['kind'] == 'IP':
            if 'dst_ip' in l and 'monitored_host_ip' in r:
                rule = 'network_destination_to_observed_host'
            elif 'monitored_host_ip' in l and 'src_ip' in r:
                rule = 'observed_host_to_network_source'
        if rule:
            roles.append({**m, 'rule_id': rule})
    transitions = []
    for rule in policy['transitions']:
        if rule['from'] in ca and rule['to'] in cb:
            transitions.append(dict(rule_id=rule['id'], from_class=rule['from'], to_class=rule['to'],
                                    compatibility=rule['strength'],
                                    provenance=ca[rule['from']]+cb[rule['to']]))
    verified = directional['status'] == 'DERIVED_VERIFIED_DIRECTION'
    bound = (directional['forward_evidence'] if directional['source_alert_id'] == a.alert_id
             else directional['reverse_evidence']) if verified else []
    level = 3 if verified else 2 if transitions else 1 if roles else 0
    context = None
    if shared:
        # Existing frequency only describes specificity. It is not maliciousness.
        context = min(shared, key=lambda m: (index.df[m['entity_id']], m['entity_id']))
        context = {**context, 'specificity': index.rarity(context['entity_id'], rarity_parameters)}
    return dict(level=level, name=('CONTEXT_ONLY', 'ROLE_COMPATIBLE', 'BEHAVIORAL_TRANSITION', 'BOUND_TRANSITION')[level],
                identity_evidence=shared, role_evidence=roles, behavior_evidence=transitions,
                binding_evidence=bound, context=context, verified_role_bridge=bool(roles),
                observed_behavior_transition=bool(transitions), progression_proven=verified,
                binding_state='OBSERVED_SUPPORT' if verified else 'UNOBSERVABLE',
                contradiction=directional['contradiction'])

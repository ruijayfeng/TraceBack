"""Directional field proof, independent of undirected correlation magnitude."""
from .evidence import bridges, ref, value, field_refs


def directed_clues(a,b,index,policy):
    shared=bridges(a,b,index);clues=[]
    account=[m for m in shared if m['kind']=='ACCOUNT' and 'target_account' in m['source_roles']
             and 'authenticated_account' in m['target_roles']]
    endpoint=[m for m in shared if m['kind']=='IP' and 'monitored_host_ip' in m['source_roles']
              and 'src_ip' in m['target_roles']]
    success=value(b,policy['wazuh_fields']['auth_status']) in policy['auth_success']
    if a.host and b.host and a.host!=b.host and account and endpoint and success:
        clues=[dict(channel='account_target_to_actor',provenance=account[0]['provenance'],
                    entity_ids=[account[0]['entity_id']]),
               dict(channel='host_to_login_source',provenance=endpoint[0]['provenance']+
                    field_refs(a,'host')+field_refs(b,'host')+[ref(b,policy['wazuh_fields']['auth_status'])],
                    entity_ids=[endpoint[0]['entity_id']])]
    # Matching receive/execute observations need a concrete flow identity plus
    # the destination -> observed-host role bridge. An ordinary same host pair
    # cannot satisfy this pathway.
    flow_a=value(a,policy['flow_fields']['source_id']);flow_b=value(b,policy['flow_fields']['received_id'])
    receive=value(b,policy['flow_fields']['receive_action']) in policy['receive_actions']
    dst=[m for m in shared if m['kind']=='IP' and 'dst_ip' in m['source_roles']
         and 'monitored_host_ip' in m['target_roles']]
    if flow_a is not None and flow_a==flow_b and receive and dst:
        clues.extend([dict(channel='bound_flow_receive',entity_ids=[],provenance=[ref(a,policy['flow_fields']['source_id']),
            ref(b,policy['flow_fields']['received_id']),ref(b,policy['flow_fields']['receive_action'])]),
            dict(channel='destination_observed_host',entity_ids=[dst[0]['entity_id']],provenance=dst[0]['provenance'])])
    return sorted(clues,key=lambda c:c['channel'])


def decide(a,b,index,policy,*,hard=False,explicit_relations=()):
    forward=directed_clues(a,b,index,policy);reverse=directed_clues(b,a,index,policy)
    for r in explicit_relations:
        target=forward if r['source_alert_id']==a.alert_id else reverse
        target.extend(dict(channel=c,entity_ids=[r['source_entity_id'],r['target_entity_id']],
            provenance=r['raw_pointers']) for c in ('explicit_operation','explicit_endpoints'))
    def strength(clues):
        # Two channels are required but are NOT treated as independent Bernoulli
        # probabilities. This is a policy support index with shared dependencies.
        return policy['direction_support'] if len({c['channel'] for c in clues})>=2 else 0.
    f,r=strength(forward),strength(reverse)
    status='AMBIGUOUS_DIRECTION';reason='insufficient_role_grounded_operation_proof';source=target=None
    if hard:reason='hard_contradiction'
    elif f and r:reason='conflicting_forward_reverse_proofs'
    elif max(f,r)>=policy['direction_threshold'] and abs(f-r)>=policy['direction_margin']:
        src,dst=(a,b) if f>r else (b,a)
        if (index.times[src.alert_id]-index.times[dst.alert_id])/1e6>policy['clock_skew_seconds']:
            reason='explicit_reverse_chronology'
        else:
            status='DERIVED_VERIFIED_DIRECTION';reason='two_consistent_operation_role_channels'
            source,target=src.alert_id,dst.alert_id
    return dict(status=status,source_alert_id=source,target_alert_id=target,
        forward_support=f,reverse_support=r,contradiction=bool(hard or f and r),
        direction_confidence=max(f,r) if source else 0.,forward_evidence=forward,reverse_evidence=reverse,
        rejection_reason=None if source else reason,direction_reason=reason,
        semantic_scope='Supported operation/propagation direction; not proof of attacker intent or compromise')

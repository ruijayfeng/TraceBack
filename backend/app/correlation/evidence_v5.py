"""Production projection onto the V5 four-state evidence contract."""
from .formula_v5 import aggregate
from .reasons import bound_fields


def evaluate(scorer, a, b, audit, values, relations, conflicts):
    policy = scorer.algorithm.score.evidence_v5.model_dump()
    reliability = policy['reliability']
    features = []
    byid = {r['entity_id']:r for r in audit['entity_reliability']}
    shared = set(a.entity_ids)&set(b.entity_ids)
    for d in audit['dimensions']:
        name, family, strength = d['dimension'], d['family'], d['strength']
        state = {'AVAILABLE_MATCH':'SUPPORTED','AVAILABLE_MISMATCH':'OBSERVED_ZERO',
                 'UNAVAILABLE':'UNOBSERVABLE','NOT_APPLICABLE':'UNOBSERVABLE'}[d['state']]
        role = 'generic'
        refs, ids = [], list(d['entity_ids'])
        kind = name.removeprefix('entity.')
        r = reliability.get(kind, reliability.get(family, .1))
        hot = False
        for eid in ids:
            if eid not in shared:
                continue
            lr, rr = scorer.index.roles[a.alert_id].get(eid,set()),scorer.index.roles[b.alert_id].get(eid,set())
            record = byid.get(eid)
            hot |= bool(record and record['hot'])
            if name=='entity.HOST' and 'host' in lr&rr:
                role,r='host',reliability['role_host']
            elif name=='entity.ACCOUNT' and any({l,t} <= {'authenticated_account','target_account','source_account','audit_account'} for l in lr for t in rr):
                role,r='account',reliability['role_account']
                if record and record['role_factor']:
                    strength=min(1.,strength/record['role_factor'])
            elif name=='entity.IP' and 'monitored_host_ip' in lr|rr:
                role,r='endpoint',reliability['monitored_endpoint']
                if record and record['role_factor']:
                    strength=min(1.,strength/record['role_factor'])
            refs += [dict(alert_id=alert.alert_id,pointer=o.raw_pointer,side='shared')
                     for alert in (a,b) for o in alert.entity_occurrences if o.entity_id==eid]
        if family=='relation' and strength:
            role='direct' if name=='topology.attested_relation' else 'flow'
            r=reliability['attested_relation'] if role=='direct' else reliability['flow']
            refs += [p for relation in relations for p in relation.raw_pointers]
            if role=='flow':
                refs += bound_fields(a,['src_ip','dst_ip','src_port','dst_port','timestamp'])+bound_fields(b,['src_ip','dst_ip','src_port','dst_port','timestamp'])
        if not refs:
            fields = ['timestamp'] if family=='time' else ['category','rule_id','signature'] if family=='behavior' else ['host','account','session','process','src_ip','dst_ip','url','domain','file','command'] if family=='entity' else []
            refs=bound_fields(a,fields)+bound_fields(b,fields)
        features.append(dict(name=name,family=family,state=state,strength=strength,reliability=r,
            role=role,hot=hot,entity_ids=sorted(ids),provenance=refs))
    # Unknown equivalence (HOST vs endpoint, or different targets in different
    # operations) is not an exclusive identity contradiction. Existing hard and
    # time-reversal proofs retain their force.
    for rule, strength in conflicts['soft']:
        if rule not in {'different_target_without_bridge','no_context_bridge'}:
            features.append(dict(name='conflict.'+rule,family='conflict',state='CONTRADICTED',
                strength=0.,reliability=strength,role='generic',hot=False,entity_ids=[],provenance=[]))
    features.sort(key=lambda f:f['name'])
    if policy['formula']=='evidence-semantics-v1':
        from .evidence_semantics import repair
        return repair(features,scorer,a,b,audit,policy,values,conflicts)
    result=aggregate(features,policy,hard=bool(conflicts['hard']),
        duplicate_risk=audit['duplicate_observation_risk'],duplicate=values['duplicate'])
    return dict(features=features,policy=policy,duplicate=values['duplicate'],**result)

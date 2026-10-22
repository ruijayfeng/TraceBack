"""Typed evidence resolution, descriptors and P1 proofs from existing facts."""
from collections import defaultdict
import json

from .loader import pointer
from .models import P1, PrototypeError, jcs, require, unique

def reference(kind, target):
    return dict(artifact='stage8',kind=kind,target_id=target,resolution='RESOLVED')

def raw_reference(ref):
    return dict(artifact='stage8',kind='raw_alert_pointer',**ref,resolution='RESOLVED')

def resolve(s, ref):
    """Return backing alert IDs and raw locations; never trust resolution flags."""
    kind=ref['kind']; i=s.indexes
    if kind=='raw_alert_pointer':
        r={k:ref[k] for k in ['alert_id','pointer','side']}; pointer(s,r)
        return {r['alert_id']}, {(r['alert_id'],r['pointer'])}
    node=i[kind][ref['target_id']]
    refs=[]; aids=set()
    if kind=='raw_pointer': refs=[raw_reference(node['raw_pointer'])]
    elif kind=='observation':
        aids.update([node['alert_a_id'],node['alert_b_id']])
        refs=[reference('raw_pointer',p) for p in node['raw_pointer_ids']]+[reference('validation',node['validation_id'])]
    elif kind=='claim': refs=[reference('observation',o) for o in node['observation_ids']]
    elif kind=='relation_decision':
        refs=[reference('claim',x) for k in ['relation_claim_ids','context_claim_ids','supporting_claim_ids','invalid_claim_ids'] for x in node[k]]
    elif kind=='context_posting': refs=[reference('raw_pointer',p) for m in node['memberships'] for p in m['raw_pointer_ids']]
    elif kind in {'host_alias_binding','auth_session_binding','context_binding'}:
        refs=[raw_reference(p) for o in node['observations'] for p in o['raw_pointers']]
    elif kind=='stage':
        aids.update(node['alert_ids']); refs=[raw_reference(p) for b in node['aggregation_basis'] for p in b['evidence']]
    elif kind=='behavior_annotation':
        aids.add(node['alert_id']); refs=[raw_reference(p) for p in node['evidence']]
    elif kind=='entity': aids.update(node['alert_ids'])
    elif kind!='validation': raise PrototypeError('unknown_evidence_kind:' + kind)
    locations=set()
    for r in refs:
        aa,pp=resolve(s,r); aids.update(aa); locations.update(pp)
    require(aids<=s.indexes['alert'].keys(),'dangling_reference_alert')
    return aids,locations

def checked_reference(s, ref):
    result=dict(ref)
    try:
        resolve(s,result)
        result['resolution']='RESOLVED'
    except KeyError:
        result['resolution']='MISSING'
    except (PrototypeError,IndexError,TypeError,ValueError):
        result['resolution']='INVALID'
    return result

def partition_evidence(s,refs,contradictions):
    """Separate rejected/invalid evidence from usable support in the sidecar.

    Full references remain in evidence_items/the semantic output for traceability.
    An invalid claim is never labeled positive merely because its ID resolves.
    """
    negative=[]; positive=[]
    contradiction_keys={jcs(r) for c in contradictions for r in c['evidence_refs']}
    for ref in refs:
        kind=ref['kind']; node=s.indexes.get(kind,{}).get(ref.get('target_id'))
        is_negative=(ref['resolution']!='RESOLVED' or jcs(ref) in contradiction_keys or
            kind=='relation_decision' and node['relation_type']=='NO_RELATION' or
            kind in {'claim','validation'} and not node['valid'] or
            kind=='observation' and not s.indexes['validation'][node['validation_id']]['valid'])
        (negative if is_negative else positive).append(ref)
    negative.extend(r for c in contradictions for r in c['evidence_refs'])
    return unique(positive),unique(negative)

def claim_refs(s, cid):
    c=s.indexes['claim'][cid]; refs=[reference('claim',cid)]
    for oid in c['observation_ids']:
        ob=s.indexes['observation'][oid]
        refs.extend([reference('observation',oid),reference('validation',ob['validation_id'])])
        refs.extend(reference('raw_pointer',pid) for pid in ob['raw_pointer_ids'])
    return unique(refs)

def evidence_refs(s,members):
    members=set(members); refs=[]
    for sid in sorted(members):
        refs.append(reference('stage',sid))
        for aid in s.indexes['stage'][sid]['alert_ids']:
            refs.append(reference('behavior_annotation',aid))
    for d in s.indexes['relation_decision'].values():
        if {d['stage_a_id'],d['stage_b_id']}<=members:
            refs.append(reference('relation_decision',d['candidate_id']))
            for key in ['relation_claim_ids','context_claim_ids','supporting_claim_ids','invalid_claim_ids']:
                for cid in d[key]: refs.extend(claim_refs(s,cid))
    for ctx in s.indexes['context_posting'].values():
        if members<=set(ctx['stage_ids']): refs.append(reference('context_posting',ctx['context_identity_id']))
    return unique(checked_reference(s,r) for r in refs)

def descriptors(s):
    result=[]; i=s.indexes
    for sid,st in sorted(i['stage'].items()):
        alerts=[i['alert'][a] for a in sorted(st['alert_ids'])]
        bindings={k:[] for k in ['host_alias_binding','auth_session_binding','context_binding']}
        for a in alerts:
            for bid in a.get('identity_binding_ids',[]):
                for kind in bindings:
                    if bid in i[kind]: bindings[kind].append(i[kind][bid])
        result.append(dict(stage_id=sid,community_id=st['community_id'],chain_id=i['chain_owner'][sid],
            member_alert_ids=sorted(st['alert_ids']),behavior_annotations=[i['behavior_annotation'][a] for a in sorted(st['alert_ids'])],
            normalized_behavior=st['behavior'],host=[i['entity'][x] for x in st['host_entities']],
            account=[i['entity'][x] for x in st['account_entities']],process=[i['entity'][x] for x in st['process_entities']],
            process_lineage=[dict(alert_id=a['alert_id'],process=a.get('process'),parent_process=a.get('parent_process'),
                                  entity_occurrences=a['entity_occurrences']) for a in alerts],
            flow=list(st['flow_bindings']),session_bindings=list(st['session_bindings']),
            network_session=[dict(alert_id=a['alert_id'],context=c) for a in alerts for c in a['contexts'] if c['kind']=='network_session'],
            http_request=list(st['request_bindings']),
            contexts=[dict(alert_id=a['alert_id'],contexts=a['contexts']) for a in alerts],
            connection=unique([b for b in bindings['context_binding'] if b['kind']=='connection']),
            auth_session=unique(bindings['auth_session_binding']),identity_bindings={k:unique(v) for k,v in bindings.items()},
            url_method=[dict(alert_id=a['alert_id'],url=a.get('url'),url_provenance=a['field_provenance'].get('url'),
                method_observations=[dict(pointer='/'+k.replace('~','~0').replace('/','~1'),value=v)
                    for k,v in a['raw_alert'].items() if k.lower() in {'method','http_method','request_method'}]) for a in alerts],
            command=[dict(alert_id=a['alert_id'],command=a.get('command'),provenance=a['field_provenance'].get('command')) for a in alerts],
            start_time=st['start_time'],end_time=st['end_time'],source_types=list(st['source_types']),
            relation_references=sorted(d['candidate_id'] for d in i['relation_decision'].values() if sid in [d['stage_a_id'],d['stage_b_id']]),
            witness_alerts=sorted({ob['alert_'+side+'_id'] for c in i['claim'].values() if sid in [c['stage_a_id'],c['stage_b_id']]
                                   for oid in c['observation_ids'] for ob in [i['observation'][oid]] for side in ['a','b']}),
            evidence_pointers=evidence_refs(s,[sid]),
            limitations=['Descriptor only; original Action Stage membership and normalized behavior preserved.',
                'Mixed upstream session_bindings are not presumed to be network sessions; network_session requires an explicitly typed existing context.']))
    return result

def complete_request_identity(identity):
    """Only actual scoped request projection forms, never a bare token."""
    if not isinstance(identity,dict) or not identity.get('value') or identity.get('subtype')!='request': return False
    scope=identity.get('scope')
    if not isinstance(scope,str): return False
    try: scope=json.loads(scope)
    except (ValueError,TypeError): return False
    if not isinstance(scope,dict): return False
    authority=scope.get('authority')
    if isinstance(authority,str):
        try: authority=json.loads(authority)
        except ValueError: return False
    projected=scope.get('context_projection')=='v1' and isinstance(authority,dict) and bool(authority.get('authority_domain'))
    native=scope.get('kind')=='request' and bool(scope.get('namespace'))
    return bool((projected or native) and (scope.get('host') or scope.get('host_scope')))

def claim_is_valid(s,c):
    return (c['valid'] is True and not c['conflict_status'] and c['observation_ids'] and
            all(s.indexes['validation'][s.indexes['observation'][o]['validation_id']]['valid'] is True and
                not s.indexes['validation'][s.indexes['observation'][o]['validation_id']]['conflict_status']
                for o in c['observation_ids']))

def alert_has_request(s,aid,identity):
    alert=s.indexes['alert'][aid]
    if any(c['kind']=='request' and c['scope']==identity['scope'] and str(c['value'])==str(identity['value']) for c in alert['contexts']):
        return True
    return any(b['kind']=='request' and b['scope']==identity['scope'] and str(b['value'])==str(identity['value']) and
               aid in {o['alert_id'] for o in b['observations']} for b in s.indexes['context_binding'].values())

def p1_proof(s,members):
    """Check all members; a path of good pairs never certifies unobserved members."""
    members=set(members); i=s.indexes
    selected=[]; identities=set(); covered=set(); failures=[]; request_seen=False; response_seen=False
    for d in i['accepted'].values():
        if d['relation_type']!='DIRECTED_EDGE' or not {d['stage_a_id'],d['stage_b_id']}<=members: continue
        for cid in d['relation_claim_ids']:
            c=i['claim'][cid]
            if c['evidence_type']!='REQUEST_RESPONSE': continue
            identity=c['identity']; expected={'A_TO_B':('REQUEST','RESPONSE'),'B_TO_A':('RESPONSE','REQUEST')}.get(c['direction_claim'])
            valid=(claim_is_valid(s,c) and c['semantic_class']=='DIRECTIONAL_RELATION' and
                   (c['role_a'],c['role_b'])==expected and c['direction_claim']==d['direction_claim'] and
                   complete_request_identity(identity) and
                   c['metadata'].get('projection_identity')==identity and
                   not any(checked_reference(s,r)['resolution']!='RESOLVED' for r in claim_refs(s,cid)))
            if not valid:
                failures.append('Invalid/incomplete request-response claim '+cid); continue
            claim_cover=set()
            for oid in c['observation_ids']:
                ob=i['observation'][oid]; v=i['validation'][ob['validation_id']]
                if v['temporal_check'].get('status')!='CONSISTENT':
                    failures.append('Request-response temporal validation not CONSISTENT'); continue
                # Existing typed claim supplies complementary roles. Its backing
                # raw evidence must also be non-null; no new operation parser.
                if any(pointer(s,i['raw_pointer'][p]['raw_pointer']) is None for p in ob['raw_pointer_ids']):
                    failures.append('Null request-response raw witness'); continue
                if not all(alert_has_request(s,aid,identity) for aid in [ob['alert_a_id'],ob['alert_b_id']]):
                    failures.append('Request identity is not bound to each observed alert.'); continue
                claim_cover.update([ob['alert_a_id'],ob['alert_b_id']])
            if claim_cover:
                selected.append(cid); identities.add(jcs(identity)); covered.update(claim_cover)
                request_seen=True; response_seen=True
    all_alerts={a for sid in members for a in i['stage'][sid]['alert_ids']}
    if len(members)<2: failures.append('P1 does not cover a singleton.')
    if not selected: failures.append('No valid accepted REQUEST_RESPONSE proof.')
    if len(identities)!=1: failures.append('One complete authoritative scoped request is required.')
    if covered!=all_alerts: failures.append('Not every member alert has purpose evidence.')
    if not request_seen or not response_seen: failures.append('Complementary roles absent.')
    return dict(complete=not failures,claim_ids=sorted(set(selected)),identities=sorted(identities),
                covered_alert_ids=sorted(covered),uncovered_alert_ids=sorted(all_alerts-covered),failures=sorted(set(failures)))

def identity_contradictions(s,members,kind):
    """Reject only an explicit SAME identity hypothesis, not arbitrary differences."""
    if not kind: return []
    buckets=defaultdict(lambda:defaultdict(list))
    for sid in members:
        for aid in s.indexes['stage'][sid]['alert_ids']:
            for context in s.indexes['alert'][aid]['contexts']:
                if context['kind']!=kind: continue
                buckets[context['scope']][str(context['value'])].append(raw_reference(dict(
                    alert_id=aid,pointer=context['raw_pointer'],side='shared')))
    contradictions=[]
    for scope,values in sorted(buckets.items()):
        if len(values)>1:
            refs=unique(r for rows in values.values() for r in rows)
            if all(checked_reference(s,r)['resolution']=='RESOLVED' for r in refs):
                contradictions.append(dict(code='INCOMPATIBLE_ACTIVITY_IDENTITY',
                    detail='Explicit same-'+kind+' hypothesis has distinct observed values in one existing scope: '+scope,
                    evidence_refs=refs))
    return contradictions

"""Bounded field projections and role bridges over immutable canonical alerts."""
import ipaddress
from app.models import EvidencePointer
from app.models.base import resolve_pointer


def value(alert, pointer):
    try:return resolve_pointer(alert.raw_alert,pointer)
    except ValueError:return None


def ref(alert, pointer, side='shared'):
    if value(alert, pointer) is None:
        raise ValueError('unresolvable_candidate_evidence')
    return EvidencePointer(alert_id=alert.alert_id,pointer=pointer,side=side).model_dump(mode='json')


def field_refs(alert, *fields):
    return [ref(alert,alert.field_provenance[f].raw_pointer) for f in fields
            if getattr(alert,f) is not None and f in alert.field_provenance
            and alert.field_provenance[f].raw_pointer]


def behavior(alert, policy):
    """Classify observations, never assign an ATT&CK stage or mutate category.

    Source-local typed operations are read only at versioned allowlisted paths.
    Detector token rules apply to canonical signature and remain mere alert
    semantics. Neither a file path nor a command value implies maliciousness.
    """
    found=[]
    def add(name,refs):
        if refs:found.append(dict(name=name,provenance=refs))
    if alert.category.value!='unknown':
        name=policy['category_classes'].get(alert.category.value)
        if name:add(name,field_refs(alert,'category','signature'))
    if alert.source_type.value=='wazuh':
        paths=policy['wazuh_fields']
        op=value(alert,paths['execution_type'])
        if op in policy['execution_types'] and alert.process is not None:
            add('execution',[ref(alert,paths['execution_type']),*field_refs(alert,'process','command')])
        operation=value(alert,paths['operation']); resource=value(alert,paths['file'])
        if operation in policy['resource_operations'] and isinstance(resource,str) and resource:
            add('resource_access',[ref(alert,paths['operation']),ref(alert,paths['file'])])
        status=value(alert,paths['auth_status'])
        if alert.category.value=='authentication' and status in policy['auth_success']:
            add('authentication',[ref(alert,paths['auth_status']),*field_refs(alert,'account')])
    text=(alert.signature or '').casefold()
    if alert.source_type.value in policy['network_sources'] and alert.src_ip and alert.dst_ip:
        add('network_access',field_refs(alert,'src_ip','dst_ip'))
        for name,tokens in policy['detector_tokens'].items():
            if any(token.casefold() in text for token in tokens):
                add(name,field_refs(alert,'signature'))
    # One proof per class. Multiple matching strings do not multiply support.
    result={}
    for row in found:result.setdefault(row['name'],[]).extend(row['provenance'])
    return {name:sorted({(p['alert_id'],p['pointer'],p['side']):p for p in refs}.values(),
        key=lambda p:(p['alert_id'],p['pointer'],p['side'])) for name,refs in sorted(result.items())}


def bridges(a,b,index):
    result=[]
    for eid in sorted(set(a.entity_ids)&set(b.entity_ids)):
        entity=index.entities[eid]
        left=index.roles[a.alert_id][eid];right=index.roles[b.alert_id][eid]
        kind=entity.type.value
        if kind not in {'HOST','IP','ACCOUNT','SESSION','PROCESS'}:continue
        refs=[ref(alert,o.raw_pointer) for alert in (a,b) for o in alert.entity_occurrences if o.entity_id==eid]
        result.append(dict(entity_id=eid,kind=kind,source_roles=sorted(left),target_roles=sorted(right),
            provenance=refs))
    return result


def transition(a,b,index,settings,policy,rarity_parameters):
    ca,cb=behavior(a,policy),behavior(b,policy)
    matches=bridges(a,b,index)
    # Role conjunctions are alternative interpretations of existing components,
    # never additional independent groups. Unknown roles cannot supply a proof.
    forward=[]
    for m in matches:
        l,r=set(m['source_roles']),set(m['target_roles'])
        compatible=(m['kind']=='HOST' and 'host' in l&r or
            m['kind']=='IP' and ('monitored_host_ip' in l|r or l&r&{'src_ip','dst_ip'}) or
            m['kind']=='ACCOUNT' and bool(l&{'audit_account','target_account','authenticated_account'}) and
            bool(r&{'audit_account','target_account','authenticated_account'}))
        if compatible:
            hot=index.df[m['entity_id']]>=policy['hot_min_count'] and index.df[m['entity_id']]/index.N>=policy['hot_ratio']
            if not hot:forward.append({**m,'specificity':index.rarity(m['entity_id'],rarity_parameters)})
    choices=[]
    for rule in policy['transitions']:
        if rule['from'] in ca and rule['to'] in cb and forward:
            allowed=[m for m in forward if m['kind'] in rule['contexts']]
            if not allowed:continue
            best=min(allowed,key=lambda m:(-m['specificity'],m['entity_id']))
            choices.append(dict(rule_id=rule['id'],from_class=rule['from'],to_class=rule['to'],
                compatibility=rule['strength'],specificity=best['specificity'],context=best,
                provenance=ca[rule['from']]+cb[rule['to']]+best['provenance']))
    return max(choices,key=lambda r:(r['compatibility']*r['specificity'],r['rule_id'])) if choices else None


def alias_groups(groups,a,b,index):
    """A numeric HTTP hostname is an address view, not another resource fact."""
    result=dict(groups)
    if 'resource' not in result or 'asset' not in result:return result
    for alert in (a,b):
        try:
            ip=ipaddress.ip_address(alert.domain or '')
        except ValueError:return result
        if str(ip) not in {alert.src_ip,alert.dst_ip}:return result
    if a.domain!=b.domain:return result
    # A shared URL with a genuine path remains a resource in its own right.
    shared=set(a.entity_ids)&set(b.entity_ids)
    if any(index.entities[e].type.value=='URL' for e in shared):return result
    result['asset']=max(result['asset'],result.pop('resource'))
    return result

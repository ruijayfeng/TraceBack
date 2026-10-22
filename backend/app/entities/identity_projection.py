"""Two-pass identity binding inside formal entity extraction; never a resolver bypass.

Host aliases require native hostname/asset co-observation and bounded authority
scope. Session projection consumes canonical HOSTs and a declared token contract.
Source ContextRefs remain in binding observations; active refs use canonical scope
so source-local token reuse cannot bypass lifecycle separation downstream.
"""
from collections import defaultdict
from datetime import datetime, timedelta
import json
from typing import Literal
from pydantic import Field

from app.models import Entity, EntityOccurrence, EvidencePointer
from app.models.alerts import ContextRef
from app.models.base import StrictModel, Text, EntityID
from app.utils.stable_id import canonical_json, content_digest, id_for, utc_text
from .context import clean, observed
from .normalization import hostname


class IdentityObservation(StrictModel):
    alert_id: Text
    source_namespace: Text
    timestamp: Text
    raw_pointers: list[EvidencePointer]
    source_contexts: list[ContextRef] = Field(default_factory=list)


class HostAliasBinding(StrictModel):
    alias_binding_id: Text
    canonical_host_entity_id: EntityID | None
    alias_type: Literal['HOSTNAME'] = 'HOSTNAME'
    alias_value: Text
    authority_scope: Text
    source_namespaces: list[Text]
    first_seen: Text
    last_seen: Text
    evidence_alert_ids: list[Text]
    raw_pointers: list[EvidencePointer]
    status: Literal['BOUND', 'AMBIGUOUS_ALIAS']
    observations: list[IdentityObservation]
    metadata: dict = Field(default_factory=dict)


class AuthSessionBinding(StrictModel):
    projection_id: Text
    canonical_session_entity_id: EntityID
    canonical_host_entity_id: EntityID
    authority_scope: Text
    source_namespaces: list[Text]
    first_seen: Text
    last_seen: Text
    lifecycle_status: Literal['BOUNDED', 'OPEN', 'LIFECYCLE_UNKNOWN']
    observations: list[IdentityObservation]
    metadata: dict = Field(default_factory=dict)


class IdentityDiagnostic(StrictModel):
    code: Text
    alert_ids: list[Text]
    detail: Text


class ContextIdentityBinding(StrictModel):
    projection_id: Text
    kind: Literal['request', 'connection']
    scope: Text
    value: Text
    observations: list[IdentityObservation]


class IdentityProjectionResult(StrictModel):
    host_alias_bindings: list[HostAliasBinding] = Field(default_factory=list)
    auth_session_bindings: list[AuthSessionBinding] = Field(default_factory=list)
    process_bindings: list = Field(default_factory=list)
    context_bindings: list[ContextIdentityBinding] = Field(default_factory=list)
    diagnostics: list[IdentityDiagnostic] = Field(default_factory=list)

    def validate_trace(self, alerts, entities):
        aa = {a.alert_id:a for a in alerts}
        ee = {e.entity_id:e for e in entities}
        bindings = {b.alias_binding_id:b for b in self.host_alias_bindings}
        bindings.update({b.projection_id:b for b in self.auth_session_bindings})
        bindings.update({b.projection_id:b for b in self.context_bindings})
        if len(bindings) != len(self.host_alias_bindings)+len(self.auth_session_bindings)+len(self.context_bindings):
            raise ValueError('duplicate_identity_binding_id')
        for a in alerts:
            if set(a.identity_binding_ids)-bindings.keys():
                raise ValueError('dangling_identity_binding')
        for b in bindings.values():
            if isinstance(b, ContextIdentityBinding):
                linked = {a.alert_id for a in alerts if b.projection_id in a.identity_binding_ids}
                if linked != {o.alert_id for o in b.observations}:
                    raise ValueError('context_binding_partition_mismatch')
                for o in b.observations:
                    a = aa[o.alert_id]
                    if o.source_namespace != a.source_namespace or o.timestamp != a.timestamp:
                        raise ValueError('context_binding_source_mismatch')
                    if not any(c.scope == b.scope and c.value == b.value for c in a.contexts):
                        raise ValueError('context_binding_missing_projection')
                    for p in o.raw_pointers:
                        if p.alert_id != o.alert_id or p.resolve(aa) is None:
                            raise ValueError('context_binding_raw_pointer_invalid')
                    for c in o.source_contexts:
                        if clean(observed(a.raw_alert,c.raw_pointer)[0]) != c.value:
                            raise ValueError('context_binding_original_token_mismatch')
                continue
            eid = b.canonical_host_entity_id if isinstance(b, HostAliasBinding) else b.canonical_session_entity_id
            if eid is not None and eid not in ee:
                raise ValueError('dangling_canonical_identity')
            expected_type = 'HOST' if isinstance(b,HostAliasBinding) else 'SESSION'
            if eid is not None and ee[eid].type.value != expected_type:
                raise ValueError('identity_binding_entity_type_mismatch')
            if b.source_namespaces != sorted({o.source_namespace for o in b.observations}):
                raise ValueError('identity_binding_source_mismatch')
            bid = b.alias_binding_id if isinstance(b,HostAliasBinding) else b.projection_id
            linked = {a.alert_id for a in alerts if bid in a.identity_binding_ids}
            if linked-{o.alert_id for o in b.observations}:
                raise ValueError('identity_binding_missing_source_observation')
            for o in b.observations:
                if o.source_namespace != aa[o.alert_id].source_namespace or o.timestamp != aa[o.alert_id].timestamp:
                    raise ValueError('identity_source_observation_mismatch')
                for p in o.raw_pointers:
                    if p.alert_id != o.alert_id or p.resolve(aa) is None:
                        raise ValueError('dangling_identity_raw_pointer')
                for ref in o.source_contexts:
                    if clean(observed(aa[o.alert_id].raw_alert, ref.raw_pointer)[0]) != ref.value:
                        raise ValueError('identity_context_witness_mismatch')
            if isinstance(b, HostAliasBinding):
                for p in b.raw_pointers:
                    p.resolve(aa)
                if set(b.evidence_alert_ids)-aa.keys():
                    raise ValueError('dangling_alias_evidence')
                if (b.status=='AMBIGUOUS_ALIAS') != (eid is None) or (eid is None and linked):
                    raise ValueError('ambiguous_alias_cannot_project')
                for aid in linked:
                    a=aa[aid]
                    if (eid not in a.entity_ids or not any(lo<=a.timestamp<=hi for lo,hi in b.metadata['valid_intervals'])):
                        raise ValueError('alias_outside_validity_or_host_scope')
            elif (b.canonical_host_entity_id not in ee or linked != {o.alert_id for o in b.observations}
                    or set(ee[eid].alert_ids) != linked or any(b.canonical_host_entity_id not in aa[aid].entity_ids for aid in linked)):
                raise ValueError('session_projection_partition_mismatch')
        if any(set(d.alert_ids)-aa.keys() for d in self.diagnostics):
            raise ValueError('dangling_identity_diagnostic')


def pointer(a, path):
    return EvidencePointer(alert_id=a.alert_id, pointer=path, side='shared')


def observation(a, paths, refs=()):
    return IdentityObservation(alert_id=a.alert_id, source_namespace=a.source_namespace,
        timestamp=a.timestamp, raw_pointers=[pointer(a,p) for p in sorted(set(paths))], source_contexts=list(refs))


def diagnostic(code, alerts, detail):
    return IdentityDiagnostic(code=code, alert_ids=sorted({a.alert_id for a in alerts}), detail=detail)


def host_authority_scope(a, settings):
    policy = settings.identity_contract.host
    if policy is None:
        return None
    return canonical_json(dict(authority_domain=policy.authority_domain, deployment_scope=policy.deployment_scope,
        network_scope=policy.network_scope, observed_scopes={p:clean(observed(a.raw_alert,p)[0]) for p in policy.scope_pointers}))


def host_alias_plan(alerts, settings):
    groups, diagnostics = defaultdict(list), []
    name_scopes = defaultdict(set)
    for a in sorted(alerts,key=lambda a:a.alert_id):
        s = settings[a.source_namespace]
        if s.format_profile != 'multisource_native_v1' or not a.host:
            continue
        scope = host_authority_scope(a,s)
        if scope is None:
            diagnostics.append(diagnostic('SOURCE_AUTHORITY_UNDECLARED',[a],'Host alias authority is undeclared; no alias projection.'))
            continue
        name = hostname(a.host)
        assets = [(clean(observed(a.raw_alert,p)[0]),p) for p in ('/asset_id','/host_id','/server_host_id')]
        assets = [(asset,p) for asset,p in assets if asset]
        for asset,path in assets or [(None,None)]:
            groups[scope,name].append((a,asset,path))
        name_scopes[name].add(scope)
    bindings, plan = [], {}
    for (scope,name),rows in sorted(groups.items()):
        evidence = [(a,asset,p) for a,asset,p in rows if asset]
        if not evidence:
            continue
        assets = sorted({asset for _,asset,_ in evidence})
        ambiguous = len(assets)>1
        first,last = min(a.timestamp for a,_,_ in evidence),max(a.timestamp for a,_,_ in evidence)
        # Both backward and forward bounds are an explicit adapter policy, never permanent aliasing.
        ttl = min(settings[a.source_namespace].identity_contract.host.max_alias_age_seconds for a,_,_ in rows)
        lo = utc_text(datetime.fromisoformat(first.replace('Z','+00:00'))-timedelta(seconds=ttl))
        hi = utc_text(datetime.fromisoformat(last.replace('Z','+00:00'))+timedelta(seconds=ttl))
        intervals = []
        for event_time in sorted({a.timestamp for a,_,_ in evidence}):
            t = datetime.fromisoformat(event_time.replace('Z','+00:00'))
            start,end = utc_text(t-timedelta(seconds=ttl)),utc_text(t+timedelta(seconds=ttl))
            if intervals and start<=intervals[-1][1]:
                intervals[-1][1] = max(intervals[-1][1],end)
            else:
                intervals.append([start,end])
        asset_scope = canonical_json(dict(identity_kind='asset_id',identity_authority=scope))
        eid = None if ambiguous else id_for('Entity',dict(type='HOST',scope=asset_scope,value=assets[0]))
        bid = 'hal_'+content_digest(dict(scope=scope,alias=name,assets=assets,valid_intervals=intervals))
        observations = []
        for a,asset,p in rows:
            paths = [a.field_provenance['host'].raw_pointer]+([p] if p else [])
            paths += [q for q in settings[a.source_namespace].identity_contract.host.scope_pointers if observed(a.raw_alert,q)[0] is not None]
            observations.append(observation(a,paths))
            if not ambiguous and any(start<=a.timestamp<=end for start,end in intervals):
                plan[a.alert_id] = (assets[0],asset_scope,bid)
        bindings.append(HostAliasBinding(alias_binding_id=bid, canonical_host_entity_id=eid, alias_value=name,
            authority_scope=scope,source_namespaces=sorted({a.source_namespace for a,_,_ in rows}),first_seen=first,last_seen=last,
            evidence_alert_ids=sorted(a.alert_id for a,_,_ in evidence),
            raw_pointers=sorted([pointer(a,p) for a,_,p in evidence]+[pointer(a,a.field_provenance['host'].raw_pointer) for a,_,_ in evidence],key=lambda p:(p.alert_id,p.pointer)),
            status='AMBIGUOUS_ALIAS' if ambiguous else 'BOUND',observations=observations,
            metadata=dict(assets=assets,valid_from=lo,valid_until=hi,max_alias_age_seconds=ttl,evidence_type='NATIVE_CO_OBSERVATION',
                valid_intervals=intervals,applied_alert_ids=sorted({a.alert_id for a,_,_ in rows if a.alert_id in plan}))))
        if ambiguous:
            diagnostics.append(diagnostic('ALIAS_AMBIGUOUS',[a for a,_,_ in rows],'Conflicting assets in the same effective alias scope; projection refused.'))
    for name, scopes in sorted(name_scopes.items()):
        if len(scopes)>1:
            diagnostics.append(diagnostic('ALIAS_SCOPE_CONFLICT',[a for (scope,n),rows in groups.items() if n==name for a,_,_ in rows],
                'Hostname observations span distinct authority/deployment/network scopes; aliases stay independent.'))
    return plan,bindings,diagnostics


def project_auth_sessions(alerts, entities, settings, host_bindings, diagnostics):
    groups, all_tokens = defaultdict(list), defaultdict(list)
    for a in alerts:
        s = settings[a.source_namespace]
        policy = s.identity_contract.auth_session
        token = clean(observed(a.raw_alert,policy.token_pointer if policy else '/logon_id')[0])
        if token is None:
            continue
        if policy is None:
            diagnostics.append(diagnostic('SOURCE_AUTHORITY_UNDECLARED',[a],'Authentication token authority is undeclared; projection refused.'))
            all_tokens[token].append((a,None,None))
            continue
        host = next((o.entity_id for o in a.entity_occurrences if o.role.value=='host'),None)
        authority = canonical_json(policy.model_dump(mode='json',exclude={'token_pointer','equivalent_token_pointers'}))
        all_tokens[token].append((a,host,authority))
        if host is None:
            diagnostics.append(diagnostic('INSUFFICIENT_IDENTITY_EVIDENCE',[a],'Authentication session needs a canonical host.'))
            continue
        groups[host,authority,token].append(a)
    for token,rows in sorted(all_tokens.items()):
        if len({h for _,h,_ in rows if h})>1:
            diagnostics.append(diagnostic('SESSION_HOST_CONFLICT',[a for a,_,_ in rows],'Equal token on different hosts is not a common session.'))
        if len({v for _,_,v in rows})>1:
            diagnostics.append(diagnostic('SESSION_AUTHORITY_MISMATCH',[a for a,_,_ in rows],'Token authorities are absent or incompatible.'))
    replacements, bindings, session_entities = {}, [], []
    for (host,authority,token),rows in sorted(groups.items()):
        rows = sorted(rows,key=lambda a:(a.timestamp,a.alert_id))
        # Boundaries from all declared compatible sources. Simultaneous contradictory
        # boundaries stay separate by event ID; no alert-ID tie-breaking for causality.
        opens,closes = defaultdict(list),defaultdict(list)
        attrs = {}
        for a in rows:
            policy = settings[a.source_namespace].identity_contract.auth_session
            operation = clean(observed(a.raw_alert,'/operation')[0])
            if operation in policy.start_operations: opens[a.timestamp].append(a.alert_id)
            if operation in policy.close_operations: closes[a.timestamp].append(a.alert_id)
            attrs[a.alert_id] = dict(account=clean(a.account),realm=clean(observed(a.raw_alert,*policy.realm_pointers)[0]),
                **{p:clean(observed(a.raw_alert,p)[0]) for p in policy.epoch_pointers})
        known = {k:{v[k] for v in attrs.values() if v[k] is not None} for k in next(iter(attrs.values()))}
        conflicts = {k for k,v in known.items() if len(v)>1}
        partitions = defaultdict(list)
        for a in rows:
            # Close belongs to the preceding lifetime; observations strictly after it
            # cannot join that lifetime, including another later explicit start.
            events = [(t,'start',ids) for t,ids in opens.items() if t<=a.timestamp]
            events += [(t,'closed',ids) for t,ids in closes.items() if t<a.timestamp]
            event = max(events,key=lambda e:e[0]) if events else None
            boundary = [event[0],event[1],sorted(event[2])] if event else None
            if (event and (event[0] in opens and event[0] in closes or len(opens.get(event[0],[]))>1)
                    or a.timestamp in closes and a.alert_id not in closes[a.timestamp]):
                boundary = ['AMBIGUOUS_BOUNDARY',a.alert_id]
            effective_attrs = {k:attrs[a.alert_id][k] if k in conflicts else next(iter(v),None) for k,v in known.items()}
            partitions[canonical_json(dict(boundary=boundary,attributes=effective_attrs))].append(a)
        if len(partitions)>1:
            diagnostics.append(diagnostic('SESSION_LIFECYCLE_CONFLICT',rows,'Session lifecycle, account or epoch conflicts partition equal tokens.'))
        for partition,members in sorted(partitions.items()):
            scope = canonical_json(dict(auth_session_projection='v1',host=host,authority=authority,lifecycle=partition))
            eid = id_for('Entity',dict(type='SESSION',scope=scope,value=token))
            bid = 'asp_'+content_digest(dict(entity_id=eid))
            obs = []
            for a in members:
                policy = settings[a.source_namespace].identity_contract.auth_session
                paths = {policy.token_pointer,*policy.equivalent_token_pointers}
                originals = [c for c in a.contexts if c.kind=='session' and c.raw_pointer in paths and c.value==token]
                if not any(c.raw_pointer==policy.token_pointer for c in originals):
                    # Contracts cannot attest a field omitted by the formal source adapter.
                    raise ValueError('auth_authority_token_missing_context_projection')
                projected = ContextRef(kind='session',value=token,raw_pointer=policy.token_pointer,scope=scope)
                preserved = [c for c in a.contexts if c not in originals]
                relevant_paths = [c.raw_pointer for c in originals]
                relevant_paths += [o.raw_pointer for o in a.entity_occurrences if o.role.value=='host']
                relevant_paths += [p for p in (*policy.epoch_pointers,*policy.realm_pointers,'/operation') if observed(a.raw_alert,p)[0] is not None]
                if a.account: relevant_paths.append(a.field_provenance['account'].raw_pointer)
                obs.append(observation(a,relevant_paths,originals))
                data = a.model_dump()
                data.update(contexts=sorted(preserved+[projected],key=lambda c:(c.kind,c.scope,c.value,c.raw_pointer)),
                    entity_ids=sorted(set(a.entity_ids)|{eid}),
                    entity_occurrences=list(a.entity_occurrences)+[EntityOccurrence(entity_id=eid,role='session',raw_pointer=policy.token_pointer)],
                    identity_binding_ids=sorted(set(a.identity_binding_ids)|{bid}))
                replacements[a.alert_id] = type(a).model_validate(data)
            session_entities.append(Entity(entity_id=eid,type='SESSION',scope=scope,value=token,display_value=token,
                alert_ids=sorted(a.alert_id for a in members)))
            first,last = min(a.timestamp for a in members),max(a.timestamp for a in members)
            boundary = json.loads(partition)['boundary']
            lifecycle_start = boundary[0] if boundary and len(boundary)==3 and boundary[1]=='start' else None
            lifecycle_end = min((t for t in set(opens)|set(closes) if t>first),default=None)
            status = ('BOUNDED' if lifecycle_end else 'OPEN') if lifecycle_start else 'LIFECYCLE_UNKNOWN'
            bindings.append(AuthSessionBinding(projection_id=bid,canonical_session_entity_id=eid,canonical_host_entity_id=host,
                authority_scope=authority,source_namespaces=sorted({a.source_namespace for a in members}),first_seen=first,last_seen=last,
                lifecycle_status=status,observations=obs,metadata=dict(token=token,partition=partition,
                    lifecycle_start=lifecycle_start,lifecycle_end=lifecycle_end)))
    # Never promote PID-only observations. Record why continuity cannot be proven.
    process_rows = defaultdict(list)
    for a in alerts:
        host = next((o.entity_id for o in a.entity_occurrences if o.role.value=='host'),None)
        for role in ('process','parent_process'):
            p = getattr(a,role)
            if p and p.pid is not None:
                process_rows[host,p.pid].append((a,p))
                if not(p.start_time or p.guid or p.instance_id):
                    diagnostics.append(diagnostic('INSUFFICIENT_IDENTITY_EVIDENCE',[a],'PROCESS_IDENTITY_PROJECTION_NOT_PROVABLE: boot, clock and continuous lifetime authority unavailable.'))
                if p.start_time and p.start_time>a.timestamp:
                    diagnostics.append(diagnostic('PROCESS_LIFETIME_CONFLICT',[a],'Observed process birth is after the event.'))
    for rows in process_rows.values():
        if len({p.start_time for _,p in rows})>1:
            diagnostics.append(diagnostic('PROCESS_PID_REUSE_RISK',[a for a,_ in rows],'Equal PID has missing or different instance starts; no continuity projection.'))
    result = IdentityProjectionResult(host_alias_bindings=host_bindings,auth_session_bindings=bindings,
        diagnostics=sorted(diagnostics,key=lambda d:(d.code,d.alert_ids,d.detail)))
    updated = [replacements.get(a.alert_id,a) for a in alerts]
    combined = sorted(entities+session_entities,key=lambda e:e.entity_id)
    result.validate_trace(updated,combined)
    return updated,combined,result


def project_context_identities(alerts, entities, settings, result):
    """Bound native request/connection issuers; ambiguous tokens stay source-local.

    Connections need a complete tuple witness plus >=3 explicit endpoint fields
    per member. Partial observations never choose between competing tuples.
    Requests require the same canonical host. Neither projection creates an edge.
    """
    groups = defaultdict(list)
    for a in alerts:
        for policy in settings[a.source_namespace].identity_contract.contexts or []:
            refs = [c for c in a.contexts if c.raw_pointer == policy.token_pointer]
            if not refs:
                continue
            host = next((o.entity_id for o in a.entity_occurrences if o.role.value == 'host'),None)
            if policy.kind == 'request' and host is None:
                continue
            authority = policy.model_dump(mode='json',exclude={'token_pointer','max_age_seconds','destination_ip_pointer'})
            scope = canonical_json(dict(context_projection='v1',authority=authority,
                observed_scopes={p:clean(observed(a.raw_alert,p)[0]) for p in policy.scope_pointers},
                host=host if policy.kind == 'request' else None))
            for ref in refs:
                groups[scope,ref.value].append((a,ref,policy))
    replacements = {a.alert_id:a for a in alerts}
    for (scope,token), rows in sorted(groups.items()):
        members = {a.alert_id:a for a,_,_ in rows}
        first,last = min(a.timestamp for a in members.values()),max(a.timestamp for a in members.values())
        span = (datetime.fromisoformat(last.replace('Z','+00:00'))-datetime.fromisoformat(first.replace('Z','+00:00'))).total_seconds()
        issues = set()
        if span > min(p.max_age_seconds for _,_,p in rows):
            issues.add('CONTEXT_TOKEN_AGE_EXCEEDED')
        if any(len({clean(observed(a.raw_alert,p)[0]) for a in members.values()}-{None}) > 1
               for p in ('/boot_id','/session_epoch')):
            issues.add('CONTEXT_EPOCH_CONFLICT')
        tuples = []
        paths = {}
        if rows[0][2].kind == 'connection':
            for a in members.values():
                facts = {k:getattr(a,k) for k in ('src_ip','src_port','dst_ip','dst_port')}
                ptrs = [a.field_provenance[k].raw_pointer for k,v in facts.items() if v is not None]
                # Authentication records explicitly identify their monitored
                # destination via host_ip, without an invented canonical field.
                policy = next(p for ar,_,p in rows if ar.alert_id == a.alert_id)
                if facts['dst_ip'] is None and policy.destination_ip_pointer:
                    facts['dst_ip'], p = observed(a.raw_alert,policy.destination_ip_pointer)
                    if p: ptrs.append(p)
                protocol,p = observed(a.raw_alert,'/protocol','/proto')
                facts['protocol'] = clean(protocol).lower() if clean(protocol) else None
                if p: ptrs.append(p)
                if sum(v is not None for v in facts.values()) < 3:
                    issues.add('CONTEXT_ENDPOINTS_INSUFFICIENT')
                tuples.append(facts)
                paths[a.alert_id] = ptrs
            if not any(all(v is not None for v in t.values()) for t in tuples):
                issues.add('CONTEXT_COMPLETE_TUPLE_MISSING')
            if any(len({t[k] for t in tuples if t[k] is not None}) > 1 for k in tuples[0]):
                issues.add('CONTEXT_ENDPOINT_CONFLICT')
        else:
            for a in members.values():
                paths[a.alert_id] = [o.raw_pointer for o in a.entity_occurrences if o.role.value == 'host']
        if issues:
            result.diagnostics.extend(diagnostic(code,list(members.values()),'Native context projection refused; source scopes retained.') for code in sorted(issues))
            continue
        bid = 'cib_'+content_digest(dict(scope=scope,value=token))
        observations=[]
        for aid,a in sorted(members.items()):
            current = replacements[aid]
            originals=[ref for ar,ref,_ in rows if ar.alert_id == aid]
            projected=[c.model_copy(update=dict(scope=scope)) for c in originals]
            data=current.model_dump()
            data['contexts']=sorted([c for c in current.contexts if c not in originals]+projected,
                key=lambda c:(c.kind,c.scope,c.value,c.raw_pointer))
            data['identity_binding_ids']=sorted(set(current.identity_binding_ids)|{bid})
            replacements[aid]=type(a).model_validate(data)
            observations.append(observation(a,paths[aid]+[a.field_provenance['timestamp'].raw_pointer]+[c.raw_pointer for c in originals]+
                [p for p in ('/boot_id','/session_epoch',*rows[0][2].scope_pointers) if observed(a.raw_alert,p)[0] is not None],originals))
        result.context_bindings.append(ContextIdentityBinding(projection_id=bid,kind=rows[0][2].kind,
            scope=scope,value=token,observations=observations))
    result.diagnostics.sort(key=lambda d:(d.code,d.alert_ids,d.detail))
    updated=[replacements[a.alert_id] for a in alerts]
    result.validate_trace(updated,entities)
    return updated,entities,result


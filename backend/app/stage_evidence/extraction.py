"""Typed postings and witness checks. Candidate hints never certify evidence.

Reuses only the canonical binding projection from ②/⑤, not community or Stage
aggregation conflict rules, relation decisions, correlation scores or windows.
"""
from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import PurePosixPath, PureWindowsPath

from app.community.evidence import profile, seconds
from app.entities.context import clean
from app.models.alerts import EvidencePointer, canonical_pointers
from app.models.base import resolve_pointer
from app.utils.stable_id import canonical_json, content_digest
from .config import DIRECTIONAL, ASSOCIATIVE


@dataclass(frozen=True)
class Observation:
    alert_id: str
    kind: str
    key: str
    identity: str
    role: str
    pointers: tuple[str, ...]
    network_facts: tuple = ()


def project_witnesses(stages, alerts, entities, settings, community_config, policy):
    indexes = {}
    for stage in sorted(stages, key=lambda s:s.stage_id):
        index = defaultdict(list)
        for aid in sorted(stage.alert_ids):
            alert = alerts[aid]
            source = settings[alert.source_namespace]
            p = profile(alert, entities, source, community_config)

            def add(kind, identity, role, pointers, network_facts=()):
                if not pointers:
                    return
                text = canonical_json(identity)
                index[(kind,content_digest(identity))].append(Observation(aid,kind,
                    content_digest(identity),text,role,tuple(sorted(set(pointers))),network_facts))

            for binding in p.bindings:
                if binding.projection != 'binding' or not binding.complete:
                    continue
                identity = json.loads(binding.identity)
                if binding.kind == 'flow':
                    # A reusable five-tuple alone is only supporting context.
                    add('flow_tuple',dict(scope=source.network_namespace or alert.source_namespace,
                        tuple=identity),'tuple',binding.pointers)
                    for ref in alert.contexts:
                        if ref.kind == 'flow':
                            add('flow',dict(scope=ref.scope,native_id=ref.value,tuple=identity),
                                'flow',(*binding.pointers,ref.raw_pointer))
                elif binding.kind in {'request','session','connection','application_session','task',
                        'process_instance','object','direct_reference'}:
                    if binding.kind == 'direct_reference' and binding.role == 'reference':
                        continue  # Project explicit directional/associative roles below.
                    add(binding.kind,identity,binding.role,binding.pointers)
                    if binding.kind == 'connection':
                        # Only a declared, projected connection issuer can
                        # attest initiation/acceptance across source scopes.
                        scope = json.loads(identity['scope'])
                        contracts = [c for c in source.identity_contract.contexts or [] if c.kind == 'connection']
                        if scope.get('context_projection') == 'v1' and contracts:
                            contract = contracts[0]
                            facts = {k:getattr(alert,k) for k in ('src_ip','src_port','dst_ip','dst_port')}
                            refs = [alert.field_provenance[k].raw_pointer for k,v in facts.items() if v is not None]
                            if facts['dst_ip'] is None and contract.destination_ip_pointer:
                                from app.entities.context import observed
                                facts['dst_ip'],path = observed(alert.raw_alert,contract.destination_ip_pointer)
                                if path: refs.append(path)
                            protocols = p.observed.get('protocol',[])
                            facts['protocol'] = protocols[0][0].lower() if len({v.lower() for v,_ in protocols}) == 1 else None
                            refs.extend(path for _,path in protocols)
                            initiate = alert.alert_type in policy.connection_initiate_operations
                            accept = alert.alert_type in policy.connection_accept_operations
                            if (initiate and all(v is not None for v in facts.values()) or
                                    accept and sum(v is not None for v in facts.values()) >= 3):
                                add('connection_role',identity,'initiate' if initiate else 'accept',
                                    (*binding.pointers,*refs),tuple(sorted(facts.items())))
            for role, fields in (('predecessor',policy.directional_reference_fields),
                                 ('reference',policy.associative_reference_fields)):
                for pointer in fields.get(source.format_profile,[]):
                    try:
                        raw_value = resolve_pointer(alert.raw_alert,pointer)
                    except ValueError:
                        continue
                    if raw_value is None or isinstance(raw_value,(dict,list,bool)):
                        continue
                    value = clean(raw_value)
                    if value:
                        add('direct_reference',dict(scope=alert.source_namespace,value=value),role,[pointer])
            for occurrence in alert.entity_occurrences:
                entity = entities[occurrence.entity_id]
                if entity.type.value in {'HOST','ACCOUNT','PROCESS','FILE','URL','COMMAND'}:
                    if entity.type.value == 'PROCESS' and occurrence.role.value != 'process':
                        continue
                    add('entity.'+entity.type.value,dict(entity_id=entity.entity_id),
                        occurrence.role.value,[occurrence.raw_pointer])
            for name in ('url','command','src_ip','dst_ip'):
                value, prov = getattr(alert,name), alert.field_provenance.get(name)
                if value is not None and prov:
                    kind = 'endpoint' if name.endswith('_ip') else name
                    scope = (source.network_namespace or alert.source_namespace) if kind == 'endpoint' else alert.source_namespace
                    add(kind,dict(scope=scope,value=value),name,[prov.raw_pointer])
            # Exact scoped absolute path plus explicit operation semantics.
            # Bare file names cannot become object-instance witnesses.
            paths = [(alert.file,'created_file','file')]
            if alert.process:
                paths.append((alert.process.executable,'executable','process.executable'))
            for value, role, field in paths:
                if not value or not (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()):
                    continue
                prov = alert.field_provenance.get(field) or alert.field_provenance.get('process' if role == 'executable' else field)
                if prov:
                    for host in (o for o in alert.entity_occurrences if o.role.value == 'host'):
                        add('object_path',dict(host=host.entity_id,path=value),role,[host.raw_pointer,prov.raw_pointer])
        indexes[stage.stage_id] = index
    return indexes


def process_conflicts(left, right, alerts):
    a, b = alerts[left.alert_id], alerts[right.alert_id]
    pa, pb = getattr(a,left.role), getattr(b,right.role)
    problems = []
    if not pa or not pb or not all(p.guid or p.instance_id or (p.pid is not None and p.start_time) for p in (pa,pb)):
        return ['PROCESS_IDENTITY_INCOMPLETE']
    for name in ('pid','start_time','guid','instance_id'):
        va,vb = getattr(pa,name),getattr(pb,name)
        if va is not None and vb is not None and va != vb:
            problems.append('PROCESS_IDENTITY_CONFLICT')
    hosts = [{o.entity_id for o in a.entity_occurrences if o.role.value == 'host'} for a in (a,b)]
    if all(hosts) and not hosts[0] & hosts[1]:
        problems.append('SCOPE_CONFLICT')
    return problems


def temporal_validation(kind, direction, left, right, alerts, policy):
    if kind not in DIRECTIONAL:
        return dict(status='NOT_APPLICABLE',rule='time_cannot_create_relation_or_direction'), []
    src,dst = (alerts[left.alert_id],alerts[right.alert_id]) if direction == 'A_TO_B' else (alerts[right.alert_id],alerts[left.alert_id])
    tolerance = policy.reversal_tolerance_seconds[kind]
    if kind == 'PARENT_CHILD_PROCESS':
        # A parent can be observed after its child; birth facts are authoritative.
        parent = src.process
        child = dst.process
        if not parent or not child or not parent.start_time or not child.start_time:
            return dict(status='UNKNOWN',rule='process_birth_facts_unavailable',tolerance_seconds=tolerance), []
        start,end = parent.start_time,child.start_time
        rule = 'parent_birth_must_not_follow_child_birth'
    else:
        start,end = src.timestamp,dst.timestamp
        rule = 'semantic_predecessor_observation_must_not_follow_successor'
    gap = seconds(end)-seconds(start)
    bad = gap < -tolerance
    return dict(status='TEMPORAL_CONFLICT' if bad else 'CONSISTENT',rule=rule,
        from_time=start,to_time=end,gap_seconds=gap,tolerance_seconds=tolerance,
        maximum_age_seconds=None), ['TEMPORAL_CONFLICT'] if bad else []


def extract_pair_evidence(a, b, indexes, alerts, entities, policy, collector):
    claim_ids = set()

    def add(kind, left, right, reason, direction=None, extra=(), conflicts=()):
        if kind not in policy.enabled_evidence_types:
            return
        strength = 'DIRECTIONAL_STRONG' if kind in DIRECTIONAL else 'ASSOCIATIVE_STRONG' if kind in ASSOCIATIVE else 'SUPPORTING_ONLY'
        claim = direction or ('UNDIRECTED' if strength == 'ASSOCIATIVE_STRONG' else 'NONE')
        issues = list(conflicts)
        # Claim-local identity and scope check, independent of Stage ⑥ vetoes.
        if left.kind != right.kind or left.identity != right.identity or left.key != right.key:
            issues.append('IDENTITY_CONFLICT')
            lid,rid = json.loads(left.identity),json.loads(right.identity)
            if isinstance(lid,dict) and isinstance(rid,dict) and any(
                    k in lid and k in rid and lid[k] != rid[k] for k in ('scope','host','network_scope')):
                issues.append('SCOPE_CONFLICT')
        if left.kind == 'process_instance':
            issues.extend(process_conflicts(left,right,alerts))
        refs = canonical_pointers([EvidencePointer(alert_id=o.alert_id,pointer=p,side='shared')
            for o in (left,right) for p in o.pointers] + list(extra))
        for p in refs:
            try:
                if p.resolve(alerts) is None:
                    issues.append('RAW_EVIDENCE_MISSING')
            except (ValueError,KeyError,IndexError,TypeError):
                # An unresolvable pointer is an input integrity error, never an
                # exported dangling reference disguised as an invalid witness.
                raise ValueError('cross_stage_raw_pointer_invalid') from None
        time, time_issues = temporal_validation(kind,claim,left,right,alerts,policy)
        issues = sorted(set(issues + time_issues))
        claim_ids.add(collector.add(a,b,kind,left,right,claim,refs,time,issues,reason,json.loads(left.identity)))

    def operation_refs(left,right):
        return [EvidencePointer(alert_id=aid,pointer=alerts[aid].field_provenance['alert_type'].raw_pointer,side='shared')
                for aid in (left.alert_id,right.alert_id)]

    li,ri = indexes[a.stage_id],indexes[b.stage_id]
    for key in sorted(li.keys() & ri.keys()):
        for left in li[key]:
            for right in ri[key]:
                la,ra = alerts[left.alert_id],alerts[right.alert_id]
                kind = left.kind
                lo,ro = la.alert_type,ra.alert_type
                if kind == 'process_instance':
                    if left.role == right.role == 'process':
                        add('SAME_PROCESS_INSTANCE',left,right,'Same complete scoped current process instance; identity supplies association only.')
                    elif {left.role,right.role} == {'process','parent_process'}:
                        parent,child = (la,ra) if left.role == 'process' else (ra,la)
                        cp = child.process
                        problems = []
                        if not cp or not (cp.guid or cp.instance_id or (cp.pid is not None and cp.start_time)):
                            problems.append('CHILD_PROCESS_IDENTITY_INCOMPLETE')
                        if not any(o.role.value=='process' for o in child.entity_occurrences):
                            problems.append('CHILD_SCOPED_PROCESS_IDENTITY_MISSING')
                        if cp and (cp == child.parent_process or (cp.pid is not None and cp.pid == child.parent_process.pid)):
                            problems.append('CHILD_EQUALS_PARENT')
                        child_refs = [EvidencePointer(alert_id=child.alert_id,pointer=p.raw_pointer,side='shared')
                            for field,p in child.field_provenance.items() if field.startswith('process') or field.startswith('native.process_')]
                        child_observations = [o for bucket in indexes[b.stage_id if child == ra else a.stage_id].values()
                            for o in bucket if o.alert_id == child.alert_id and o.kind == 'process_instance' and o.role == 'process']
                        child_refs.extend(EvidencePointer(alert_id=child.alert_id,pointer=p,side='shared') for o in child_observations for p in o.pointers)
                        add('PARENT_CHILD_PROCESS',left,right,'Current process is the other event parent; full instance identity validates lineage.',
                            'A_TO_B' if parent == la else 'B_TO_A',child_refs,problems)
                elif kind == 'connection_role' and {left.role,right.role} == {'initiate','accept'}:
                    lf,rf = dict(left.network_facts),dict(right.network_facts)
                    conflicts = ['CONNECTION_ENDPOINT_CONFLICT'] if any(
                        lf[k] is not None and rf[k] is not None and lf[k] != rf[k] for k in lf) else []
                    add('CONNECTION_ESTABLISH_ACCEPT',left,right,
                        'Native trusted connection plus compatible endpoints and explicit initiation/credential-acceptance roles.',
                        'A_TO_B' if left.role == 'initiate' else 'B_TO_A',operation_refs(left,right),conflicts)
                elif kind == 'flow':
                    add('SAME_SCOPED_FLOW',left,right,'Same scoped native flow ID and complete network tuple; no causal direction.')
                elif kind == 'flow_tuple':
                    add('INCOMPLETE_FLOW',left,right,'Tuple continuity without certified native flow identity is supporting context only.')
                elif kind in {'request','session','connection','application_session','task'}:
                    assoc = {'request':'SAME_SCOPED_REQUEST','session':'SAME_STRONG_SESSION',
                        'application_session':'SAME_STRONG_SESSION','connection':'SAME_TRUSTED_CONNECTION','task':'SAME_SCOPED_TASK'}[kind]
                    add(assoc,left,right,'Same typed identity in the same declared scope; identity alone supplies no direction.')
                    if kind == 'request' and ((lo in policy.request_operations and ro in policy.response_operations) or
                            (ro in policy.request_operations and lo in policy.response_operations)):
                        add('REQUEST_RESPONSE',left,right,'Explicit complementary request and response operations share the same scoped request.',
                            'A_TO_B' if lo in policy.request_operations else 'B_TO_A',operation_refs(left,right))
                    elif kind in {'session','application_session'} and (
                            (lo in policy.session_start_operations and ro in policy.session_use_operations) or
                            (ro in policy.session_start_operations and lo in policy.session_use_operations)):
                        add('AUTH_ESTABLISH_USE',left,right,'Explicit successful authentication/session establishment precedes an explicit use operation on the same context.',
                            'A_TO_B' if lo in policy.session_start_operations else 'B_TO_A',operation_refs(left,right))
                elif kind == 'object':
                    add('SAME_SCOPED_OBJECT',left,right,'Same explicit scoped object identity; no direction implied by identity.')
                    if {left.role,right.role} == {'response_object_id','request_object_id'}:
                        add('OBJECT_HANDOFF',left,right,'Object returned by one event is explicitly consumed as request input by the other.',
                            'A_TO_B' if left.role == 'response_object_id' else 'B_TO_A')
                elif kind == 'object_path':
                    # Path equality is supporting context; create/consume roles
                    # plus a scoped absolute identity can attest a handoff.
                    add('SHARED_FILE_PATH',left,right,'Same scoped absolute object path; path alone does not identify an object lifetime.')
                    if ((left.role == 'created_file' and lo in policy.object_create_operations and right.role == 'executable' and ro in policy.object_execute_operations) or
                            (right.role == 'created_file' and ro in policy.object_create_operations and left.role == 'executable' and lo in policy.object_execute_operations)):
                        add('OBJECT_CREATE_EXECUTE',left,right,'Explicit create and execute/consume operations refer to the identical absolute object on the same scoped host.',
                            'A_TO_B' if left.role == 'created_file' else 'B_TO_A',operation_refs(left,right))
                elif kind == 'direct_reference' and 'record' in {left.role,right.role} and left.role != right.role:
                    ref = left if left.role != 'record' else right
                    predecessor = ref.role == 'predecessor'
                    add('EXPLICIT_ATTESTED_RELATION' if predecessor else 'EXPLICIT_RELATED_EVENT',left,right,
                        'Native scoped record reference explicitly names the predecessor.' if predecessor else 'Native record reference links the events without direction semantics.',
                        ('B_TO_A' if left.role != 'record' else 'A_TO_B') if predecessor else None)
                elif kind.startswith('entity.') or kind in {'url','command','endpoint'}:
                    typ = {'entity.HOST':'SAME_HOST','entity.ACCOUNT':'SAME_ACCOUNT','entity.PROCESS':'SHARED_PROCESS_DESCRIPTOR',
                        'entity.FILE':'SHARED_FILE_PATH','entity.URL':'SAME_URL','entity.COMMAND':'SAME_COMMAND',
                        'url':'SAME_URL','command':'SAME_COMMAND','endpoint':'NETWORK_ENDPOINT_OVERLAP'}.get(kind)
                    if typ:
                        add(typ,left,right,'Shared public/weak context cannot independently establish a Stage relation.')

    # Consume existing structured Adapter attestations only. No relation is
    # synthesized from matching IPs, accounts, URLs, or behavior adjacency.
    for owner in sorted({*a.alert_ids,*b.alert_ids}):
        for relation in alerts[owner].relations:
            if relation.relation_type.value == 'parent_child_process':
                continue  # Covered by instance postings and process birth validation.
            refs = relation.raw_pointers
            srcs = {p.alert_id for p in refs if p.side == 'src'}
            dsts = {p.alert_id for p in refs if p.side == 'dst'}
            if len(srcs) != 1 or len(dsts) != 1 or srcs == dsts:
                continue
            src,dst = next(iter(srcs)),next(iter(dsts))
            if not ((src in a.alert_ids and dst in b.alert_ids) or (src in b.alert_ids and dst in a.alert_ids)):
                continue
            if {p.alert_id for p in refs} != {src,dst}:
                continue
            problems = []
            if relation.source_entity_id not in alerts[src].entity_ids or relation.target_entity_id not in alerts[dst].entity_ids:
                problems.append('EXPLICIT_ENDPOINT_CONFLICT')
            if relation.source_entity_id not in entities or relation.target_entity_id not in entities:
                problems.append('EXPLICIT_ENDPOINT_CONFLICT')
            else:
                se,te = entities[relation.source_entity_id],entities[relation.target_entity_id]
                sa,ta = alerts[src],alerts[dst]
                relation_kind = relation.relation_type.value
                if relation_kind == 'network_pivot':
                    valid = (sa.dst_ip is not None and sa.dst_ip == ta.src_ip and se.type.value == te.type.value == 'IP'
                        and se.scope == te.scope and se.value == sa.dst_ip and te.value == ta.src_ip
                        and any(o.entity_id == se.entity_id and o.role.value == 'dst_ip' for o in sa.entity_occurrences)
                        and any(o.entity_id == te.entity_id and o.role.value == 'src_ip' for o in ta.entity_occurrences))
                elif relation_kind == 'account_host_pivot':
                    common = set(sa.entity_ids) & set(ta.entity_ids)
                    valid = (bool(sa.host and ta.host and sa.host != ta.host)
                        and any(entities[eid].type.value in {'ACCOUNT','SESSION'} for eid in common)
                        and se.type.value in {'HOST','ACCOUNT','SESSION'} and te.type.value in {'HOST','ACCOUNT','SESSION'})
                elif relation_kind == 'session_continuity':
                    valid = se.type.value == te.type.value == 'SESSION' and se.entity_id == te.entity_id and bool(sa.session and sa.session == ta.session)
                else:  # Explicit target -> process launch still needs a substantive connector.
                    common_hosts = {o.entity_id for o in sa.entity_occurrences if o.role.value == 'host'} & {o.entity_id for o in ta.entity_occurrences if o.role.value == 'host'}
                    context_paths = {p.raw_pointer for x in (sa,ta) for field,p in x.field_provenance.items()
                        if field in {'host','process','timestamp','session','category','alert_type','source_type'}}
                    connectors = [p for p in refs if p.pointer not in context_paths and p.pointer.rsplit('/',1)[-1] not in {'request_id','session_id','logon_id','connection_id'}]
                    valid = (se.type.value == 'HOST' and te.type.value == 'PROCESS' and se.entity_id in common_hosts
                        and any(o.entity_id == te.entity_id and o.role.value == 'process' for o in ta.entity_occurrences)
                        and bool(ta.process and (ta.process.guid or ta.process.instance_id or (ta.process.pid is not None and ta.process.start_time))) and bool(connectors))
                if not valid:
                    problems.append('EXPLICIT_SEMANTIC_CONFLICT')
            identity = canonical_json(relation.model_dump(mode='json'))
            observations = [Observation(aid,'attested',content_digest(identity),identity,'source' if aid == src else 'target',
                tuple(p.pointer for p in refs if p.alert_id == aid)) for aid in (src,dst)]
            left,right = observations if src in a.alert_ids else list(reversed(observations))
            # Session continuity is associative; endpoint ordering alone is
            # not authentication establishment/use or propagation semantics.
            continuity = relation.relation_type.value == 'session_continuity'
            add('EXPLICIT_RELATED_EVENT' if continuity else 'EXPLICIT_ATTESTED_RELATION',left,right,
                'Existing structured Adapter relation with explicit bound endpoints.',
                None if continuity else 'A_TO_B' if src in a.alert_ids else 'B_TO_A',conflicts=problems)
    return sorted(claim_ids)

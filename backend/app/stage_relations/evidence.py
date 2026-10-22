"""Compare Stage evidence postings; never run an Alert correlation scorer.

Profiles only project the existing canonical facts/bindings with original raw
witnesses. Vendor text, behavior adjacency and timestamps never nominate edges.
"""
from collections import defaultdict
from dataclasses import dataclass

from app.community.evidence import profile
from app.models.alerts import EvidencePointer, canonical_pointers
from app.utils.stable_id import canonical_json
from .models import RelationEvidence, SemanticDirection, stable


@dataclass(frozen=True)
class Observation:
    alert_id: str
    kind: str
    key: str
    role: str
    pointers: tuple[str, ...]
    entity_ids: tuple[str, ...]


def postings(stages, alerts, entities, settings, community_config):
    """One typed inverted index per Stage, derived without altering its input."""
    result = {}
    for stage in stages:
        index = defaultdict(list)
        for aid in stage.alert_ids:
            alert = alerts[aid]
            p = profile(alert, entities, settings[alert.source_namespace], community_config)
            for binding in p.bindings:
                if binding.projection != 'binding' or not binding.complete:
                    continue
                if binding.kind not in {'request', 'session', 'connection', 'application_session',
                        'task', 'flow', 'process_instance', 'object', 'direct_reference'}:
                    continue
                o = Observation(aid, binding.kind, binding.key, binding.role,
                                binding.pointers, binding.entity_ids)
                index[(binding.kind, binding.key)].append(o)
            for occurrence in alert.entity_occurrences:
                entity = entities[occurrence.entity_id]
                if entity.type.value not in {'HOST', 'ACCOUNT', 'PROCESS', 'FILE', 'URL', 'SESSION', 'COMMAND'}:
                    continue
                # A weak process context must refer to the observed current
                # process; sharing only a parent never proves a handoff.
                if entity.type.value == 'PROCESS' and occurrence.role.value != 'process':
                    continue
                index[('entity', entity.entity_id)].append(Observation(aid, 'entity', entity.entity_id,
                    occurrence.role.value, (occurrence.raw_pointer,), (entity.entity_id,)))
            # Endpoint fields remain scoped context even when no IP entities
            # were extracted. Port/protocol alone cannot nominate a relation.
            scope = settings[alert.source_namespace].network_namespace or alert.source_namespace
            for name in ('src_ip', 'dst_ip'):
                value = getattr(alert, name)
                if value is not None and name in alert.field_provenance:
                    key = canonical_json(dict(scope=scope, value=value))
                    index[('endpoint', key)].append(Observation(aid, 'endpoint', key, name,
                        (alert.field_provenance[name].raw_pointer,), ()))
        result[stage.stage_id] = index
    return result


def operation(alert):
    # alert_type is already normalized by the native source adapter.
    return alert.alert_type


def evidence_for_pair(a, b, indexes, alerts, entities, policy):
    candidates = {}

    def add(kind, left, right, reason, direction=None, extra=(), entity_ids=()):
        refs = [EvidencePointer(alert_id=o.alert_id, pointer=ptr, side='shared')
                for o in (left, right) for ptr in o.pointers]
        refs.extend(extra)
        refs = canonical_pointers(refs)
        semantic = None
        if direction:
            src, dst = direction
            semantic = SemanticDirection(from_stage_id=a.stage_id if src == left.alert_id else b.stage_id,
                to_stage_id=b.stage_id if dst == right.alert_id else a.stage_id,
                from_alert_id=src, to_alert_id=dst)
        identity = dict(evidence_type=kind, alert_ids=sorted([left.alert_id, right.alert_id]),
            identity_key=left.key, pointers=[p.model_dump(mode='json') for p in refs],
            semantic_direction=semantic.model_dump(mode='json') if semantic else None)
        ep = policy.evidence[kind]
        data = dict(**identity, evidence_id=stable('sre', 'StageRelationEvidence', identity),
            rank=ep.rank, evidence_strength=ep.strength, strong=direction is not None or kind == 'same_instance',
            entity_ids=sorted(set(left.entity_ids) | set(right.entity_ids) | set(entity_ids)), reason=reason)
        candidates[data['evidence_id']] = RelationEvidence.model_validate(data, context=dict(alerts=alerts))

    li, ri = indexes[a.stage_id], indexes[b.stage_id]
    for key in sorted(li.keys() & ri.keys()):
        for left in li[key]:
            for right in ri[key]:
                la, ra = alerts[left.alert_id], alerts[right.alert_id]
                kind = left.kind
                direction, ek, reason = None, None, None
                if kind == 'process_instance':
                    if left.role == right.role == 'parent_process':
                        continue
                    ek = 'shared_process_instance'
                    reason = 'Same complete scoped current process instance; this alone gives no propagation direction.'
                    if {left.role, right.role} == {'process', 'parent_process'}:
                        parent, child = (la, ra) if left.role == 'process' else (ra, la)
                        # The child's own complete process must be different,
                        # not just a parent descriptor in an otherwise unknown event.
                        cp = child.process
                        complete = cp and (cp.guid or cp.instance_id or (cp.pid is not None and cp.start_time))
                        child_ids = {o.entity_id for o in child.entity_occurrences if o.role.value == 'process'}
                        if not complete or not child_ids or set(left.entity_ids) & child_ids:
                            continue
                        ph = {o.entity_id for o in parent.entity_occurrences if o.role.value == 'host'}
                        ch = {o.entity_id for o in child.entity_occurrences if o.role.value == 'host'}
                        if not ph & ch:
                            continue
                        ek, direction = 'parent_child_process', (parent.alert_id, child.alert_id)
                        reason = 'Current process instance is explicitly the other alert parent; direction comes from lineage.'
                        extra = []
                        for name, prov in child.field_provenance.items():
                            if name == 'process' or name.startswith('native.process_'):
                                extra.append(EvidencePointer(alert_id=child.alert_id, pointer=prov.raw_pointer, side='dst'))
                        # Every identity component must have a raw witness,
                        # including split native child GUID/start-time fields.
                        if isinstance(child.raw_alert, dict):
                            extra.extend(EvidencePointer(alert_id=child.alert_id,pointer='/'+name,side='dst')
                                for name in ('process_guid','process_instance_id','process_start_time')
                                if child.raw_alert.get(name) is not None)
                        add(ek, left, right, reason, direction, extra, child_ids)
                        continue
                    if left.role == right.role == 'process' and 'same_instance' in policy.evidence:
                        ek = 'same_instance'
                        reason = 'Same complete scoped current process instance binds these observations; identity does not establish propagation direction.'
                elif kind == 'direct_reference':
                    if {left.role, right.role} != {'record', 'reference'}:
                        continue
                    # Only parent_event_id has explicit predecessor semantics;
                    # a generic reference alone does not specify direction.
                    ref = left if left.role == 'reference' else right
                    if any(p.rsplit('/', 1)[-1] == 'parent_event_id' for p in ref.pointers):
                        ek = 'attested_relation'
                        direction = (right.alert_id, left.alert_id) if left.role == 'reference' else (left.alert_id, right.alert_id)
                        reason = 'Native parent_event_id names the predecessor record in the same source namespace.'
                    else:
                        ek, reason = 'shared_binding', 'Explicit native reference links the alerts without a declared direction.'
                elif kind == 'object':
                    if {left.role, right.role} == {'response_object_id', 'request_object_id'}:
                        direction = (left.alert_id, right.alert_id) if left.role == 'response_object_id' else (right.alert_id, left.alert_id)
                        ek, reason = 'object_handoff', 'Scoped response object is explicitly consumed as a request object.'
                    else:
                        ek, reason = 'shared_binding', 'Same observed scoped object; direction is not asserted by object identity.'
                elif kind in {'request', 'session', 'connection', 'application_session', 'task', 'flow'}:
                    lo, ro = operation(la), operation(ra)
                    ek, reason = 'shared_binding', 'Same typed scoped binding; identity alone does not prove causation.'
                    if kind == 'request' and ((lo in policy.request_operations and ro in policy.response_operations)
                            or (ro in policy.request_operations and lo in policy.response_operations)):
                        ek = 'request_response'
                        direction = (left.alert_id, right.alert_id) if lo in policy.request_operations else (right.alert_id, left.alert_id)
                        reason = 'Same scoped request ID with explicit request and response operation roles.'
                    elif kind in {'session', 'connection', 'application_session'} and (
                            (lo in policy.session_start_operations) != (ro in policy.session_start_operations)) and lo and ro:
                        ek = 'session_followup'
                        direction = (left.alert_id, right.alert_id) if lo in policy.session_start_operations else (right.alert_id, left.alert_id)
                        reason = 'Explicit session-open/login operation and a member operation share the same scoped session.'
                    if direction:
                        refs = [EvidencePointer(alert_id=x.alert_id, pointer=x.field_provenance['alert_type'].raw_pointer, side='shared') for x in (la, ra)]
                        add(ek, left, right, reason, direction, refs)
                        continue
                    if kind == 'flow' and 'same_instance' in policy.evidence:
                        # A five-tuple can be reused. Require a native flow ID
                        # in the SAME declared scope as well as this complete
                        # tuple; an equal token across sources is insufficient.
                        native = [(lc, rc) for lc in la.contexts for rc in ra.contexts
                            if lc.kind == rc.kind == 'flow' and lc.scope == rc.scope and lc.value == rc.value]
                        if native:
                            refs = [EvidencePointer(alert_id=alert.alert_id,pointer=ref.raw_pointer,side='shared')
                                for lc, rc in native for alert, ref in ((la,lc),(ra,rc))]
                            add('same_instance',left,right,
                                'Same complete flow tuple and native flow ID in the same declared scope; connection identity does not establish propagation direction.',
                                extra=refs)
                elif kind == 'entity':
                    ek, reason = 'shared_entity', 'Same scoped observed entity; only weak association plus observation order is claimed.'
                elif kind == 'endpoint':
                    ek, reason = 'network_context', 'Same endpoint IP in the same network scope; endpoint continuity alone is weak evidence.'
                if ek:
                    add(ek, left, right, reason, direction)

    # Canonical create -> executable-object consumption, on an identical host.
    # Match only actual fields; never parse commands or infer a missing path.
    for src_stage, dst_stage in ((a, b), (b, a)):
        for sid in src_stage.alert_ids:
            src = alerts[sid]
            if operation(src) not in policy.object_create_operations or not src.file:
                continue
            for tid in dst_stage.alert_ids:
                dst = alerts[tid]
                if operation(dst) not in policy.object_execute_operations or not dst.process or src.file != dst.process.executable:
                    continue
                sh = {o.entity_id for o in src.entity_occurrences if o.role.value == 'host'}
                dh = {o.entity_id for o in dst.entity_occurrences if o.role.value == 'host'}
                if not sh & dh:
                    continue
                key = canonical_json(dict(hosts=sorted(sh & dh), object=src.file))
                obs = [Observation(x.alert_id, 'object', key, '', tuple(sorted({
                    x.field_provenance[field].raw_pointer, x.field_provenance['alert_type'].raw_pointer,
                    *[o.raw_pointer for o in x.entity_occurrences if o.entity_id in sh & dh]})), tuple(sorted(sh & dh)))
                    for x, field in ((src, 'file'), (dst, 'process'))]
                left, right = obs if sid in a.alert_ids else list(reversed(obs))
                extra = []
                if isinstance(dst.raw_alert, dict) and dst.raw_alert.get('executable') == dst.process.executable:
                    extra.append(EvidencePointer(alert_id=tid,pointer='/executable',side='dst'))
                add('object_create_execute', left, right,
                    'Observed object creation and execution of the identical path on the same scoped host.', (sid, tid), extra)

    # Existing structured explicit relations retain their semantic endpoint
    # roles. Never treat arbitrary pointer existence as propagation evidence.
    for owner in [alerts[aid] for aid in sorted(set(a.alert_ids) | set(b.alert_ids))]:
        for relation in owner.relations:
            if relation.relation_type.value not in {'network_pivot', 'account_host_pivot', 'target_to_process', 'session_continuity'}:
                continue
            refs = relation.raw_pointers
            srcs = {p.alert_id for p in refs if p.side == 'src'}
            dsts = {p.alert_id for p in refs if p.side == 'dst'}
            if len(srcs) != 1 or len(dsts) != 1 or srcs == dsts:
                continue
            sid, tid = next(iter(srcs)), next(iter(dsts))
            if not ((sid in a.alert_ids and tid in b.alert_ids) or (sid in b.alert_ids and tid in a.alert_ids)):
                continue
            if {p.alert_id for p in refs} != {sid, tid} or any(not p.pointer for p in refs):
                continue
            src, dst = alerts[sid], alerts[tid]
            if relation.source_entity_id not in src.entity_ids or relation.target_entity_id not in dst.entity_ids:
                continue
            se, te = entities[relation.source_entity_id], entities[relation.target_entity_id]
            relation_kind = relation.relation_type.value
            if relation_kind == 'network_pivot':
                valid = (src.dst_ip is not None and src.dst_ip == dst.src_ip and se.type.value == te.type.value == 'IP'
                    and se.scope == te.scope and se.value == src.dst_ip and te.value == dst.src_ip
                    and any(o.entity_id == se.entity_id and o.role.value == 'dst_ip' for o in src.entity_occurrences)
                    and any(o.entity_id == te.entity_id and o.role.value == 'src_ip' for o in dst.entity_occurrences))
            elif relation_kind == 'account_host_pivot':
                common = set(src.entity_ids) & set(dst.entity_ids)
                valid = (bool(src.host and dst.host and src.host != dst.host)
                    and any(entities[eid].type.value in {'ACCOUNT','SESSION'} for eid in common)
                    and se.type.value in {'HOST','ACCOUNT','SESSION'} and te.type.value in {'HOST','ACCOUNT','SESSION'})
            elif relation_kind == 'session_continuity':
                valid = (se.type.value == te.type.value == 'SESSION' and se.entity_id == te.entity_id
                    and src.session is not None and src.session == dst.session)
            else:  # target_to_process: a shared request/session alone cannot attest launch.
                process = dst.process
                common_hosts = {o.entity_id for o in src.entity_occurrences if o.role.value == 'host'} & {
                    o.entity_id for o in dst.entity_occurrences if o.role.value == 'host'}
                endpoint_paths = {p.raw_pointer for x in (src,dst) for name,p in x.field_provenance.items()
                    if name in {'host','process','timestamp','session','category','alert_type','source_type'}}
                connector = [p for p in refs if p.pointer not in endpoint_paths and
                    p.pointer.rsplit('/',1)[-1] not in {'request_id','session_id','logon_id','connection_id'}]
                valid = (se.type.value == 'HOST' and te.type.value == 'PROCESS' and se.entity_id in common_hosts
                    and any(o.entity_id == te.entity_id and o.role.value == 'process' for o in dst.entity_occurrences)
                    and bool(process and (process.guid or process.instance_id or (process.pid is not None and process.start_time)))
                    and src.category.value in {'web_attack','initial_access'}
                    and dst.category.value in {'process_execution','command_execution'} and bool(connector))
            if not valid:
                continue
            # Upstream contract attests propagation; this layer accepts only
            # an existing relation, never synthesizes one from endpoint matches.
            key = canonical_json(relation.model_dump(mode='json'))
            obs = [Observation(aid, 'attested', key, '', tuple(p.pointer for p in refs if p.alert_id == aid),
                (eid,)) for aid, eid in ((sid, relation.source_entity_id), (tid, relation.target_entity_id))]
            left, right = obs if sid in a.alert_ids else list(reversed(obs))
            add('attested_relation', left, right, 'Existing structured '+relation.relation_type.value+' attestation with bound source/destination witnesses.', (sid, tid))
    return sorted(candidates.values(), key=lambda e: (e.rank, -e.evidence_strength, e.evidence_id))

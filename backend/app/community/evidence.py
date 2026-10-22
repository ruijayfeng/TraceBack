"""Scoped matching keys, each carrying witnesses from the original alert.

Projections are explicit scalar fields, never recursive payload searches. Equal
short identifiers from different kinds/scopes cannot meet in an index bucket.
"""
from dataclasses import dataclass, field
from datetime import datetime

from app.entities.context import clean, weak_observations
from app.models.alerts import EvidencePointer
from app.models.base import resolve_pointer
from app.utils.stable_id import canonical_json, content_digest

PROJECTION_VERSION = 'entity-binding-index-v2'

# Evidence tiers are semantic, independent of historical numeric match levels.
STRONG_KINDS = frozenset({'request', 'flow', 'session', 'connection',
                         'application_session', 'task', 'direct_reference', 'cross_source_process_instance'})


def evidence_tier(kind):
    return 'A' if kind in STRONG_KINDS else 'C' if kind == 'network_ip' else 'B'

@dataclass(frozen=True)
class Binding:
    level: int
    kind: str
    key: str
    pointers: tuple[str, ...]
    entity_ids: tuple[str, ...] = ()
    role: str = ''
    projection: str = 'binding'
    complete: bool = True
    missing_fields: tuple[str, ...] = ()
    identity: str = ''


@dataclass
class Profile:
    alert: object
    seconds: float
    bindings: list[Binding] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    accounts: set[str] = field(default_factory=set)
    processes: set[str] = field(default_factory=set)
    contexts: dict[str, set[str]] = field(default_factory=dict)
    observed: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    weak_contexts: list[tuple[str, str, str]] = field(default_factory=list)
    behaviors: set[str] = field(default_factory=set)
    behavior_pointers: set[str] = field(default_factory=set)


def seconds(timestamp):
    return datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()


def profile(alert, entities, settings, config):
    p = Profile(alert, seconds(alert.timestamp))
    occurrences = alert.entity_occurrences
    hosts = [o for o in occurrences if o.role.value == 'host']
    accounts = [o for o in occurrences if entities[o.entity_id].type.value == 'ACCOUNT']
    p.hosts = {o.entity_id for o in hosts}
    p.accounts = {o.entity_id for o in accounts}

    def add(level, kind, identity, pointers, eids=(), role='', projection='binding', complete=True, missing=()):
        p.bindings.append(Binding(level, kind, kind + ':' + content_digest(identity),
                                  tuple(sorted(set(pointers))), tuple(sorted(set(eids))), role,
                                  projection, complete, tuple(missing), canonical_json(identity)))

    p.weak_contexts = weak_observations(alert, settings)
    protocols = [(value, pointer) for kind, value, pointer in p.weak_contexts if kind == 'protocol']
    flow = {name: getattr(alert, name) for name in ('src_ip', 'src_port', 'dst_ip', 'dst_port')}
    flow['protocol'] = protocols[0][0] if protocols and len({v for v, _ in protocols}) == 1 else None
    missing = tuple(k for k, value in flow.items() if value is None)
    flow_pointers = [alert.field_provenance[k].raw_pointer for k in flow if k != 'protocol' and flow[k] is not None]
    flow_pointers += [pointer for _, pointer in protocols]
    if settings.network_namespace:
        flow['network_scope'] = settings.network_namespace
    if not missing:
        add(1, 'flow', flow, flow_pointers)
    elif flow_pointers or any(c.kind == 'flow' for c in alert.contexts):
        # Partial tuples are retained for audit and recall, never strong matches.
        partial = dict(flow, native_ids=sorted([c.scope, c.value] for c in alert.contexts if c.kind == 'flow'))
        add(5, 'incomplete_flow', partial, flow_pointers + [c.raw_pointer for c in alert.contexts if c.kind == 'flow'],
            projection='incomplete_binding', complete=False, missing=missing)

    # ContextRef already carries the deployment/application scope. Retain native
    # subtype too: connection_id is not flow_id; logon/session aliases are typed.
    for ref in alert.contexts:
        if ref.kind == 'flow':
            continue  # A native flow ID cannot replace the required tuple.
        leaf = ref.raw_pointer.rsplit('/', 1)[-1]
        subtype = ('connection' if leaf == 'connection_id' else 'application_session'
                   if leaf == 'application_session_id' else ref.kind)
        key = dict(scope=ref.scope, value=ref.value, subtype=subtype)
        add(2 if ref.kind == 'task' else 1, subtype, key,
            [ref.raw_pointer] + [host.raw_pointer for host in hosts])
        scope = canonical_json(dict(scope=ref.scope, subtype=subtype))
        p.contexts.setdefault(scope, set()).add(ref.value)

    paths = config.projections.get(settings.format_profile, {})
    for kind, pointers in paths.items():
        values = []
        for pointer in pointers:
            try:
                value = resolve_pointer(alert.raw_alert, pointer)
            except ValueError:
                continue
            if value is None:
                continue
            if isinstance(value, (dict, list, bool)):
                raise ValueError('community_projection_requires_scalar:' + kind)
            value = clean(value)
            if value:
                values.append((value, pointer))
        p.observed[kind] = values

    # Reuse observed semantics only. No Stage/ATT&CK mapping is performed here.
    if p.observed.get('behavior'):
        p.behaviors = {'behavior:' + value.casefold() for value, _ in p.observed['behavior']}
        p.behavior_pointers = {pointer for _, pointer in p.observed['behavior']}
    elif alert.category.value != 'unknown':
        p.behaviors = {canonical_json(dict(category=alert.category.value, signature=alert.signature))}
        p.behavior_pointers = {alert.field_provenance[k].raw_pointer for k in ('category', 'signature')
                               if k in alert.field_provenance and alert.field_provenance[k].raw_pointer}

    for kind, value, pointer in p.weak_contexts:
        if kind in ('src_ip', 'dst_ip'):
            add(5, 'network_ip', dict(scope=settings.network_namespace or alert.source_namespace, value=value),
                [pointer], projection='network_auxiliary')

    if alert.source_record_id:
        add(1, 'direct_reference', dict(scope=alert.source_namespace, value=alert.source_record_id),
            [alert.field_provenance['source_record_id'].raw_pointer], role='record')
    for value, pointer in p.observed.get('direct_reference', []):
        add(1, 'direct_reference', dict(scope=alert.source_namespace, value=value), [pointer], role='reference')

    # Process identity requires an instance GUID or host+PID+start time. PID-only
    # entities from the existing extractor are deliberately not promoted to L2.
    for role in ('process', 'parent_process'):
        process = getattr(alert, role)
        if not process:
            continue
        strong = bool(process.guid or process.instance_id or (process.pid is not None and process.start_time))
        for occurrence in [o for o in occurrences if o.role.value == role]:
            if strong:
                p.processes.add(occurrence.entity_id)
                for host in hosts or [None]:
                    pointers = [occurrence.raw_pointer] + ([host.raw_pointer] if host else [])
                    # Include every field defining this process instance.
                    for name, provenance in alert.field_provenance.items():
                        if name == role or name in ('native.'+role+'_start_time', 'native.'+role+'_id'):
                            pointers.append(provenance.raw_pointer)
                    # ProcessRef components can originate from separate fields.
                    # Only existing declared profile paths are used below.
                    if settings.format_profile == 'multisource_native_v1':
                        raw = alert.raw_alert
                        names = ('process_start_time', 'process_guid', 'process_instance_id', 'worker_process_start_time') if role == 'process' else ('parent_process_start_time', 'parent_process_guid', 'parent_process_instance_id')
                        pointers += ['/'+name for name in names if raw.get(name) is not None]
                    add(2, 'process_instance', dict(process=occurrence.entity_id),
                        pointers, [occurrence.entity_id] + ([host.entity_id] if host else []), role=role)
            elif role == 'process':
                for host in hosts:
                    add(3, 'host_process', dict(host=host.entity_id, process=occurrence.entity_id),
                        [host.raw_pointer, occurrence.raw_pointer], [host.entity_id, occurrence.entity_id])

    for host in hosts:
        add(4, 'host', host.entity_id, [host.raw_pointer], [host.entity_id])
        for account in accounts:
            add(3, 'host_account', [host.entity_id, account.entity_id],
                [host.raw_pointer, account.raw_pointer] + [pointer for pointer in (
                    '/realm', '/account_domain', '/user_domain', '/tenant')
                    if isinstance(alert.raw_alert, dict) and alert.raw_alert.get(pointer[1:]) not in (None, '')],
                [host.entity_id, account.entity_id])
        for kind in ('object',):
            for value, pointer in p.observed.get(kind, []):
                # Explicit object handoff remains subject to the existing gate.
                add(2, kind, dict(host=host.entity_id, value=value),
                    [host.raw_pointer, pointer], [host.entity_id],
                    role=pointer.rsplit('/', 1)[-1])

    # Typed recall postings cannot by themselves admit community membership.
    for occurrence in occurrences:
        entity = entities[occurrence.entity_id]
        add(5, 'core_' + entity.type.value.lower(), entity.entity_id, [occurrence.raw_pointer],
            [entity.entity_id], projection='entity')
    for kind, value, pointer in p.weak_contexts:
        add(5, 'context.' + kind, dict(value=value), [pointer], projection='context')

    # Endpoint continuity uses a complete observed tuple AND explicit roles and
    # direction. No private/public classification or vendor-based role guessing.
    network_fields = ('protocol', 'direction', 'source_role', 'destination_role')
    if all(getattr(alert, f) is not None for f in ('src_ip', 'dst_ip', 'src_port', 'dst_port')) and all(p.observed.get(k) for k in network_fields):
        values = {k: p.observed[k][0][0] for k in network_fields}
        pointers = [p.observed[k][0][1] for k in network_fields]
        pointers += [alert.field_provenance[k].raw_pointer for k in ('src_ip', 'dst_ip', 'src_port', 'dst_port', 'source_type')]
        add(5, 'network_roles', dict(scope=settings.network_namespace or alert.source_namespace,
            src_ip=alert.src_ip, dst_ip=alert.dst_ip, src_port=alert.src_port, dst_port=alert.dst_port,
            source_type=alert.source_type.value, sensor=alert.sensor, **values), pointers)
    p.bindings = sorted(set(p.bindings), key=lambda b: (b.level, b.kind, b.key, b.role))
    return p


def context_conflict(left, right):
    return any(left.contexts[s].isdisjoint(right.contexts[s]) for s in left.contexts.keys() & right.contexts.keys())


def shared_context(left, right):
    return any(left.contexts[s] & right.contexts[s] for s in left.contexts.keys() & right.contexts.keys())


def match(left, right, lb, rb, config, common):
    """One evidence tier wins; auxiliary values never accumulate into a score."""
    from .models import MatchingEvidence
    level, kind = lb.level, lb.kind
    if lb.key != rb.key:
        return None, 'IDENTITY_MISMATCH'
    if lb.projection in ('context', 'entity', 'incomplete_binding') and kind != 'core_account':
        return None, 'RECALL_ONLY_' + lb.projection.upper()
    delta = abs(left.seconds-right.seconds)
    tier = evidence_tier(kind)
    if tier == 'A' and delta > config.windows_seconds[str(level)]:
        return None, 'TIER_WINDOW_EXCEEDED'
    if kind == 'direct_reference' and lb.role == rb.role:
        return None, 'REFERENCE_REQUIRES_RECORD_ENDPOINT'
    if kind == 'process_instance' and lb.role == rb.role == 'parent_process':
        return None, 'COMMON_PARENT_IS_NOT_HANDOFF'
    hosts = left.hosts & right.hosts
    accounts = left.accounts & right.accounts
    processes = left.processes & right.processes
    behavior = bool(left.behaviors & right.behaviors)
    if kind == 'process_instance' and not (hosts or behavior):
        return None, 'PROCESS_REQUIRES_HOST_OR_BEHAVIOR'
    if kind == 'object':
        handoff = kind == 'object' and {lb.role, rb.role} == {'response_object_id', 'request_object_id'}
        if not handoff and not shared_context(left, right):
            return None, 'OBJECT_REQUIRES_HANDOFF_OR_BOUND_CONTEXT'
    if tier != 'A':
        if left.hosts and right.hosts and left.hosts.isdisjoint(right.hosts):
            return None, 'DIFFERENT_TARGETS_WITHOUT_BINDING'
        if context_conflict(left, right):
            return None, 'DISTINCT_CONTEXTS_BLOCK_WEAK_MATCH'
        if left.accounts and right.accounts and left.accounts.isdisjoint(right.accounts):
            return None, 'DISTINCT_ACCOUNTS_BLOCK_WEAK_MATCH'
        if kind != 'process_instance' and left.alert.process and right.alert.process:
            a, b = left.alert.process, right.alert.process
            if a.pid is not None and b.pid is not None and a.pid != b.pid:
                return None, 'DISTINCT_PROCESSES_BLOCK_WEAK_MATCH'
            if a.start_time and b.start_time and a.start_time != b.start_time:
                return None, 'REUSED_PID_BLOCKS_WEAK_MATCH'
            if any(getattr(a, name) and getattr(b, name) and getattr(a, name) != getattr(b, name)
                   for name in ('guid', 'instance_id')):
                return None, 'DISTINCT_PROCESS_INSTANCES_BLOCK_WEAK_MATCH'
        if kind == 'host_process' and not (accounts or behavior or shared_context(left, right)):
            return None, 'PROCESS_DESCRIPTOR_REQUIRES_ACCOUNT_OR_CONTEXT'
        if kind == 'host_account':
            if (hosts | accounts) & common and not (processes or behavior or shared_context(left, right)):
                return None, 'HIGH_DEGREE_CONTEXT_REQUIRES_EXTRA_EVIDENCE'
        if kind == 'host':
            if not behavior:
                return None, 'HOST_REQUIRES_SEMANTIC_CONTINUITY'
            if hosts & common and not (processes or accounts):
                return None, 'HIGH_DEGREE_CONTEXT_REQUIRES_EXTRA_EVIDENCE'
            if not (processes or accounts or shared_context(left, right)):
                return None, 'HOST_REQUIRES_INDEPENDENT_CONTEXT'
        if kind == 'core_account':
            if not behavior:
                return None, 'ACCOUNT_REQUIRES_BEHAVIOR'
            if accounts & common and not (hosts or processes):
                return None, 'HIGH_DEGREE_CONTEXT_REQUIRES_EXTRA_EVIDENCE'
            if not (hosts or processes or shared_context(left, right)):
                return None, 'ACCOUNT_REQUIRES_INDEPENDENT_CONTEXT'
        if kind == 'network_ip':
            if not behavior:
                return None, 'NETWORK_REQUIRES_BEHAVIOR'
            if lb.key in common and not (hosts or processes or accounts):
                return None, 'HIGH_DEGREE_IP_REQUIRES_CONTEXT'
            if not (hosts or processes or accounts or shared_context(left, right)):
                return None, 'NETWORK_REQUIRES_INDEPENDENT_CONTEXT'
    refs = [EvidencePointer(alert_id=p.alert.alert_id, pointer=pointer, side='shared')
            for p, binding in ((left, lb), (right, rb)) for pointer in binding.pointers]
    if tier != 'A':
        shared_entities = hosts | accounts | processes
        for p in (left, right):
            refs += [EvidencePointer(alert_id=p.alert.alert_id, pointer=o.raw_pointer, side='shared')
                     for o in p.alert.entity_occurrences if o.entity_id in shared_entities]
            if behavior:
                refs += [EvidencePointer(alert_id=p.alert.alert_id, pointer=pointer, side='shared')
                         for pointer in p.behavior_pointers]
            refs += [EvidencePointer(alert_id=p.alert.alert_id,
                     pointer=p.alert.field_provenance['timestamp'].raw_pointer, side='shared')]
    if kind in ('object', 'host_account', 'host_process'):
        # Preserve the actual independent continuity fields used by the gate.
        for p in (left, right):
            refs += [EvidencePointer(alert_id=p.alert.alert_id, pointer=c.raw_pointer, side='shared') for c in p.alert.contexts]
            refs += [EvidencePointer(alert_id=p.alert.alert_id, pointer=pointer, side='shared')
                     for k in ('service', 'operation') for _, pointer in p.observed.get(k, [])]
    eids = set(lb.entity_ids) | set(rb.entity_ids)
    if tier != 'A':
        eids.update(hosts | accounts | processes)
    if kind == 'host_process':
        common_accounts = left.accounts & right.accounts
        eids.update(common_accounts)
        for p in (left, right):
            refs += [EvidencePointer(alert_id=p.alert.alert_id, pointer=o.raw_pointer, side='shared')
                     for o in p.alert.entity_occurrences if o.entity_id in common_accounts]
    reason = dict(process_instance='PROCESS_INSTANCE_OR_LINEAGE_BINDING', host_process='HOST_PROCESS_BINDING',
                  host_account='HOST_ACCOUNT_CONTINUITY', host='HOST_TIME_CONTINUITY',
                  core_account='ACCOUNT_BEHAVIOR_CONTINUITY', network_ip='IP_BEHAVIOR_TIME',
                  network_roles='NETWORK_ROLE_CONTINUITY').get(kind, kind.upper()+'_BINDING')
    # Independent telemetry certifies identity, not a scenario merge. Promote
    # only current-instance observations corroborating the same explicit
    # command AND object action; a request-less process mention remains bounded
    # context and cannot bridge several otherwise separate regions.
    action_handoff = (kind == 'process_instance' and lb.role == rb.role == 'process'
        and left.alert.source_namespace != right.alert.source_namespace
        and bool(left.alert.command and left.alert.file)
        and left.alert.command == right.alert.command and left.alert.file == right.alert.file)
    if action_handoff:
        refs += [EvidencePointer(alert_id=p.alert.alert_id,pointer=p.alert.field_provenance[field].raw_pointer,side='shared')
                 for p in (left,right) for field in ('command','file')]
    admitted_kind = 'cross_source_process_instance' if action_handoff else kind
    evidence = MatchingEvidence(match_reason=reason, match_level=level,
        alert_ids=sorted([left.alert.alert_id, right.alert.alert_id]), identity_kind=admitted_kind,
        identity_key=lb.key, entity_ids=sorted(eids),
        time_delta_seconds=float(delta), supporting_evidence=refs)
    return evidence, None

"""Same-stage eligibility from existing scoped projections and semantic labels."""
from app.models.alerts import EvidencePointer
from app.models.base import resolve_pointer
import json
from urllib.parse import urlsplit
from .models import AggregationBasis

BINDING_KINDS = {'request', 'flow', 'session', 'connection', 'application_session', 'task',
                 'process_instance', 'object'}
OBSERVATION_BEHAVIORS = frozenset({'EXECUTION', 'FILE_ACTIVITY', 'NETWORK_ACTIVITY', 'UNKNOWN'})


def behavior_conflict(left_behavior, right_behavior):
    # UNKNOWN is an absent application interpretation, not contrary Web intent.
    # Pair admission below still requires a precise HTTP observation proof.
    if {left_behavior, right_behavior} == {'UNKNOWN', 'WEB_EXPLOIT'}:
        return False
    return left_behavior != right_behavior and not {left_behavior, right_behavior} <= OBSERVATION_BEHAVIORS


def http_fact(p, keys):
    """Only adapter-declared native fields; no payload or locator searches."""
    values = []
    for key in keys:
        provenance = p.alert.field_provenance.get(key)
        if provenance:
            value = resolve_pointer(p.alert.raw_alert, provenance.raw_pointer)
            if type(value) in (str, int) and str(value).strip():
                values.append((value, provenance.raw_pointer))
    if not values or len({(type(v), v) for v, _ in values}) != 1:
        return None, ()
    return values[0][0], tuple(pointer for _, pointer in values)


def http_context(left, right):
    if not any(a.kind == 'flow' for a, _ in shared_bindings(left, right)):
        return False
    a, _ = http_fact(left, ('native.method', 'native.http/http_method'))
    b, _ = http_fact(right, ('native.method', 'native.http/http_method'))
    return (type(a) is str and bool(a.strip()) and a == b and bool(left.alert.url and right.alert.url)
            and not (left.alert.domain and right.alert.domain and left.alert.domain != right.alert.domain))


def same_http_transaction(left, right):
    """Corroborated cross-source co-observation, not a shared native ID authority.

    tx_id alone has no cross-source identity. Require the complete tuple, exact
    event time, HTTP method and compatible path/query observations as well.
    """
    if left.alert.source_namespace == right.alert.source_namespace or not http_context(left, right):
        return False
    a, _ = http_fact(left, ('native.tx_id',))
    b, _ = http_fact(right, ('native.tx_id',))
    valid_tx = (type(a) is int and a >= 0) or (type(a) is str and a.isdecimal())
    return (valid_tx and type(a) is type(b) and a == b and left.seconds == right.seconds
            and partial_url(left.alert.url, right.alert.url))


def same_http_activity(left, right):
    """Request IDs distinguish iterations only with a full repeated-action proof."""
    return (left.alert.source_namespace == right.alert.source_namespace and http_context(left, right)
            and bool(left.alert.signature) and left.alert.signature == right.alert.signature
            and bool(left.alert.rule_id) and left.alert.rule_id == right.alert.rule_id
            and left.alert.url == right.alert.url)


def same_process_action(left, right):
    """A command describes process context, not every action in its lifetime.

    Crossing a process/file action into network or request activity additionally
    needs the same explicitly observed object. Missing optional file fields
    remain acceptable between execution and file instrumentation.
    """
    roles = {action_role(left), action_role(right)}
    cross_action = bool(roles & {'network_connection', 'application_request', 'http', 'transport'}) and len(roles) > 1
    return (bool(left.alert.command) and left.alert.command == right.alert.command
            and (not cross_action or bool(left.alert.file and left.alert.file == right.alert.file))
            and any(a.kind == 'process_instance' and a.role == b.role == 'process'
                    for a, b in shared_bindings(left, right)))


def action_role(p):
    """Roles from existing adapter observations, independent of source names."""
    operation = ''.join(c for c in (p.alert.alert_type or '').lower() if c.isalnum())
    if operation in {'processstart', 'commandexecution'}:
        return 'execution'
    if operation.startswith('file'):
        return 'file'
    if operation in {'networkconnection', 'applicationrequest'}:
        return {'networkconnection': 'network_connection', 'applicationrequest': 'application_request'}[operation]
    method, _ = http_fact(p, ('native.method', 'native.http/http_method'))
    if method and p.alert.url:
        return 'http'
    if any(b.kind == 'flow' and b.complete for b in p.bindings) and not operation:
        return 'transport'
    return operation or 'unspecified'


def action_conflict(left, right):
    """An observed role boundary cannot be bridged by identity-only records."""
    roles = {action_role(left), action_role(right)}
    if len(roles) < 2 or 'unspecified' in roles:
        return None
    # Transport instrumentation can corroborate an application/network action;
    # its temporal eligibility is still evaluated in that action's own context.
    if roles <= {'transport', 'http', 'network_connection'}:
        return None
    if same_process_action(left, right):
        return None
    if roles == {'execution', 'file'}:
        return None  # Cross-label admission still requires the process action.
    if roles & {'execution', 'file', 'network_connection', 'application_request', 'http'}:
        # A request sensor and application instrumentation need observed HTTP
        # content, not just the same worker and request identifier.
        if http_context(left, right) and partial_url(left.alert.url, right.alert.url):
            return None
        return 'distinct_action_roles_without_action_proof'
    return None


def partial_url(left, right):
    if not left or not right:
        return False
    try:
        a, b = urlsplit(left), urlsplit(right)
    except ValueError:
        return left == right  # Malformed observations cannot justify equivalence.
    return ((a.scheme, a.netloc, a.path, a.fragment) == (b.scheme, b.netloc, b.path, b.fragment)
            and (a.query == b.query or not a.query or not b.query))


def flow_observation_fields(left, right):
    """Positive application corroboration over a complete scoped flow."""
    if not any(a.kind == 'flow' for a, _ in shared_bindings(left, right)):
        return ()
    if left.alert.signature and left.alert.signature == right.alert.signature:
        return ('signature',)
    if partial_url(left.alert.url, right.alert.url):
        return ('url',)
    return ()


def compatible_url_observations(left, right):
    if not any(a.kind == 'flow' for a, _ in shared_bindings(left, right)):
        return False
    if partial_url(left.alert.url, right.alert.url):
        return True
    # Multiple URLs describe a series only without authoritative request IDs.
    # A single identified request with disagreeing paths remains a conflict.
    return (left.alert.signature and left.alert.signature == right.alert.signature
            and not any(b.kind == 'request' and b.complete for p in (left, right) for b in p.bindings))


def generic_network_observation(left, right, lb, rb):
    if {lb, rb} != {'UNKNOWN', 'NETWORK_ACTIVITY'}:
        return False
    generic = left if lb == 'NETWORK_ACTIVITY' else right
    # A policy/transport observation has no application action to contradict.
    return (not any((generic.alert.url, generic.alert.command, generic.alert.file))
            and any(a.kind == 'flow' for a, _ in shared_bindings(left, right)))


def temporal_check(left, right, lb, rb, temporal, stage_config=None):
    delta = abs(left.seconds - right.seconds)
    threshold = temporal['dynamic_threshold_seconds']
    check = dict(temporal, delta_seconds=delta, policy='bound_action_cadence')
    if stage_config is not None and (same_process_action(left, right) or flow_observation_fields(left, right)
                                    or generic_network_observation(left, right, lb, rb)):
        threshold = max(threshold, stage_config.max_stage_span_seconds)
        check.update(policy='bound_action_horizon', action_horizon_seconds=stage_config.max_stage_span_seconds)
    check.update(effective_threshold_seconds=threshold, passed=delta <= threshold)
    return check


def shared_bindings(left, right):
    matches = []
    for a in left.bindings:
        if a.projection != 'binding' or not a.complete or a.kind not in BINDING_KINDS:
            continue
        for b in right.bindings:
            if (a.kind, a.key, a.projection) != (b.kind, b.key, b.projection) or not b.complete:
                continue
            if a.kind == 'process_instance' and a.role == b.role == 'parent_process':
                continue
            matches.append((a, b))
    return matches


def hard_conflict(left, right):
    matches = shared_bindings(left, right)
    lineage = any(a.kind == 'process_instance' and {a.role, b.role} == {'process', 'parent_process'}
                  for a, b in matches)
    for name, a, b in (('host', left.hosts, right.hosts), ('account', left.accounts, right.accounts)):
        if a and b and a.isdisjoint(b):
            return 'distinct_' + name + '_context'
    a, b = left.alert.process, right.alert.process
    if a and b and not lineage:
        for field in ('pid', 'start_time', 'guid', 'instance_id'):
            x, y = getattr(a, field), getattr(b, field)
            if x is not None and y is not None and x != y:
                return 'distinct_process_' + field
    for field in ('command', 'file'):
        x, y = getattr(left.alert, field), getattr(right.alert, field)
        if x and y and x != y:
            return 'distinct_observed_' + field
    x, y = left.alert.url, right.alert.url
    if x and y and x != y and not compatible_url_observations(left, right):
        return 'distinct_observed_url'
    for scope in left.contexts.keys() & right.contexts.keys():
        if left.contexts[scope].isdisjoint(right.contexts[scope]):
            if json.loads(scope)['subtype'] == 'request' and same_http_activity(left, right):
                continue
            return 'distinct_strong_context'
    flows = [{b.key for b in p.bindings if b.kind == 'flow' and b.complete} for p in (left, right)]
    if all(flows) and flows[0].isdisjoint(flows[1]):
        return 'distinct_complete_flow'
    return None


def pair_evidence(left, right, left_behavior, right_behavior, temporal, stage_config=None):
    process_action = same_process_action(left, right)
    network_observation = generic_network_observation(left, right, left_behavior, right_behavior)
    http_transaction = same_http_transaction(left, right)
    http_activity = left_behavior == right_behavior and same_http_activity(left, right)
    if behavior_conflict(left_behavior, right_behavior):
        return None, 'semantic_conflict'
    generic_compatible = ({left_behavior, right_behavior} <= OBSERVATION_BEHAVIORS
                          and (process_action or network_observation))
    http_compatible = (http_transaction and 'UNKNOWN' in {left_behavior, right_behavior}
                       and {left_behavior, right_behavior} <= {'UNKNOWN', 'WEB_EXPLOIT', 'NETWORK_ACTIVITY'})
    if left_behavior != right_behavior and not (generic_compatible or http_compatible):
        return None, 'insufficient_semantic_context'
    conflict = hard_conflict(left, right)
    if conflict:
        return None, conflict
    conflict = action_conflict(left, right)
    if conflict:
        return None, conflict
    fields = ('command', 'file') if process_action else flow_observation_fields(left, right)
    # Cadence of unrelated/duplicate observations is not an action lifetime.
    # Reuse the existing configured horizon only with identity + action proof.
    check = temporal_check(left, right, left_behavior, right_behavior, temporal, stage_config)
    if not check['passed']:
        return None, 'dynamic_time_conflict'
    matches = shared_bindings(left, right)
    shared_entities = left.hosts & right.hosts | left.accounts & right.accounts
    if matches:
        selected = matches
        strength = 'STRONG'
        rule = ('consistent_core_context' if all(a.kind == 'process_instance' for a, _ in matches)
                else 'shared_strong_binding')
    else:
        if left_behavior == 'UNKNOWN':
            return None, 'unknown_requires_typed_binding'
        # Two independent entity contexts, never host/IP/time alone. PID-only
        # descriptors remain weak; they are not promoted to process instances.
        selected = [(a, b) for a in left.bindings for b in right.bindings
                    if a.kind in {'host_account', 'host_process'} and
                    (a.kind, a.key) == (b.kind, b.key)]
        if not selected:
            return None, 'insufficient_context'
        strength = 'NORMAL' if any(a.kind == 'host_account' for a, _ in selected) else 'WEAK'
        rule = 'consistent_core_context'
    refs = [EvidencePointer(alert_id=p.alert.alert_id, pointer=pointer, side='shared')
            for a, b in selected for p, binding in ((left, a), (right, b))
            for pointer in binding.pointers]
    refs += [EvidencePointer(alert_id=p.alert.alert_id,
                pointer=p.alert.field_provenance[field].raw_pointer, side='shared')
             for p in (left, right) for field in fields
             if field in p.alert.field_provenance]
    # Record the observed roles as well as identity, including method-only HTTP
    # sensors whose canonical alert_type is absent.
    refs += [EvidencePointer(alert_id=p.alert.alert_id,
                pointer=p.alert.field_provenance[field].raw_pointer, side='shared')
             for p in (left, right) for field in ('alert_type', 'native.operation', 'native.method', 'native.http/http_method')
             if field in p.alert.field_provenance]
    http_types = (['http_transaction'] if http_transaction else []) + (['http_activity'] if http_activity else [])
    if http_types:
        for p in (left, right):
            pointers = set()
            for keys in (('native.method', 'native.http/http_method'), ('native.query',)):
                _, observed = http_fact(p, keys)
                pointers.update(observed)
            if http_transaction:
                _, observed = http_fact(p, ('native.tx_id',))
                pointers.update(observed)
            for field in ('url', 'signature', 'rule_id', 'domain'):
                if field in p.alert.field_provenance:
                    pointers.add(p.alert.field_provenance[field].raw_pointer)
            refs += [EvidencePointer(alert_id=p.alert.alert_id, pointer=pointer, side='shared') for pointer in sorted(pointers)]
    return AggregationBasis(alert_ids=sorted([left.alert.alert_id, right.alert.alert_id]),
        rule=rule, shared_keys=sorted({a.key for a, _ in selected}), evidence=refs,
        edge_strength=strength, behavior_compatible=True,
        evidence_types=sorted({a.kind for a, _ in selected} | set(http_types)),
        binding_evidence=sorted({a.key for a, _ in matches}),
        entity_evidence=sorted(shared_entities | {eid for a, b in selected for x in (a, b) for eid in x.entity_ids}),
        temporal_check=check), None

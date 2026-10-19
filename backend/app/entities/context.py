"""Bounded source projections and scoped context identities. No inference."""
from app.models.alerts import ContextCandidate, ContextRef
from app.models.base import resolve_pointer
from app.utils.stable_id import canonical_json, content_digest
from .normalization import text

KINDS = ('request', 'flow', 'session', 'task')


def clean(value):
    value = text(value)
    return value.strip() or None if value is not None else None


def observed(raw, *paths):
    for path in paths:
        try:
            value = resolve_pointer(raw, path)
        except ValueError:
            continue
        if value not in (None, ''):
            return value, path
    return None, None


def project_candidates(raw, settings):
    """Only declared ID fields; URL/rule/signature/tx_id never synthesize IDs."""
    if settings.format_profile == 'multisource_native_v1':
        paths = dict(request=['/request_id', '/trace_id', '/transaction_id', '/correlation_id'], flow=['/flow_id'],
                     session=['/session_id', '/auth_session_id', '/connection_id', '/logon_id', '/application_session_id', '/session'],
                     task=['/task_id', '/job_id', '/operation_id', '/execution_id'])
    elif settings.format_profile == 'suricata_eve_v1':
        paths = dict(flow=['/flow_id'])
    elif settings.format_profile == 'wazuh_json_v1':
        paths = dict(request=['/data/request_id', '/data/trace_id', '/data/transaction_id', '/data/correlation_id'], flow=['/data/flow_id'],
                     session=['/data/session', '/data/audit/session', '/data/session_id', '/data/auth_session_id', '/data/connection_id'],
                     task=['/data/task_id', '/data/job_id', '/data/operation_id', '/data/execution_id'])
    else:
        paths = {}  # No undocumented AMiner ID field assumptions.
    result = []
    for kind, pointers in paths.items():
        for pointer in pointers:
            value, _ = observed(raw, pointer)
            value = clean(value)
            if value is not None:
                result.append(ContextCandidate(kind=kind, value=value, raw_pointer=pointer))
    return sorted(result, key=lambda c: (c.kind, c.value, c.raw_pointer))


def context_refs(alert, settings, host_scope):
    refs = []
    for candidate in alert.context_candidates:
        # Do not merge distinct products' short IDs merely because host/IP matches.
        # Cross-source context sharing requires an explicit shared session scope.
        base = settings.session_scope or alert.source_namespace
        scope = canonical_json(dict(namespace=base,
                                    host_scope=host_scope if not settings.session_scope else None,
                                    identity_field=candidate.raw_pointer.rsplit('/', 1)[-1],
                                    kind=candidate.kind))
        refs.append(ContextRef(**candidate.model_dump(), scope=scope))
    return sorted(refs, key=lambda c: (c.kind, c.scope, c.value, c.raw_pointer))


def context_key(ref):
    return ref.kind + ':' + content_digest(dict(kind=ref.kind, scope=ref.scope, value=ref.value))


def weak_observations(alert, settings):
    """Typed scalar context and exact raw witnesses, never entity identities.

    Explicit format paths only. Different endpoint roles retain different keys.
    The source field, raw value and normalized value can be recovered/exported
    together with alert_id and source without extending CanonicalAlert.
    """
    result = set()
    for name in ('src_ip', 'dst_ip', 'src_port', 'dst_port', 'url', 'domain',
                 'file', 'command', 'rule_id', 'signature', 'severity', 'alert_type'):
        value = getattr(alert, name)
        provenance = alert.field_provenance.get(name)
        # A root mapping pointer is not an observed scalar severity/category.
        if value is not None and provenance and provenance.raw_pointer:
            result.add((name, str(value.value if hasattr(value, 'value') else value), provenance.raw_pointer))
    if settings.format_profile == 'multisource_native_v1':
        paths = dict(protocol=['/protocol', '/proto'], http_method=['/method', '/http/http_method'],
                     user_agent=['/user_agent', '/http/http_user_agent'], path=['/path', '/file_path', '/uri'],
                     domain=['/domain', '/http/hostname'], filename=['/filename'], file_hash=['/file_hash'],
                     registry_path=['/registry_path'], rule_id=['/rule_id', '/alert/signature_id'],
                     signature=['/signature', '/rule_name', '/alert/signature'], severity=['/severity', '/alert/severity'],
                     event_type=['/event_type', '/audit_type'], detector=['/detector'])
    elif settings.format_profile == 'suricata_eve_v1':
        paths = dict(protocol=['/proto'], http_method=['/http/http_method'], user_agent=['/http/http_user_agent'],
                     severity=['/alert/severity'], event_type=['/event_type'], detector=['/alert/signature'])
    elif settings.format_profile == 'wazuh_json_v1':
        paths = dict(protocol=['/data/protocol'], http_method=['/data/http_method'],
                     user_agent=['/data/user_agent'], filename=['/data/filename'], file_hash=['/data/file_hash'],
                     registry_path=['/data/registry_path'], severity=['/rule/level'], detector=['/decoder/name'])
    else:
        paths = {}
    for kind, pointers in paths.items():
        for pointer in pointers:
            value, _ = observed(alert.raw_alert, pointer)
            value = clean(value)
            if value is not None:
                if kind == 'protocol':
                    value = value.lower()
                result.add((kind, value, pointer))
    return sorted(result)

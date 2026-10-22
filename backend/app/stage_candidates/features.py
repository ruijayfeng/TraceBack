"""Project existing typed facts once per member; never compare Stage pairs."""
from collections import defaultdict
import json

from app.community.evidence import profile
from app.models.alerts import EvidencePointer
from app.utils.stable_id import canonical_json, content_digest
from .models import FeatureWitness, StageCandidateFeature

STRONG = 'STRONG_RETRIEVAL_HINT'
NORMAL = 'NORMAL_RETRIEVAL_HINT'
WEAK = 'WEAK_RETRIEVAL_HINT'


def extract_stage_candidate_features(stages, alerts, entities, settings, community_config, policy):
    result = []
    for stage in sorted(stages, key=lambda s:s.stage_id):
        features = {}

        def add(kind, identity, aid, pointers, role='observed', hint=STRONG, mode='DIRECT', context_scope=None):
            if kind not in policy.enabled_feature_kinds or not pointers:
                return
            key = kind + ':' + content_digest(identity)
            item = features.setdefault(key, dict(kind=kind, identity=identity, hint=hint, mode=mode, witnesses={}))
            refs = [EvidencePointer(alert_id=aid, pointer=p, side='shared') for p in sorted(set(pointers))]
            for ref in refs:
                ref.resolve(alerts)
            witness = FeatureWitness(alert_id=aid, source_namespace=alerts[aid].source_namespace,
                context_scope=context_scope, role=role, pointers=refs)
            item['witnesses'][canonical_json(witness.model_dump(mode='json'))] = witness

        for aid in sorted(stage.alert_ids):
            alert = alerts[aid]
            source = settings[alert.source_namespace]
            p = profile(alert, entities, source, community_config)
            for binding in p.bindings:
                if binding.projection != 'binding' or not binding.complete:
                    continue
                if binding.kind in {'request', 'session', 'connection', 'application_session', 'task', 'object',
                                    'process_instance', 'direct_reference', 'host_account'}:
                    # Profiles already encode typed scopes and observed identity.
                    identity = json.loads(binding.identity)
                    add(binding.kind, identity if isinstance(identity, dict) else dict(components=identity), aid, binding.pointers,
                        binding.role or 'observed', NORMAL if binding.kind in {'object', 'host_account'} else STRONG)
                elif binding.kind == 'flow':
                    # The profile's tuple lacks a source fallback scope. Supply
                    # the existing network/source scope, never a global scope.
                    add('network_tuple', dict(scope=source.network_namespace or alert.source_namespace,
                        tuple=json.loads(binding.identity)), aid, binding.pointers)
            for ref in alert.contexts:
                if ref.kind == 'flow':
                    add('native_flow', dict(scope=ref.scope, value=ref.value), aid, [ref.raw_pointer], context_scope=ref.scope)
                # Host-local login IDs are useful across telemetry sources. This
                # compound retrieval key does not merge upstream ContextRefs.
                if ref.kind == 'session' and ref.raw_pointer.rsplit('/',1)[-1] in {'logon_id','auth_session_id'}:
                    for host in alert.entity_occurrences:
                        if host.role.value == 'host':
                            add('host_auth_session', dict(host_entity=host.entity_id, identity_kind='auth_session', value=ref.value),
                                aid, [host.raw_pointer,ref.raw_pointer], hint=NORMAL, context_scope=ref.scope)
            # Keep both observed hostname and the entity identity. A native
            # record can carry hostname plus asset_id; lexical hostname+object
            # is a separate retrieval hint, not a replacement entity binding.
            if alert.host and 'host' in alert.field_provenance:
                for value, pointer in p.observed.get('object', []):
                    add('object_at_observed_host', dict(asset_scope=source.asset_namespace,
                        hostname=alert.host, object=value), aid,
                        [alert.field_provenance['host'].raw_pointer,pointer], hint=NORMAL)

            observed = defaultdict(list)
            for occurrence in alert.entity_occurrences:
                entity = entities[occurrence.entity_id]
                kind = entity.type.value.lower()
                observed[kind].append((entity.entity_id, occurrence.raw_pointer))
                if kind == 'host':
                    add('host', dict(entity_id=entity.entity_id), aid, [occurrence.raw_pointer], hint=WEAK, mode='SELECTIVE_WEAK')
                elif kind in {'url', 'command'}:
                    add(kind, dict(entity_id=entity.entity_id), aid, [occurrence.raw_pointer], hint=WEAK, mode='CONTEXT_ONLY')
                elif kind in {'file', 'session'}:
                    add('session_entity' if kind == 'session' else kind, dict(entity_id=entity.entity_id),
                        aid, [occurrence.raw_pointer], hint=NORMAL)
            # Current front-data-v1 deliberately retains URL/command as context,
            # not entities. Preserve their observed target/host scope here.
            for kind in ('url', 'command'):
                value, provenance = getattr(alert, kind), alert.field_provenance.get(kind)
                if value is not None and provenance and not observed[kind]:
                    if kind == 'url':
                        scope = dict(domain=alert.domain) if alert.domain else dict(source=alert.source_namespace)
                    else:
                        scope = dict(hosts=sorted(p.hosts)) if p.hosts else dict(source=alert.source_namespace)
                    key = canonical_json(dict(scope=scope, value=value))
                    observed[kind].append((key, provenance.raw_pointer))
                    add(kind, dict(context=key), aid, [provenance.raw_pointer], hint=WEAK, mode='CONTEXT_ONLY')
            for host, hp in observed['host']:
                # Exact observed paths can be a file/object retrieval clue even
                # when ② deliberately leaves FILE as context. No create/execute
                # operation roles or propagation direction are evaluated here.
                paths = [(alert.file, alert.field_provenance.get('file'))]
                if alert.process:
                    paths.append((alert.process.executable, alert.field_provenance.get('process.executable')))
                for path, provenance in paths:
                    if path is not None and provenance:
                        add('file_at_host', dict(host_entity=host, path=path),aid,[hp,provenance.raw_pointer],hint=NORMAL)
                for kind in ('url', 'command'):
                    for value, pointer in observed[kind]:
                        add('host_' + kind, dict(host=host, context=value), aid, [hp, pointer], hint=NORMAL, mode='COMPOUND')

            network_scope = source.network_namespace or alert.source_namespace
            endpoints = []
            for name in ('src_ip', 'dst_ip'):
                value, provenance = getattr(alert, name), alert.field_provenance.get(name)
                if value is not None and provenance:
                    endpoints.append((value, provenance.raw_pointer))
                    add('endpoint', dict(scope=network_scope, value=value), aid,
                        [provenance.raw_pointer], role=name, hint=WEAK, mode='CONTEXT_ONLY')
            if len(endpoints) == 2:
                pair = dict(scope=network_scope, endpoints=sorted({value for value, _ in endpoints}))
                refs = [pointer for _, pointer in endpoints]
                add('endpoint_pair', pair, aid, refs, hint=WEAK, mode='SELECTIVE_WEAK')
                # A connection token alone is source-local. Together with both
                # observed endpoints it can nominate a cross-source candidate.
                # Null scope is retained as unknown, never certified as a
                # shared network. Explicit incompatible scopes cannot match.
                for ref in alert.contexts:
                    if ref.kind == 'session' and ref.raw_pointer.rsplit('/',1)[-1] == 'connection_id':
                        add('connection_endpoints_hint', dict(declared_network_scope=source.network_namespace,
                            endpoints=pair['endpoints'], identity_kind='connection', value=ref.value),
                            aid,[*refs,ref.raw_pointer],hint=NORMAL,mode='COMPOUND',context_scope=ref.scope)
                for value, pointer in observed['url']:
                    add('url_endpoint_pair', dict(network=pair, url=value), aid,
                        [*refs, pointer], hint=NORMAL, mode='COMPOUND')
        for key, f in sorted(features.items()):
            result.append(StageCandidateFeature(stage_id=stage.stage_id, key=key, kind=f['kind'],
                identity=f['identity'], retrieval_hint=f['hint'], mode=f['mode'],
                witnesses=[f['witnesses'][k] for k in sorted(f['witnesses'])]))
    return result

"""Threshold evidence graph inside each existing Community partition."""
from collections import Counter, defaultdict

from app.community.evidence import profile
from app.community.index import CommunityIndex
from app.community.models import IncidentCandidate
from app.community.temporal import TemporalHistory
from app.models.alerts import EvidencePointer
from app.utils.stable_id import canonical_json, content_digest
from .evidence import hard_conflict, pair_evidence, behavior_conflict, temporal_check, action_role, action_conflict, http_fact
from .graph import connected_components, weak_bridge_check
from .models import Stage, StageResult, stage_id

BINDING_FAMILY = dict(request='request', flow='flow', session='session',
                      connection='session', application_session='session', task='task')
STAGE_BUILDER_VERSION = 'threshold-graph-v5-action-scoped-cadence'


def cadence_scopes(p, behavior):
    """One history per bound action; a Community is only a recall partition.

    Use the most specific binding shared by a candidate pair. Native operation
    and observed action descriptors prevent unrelated activity on that binding
    from training its cadence. No source names or benchmark labels participate.
    """
    method, _ = http_fact(p, ('native.method', 'native.http/http_method'))
    descriptor = (behavior, action_role(p), p.alert.alert_type, p.alert.command,
                  p.alert.file if not p.alert.command else None,
                  p.alert.signature, p.alert.rule_id, method)
    return {b.key: (*descriptor, b.kind, b.key) for b in p.bindings
            if b.complete and b.projection == 'binding' and b.role != 'parent_process'}


def pair_cadence(left, right, snapshots, config):
    later = max((left, right), key=lambda p: (p.seconds, p.alert.alert_id))
    shared = {a.key: a.kind for a in left.bindings for b in right.bindings
              if a.key == b.key and a.complete and b.complete
              and a.projection == b.projection == 'binding'
              and a.role != 'parent_process' and b.role != 'parent_process'}
    priority = {kind: i for i, kind in enumerate(('request', 'task', 'object', 'process_instance',
                'connection', 'application_session', 'flow', 'session', 'host_account', 'host_process'))}
    if not shared:
        return dict(TemporalHistory().snapshot(config.temporal), cadence_scope='unbound')
    key = min(shared, key=lambda key: (priority.get(shared[key], len(priority)), key))
    return dict(snapshots[later.alert.alert_id][key], cadence_scope=key,
                cadence_role=action_role(later))


def strong_bindings(p):
    return [b for b in p.bindings if b.kind in BINDING_FAMILY and b.projection == 'binding' and b.complete]


def community_graph(ids, profiles, annotations, config, stage_config=None):
    """Reuse typed postings for recall, then evaluate each candidate pair once.

    Cadence uses prior observations of the bound action. The later endpoint
    never trains the threshold for its own gap.
    """
    index, histories, edges, diagnostics = CommunityIndex(config), defaultdict(TemporalHistory), [], []
    counts = Counter()
    temporal_by_alert = {}
    for aid in sorted(ids, key=lambda i: (profiles[i].seconds, i)):
        p, behavior = profiles[aid], annotations[aid].behavior
        scopes = cadence_scopes(p, behavior)
        temporal_by_alert[aid] = {key: histories[scope].snapshot(config.temporal) for key, scope in scopes.items()}
        neighbors = sorted({row[1].alert.alert_id for row in index.query(p)})
        for other in neighbors:
            temporal = pair_cadence(p, profiles[other], temporal_by_alert, config)
            counts['STAGE_CANDIDATE_PAIR_COUNT'] += 1
            edge, reason = pair_evidence(p, profiles[other], behavior, annotations[other].behavior, temporal, stage_config)
            if edge is None:
                diagnostics.append(dict(alert_ids=sorted([aid, other]), decision='keep_separate', reason=reason,
                    temporal_check=temporal_check(p, profiles[other], behavior,
                        annotations[other].behavior, temporal, stage_config)))
                if reason not in {'insufficient_context', 'insufficient_semantic_context', 'unknown_requires_typed_binding'}:
                    counts['HARD_CONFLICT_REJECT_COUNT'] += 1
            else:
                data = edge.model_dump()
                data['evidence'] += [r.model_dump() for i in edge.alert_ids for r in annotations[i].evidence]
                data['evidence'] += [EvidencePointer(alert_id=i, side='shared',
                    pointer=profiles[i].alert.field_provenance['timestamp'].raw_pointer).model_dump()
                    for i in edge.alert_ids]
                edges.append(type(edge).model_validate(data))
        index.add(p)
        for scope in set(scopes.values()):
            histories[scope].times.append(p.seconds)
    counts['STAGE_INDEX_PRUNED_COUNT'] = index.policy_pruned
    # Strongest edges first. Reject edges that would transmit an already
    # observable hard conflict through an endpoint with missing fields.
    owners = {i: i for i in ids}
    members = {i: {i} for i in ids}
    kept = []
    def specificity(edge):
        return (0 if 'http_transaction' in edge.evidence_types else
                1 if 'http_activity' in edge.evidence_types else 2)

    # Preserve precise observations before coarse flow-series proofs can consume
    # their endpoints. All component conflicts still apply at every union.
    for edge in sorted(edges, key=lambda e: ({'STRONG': 0, 'NORMAL': 1, 'WEAK': 2}[e.edge_strength], specificity(e), e.alert_ids)):
        a, b = (owners[i] for i in edge.alert_ids)
        conflict = None
        if a != b:
            for x in sorted(members[a]):
                for y in sorted(members[b]):
                    reason = ('semantic_conflict' if behavior_conflict(annotations[x].behavior, annotations[y].behavior)
                              else hard_conflict(profiles[x], profiles[y]) or action_conflict(profiles[x], profiles[y]))
                    if reason:
                        conflict = dict(conflicting_alert_ids=sorted([x, y]), conflict_reason=reason)
                        break
                if conflict:
                    break
        if conflict:
            counts['HARD_CONFLICT_REJECT_COUNT'] += 1
            counts['COMPONENT_CONFLICT_REJECT_COUNT'] += 1
            diagnostics.append(dict(alert_ids=edge.alert_ids, decision='keep_separate',
                reason='component_hard_conflict', **conflict))
            continue
        kept.append(edge)
        if a != b:
            root, removed = sorted([a, b])
            members[root].update(members.pop(removed))
            for node in members[root]:
                owners[node] = root
    def pair_support(a, b):
        evidence, reason = pair_evidence(profiles[a], profiles[b], annotations[a].behavior,
            annotations[b].behavior, pair_cadence(profiles[a], profiles[b], temporal_by_alert, config), stage_config)
        return evidence is not None, reason

    checks = []
    kept, bridges, removed = weak_bridge_check(ids, kept, pair_support=pair_support, checks=checks)
    counts['BRIDGE_EDGE_COUNT'] = len(bridges)
    counts['WEAK_BRIDGE_REMOVED_COUNT'] = len(removed)
    for edge, check in zip(removed, checks):
        diagnostics.append(dict(alert_ids=edge.alert_ids, decision='remove_weak_bridge',
            reason='weak_bridge_without_component_consistency', component_check=check,
            edge=edge.model_dump(mode='json')))
    return sorted(kept, key=lambda e: e.alert_ids), diagnostics, counts


def aggregate_stages(run, source_settings, community_config, config, resolver=None):
    # Input adaptation only: Stage never computes or resolves alert semantics.
    if resolver is not None:
        raise ValueError('semantic_resolver_must_run_before_community')
    if run.behaviors is None or run.behavior_config_hash != config.digest:
        raise ValueError('precommunity_behavior_annotations_required')
    alerts = {a.alert_id: a for a in run.alerts}
    entities = {e.entity_id: e for e in run.entities}
    if len(alerts) != len(run.alerts) or len(entities) != len(run.entities):
        raise ValueError('stage_input_requires_unique_ids')
    communities = sorted(run.result.incident_candidates, key=lambda c: c.community_id)
    members = [aid for c in communities for aid in c.alert_ids]
    if sorted(members) != sorted(alerts):
        raise ValueError('community_partition_must_cover_input_exactly_once')
    precomputed = {b.alert_id: b for b in run.behaviors}
    if len(precomputed) != len(run.behaviors) or set(precomputed) != set(alerts):
        raise ValueError('precommunity_behavior_partition_mismatch')
    for c in communities:
        IncidentCandidate.model_validate(c, context=dict(alerts=alerts))
    context = dict(alerts=alerts, entities=entities, communities={c.community_id: c for c in communities})
    profiles = {aid: profile(a, entities, source_settings[a.source_namespace], community_config) for aid, a in alerts.items()}
    behaviors, stages, diagnostics, graph_counts = [], [], [], Counter()
    for community in communities:
        annotations = {aid: precomputed[aid].model_copy(update=dict(community_id=community.community_id))
                       for aid in sorted(community.alert_ids)}
        for annotation in annotations.values():
            type(annotation).model_validate(annotation, context=context)
        behaviors.extend(annotations.values())
        edges, decisions, counts = community_graph(community.alert_ids, profiles, annotations, community_config, config)
        diagnostics.extend(dict(community_id=community.community_id, **d) for d in decisions)
        graph_counts.update(counts)
        graph_counts['STAGE_GRAPH_EDGE_COUNT'] += len(edges)
        graph_counts.update(e.edge_strength + '_STAGE_EDGE_COUNT' for e in edges)
        for group in connected_components(community.alert_ids, edges):
            pp, group_set = [profiles[aid] for aid in group], set(group)
            # Preserve ④'s per-alert annotations. A stable representative names
            # compatible observations of the same proved action, not a new label.
            labels = {annotations[i].behavior for i in group}
            priority = {'EXECUTION': 0, 'FILE_ACTIVITY': 1, 'NETWORK_ACTIVITY': 2, 'UNKNOWN': 3}
            behavior = min(labels, key=lambda label: (priority.get(label, -1), label))
            bindings = {family: sorted({b.key for p in pp for b in strong_bindings(p) if BINDING_FAMILY[b.kind] == family})
                        for family in ('request', 'flow', 'session', 'task')}
            stages.append(Stage.model_validate(dict(stage_id=stage_id(community.community_id, behavior, group),
                community_id=community.community_id, behavior=behavior,
                start_time=min(alerts[i].timestamp for i in group), end_time=max(alerts[i].timestamp for i in group),
                alert_ids=sorted(group), alert_count=len(group),
                source_types=sorted({alerts[i].source_type.value for i in group}),
                host_entities=sorted({eid for p in pp for eid in p.hosts}),
                account_entities=sorted({eid for p in pp for eid in p.accounts}),
                process_entities=sorted({o.entity_id for p in pp for o in p.alert.entity_occurrences if entities[o.entity_id].type.value == 'PROCESS'}),
                **{family + '_bindings': values for family, values in bindings.items()},
                evidence_summary=f'{len(group)} observed alerts; normalized behavior {behavior}; undirected connected membership proof retained.',
                aggregation_basis=[e for e in edges if set(e.alert_ids) <= group_set]), context=context))
    stats = dict(BEHAVIOR_TOTAL=len(behaviors), MAPPING_RESOLVED=sum(b.resolver == 'mapping' for b in behaviors),
        AI_RESOLVED=sum(b.resolver == 'ai' and b.behavior != 'UNKNOWN' for b in behaviors),
        AI_ATTEMPTED=sum(b.resolver == 'ai' or 'semantic_' in b.reason for b in behaviors),
        UNKNOWN_BEHAVIORS=sum(b.behavior == 'UNKNOWN' for b in behaviors),
        UNKNOWN_ALERT_COUNT=sum(b.behavior == 'UNKNOWN' for b in behaviors),
        UNKNOWN_SINGLETON_COUNT=sum(s.behavior == 'UNKNOWN' and s.alert_count == 1 for s in stages),
        BEHAVIOR_DISTRIBUTION=dict(sorted(Counter(b.behavior for b in behaviors).items())),
        STAGE_COUNT=len(stages), STAGES_PER_COMMUNITY=dict(sorted(Counter(s.community_id for s in stages).items())),
        STAGE_SIZE_DISTRIBUTION={str(k): v for k, v in sorted(Counter(s.alert_count for s in stages).items())},
        SINGLE_ALERT_STAGES=sum(s.alert_count == 1 for s in stages), SINGLETON_STAGE_COUNT=sum(s.alert_count == 1 for s in stages),
        MAX_STAGE_SIZE=max((s.alert_count for s in stages), default=0), UNKNOWN_STAGES=sum(s.behavior == 'UNKNOWN' for s in stages),
        CROSS_COMMUNITY_STAGE_MERGES=0, STAGE_GRAPH_NODE_COUNT=len(alerts),
        **{key: graph_counts[key] for key in ('STAGE_GRAPH_EDGE_COUNT', 'STRONG_STAGE_EDGE_COUNT', 'NORMAL_STAGE_EDGE_COUNT',
            'WEAK_STAGE_EDGE_COUNT', 'BRIDGE_EDGE_COUNT', 'WEAK_BRIDGE_REMOVED_COUNT', 'HARD_CONFLICT_REJECT_COUNT',
            'COMPONENT_CONFLICT_REJECT_COUNT', 'STAGE_CANDIDATE_PAIR_COUNT', 'STAGE_INDEX_PRUNED_COUNT')},
        STAGE_BUILDER_OPTIMIZED=True, STAGE_GRAPH_IMPLEMENTED=True, CONNECTED_COMPONENTS_IMPLEMENTED=True,
        WEAK_BRIDGE_CHECK_IMPLEMENTED=True, HARD_CONFLICT_CHECK_IMPLEMENTED=True, DYNAMIC_TIME_CONSTRAINT_REUSED=True,
        CURRENT_PIPELINE_STAGE='STAGE_BUILDER_OPTIMIZED', NEXT_STAGE_NOT_STARTED=True)
    return StageResult(config_hash=content_digest(dict(behavior=config.digest, community=community_config.digest,
        stage_builder=STAGE_BUILDER_VERSION)), behaviors=sorted(behaviors, key=lambda b: b.alert_id),
        stages=sorted(stages, key=lambda s: s.stage_id), diagnostics=sorted(diagnostics, key=canonical_json), statistics=stats)

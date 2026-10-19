"""Deterministic complete-link grouping inside an existing Community partition."""
from collections import Counter
from app.community.evidence import profile
from app.community.models import IncidentCandidate
from app.models.alerts import EvidencePointer
from app.utils.stable_id import canonical_json
from .behavior import normalize_behavior
from .models import AggregationBasis, Stage, StageResult, stage_id

BINDING_FAMILY = dict(request='request', flow='flow', session='session',
                      connection='session', application_session='session', task='task')


def strong_bindings(p):
    return [b for b in p.bindings if b.kind in BINDING_FAMILY and
            b.projection == 'binding' and b.complete]


def main_processes(p):
    return {o.entity_id for o in p.alert.entity_occurrences if o.role.value == 'process'}


def pair_basis(left, right, behavior, config):
    limit = config.unknown_max_stage_span_seconds if behavior == 'UNKNOWN' else config.max_stage_span_seconds
    if abs(left.seconds - right.seconds) > limit:
        return None, 'stage_time_span_exceeded'
    for name, a, b in (('host', left.hosts, right.hosts),
                       ('account', left.accounts, right.accounts),
                       ('process', main_processes(left), main_processes(right))):
        if a and b and a != b:
            return None, 'distinct_' + name + '_context'
    # PID-only descriptions can share an Entity ID. They are not proof of the
    # same instance, but distinct observed PIDs/start times still veto a merge.
    a, b = left.alert.process, right.alert.process
    if a and b:
        for field in ('pid', 'start_time', 'guid', 'instance_id'):
            x, y = getattr(a, field), getattr(b, field)
            if x is not None and y is not None and x != y:
                return None, 'distinct_process_' + field
    # A broad activity label is insufficient to erase a distinct observed action
    # or object, even within the same long-lived process/session.
    for field in ('command', 'file', 'url'):
        x, y = getattr(left.alert, field), getattr(right.alert, field)
        if x and y and x != y:
            return None, 'distinct_observed_' + field
    if any(left.contexts[s] != right.contexts[s] for s in left.contexts.keys() & right.contexts.keys()):
        return None, 'distinct_strong_context'
    lb, rb = strong_bindings(left), strong_bindings(right)
    # Complete flow tuples describe a specific connection. Their disagreement
    # cannot be overridden by a broad shared native session.
    lf, rf = {x.key for x in lb if x.kind == 'flow'}, {x.key for x in rb if x.kind == 'flow'}
    if lf and rf and lf != rf:
        return None, 'distinct_complete_flow'
    shared = {x.key for x in lb} & {x.key for x in rb}
    witnesses = []
    if shared:
        rule = 'shared_strong_binding'
        for p, bindings in ((left, lb), (right, rb)):
            witnesses += [EvidencePointer(alert_id=p.alert.alert_id, pointer=pointer, side='shared')
                          for binding in bindings if binding.key in shared for pointer in binding.pointers]
    else:
        # A complete current process instance plus an identical host is a
        # sufficiently specific core context. Names/host/account alone are not.
        instances = main_processes(left) & main_processes(right) & left.processes & right.processes
        if not (left.hosts and left.hosts == right.hosts and instances):
            return None, 'no_shared_binding_or_complete_core_context'
        rule = 'consistent_core_context'
        shared = instances | left.hosts
        for p in (left, right):
            witnesses += [EvidencePointer(alert_id=p.alert.alert_id, pointer=pointer, side='shared')
                for binding in p.bindings if binding.kind == 'process_instance' and binding.role == 'process'
                for pointer in binding.pointers]
    return AggregationBasis(alert_ids=sorted([left.alert.alert_id, right.alert.alert_id]),
                            rule=rule, shared_keys=sorted(shared), evidence=witnesses), None


def aggregate_stages(run, source_settings, community_config, config, resolver=None):
    alerts = {a.alert_id: a for a in run.alerts}
    entities = {e.entity_id: e for e in run.entities}
    if len(alerts) != len(run.alerts) or len(entities) != len(run.entities):
        raise ValueError('stage_input_requires_unique_ids')
    communities = sorted(run.result.incident_candidates, key=lambda c: c.community_id)
    members = [aid for c in communities for aid in c.alert_ids]
    if sorted(members) != sorted(alerts):
        raise ValueError('community_partition_must_cover_input_exactly_once')
    for c in communities:
        IncidentCandidate.model_validate(c, context=dict(alerts=alerts))
    validation_context = dict(alerts=alerts, entities=entities, communities={c.community_id:c for c in communities})
    profiles = {aid: profile(a, entities, source_settings[a.source_namespace], community_config)
                for aid, a in alerts.items()}
    behaviors, stages, diagnostics = [], [], []
    for community in communities:
        annotations = {aid: normalize_behavior(alerts[aid], community.community_id, config, resolver)
                       for aid in sorted(community.alert_ids)}
        for annotation in annotations.values():
            type(annotation).model_validate(annotation, context=validation_context)
        behaviors.extend(annotations.values())
        groups, proofs = [], {}
        for aid in sorted(community.alert_ids, key=lambda i: (alerts[i].timestamp, i)):
            behavior = annotations[aid].behavior
            chosen = None
            for index, group in enumerate(groups):
                if annotations[group[0]].behavior != behavior:
                    continue
                accepted = []
                for other in group:
                    basis, rejection = pair_basis(profiles[aid], profiles[other], behavior, config)
                    if basis is None:
                        diagnostics.append(dict(community_id=community.community_id,
                            alert_ids=sorted([aid, other]), decision='keep_separate', reason=rejection))
                        break
                    accepted.append(basis)
                else:
                    chosen = index
                    proofs[index].extend(accepted)
                    break
            if chosen is None:
                chosen = len(groups)
                groups.append([])
                proofs[chosen] = []
            groups[chosen].append(aid)
        for index, group in enumerate(groups):
            pp = [profiles[aid] for aid in group]
            behavior = annotations[group[0]].behavior
            binding_sets = {family: sorted({b.key for p in pp for b in strong_bindings(p)
                                            if BINDING_FAMILY[b.kind] == family})
                            for family in ('request', 'flow', 'session', 'task')}
            data = dict(stage_id=stage_id(community.community_id, behavior, group),
                community_id=community.community_id, behavior=behavior,
                start_time=min(alerts[i].timestamp for i in group), end_time=max(alerts[i].timestamp for i in group),
                alert_ids=sorted(group), alert_count=len(group),
                source_types=sorted({alerts[i].source_type.value for i in group}),
                host_entities=sorted({eid for p in pp for eid in p.hosts}),
                account_entities=sorted({eid for p in pp for eid in p.accounts}),
                process_entities=sorted({o.entity_id for p in pp for o in p.alert.entity_occurrences
                                        if entities[o.entity_id].type.value == 'PROCESS'}),
                **{family+'_bindings': values for family, values in binding_sets.items()},
                evidence_summary=f'{len(group)} observed alerts; semantic annotation {behavior}; original evidence retained by alert_ids.',
                aggregation_basis=sorted(proofs[index], key=lambda p: p.alert_ids))
            stages.append(Stage.model_validate(data, context=validation_context))
    stats = dict(BEHAVIOR_TOTAL=len(behaviors),
        MAPPING_RESOLVED=sum(b.resolver == 'mapping' for b in behaviors),
        AI_RESOLVED=sum(b.resolver == 'ai' and b.behavior != 'UNKNOWN' for b in behaviors),
        AI_ATTEMPTED=sum(b.resolver == 'ai' or 'semantic_' in b.reason for b in behaviors),
        UNKNOWN_BEHAVIORS=sum(b.behavior == 'UNKNOWN' for b in behaviors),
        BEHAVIOR_DISTRIBUTION=dict(sorted(Counter(b.behavior for b in behaviors).items())),
        STAGE_COUNT=len(stages),
        STAGES_PER_COMMUNITY=dict(sorted(Counter(s.community_id for s in stages).items())),
        STAGE_SIZE_DISTRIBUTION={str(k): v for k, v in sorted(Counter(s.alert_count for s in stages).items())},
        SINGLE_ALERT_STAGES=sum(s.alert_count == 1 for s in stages),
        UNKNOWN_STAGES=sum(s.behavior == 'UNKNOWN' for s in stages),
        CROSS_COMMUNITY_STAGE_MERGES=0,
        CURRENT_PIPELINE_STAGE='STAGE_AGGREGATION_COMPLETE', NEXT_STAGE_NOT_STARTED=True)
    return StageResult(config_hash=config.digest, behaviors=sorted(behaviors, key=lambda b: b.alert_id),
        stages=sorted(stages, key=lambda s: s.stage_id),
        diagnostics=sorted(diagnostics, key=canonical_json), statistics=stats)

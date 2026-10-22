"""Stage-level inverted retrieval; Community and clocks cannot nominate pairs."""
from collections import Counter, defaultdict
from datetime import datetime
from itertools import combinations

from app.stages.models import StageResult
from app.utils.stable_id import content_digest
from .features import extract_stage_candidate_features
from .models import StagePairCandidate, StagePairCandidateResult, candidate_id

REASONS = dict(request='SHARED_SCOPED_REQUEST', session='SHARED_SCOPED_SESSION',
    connection='SHARED_SCOPED_CONNECTION', application_session='SHARED_SCOPED_APPLICATION_SESSION',
    task='SHARED_SCOPED_TASK', object='SHARED_SCOPED_OBJECT', native_flow='SHARED_SCOPED_FLOW',
    network_tuple='SAME_NETWORK_TUPLE', direct_reference='EXPLICIT_REFERENCE_HINT',
    host_account='SHARED_ACCOUNT_AT_HOST', file='SHARED_SCOPED_FILE', session_entity='SHARED_SCOPED_SESSION_ENTITY',
    host='SELECTIVE_HOST_WITH_TEMPORAL_LOCALITY', endpoint_pair='SELECTIVE_ENDPOINT_PAIR_WITH_TEMPORAL_LOCALITY',
    host_url='SHARED_HOST_AND_URL', host_command='SHARED_HOST_AND_COMMAND', url_endpoint_pair='SHARED_URL_AND_ENDPOINT_PAIR',
    object_at_observed_host='SHARED_OBJECT_AT_OBSERVED_HOST', host_auth_session='SHARED_HOST_AUTH_SESSION',
    connection_endpoints_hint='SHARED_CONNECTION_TOKEN_AND_ENDPOINT_PAIR', file_at_host='SHARED_FILE_AT_HOST')


def stage_gap(a, b):
    later, earlier = max(a.start_time, b.start_time), min(a.end_time, b.end_time)
    return max(0.0, (datetime.fromisoformat(later.replace('Z', '+00:00')) -
                     datetime.fromisoformat(earlier.replace('Z', '+00:00'))).total_seconds())


def generate_stage_pair_candidates(stage_result, alerts, entities, settings, community_config, policy):
    """Consume this run's ⑥ handoff. No pair evidence checks or relation objects.

    Strong scoped identities are retained regardless of posting frequency.
    Weak singleton keys must be selective and locally timed. URL/command/IP
    singleton keys are diagnostic context only. Compound keys are constructed
    within actual member alerts, so separate members cannot invent a binding.
    """
    aa, ee = {a.alert_id:a for a in alerts}, {e.entity_id:e for e in entities}
    if len(aa) != len(alerts) or len(ee) != len(entities):
        raise ValueError('candidate_input_ids_must_be_unique')
    validated = StageResult.model_validate(stage_result, context=dict(alerts=aa, entities=ee))
    ss = {s.stage_id:s for s in validated.stages}
    if sorted(aid for s in ss.values() for aid in s.alert_ids) != sorted(aa):
        raise ValueError('candidate_stages_must_partition_current_alerts')
    if {a.source_namespace for a in aa.values()} - settings.keys():
        raise ValueError('candidate_source_settings_missing')
    features = extract_stage_candidate_features(ss.values(), aa, ee, settings, community_config, policy)
    inverted = defaultdict(dict)
    for feature in features:
        inverted[feature.key][feature.stage_id] = feature
    diagnostics, pairs = [], {}
    counts = Counter()
    for key, posting in sorted(inverted.items()):
        feature = next(iter(posting.values()))
        degree = len(posting)
        common = degree >= community_config.common_entities.min_count and degree >= len(ss)*community_config.common_entities.ratio
        description = dict(key=key, kind=feature.kind, posting_size=degree, stage_ids=sorted(posting))
        if feature.mode == 'CONTEXT_ONLY' or (feature.mode == 'SELECTIVE_WEAK' and common):
            reason = 'CONTEXT_REQUIRES_INDEPENDENT_KEY' if feature.mode == 'CONTEXT_ONLY' else 'COMMON_WEAK_KEY_REQUIRES_INDEPENDENT_KEY'
            diagnostics.append(dict(**description, action='SKIP_POSTING', reason=reason))
            counts['SUPPRESSED_COMMON_WEAK_KEY_COUNT' if common else 'CONTEXT_ONLY_KEY_COUNT'] += 1
            continue
        pruned = 0
        for a, b in combinations(sorted(posting), 2):
            counts['POSTING_PAIR_VISIT_COUNT'] += 1
            left, right = posting[a], posting[b]
            if feature.kind == 'process_instance':
                lr, rr = {w.role for w in left.witnesses}, {w.role for w in right.witnesses}
                if 'process' not in lr | rr:
                    continue
                reason = 'PARENT_CHILD_PROCESS_HINT' if ('process' in lr and 'parent_process' in rr or
                    'parent_process' in lr and 'process' in rr) else 'SAME_PROCESS_INSTANCE'
            elif feature.kind == 'direct_reference':
                lr, rr = {w.role for w in left.witnesses}, {w.role for w in right.witnesses}
                if not ('record' in lr and 'reference' in rr or 'reference' in lr and 'record' in rr):
                    continue
                reason = REASONS[feature.kind]
            else:
                reason = REASONS[feature.kind]
            gap = stage_gap(ss[a], ss[b])
            if feature.mode in {'SELECTIVE_WEAK', 'COMPOUND'}:
                tier = (policy.connection_context_window_tier if feature.kind == 'connection_endpoints_hint'
                        else policy.selective_host_window_tier if feature.kind == 'host'
                        else policy.compound_context_window_tier)
                if gap > community_config.windows_seconds[tier]:
                    pruned += 1
                    continue
            value = pairs.setdefault((a,b), dict(reasons=set(), keys=set(), kinds=set(), features={}))
            value['reasons'].add(reason)
            value['keys'].add(key)
            value['kinds'].add(feature.kind)
            for f in (left, right):
                value['features'][(f.stage_id, f.key)] = f
        if pruned:
            counts['TEMPORAL_LOCALITY_PRUNED_COUNT'] += pruned
            diagnostics.append(dict(**description, action='PRUNE_POSTING_PAIRS', reason='CONTEXT_OUTSIDE_LOCALITY_WINDOW', count=pruned))
    candidates = [StagePairCandidate(candidate_id=candidate_id(a,b), stage_a_id=a, stage_b_id=b,
        same_community=ss[a].community_id == ss[b].community_id,
        community_a_id=ss[a].community_id, community_b_id=ss[b].community_id,
        candidate_reasons=sorted(v['reasons']), retrieval_keys=sorted(v['keys']), candidate_sources=sorted(v['kinds']),
        retrieval_features=[v['features'][k] for k in sorted(v['features'])],
        metadata=dict(stage_time_gap_seconds=stage_gap(ss[a], ss[b]),
            community_locality_hint=ss[a].community_id == ss[b].community_id,
            retrieval_only=True)) for (a,b),v in sorted(pairs.items())]
    full = len(ss)*(len(ss)-1)//2
    statistics = dict(INPUT_ALERTS=len(aa), INPUT_STAGE_COUNT=len(ss),
        COMMUNITY_COUNT=len({s.community_id for s in ss.values()}), FULL_STAGE_PAIR_COUNT=full,
        CANDIDATE_PAIR_COUNT=len(candidates), CANDIDATE_REDUCTION_RATIO=1-len(candidates)/full if full else 0.0,
        SAME_COMMUNITY_CANDIDATE_COUNT=sum(p.same_community for p in candidates),
        CROSS_COMMUNITY_CANDIDATE_COUNT=sum(not p.same_community for p in candidates),
        SELF_PAIR_COUNT=0, DUPLICATE_PAIR_COUNT=0,
        CANDIDATE_REASON_COUNTS=dict(sorted(Counter(r for p in candidates for r in p.candidate_reasons).items())),
        STAGE_FEATURE_COUNT=len(features), RETRIEVAL_KEY_COUNT=len(inverted),
        **{k:counts[k] for k in ('POSTING_PAIR_VISIT_COUNT','SUPPRESSED_COMMON_WEAK_KEY_COUNT',
                                'CONTEXT_ONLY_KEY_COUNT','TEMPORAL_LOCALITY_PRUNED_COUNT')},
        CURRENT_PIPELINE_STAGE='STAGE_PAIR_CANDIDATE_GENERATION_COMPLETE', NEXT_STAGE_STARTED=False,
        NEXT_STAGE_NOT_STARTED=True)
    stage_data = validated.model_dump(mode='json')
    stage_data['stages'].sort(key=lambda s:s['stage_id'])
    stage_data['behaviors'].sort(key=lambda b:b['alert_id'])
    return StagePairCandidateResult(config_hash=content_digest(dict(candidate=policy.model_dump(mode='json'),
        community=community_config.model_dump(mode='json'), sources={k:v.snapshot() for k,v in sorted(settings.items())})),
        input_digest=content_digest(dict(stages=stage_data,
            alerts=[aa[k].model_dump(mode='json') for k in sorted(aa)], entities=[ee[k].model_dump(mode='json') for k in sorted(ee)])),
        candidates=candidates, features=features, diagnostics=diagnostics, statistics=statistics)

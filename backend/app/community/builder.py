"""Deterministic chronological create/join/merge, ending at IncidentCandidate."""
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from app.adapters.base import reject_truth
from app.entities.context import context_key, project_candidates
from app.entities.extraction import extract_entities
from app.noise_filter import NoiseFilterResult
from app.utils.stable_id import content_digest

from .evidence import evidence_tier, match, profile
from .index import CommunityIndex
from .models import CommunityResult, IncidentCandidate, MembershipDecision, community_id
from .temporal import TemporalHistory


@dataclass
class Component:
    members: set[str]
    start: float
    end: float
    hosts: set[str] = field(default_factory=set)
    accounts: set[str] = field(default_factory=set)
    contexts: dict[str, set[str]] = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    decisions: list = field(default_factory=list)
    temporal: TemporalHistory = field(default_factory=TemporalHistory)

    def absorb_profile(self, p):
        self.hosts.update(p.hosts)
        self.accounts.update(p.accounts)
        for scope, values in p.contexts.items():
            self.contexts.setdefault(scope, set()).update(values)


@dataclass
class CommunityRun:
    alerts: list
    entities: list
    result: CommunityResult
    noise_filter: NoiseFilterResult | None = None
    behaviors: list | None = None
    behavior_config_hash: str | None = None


def prepare_communities(alerts, source_settings, config, *, noise_config=None, behavior_config=None, resolver=None):
    """Consume Stage 1–4 output before any Entity/Community algorithm.

    Source settings are mandatory: no cross-source namespace/realm/ID guessing.
    Duplicate imports collapse by stable identity; conflicting records fail.
    """
    from app.services.alert_pipeline import NormalizedAlerts, prepare_alerts
    prepared = alerts if isinstance(alerts, NormalizedAlerts) else prepare_alerts(
        alerts, noise_config=noise_config, behavior_config=behavior_config, resolver=resolver,
        source_settings=source_settings)
    prepared.validate_handoff()
    if isinstance(alerts, NormalizedAlerts) and (noise_config is not None or behavior_config is not None or resolver is not None):
        raise ValueError('prepared_alerts_cannot_be_renormalized_at_community_boundary')
    noise = prepared.noise_filter
    originals = noise.original_alerts
    unique = {}
    input_count = 0
    for alert in originals:
        input_count += 1
        reject_truth(alert.raw_alert)
        if alert.alert_id in unique and unique[alert.alert_id].canonical_json() != alert.canonical_json():
            raise ValueError('same_alert_id_with_conflicting_content')
        unique[alert.alert_id] = alert
    if prepared.entities is not None:
        if prepared.source_settings != source_settings:
            raise ValueError('prepared_source_settings_mismatch')
        # Official ⑤ consumes ②–④ outputs as-is, without repeating extraction.
        bound_alerts, entities = prepared.alerts, prepared.entities
    else:
        # Historical CanonicalAlert callers have no ② output. Adapt only here;
        # the official stage pipeline requires a fully bound handoff.
        projected = []
        for alert in noise.kept_alerts:
            settings = source_settings[alert.source_namespace]
            data = alert.model_dump()
            data['context_candidates'] = project_candidates(alert.raw_alert, settings)
            projected.append(type(alert).model_validate(data))
        extracted = extract_entities(projected, source_settings, contract='front-data-v1')
        bound_alerts, entities = extracted.alerts, extracted.entities
    result = build_communities(bound_alerts, entities, source_settings, config)
    result.statistics['input_records'] = input_count
    result.statistics['duplicate_imports'] = input_count-len(unique)
    result.statistics.update(noise.statistics)
    return CommunityRun(bound_alerts, entities, result, noise,
                        prepared.behaviors, prepared.behavior_config_hash)


def build_communities(alerts, entities, source_settings, config):
    by_id = {a.alert_id: a for a in alerts}
    if len(by_id) != len(alerts):
        raise ValueError('builder_requires_unique_alert_ids')
    entity_map = {e.entity_id: e for e in entities}
    profiles = {}
    for alert in sorted(alerts, key=lambda a: (a.timestamp, a.alert_id)):
        reject_truth(alert.raw_alert)
        if alert.extraction_version != 'front-data-v1':
            raise ValueError('community_requires_core_extraction')
        profiles[alert.alert_id] = profile(alert, entity_map, source_settings[alert.source_namespace], config)
    df = Counter(h for p in profiles.values() for h in p.hosts)
    n = len(profiles)
    hot = {h for h, count in df.items() if count >= config.hot_host_min_count}
    # Distinct alert frequency, not occurrence count. Typed identities remain
    # intact, including the network scope of each auxiliary IP posting.
    frequencies = Counter(key for p in profiles.values() for key in (
        p.hosts | p.accounts | {b.key for b in p.bindings if b.kind == 'network_ip'}))
    # Absolute scoped alert frequency cannot be diluted by unrelated input.
    # Legacy ratio fields remain readable, but no longer control admission.
    common = hot | {key for key, count in frequencies.items() if count >= config.common_entities.min_count}
    index = CommunityIndex(config)
    roots, components = {}, {}
    diagnostics = []
    rejection_counts = Counter()
    matches_by_level = Counter()
    matches_by_tier = Counter()
    high_degree_hits = {}
    rejected_weak = Counter()
    bridge_hits = Counter()

    def guard(component, p, evidence):
        if len(component.members)+1 > config.max_community_members:
            return 'MEMBER_CAP'
        if max(component.end, p.seconds)-min(component.start, p.seconds) > config.max_community_span_seconds:
            return 'LIFETIME_CAP'
        if evidence_tier(evidence.identity_kind) != 'A':
            if not component.temporal.compatible(evidence.time_delta_seconds, config.temporal):
                return 'DYNAMIC_TIME_INCOMPATIBLE'
            if len(component.members)+1 > config.max_weak_members:
                return 'WEAK_MEMBER_CAP'
            # The matched endpoint already passed host/instance conflict
            # checks. An independently observed complete process may join ONE
            # small component containing another network endpoint, without
            # gaining the right to merge components or bypass context/cap/time.
            scoped_process_observation = (evidence.identity_kind == 'process_instance'
                and len({by_id[i].source_namespace for i in evidence.alert_ids}) > 1)
            if component.hosts and p.hosts and component.hosts - p.hosts and not scoped_process_observation:
                return 'COMPONENT_TARGET_CONFLICT'
            if component.accounts and p.accounts and component.accounts - p.accounts:
                return 'COMPONENT_ACCOUNT_CONFLICT'
            if any(component.contexts[s] - p.contexts[s] for s in component.contexts.keys() & p.contexts.keys()):
                return 'COMPONENT_CONTEXT_CONFLICT'
        return None

    for aid, p in profiles.items():
        hit_keys = (p.hosts | p.accounts | {b.key for b in p.bindings if b.kind == 'network_ip'}) & common
        high_degree_hits[aid] = len(hit_keys)
        if hit_keys:
            diagnostics.append(dict(alert_id=aid, decision='HIGH_DEGREE_EVIDENCE', entity_keys=sorted(hit_keys)))
        proposals = defaultdict(list)
        rejects = Counter()
        samples = {}
        for _, other, binding, prior_binding in index.query(p):
            evidence, reason = match(p, other, binding, prior_binding, config, common)
            root = roots[other.alert.alert_id]
            if evidence is not None:
                reason = guard(components[root], p, evidence)
            if reason:
                rejects[reason] += 1
                if evidence_tier(binding.kind) != 'A' and not reason.startswith('RECALL_ONLY_'):
                    rejected_weak[aid] += 1
                samples.setdefault(reason, other.alert.alert_id)
            else:
                proposals[root].append(evidence)
        options = []
        for root, evidence in proposals.items():
            evidence.sort(key=lambda e: (evidence_tier(e.identity_kind), e.match_level, e.time_delta_seconds, e.alert_ids, e.identity_kind, e.identity_key))
            options.append((root, evidence[0]))
        options.sort(key=lambda item: (evidence_tier(item[1].identity_kind), item[1].match_level, item[1].time_delta_seconds, item[1].alert_ids, item[0]))
        selected = []
        if options:
            selected = [options[0]]
            # Admission and merge are different operations. A non-binding rule
            # may admit to ONE component; every merged region needs Tier A.
            if evidence_tier(options[0][1].identity_kind) == 'A':
                size = len(components[options[0][0]].members)+1
                start = min(components[options[0][0]].start, p.seconds)
                end = max(components[options[0][0]].end, p.seconds)
                for root, evidence in options[1:]:
                    c = components[root]
                    reason = ('WEAK_EVIDENCE_CANNOT_MERGE' if evidence_tier(evidence.identity_kind) != 'A' else
                              'MERGE_MEMBER_CAP' if size+len(c.members) > config.max_community_members else
                              'MERGE_LIFETIME_CAP' if max(end,c.end)-min(start,c.start) > config.max_community_span_seconds else None)
                    if reason:
                        rejects[reason] += 1
                        if reason == 'WEAK_EVIDENCE_CANNOT_MERGE':
                            bridge_hits[aid] += 1
                            rejected_weak[aid] += 1
                        samples.setdefault(reason, next(x for x in evidence.alert_ids if x != aid))
                        continue
                    selected.append((root, evidence))
                    size += len(c.members)
                    start, end = min(start,c.start), max(end,c.end)
            else:
                for root, evidence in options[1:]:
                    rejects['WEAK_EVIDENCE_CANNOT_MERGE'] += 1
                    bridge_hits[aid] += 1
                    rejected_weak[aid] += 1
                    samples.setdefault('WEAK_EVIDENCE_CANNOT_MERGE', next(x for x in evidence.alert_ids if x != aid))
        old_ids = sorted(community_id(components[root].members) for root, _ in selected)
        action = 'MERGE' if len(selected) > 1 else 'JOIN' if selected else 'CREATE'
        evidence = [e for _, e in selected]
        for prior_root, e in selected:
            if evidence_tier(e.identity_kind) != 'A':
                diagnostics.append(dict(alert_id=aid, matched_alert_id=next(x for x in e.alert_ids if x != aid),
                    decision='ADMISSION', evidence_tier=evidence_tier(e.identity_kind),
                    identity_kind=e.identity_kind, **components[prior_root].temporal.snapshot(config.temporal)))
        decision = MembershipDecision(alert_id=aid, action=action, prior_community_ids=old_ids,
            matching_evidence=evidence, reason='NO_ADMISSIBLE_CONTEXT' if not evidence else evidence[0].match_reason)
        c = Component({aid}, p.seconds, p.seconds, evidence=list(evidence), decisions=[decision])
        c.temporal.times.append(p.seconds)
        c.absorb_profile(p)
        for root, _ in selected:
            prior = components.pop(root)
            c.members.update(prior.members)
            c.start, c.end = min(c.start, prior.start), max(c.end, prior.end)
            c.hosts.update(prior.hosts)
            c.accounts.update(prior.accounts)
            for scope, values in prior.contexts.items():
                c.contexts.setdefault(scope, set()).update(values)
            c.evidence.extend(prior.evidence)
            c.decisions.extend(prior.decisions)
            c.temporal.times.extend(prior.temporal.times)
        root = min(c.members)
        components[root] = c
        for member in c.members:
            roots[member] = root
        for e in evidence:
            matches_by_level[str(e.match_level)] += 1
            matches_by_tier[evidence_tier(e.identity_kind)] += 1
        for reason in sorted(rejects):
            count = rejects[reason]
            rejection_counts[reason] += count
            diagnostics.append(dict(alert_id=aid, decision='REJECT', reason=reason,
                                    count=count, matched_alert_id=samples[reason]))
        index.add(p)

    candidates = []
    for c in components.values():
        members = sorted(c.members)
        member_alerts = [by_id[aid] for aid in members]
        evidence = sorted(c.evidence, key=lambda e: (e.match_level, e.alert_ids, e.identity_kind, e.identity_key))
        contexts = defaultdict(set)
        for alert in member_alerts:
            for ref in alert.contexts:
                contexts[ref.kind].add(context_key(ref))
        data = dict(community_id=community_id(members), incident_candidate_id='icd_'+content_digest(
            dict(id_version='v1',kind='IncidentCandidate',identity=dict(alert_ids=members))),
            alert_ids=members, start_time=min(a.timestamp for a in member_alerts),
            end_time=max(a.timestamp for a in member_alerts), sources=sorted({a.source_namespace for a in member_alerts}),
            entity_ids=sorted({e for a in member_alerts for e in a.entity_ids}),
            contexts={k: sorted(v) for k,v in sorted(contexts.items())}, member_count=len(members),
            matching_evidence=evidence, membership_decisions=sorted(c.decisions,key=lambda d:(by_id[d.alert_id].timestamp,d.alert_id)))
        candidates.append(IncidentCandidate.model_validate(data, context={'alerts': by_id}))
        tier_counts = Counter(evidence_tier(e.identity_kind) for e in evidence)
        diagnostics.append(dict(decision='COMMUNITY_SUMMARY', community_id=data['community_id'], members=members,
            association_evidence_summary=dict(Counter(e.identity_kind for e in evidence)),
            strong_binding_count=tier_counts['A'], context_relation_count=tier_counts['B'], weak_relation_count=tier_counts['C'],
            time_range=[data['start_time'], data['end_time']],
            bridge_suppression_count=sum(bridge_hits[a] for a in members),
            rejected_weak_links=sum(rejected_weak[a] for a in members),
            high_degree_entity_hits=sum(high_degree_hits[a] for a in members),
            temporal=c.temporal.snapshot(config.temporal)))
    candidates.sort(key=lambda c:c.community_id)
    stats = dict(TOTAL_ALERTS=n, COMMUNITY_COUNT=len(candidates),
        SINGLETON_COMMUNITIES=sum(c.member_count == 1 for c in candidates),
        MULTI_ALERT_COMMUNITIES=sum(c.member_count > 1 for c in candidates),
        LARGEST_COMMUNITY_SIZE=max((c.member_count for c in candidates),default=0),
        AVERAGE_COMMUNITY_SIZE=n/len(candidates) if candidates else None,
        examined_index_witnesses=index.examined, policy_pruned_witnesses_or_neighbors=index.policy_pruned,
        policy='typed_bounded_index_absolute_common_entities_composite_admission_strong_only_merge',
        resource_truncated=False, execution_complete=True, hot_host_count=len(hot),
        high_degree_entities=[dict(identity_key=key, alert_frequency=frequencies[key]) for key in sorted(common)],
        STRONG_RELATION_COUNT=matches_by_tier['A'], CONTEXT_RELATION_COUNT=matches_by_tier['B'],
        WEAK_RELATION_COUNT=matches_by_tier['C'], REJECTED_WEAK_LINK_COUNT=sum(rejected_weak.values()),
        BRIDGE_SUPPRESSION_COUNT=sum(bridge_hits.values()), HIGH_DEGREE_ENTITY_HIT_COUNT=sum(high_degree_hits.values()),
        matches_by_level=dict(sorted(matches_by_level.items())), rejection_counts=dict(sorted(rejection_counts.items())),
        merge_operations=sum(d.action == 'MERGE' for c in candidates for d in c.membership_decisions))
    result = CommunityResult(config_hash=config.digest,
        input_fingerprint=content_digest([[aid,by_id[aid].raw_fingerprint] for aid in sorted(by_id)]),
        incident_candidates=candidates, diagnostics=diagnostics, statistics=stats)
    return result

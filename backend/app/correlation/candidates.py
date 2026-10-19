"""Maximum legal retrieval → category window → budgets → unique group pairs."""

from dataclasses import dataclass, field, replace
from collections import Counter, defaultdict
from contextlib import contextmanager
from contextvars import ContextVar
import heapq
import json
import math
import time

from app.utils.stable_id import canonical_json

CANDIDATE_CONTRACT_VERSION = "v1.1"


_AUDIT = ContextVar("candidate_audit", default=None)


@contextmanager
def candidate_diagnosis(callback):
    """Opt-in observation only; never supplies eligibility, rank or budgets."""
    token = _AUDIT.set(callback)
    try:
        yield
    finally:
        _AUDIT.reset(token)


def distribution(values):
    values = sorted(values)
    if not values:
        return dict.fromkeys(("min", "median", "mean", "P90", "P95", "P99", "max"), 0)
    def percentile(q):
        position = (len(values) - 1) * q
        lo, hi = math.floor(position), math.ceil(position)
        return values[lo] + (values[hi] - values[lo]) * (position - lo)
    return {"min": values[0], "median": percentile(.5), "mean": sum(values)/len(values),
            "P90": percentile(.9), "P95": percentile(.95), "P99": percentile(.99), "max": values[-1]}


def mask_positions(mask):
    while mask:
        bit = mask & -mask
        yield bit.bit_length() - 1
        mask ^= bit


class CandidateAudit:
    """Exact counts of indexed potential, separate from enumerated top-K hits.

    Entity/time eligibility is symmetric: same scoped key, original-member
    union and the chronological effective window (equal times take max).
    Its unordered count is half the directed degree sum. Bitset unions count
    dense overlaps without enumerating N² pairs. Relation/source lookups can
    be directional and are explicitly canonicalized, never divided by two.
    No values from this observer feed back into the candidate algorithm.
    """
    SYMMETRIC = {"IP", "HOST", "ACCOUNT", "SESSION", "PROCESS", "URL", "DOMAIN", "FILE", "COMMAND", "time_only", "semantic", "request", "flow", "session", "task"}

    def __init__(self, index, config):
        self.index, self.config = index, config
        self.raw = Counter()
        self.rows = defaultdict(dict)
        self.buckets = {}
        self.asymmetric_buckets = defaultdict(dict)
        self.raw_by_rep = Counter()
        from app.services.capacity import execution_state, DiskMasks
        self.spill = execution_state()
        if self.spill:
            self.db = self.spill.database()
            def row_store():
                self.spill.counter += 1
                return DiskMasks(self.db, 'masks_'+str(self.spill.counter))
            self.row_store = row_store
            self.rows = defaultdict(row_store)
            self.asymmetric_buckets = defaultdict(row_store)

    def lookup(self, member, channel, entity_id, mask):
        count = mask.bit_count()
        self.raw[channel] += count
        self.raw_by_rep[self.index.owner[member]] += count
        key = (channel, entity_id)
        if key not in self.buckets:
            entity = self.index.entities.get(entity_id)
            context = self.index.context_refs.get(entity_id)
            self.buckets[key] = {"index_type": channel, "index_key": entity_id or "all_categories",
                "normalized_key": entity.value if entity else context.value if context else None,
                "scope": entity.scope if entity else context.scope if context else None,
                "member_count": self.index.df[entity_id] if entity or context else self.index.N,
                "representative_count": self.index.df[entity_id] if entity or context else self.index.N,
                "alert_count": len(entity.alert_ids) if entity else len(self.index.context_members[entity_id]) if context else len(self.index.alerts),
                "raw_potential_discoveries": 0, "directed_group_pairs": 0, "retained_proposals": 0,
                "accepted_for_scoring": 0}
        self.buckets[key]["raw_potential_discoveries"] += count
        if channel not in self.SYMMETRIC:
            pos = self.index.positions[self.index.owner[member]]
            rows = self.asymmetric_buckets[key]
            rows[pos] = rows.get(pos, 0) | mask

    def bucket(self, rep, channel, entity_id, mask, retained):
        row = self.buckets[(channel, entity_id)]
        row["directed_group_pairs"] += mask.bit_count()
        row["retained_proposals"] += retained
        if channel not in self.SYMMETRIC:
            pos = self.index.positions[rep]
            self.asymmetric_buckets[(channel, entity_id)][pos] = mask

    def representative(self, rep, masks):
        pos = self.index.positions[rep]
        for channel, mask in masks.items():
            self.rows[channel][pos] = mask

    def asymmetric_pairs(self, rows):
        if self.spill:
            from app.services.capacity import DiskPositionPairs
            self.spill.counter += 1
            return DiskPositionPairs(self.db, 'directional_pairs_'+str(self.spill.counter), rows)
        return {tuple(sorted((pos, other))) for pos, mask in rows.items() for other in mask_positions(mask)}

    def finish(self, result):
        index, c = self.index, self.config.candidate
        n = index.N
        from app.services.capacity import DiskVector
        union = DiskVector(self.row_store(), n) if self.spill else [0] * n
        source_rows, asymmetric = {}, {}
        for channel in sorted(self.rows):
            rows = self.rows[channel]
            if channel in self.SYMMETRIC:
                count = sum(mask.bit_count() for mask in rows.values())
                if count % 2:
                    raise ValueError("asymmetric_entity_time_diagnostic")
                contributed = sum((mask & ~union[pos]).bit_count() for pos, mask in rows.items()) // 2
                for pos, mask in rows.items():
                    union[pos] |= mask
                unique = count // 2
            else:
                asymmetric[channel] = self.asymmetric_pairs(rows)
                unique, contributed = len(asymmetric[channel]), 0
            source_rows[channel] = {"potential_source": channel, "raw_potential_discoveries": self.raw[channel],
                "unique_pairs": unique, "unique_pairs_contributed": contributed,
                "duplicate_pairs": self.raw[channel] - unique, "accepted_for_scoring": 0,
                "exclusive_scoring_contribution": 0}
        for channel, pairs in sorted(asymmetric.items()):
            contributed = 0
            for pos, other in (pairs if self.spill else sorted(pairs)):
                if not union[pos] & (1 << other):
                    contributed += 1
                    union[pos] |= 1 << other
                    union[other] |= 1 << pos
            source_rows[channel]["unique_pairs_contributed"] = contributed
        potential = sum(mask.bit_count() for mask in union) // 2
        scored = DiskVector(self.row_store(), n) if self.spill else [0] * n
        for pair in result.pairs:
            a, b = (index.positions[i] for i in pair.support_key)
            scored[a] |= 1 << b
            scored[b] |= 1 << a
            for channel in pair.channels:
                source_rows[channel]["accepted_for_scoring"] += 1
            source_rows[pair.channels[0]]["exclusive_scoring_contribution"] += 1
            for key in {(e.channel, e.entity_id) for e in pair.evidence}:
                self.buckets[key]["accepted_for_scoring"] += 1
        for row in source_rows.values():
            row["not_admitted_via_channel"] = row["unique_pairs"] - row["accepted_for_scoring"]
        buckets = []
        for key, bucket in self.buckets.items():
            row = dict(bucket)
            if key[0] in self.SYMMETRIC:
                row["unique_pair_count"] = row["directed_group_pairs"] // 2
            else:
                row["unique_pair_count"] = len(self.asymmetric_pairs(self.asymmetric_buckets[key]))
            row["actual_generated_pair_count"] = row["raw_potential_discoveries"]
            row["theoretical_pair_count"] = row["member_count"] * (row["member_count"] - 1) // 2
            # A directional relation/source index can retrieve outside its key;
            # the within-key nC2 is descriptive, never an eligibility ceiling.
            row["potential_contribution"] = row["unique_pair_count"]
            if key[1]:
                eid = key[1]
                row["rarity"] = index.rarity(eid, self.config.entity)
                row["hot"] = index.df[eid] >= c.hot_entity_min_count and index.df[eid]/n >= c.hot_entity_ratio
            buckets.append(row)
        buckets.sort(key=lambda row: (-row["unique_pair_count"], row["index_type"], row["index_key"]))
        degrees = [mask.bit_count() for mask in union]
        retained_degrees = [mask.bit_count() for mask in scored]
        coverage, by_source = Counter(), defaultdict(Counter)
        per_rep = []
        for pos, rep in enumerate(index.representatives):
            if scored[pos] & ~union[pos]:
                raise ValueError("scored_candidate_outside_diagnostic_space")
            expected_degree = result.admitted_degrees[pos] if result.admitted_degrees else retained_degrees[pos]
            state = "complete" if expected_degree == retained_degrees[pos] else "partial" if retained_degrees[pos] else "not_scheduled"
            coverage[state] += 1
            sources = sorted({index.alerts[aid].source_type.value for aid in index.groups[rep]})
            for source in sources:
                by_source[source][state] += 1
            a = index.alerts[rep]
            per_rep.append({"alert_id": rep, "source": a.source_type.value, "timestamp": a.timestamp,
                "category": a.category.value, "potential_count": degrees[pos], "admitted_count": expected_degree, "scheduled_count": retained_degrees[pos],
                "raw_generations": self.raw_by_rep[rep], "coverage": state,
                "candidate_sources": {key: rows.get(pos, 0).bit_count() for key, rows in sorted(self.rows.items())},
                "entity_summary": [{"entity_id": eid, "type": index.entities[eid].type.value,
                    "value": index.entities[eid].value} for eid in sorted({eid for aid in index.groups[rep] for eid in index.alerts[aid].entity_ids})]})
        chronology = sorted(per_rep, key=lambda row: (row["timestamp"], row["alert_id"]))
        time_coverage = []
        for quarter in range(4):
            rows = chronology[n*quarter//4:n*(quarter+1)//4]
            if rows:
                time_coverage.append({"quartile": quarter+1, "start_time": rows[0]["timestamp"],
                    "end_time": rows[-1]["timestamp"], "representatives": len(rows),
                    "coverage": dict(sorted(Counter(row["coverage"] for row in rows).items()))})
        budget = defaultdict(Counter)
        first = None
        seen_reps = set()
        for diagnostic in result.diagnostics:
            if diagnostic.get("stage") != "candidate_admission":
                continue
            rule = diagnostic["rule_id"]
            budget[rule].update({key: diagnostic.get(key, 0) for key in ("proposed", "retained", "dropped")})
            if diagnostic.get("alert_id"):
                seen_reps.add(diagnostic["alert_id"])
            if first is None and diagnostic["dropped"] and diagnostic.get("decision") == "resource_truncated":
                first = {**diagnostic, "remaining_representatives_at_first_truncation": n-len(seen_reps),
                    "remaining_input_alerts_at_first_truncation": sum(len(index.groups[rep]) for rep in index.representatives if rep not in seen_reps),
                    "all_representatives_subsequently_processed": True}
        raw = sum(self.raw.values())
        time_degrees = [self.rows.get("time_only", {}).get(pos, 0).bit_count() for pos in range(n)]
        stamps = Counter(t for members in index.groups.values() for t in {index.times[aid] for aid in members})
        width = c.time_only_window_seconds
        bins = Counter(index.times[rep]//(width*1000000) for rep in index.representatives) if width else Counter()
        suspicious = [row for row in buckets if row["normalized_key"] is not None and
            str(row["normalized_key"]).strip().lower() in {"", "unknown", "none", "default", "0.0.0.0", "-", "n/a"}]
        report = {"diagnostic_version": "candidate-audit-v1.1", "candidate_contract_version": CANDIDATE_CONTRACT_VERSION, "representative_count": n,
            "theoretical_all_unordered_pairs": n*(n-1)//2,
            "raw_potential_discoveries": raw, "unique_potential_pairs": potential,
            "duplicate_potential_discoveries": raw-potential, "duplicate_ratio": (raw-potential)/raw if raw else 0,
            "enumerated_neighbor_hits": result.examined_neighbors,
            "admitted_candidate_count": result.admitted_count, "scheduled_candidate_count": result.retained_count,
            "policy_pruned_count": potential-result.admitted_count, "resource_truncated_count": result.resource_truncated_count,
            "directed_non_time_potential_proposals": result.proposed_count, "directed_policy_proposal_drops": sum(d["dropped"] for d in result.diagnostics if d.get("rule_id") in {"channel_neighbors", "max_neighbors_per_alert"}),
            "proposal_count_semantics": "directed per-channel potential minus retained channel/endpoint/global proposals; overlapping channels and endpoints are not unique pair losses; hot drops are disclosed separately",
            "source_count_semantics": "raw = per-member lookup unique neighbor groups; sources overlap; contribution attributed in sorted symmetric channels then sorted directional channels; accepted = final candidate provenance; not_admitted_via_channel = absent from final provenance, may be admitted via another channel; time_only is observation only",
            "candidate_sources": list(source_rows.values()),
            "budget_limits": c.model_dump(), "budget_stages": {key: dict(value) for key, value in sorted(budget.items())},
            "first_resource_truncation": first, "coverage": dict(sorted(coverage.items())),
            "source_wise_coverage": {key: dict(sorted(value.items())) for key, value in sorted(by_source.items())},
            "entity_type_coverage": {channel: dict(sorted(Counter(
                "complete" if per_rep[pos]["coverage"] == "complete" else "resource_truncated"
                for pos, mask in rows.items() if mask).items())) for channel, rows in sorted(self.rows.items())},
            "time_range_coverage": time_coverage,
            "all_representatives_candidate_generation_processed": n,
            "deterministic_order": ("sorted representative Stable IDs; nearest gap/neighbor ID within channels; binding > core > IP, then gap/ID; canonical unordered pair global tie-break" if index.front_data else
                "sorted representative Stable IDs; gap/neighbor ID within channels; tier/weight*rarity/gap/ID for endpoints; canonical unordered pair global tie-break"),
            "rarity_usage": ("existing score only; candidate tiers are binding/core/IP; df/N drives the existing hot cap" if index.front_data else
                "score AND endpoint priority weight*rarity; df/N also drives frozen hot cap; no rarity eligibility cutoff"),
            "suspicious_value_buckets": suspicious,
            "time_index": {"implementation": "category-partitioned sorted temporal postings; inclusive continuous windows; no overlapping time buckets",
                "bucket_width": None, "bucket_count": 0, "category_posting_sizes": {key: len(posting.members) for key, posting in index.time.items()},
                "category_posting_size_distribution": distribution([len(posting.members) for posting in index.time.values()]),
                "same_timestamp_group_sizes": distribution(list(stamps.values())),
                "descriptive_bins_only": {"width_seconds": width, "count": len(bins), "sizes": distribution(list(bins.values()))},
                "per_alert_time_potential_count": distribution(time_degrees)}}
        return {"candidate_diagnostics": report,
            "candidate_hot_buckets": {"top_100": buckets[:100], "entity_frequency": [row for row in buckets if row["index_type"] in self.SYMMETRIC-{"time_only"}],
                "contribution_semantics": "per-key eligible unique pairs; overlapping key contributions are not additive"},
            "candidate_distribution": {"potential_unique_neighbors": distribution(degrees),
                "scheduled_candidate_neighbors": distribution(retained_degrees),
                "raw_generations": distribution(list(self.raw_by_rep.get(rep, 0) for rep in index.representatives)),
                "top_20": sorted(per_rep, key=lambda row: (-row["potential_count"], row["alert_id"]))[:20],
                "coverage": report["coverage"]}}


@dataclass(frozen=True, slots=True)
class CandidateEvidence:
    channel: str
    entity_id: str | None
    member_ids: tuple[str, str]
    gap_seconds: float
    retrieval_window_seconds: int
    effective_window_seconds: int
    override: tuple[str, str] | None
    nomination_rep: str = ""
    hot: bool = False
    admission_limit: int = 0
    neighbor_rank: int = 0
    relation_facts: tuple[str, ...] = ()
    neighbor_rep: str = ""

    def __getitem__(self, field):
        if field == "alert_ids":
            return self.member_ids
        if field == "behavior_override":
            return self.override
        return getattr(self, field)

    def json_data(self):
        return {"channel": self.channel, "entity_id": self.entity_id, "alert_ids": list(self.member_ids),
                "gap_seconds": self.gap_seconds, "retrieval_window_seconds": self.retrieval_window_seconds,
                "effective_window_seconds": self.effective_window_seconds,
                "behavior_override": list(self.override) if self.override else None,
                "nomination_rep": self.nomination_rep, "hot": self.hot, "admission_limit": self.admission_limit,
                "neighbor_rank": self.neighbor_rank, "ranking_key": [self.gap_seconds,
                    self.neighbor_rep],
                "supporting_relation_facts": [json.loads(r) for r in self.relation_facts],
                "admission_reason": "deterministic_nearest_k"}


@dataclass(frozen=True, slots=True)
class CandidatePair:
    source_alert_id: str
    target_alert_id: str
    channels: tuple[str, ...]
    evidence: tuple[CandidateEvidence, ...]
    priority: tuple

    @property
    def support_key(self):
        return (self.source_alert_id, self.target_alert_id)


@dataclass
class CandidateResult:
    pairs: list[CandidatePair]
    diagnostics: list[dict]
    proposed_count: int
    retained_count: int
    dropped_count: int
    candidate_truncated: bool
    examined_neighbors: int
    admitted_count: int = 0
    policy_pruned_count: int = 0
    resource_truncated_count: int = 0
    potential_pair_stats: dict = field(default_factory=dict)
    candidate_admission_stats: dict = field(default_factory=dict)
    admitted_degrees: tuple[int, ...] = ()
    resource_candidates: object = field(default=(), compare=False, repr=False)
    retrieval_seconds: float = field(default=0, compare=False)
    admission_seconds: float = field(default=0, compare=False)


class CandidateGenerator:
    def __init__(self, index, config, scorer=None):
        self.index = index
        self.config = config.algorithm
        self.c = self.config.candidate
        self.scorer = scorer
        self.overrides = {(r.from_category, r.to_category): r.window_seconds for r in self.c.behavior_window_overrides}
        self.examined = 0
        self.audit = None
        self.retrieval_seconds = 0
        self.endpoint_only = False
        self.lookup_boundaries = {}
        self.semantic, self.semantic_members = ({}, {})
        if not index.front_data and self.config.version in {"v2", "v3", "v4"}:
            self.semantic, self.semantic_members = index.semantic_index(self.config.score.evidence_v2.semantic_candidate_fields)

    def base_window(self, channel):
        if channel in {'request', 'flow', 'session', 'task'}:
            # Reuse the existing binding window; no new thresholds or scores.
            return self.c.entity_windows_seconds['SESSION']
        if channel == "semantic":
            return self.config.score.evidence_v2.semantic_candidate_window_seconds
        if channel == "time_only":
            return self.c.time_only_window_seconds
        if channel == "source_complement":
            return self.c.source_complement_window_seconds
        if channel == "explicit_relation":
            return self.c.explicit_relation_window_seconds
        return self.c.entity_windows_seconds.get(channel, self.c.default_window_seconds)

    def retrieval_window(self, channel):
        windows = [self.base_window(channel)]
        if channel in self.c.behavior_override_channels:
            windows.extend(self.overrides.values())
        return min(self.c.max_window_seconds, max(windows))

    def windows(self, channel, category, other_category):
        base = self.base_window(channel)
        if channel not in self.c.behavior_override_channels:
            return [("both", base, None)]
        forward = self.overrides.get((category, other_category))
        reverse = self.overrides.get((other_category, category))
        return [("before", reverse if reverse is not None else base, (other_category, category) if reverse is not None else None),
                ("after", forward if forward is not None else base, (category, other_category) if forward is not None else None)]

    def retrieve(self, member, channel, postings, limit, entity_id=None, excluded=()):
        retrieval_started = time.perf_counter()
        index = self.index
        a = index.alerts[member]
        center = index.times[member]
        own_bit = 1 << index.positions[index.owner[member]]
        proposed_mask, retrieval_mask, hits = 0, 0, {}
        retrieval = self.retrieval_window(channel)
        for category, posting in postings.items():
            retrieval_mask |= posting.mask(center - retrieval * 1000000, center + retrieval * 1000000, excluded)
            for side, effective, override in self.windows(channel, a.category.value, category):
                if side == "before":
                    start, end = center - effective * 1000000, center - 1
                elif side == "after":
                    start, end = center + 1, center + effective * 1000000
                else:
                    start, end = center - effective * 1000000, center + effective * 1000000
                ranges = [(start, end, effective, override)]
                # Same timestamp is a symmetric candidate; use the greater of
                # the two category windows, never ID to infer chronology.
                if side == "before":
                    equal_rules = self.windows(channel, a.category.value, category)
                    equal_window = max(w for _, w, _ in equal_rules)
                    equal_overrides = sorted({o for _, w, o in equal_rules if w == equal_window and o is not None})
                    ranges.append((center, center, equal_window, equal_overrides[0] if equal_overrides else None))
                for begin, stop, window, matched in ranges:
                    proposed_mask |= posting.mask(begin, stop, excluded)
                    mask_done = time.perf_counter()
                    self.retrieval_seconds += mask_done - retrieval_started
                    for rep, other_member, gap in posting.nearest(member, begin, stop, limit, excluded):
                        self.examined += 1
                        data = CandidateEvidence(channel, entity_id, tuple(sorted((member, other_member))), gap, retrieval, window, matched)
                        key = (gap, rep, member, other_member)
                        if rep not in hits or key < hits[rep][0]:
                            hits[rep] = (key, data)
                    retrieval_started = time.perf_counter()
        proposed_mask &= ~own_bit
        retrieval_mask &= ~own_bit
        if self.audit is not None:
            self.audit.lookup(member, channel, entity_id, proposed_mask)
        self.retrieval_seconds += time.perf_counter() - retrieval_started
        retained = heapq.nsmallest(limit, hits.items(), key=lambda row: row[1][0])
        hot = bool(entity_id and index.df[entity_id] >= self.c.hot_entity_min_count and index.df[entity_id]/index.N >= self.c.hot_entity_ratio)
        relations = tuple(sorted(canonical_json(r.model_dump(mode="json")) for r in a.relations
            if entity_id in (r.source_entity_id, r.target_entity_id))) if channel == "explicit_relation" else ()
        if self.endpoint_only and channel != 'time_only':
            self.lookup_boundaries.setdefault(index.owner[member], []).append({
                'member':member,'channel':channel,'entity_id':entity_id,'limit':limit,
                'retained':len(retained), 'worst_rank':list(retained[-1][1][0]) if retained else None})
        return proposed_mask, retrieval_mask, {rep: replace(data, nomination_rep=index.owner[member], hot=hot,
            admission_limit=limit, neighbor_rank=number, relation_facts=relations, neighbor_rep=rep)
            for number, (rep, (_, data)) in enumerate(retained, 1)}

    def rank(self, channel, entity_id, gap, neighbor):
        if self.index.front_data:
            tier = 0 if channel in {'request', 'flow', 'session', 'task'} else 2 if channel == 'IP' else 1
            return (tier, 0, gap, neighbor)
        if channel == "explicit_relation":
            tier, weight = 0, 0
        elif channel == "SESSION" or (channel == "PROCESS" and self.scorer and self.scorer.is_instance(entity_id)):
            tier, weight = 1, 0
        elif channel in self.c.entity_windows_seconds:
            tier = 2
            weight = -self.config.entity.weights[channel] * self.index.rarity(entity_id, self.config.entity)
        elif channel == "source_complement":
            tier, weight = 3, 0
        else:
            tier, weight = 4, 0
        return (tier, weight, gap, neighbor)

    def generate(self, *, representatives=None, endpoint_only=False):
        """Optional endpoint replay uses exactly the Full retrieval/admission path.

        Internal proposal state is before both-endpoint union/global scheduling.
        No policy or scoring parameter is overridden by the incremental caller.
        """
        from app.services.capacity import execution_state, DiskPairObjects, DiskList, DiskPairs, schedule_pairs
        state = execution_state()
        index, diagnostics = self.index, []
        db = state.database() if state and not endpoint_only else None
        if db:
            diagnostics = DiskList(db, 'admission_diagnostics')
        all_pairs = DiskPairObjects(db, 'pairs', index) if db else {}
        callback = _AUDIT.get()
        self.audit = CandidateAudit(index, self.config)
        started = time.perf_counter()
        dropped = proposed = 0
        extra_discoveries = DiskPairObjects(db, 'discoveries', index, set) if db else defaultdict(set)
        endpoint_state = {}
        self.endpoint_only = endpoint_only
        self.lookup_boundaries = {}
        for rep_number, (rep, members) in enumerate(index.groups.items(), 1):
            if representatives is not None and rep not in representatives:
                continue
            endpoint_discoveries = defaultdict(set)
            channels = {}
            def merge(channel, hits):
                target = channels.setdefault(channel, {})
                for neighbor, data in hits.items():
                    key = (data["gap_seconds"], neighbor, data["alert_ids"])
                    rank = self.rank(channel, data["entity_id"], data["gap_seconds"], neighbor)
                    if neighbor not in target:
                        target[neighbor] = (data, rank, {data})
                    else:
                        nearest, best_rank, evidence = target[neighbor]
                        if key < (nearest.gap_seconds, neighbor, nearest.member_ids):
                            nearest = data
                        evidence.add(data)
                        target[neighbor] = (nearest, min(rank, best_rank), evidence)
            masks = {}
            retrieval_masks = {}
            context_keys = sorted({key for aid in members for key in index.contexts_by_alert[aid]})
            for key in context_keys:
                channel = index.context_refs[key].kind
                hot = index.df[key] >= self.c.hot_entity_min_count and index.df[key] / index.N >= self.c.hot_entity_ratio
                limit = min(self.c.per_channel_neighbors, self.c.hot_entity_neighbors) if hot else self.c.per_channel_neighbors
                union_mask, fetched_mask, hits = 0, 0, {}
                for aid in members:
                    if key not in index.contexts_by_alert[aid]:
                        continue
                    mask, fetched, found = self.retrieve(aid, channel, index.by_context[key], limit, key)
                    union_mask |= mask
                    fetched_mask |= fetched
                    for neighbor, evidence in found.items():
                        if neighbor not in hits or (evidence.gap_seconds, evidence.member_ids) < (hits[neighbor].gap_seconds, hits[neighbor].member_ids):
                            hits[neighbor] = evidence
                hits = dict(heapq.nsmallest(limit, hits.items(), key=lambda row: (row[1].gap_seconds, row[0])))
                self.audit.bucket(rep, channel, key, union_mask, len(hits))
                masks[channel] = masks.get(channel, 0) | union_mask
                retrieval_masks[channel] = retrieval_masks.get(channel, 0) | fetched_mask
                merge(channel, hits)
            entity_ids = sorted({eid for aid in members for eid in index.alerts[aid].entity_ids})
            for eid in entity_ids:
                channel = index.entities[eid].type.value
                if index.front_data and channel not in {'HOST', 'ACCOUNT', 'PROCESS', 'IP'}:
                    continue
                hot = index.df[eid] >= self.c.hot_entity_min_count and index.df[eid] / index.N >= self.c.hot_entity_ratio
                limit = min(self.c.per_channel_neighbors, self.c.hot_entity_neighbors) if hot else self.c.per_channel_neighbors
                union_mask, retrieved_mask, hits = 0, 0, {}
                for aid in members:
                    if eid not in index.roles[aid]:
                        continue
                    mask, fetched, found = self.retrieve(aid, channel, index.compatible_entity_postings(aid, eid), limit, eid)
                    union_mask |= mask
                    retrieved_mask |= fetched
                    for neighbor, data in found.items():
                        if neighbor not in hits or (data["gap_seconds"], data["alert_ids"]) < (hits[neighbor]["gap_seconds"], hits[neighbor]["alert_ids"]):
                            hits[neighbor] = data
                hits = dict(heapq.nsmallest(limit, hits.items(), key=lambda row: (row[1]["gap_seconds"], row[0])))
                if self.audit is not None:
                    self.audit.bucket(rep, channel, eid, union_mask, len(hits))
                masks[channel] = masks.get(channel, 0) | union_mask
                retrieval_masks[channel] = retrieval_masks.get(channel, 0) | retrieved_mask
                if hot and union_mask.bit_count() > len(hits):
                    lost = union_mask.bit_count() - len(hits)
                    diagnostics.append({"stage": "candidate_admission", "alert_id": rep, "channel": channel, "entity_id": eid,
                                        "decision": "policy_pruned", "rule_id": "hot_entity_neighbors", "proposed": union_mask.bit_count(),
                                        "retained": len(hits), "dropped": lost})
                merge(channel, hits)
            for aid in members:
                for key in sorted(self.semantic_members.get(aid, ())):
                    hot = index.df[key] >= self.c.hot_entity_min_count and index.df[key]/index.N >= self.c.hot_entity_ratio
                    limit = min(self.c.per_channel_neighbors, self.c.hot_entity_neighbors) if hot else self.c.per_channel_neighbors
                    mask, fetched, found = self.retrieve(aid, "semantic", self.semantic[key], limit, key)
                    masks["semantic"] = masks.get("semantic", 0) | mask
                    retrieval_masks["semantic"] = retrieval_masks.get("semantic", 0) | fetched
                    self.audit.bucket(rep, "semantic", key, mask, len(found))
                    merge("semantic", found)
                mask, fetched, found = (0, 0, {}) if index.front_data else self.retrieve(aid, "time_only", index.time, 0)
                masks["time_only"] = masks.get("time_only", 0) | mask
                retrieval_masks["time_only"] = retrieval_masks.get("time_only", 0) | fetched
                # Time retrieval is diagnostic potential only; never a nomination.
                relation_entities = {eid for r in index.alerts[aid].relations for eid in (r.source_entity_id, r.target_entity_id)}
                for eid in sorted(relation_entities):
                    mask, fetched, found = self.retrieve(aid, "explicit_relation", index.by_entity[eid], self.c.per_channel_neighbors, eid)
                    masks["explicit_relation"] = masks.get("explicit_relation", 0) | mask
                    retrieval_masks["explicit_relation"] = retrieval_masks.get("explicit_relation", 0) | fetched
                    merge("explicit_relation", found)
            # Source complement is separately retrieved at its own window, not
            # derived from entity top-K (which could hide an eligible source).
            if self.scorer is not None and self.scorer.has_independence_mappings:
                for aid in members:
                    for eid, roles in index.roles[aid].items():
                        if not roles.intersection({"host", "session"}):
                            continue
                        for postings, excluded in self.scorer.source_postings(aid, eid):
                            mask, fetched, found = self.retrieve(aid, "source_complement", postings, self.c.per_channel_neighbors, eid, excluded)
                            masks["source_complement"] = masks.get("source_complement", 0) | mask
                            retrieval_masks["source_complement"] = retrieval_masks.get("source_complement", 0) | fetched
                            merge("source_complement", found)
            if self.audit is not None:
                if not index.front_data:
                    self.audit.bucket(rep, "time_only", None, masks["time_only"], 0)
                self.audit.representative(rep, masks)
            proposals = {}
            for channel, hits in sorted(channels.items()):
                for neighbor, (_, _, evidence) in hits.items():
                    discovered_key = tuple(sorted((rep, neighbor)))
                    found_evidence = extra_discoveries[discovered_key]
                    found_evidence.update(evidence)
                    extra_discoveries[discovered_key] = found_evidence
                    endpoint_discoveries[neighbor].update(evidence)
                limit = self.c.time_only_neighbors if channel == "time_only" else self.c.per_channel_neighbors
                retained = heapq.nsmallest(limit, hits.items(), key=lambda row: (row[1][0].gap_seconds, row[0]))
                count = masks[channel].bit_count()
                # Hot drops are already disclosed above; this count discloses
                # the complete channel potential and its final retained set.
                lost = count - len(retained)
                proposed += count
                dropped += lost
                diagnostics.append({"stage": "candidate_admission", "alert_id": rep, "channel": channel,
                                    "decision": "policy_pruned", "rule_id": "channel_neighbors", "proposed": count, "retained": len(retained), "dropped": lost,
                                    "retrieval_proposed": retrieval_masks[channel].bit_count(),
                                    "window_filtered": (retrieval_masks[channel] & ~masks[channel]).bit_count()})
                for neighbor, (_, rank, matching_evidence) in retained:
                    if neighbor not in proposals:
                        proposals[neighbor] = (rank, [])
                    best, evidence = proposals[neighbor]
                    evidence.extend(sorted(matching_evidence,key=lambda e:(e.channel,e.entity_id or "",e.member_ids,e.gap_seconds)))
                    proposals[neighbor] = (min(best, rank), evidence)
            retained = heapq.nsmallest(self.c.max_neighbors_per_alert, proposals.items(), key=lambda row: row[1][0])
            if endpoint_only:
                endpoint_state[rep] = {"proposals": proposals, "discoveries": dict(endpoint_discoveries),
                    'lookup_boundaries':self.lookup_boundaries.get(rep,[])}
            lost = len(proposals) - len(retained)
            dropped += lost
            diagnostics.append({"stage": "candidate_admission", "alert_id": rep, "channel": "all",
                                "decision": "policy_pruned", "rule_id": "max_neighbors_per_alert", "proposed": len(proposals), "retained": len(retained), "dropped": lost})
            for neighbor, (rank, evidence) in retained:
                pair = tuple(sorted((rep, neighbor)))
                global_rank = (*rank[:3], pair)
                if pair not in all_pairs:
                    all_pairs[pair] = (global_rank, [])
                prior, existing = all_pairs[pair]
                existing.extend(evidence)
                all_pairs[pair] = (min(prior, global_rank), existing)
            if db and rep_number % 10000 == 0 and hasattr(state, 'progress'):
                state.progress(dict(stage='candidate_emission', processed_representatives=rep_number,
                    total_representatives=index.N, admitted_so_far=len(all_pairs),
                    full_candidate_count_available=False))
        if endpoint_only:
            return endpoint_state
        total = len(all_pairs)
        admitted_degrees = [0] * index.N
        for a, b in all_pairs:
            admitted_degrees[index.positions[a]] += 1
            admitted_degrees[index.positions[b]] += 1
        retained_count = min(self.c.max_candidate_pairs, total)
        retained = schedule_pairs(db, all_pairs, retained_count) if db else heapq.nsmallest(self.c.max_candidate_pairs, all_pairs.items(), key=lambda row: row[1][0])
        lost = total - retained_count
        dropped += lost
        diagnostics.append({"stage": "candidate_admission", "channel": "all", "rule_id": "max_candidate_pairs",
                            "decision": "resource_truncated", "proposed": total, "retained": retained_count, "dropped": lost})
        # Endpoints often propose the same hit; retain its evidence once. Small
        # slotted records keep million-pair snapshots from duplicating dictionaries.
        pairs = DiskPairObjects(db, 'final_pairs', index) if db else []
        for pair, (rank, evidence) in (retained if db else sorted(retained)):
            unique = tuple(sorted(set(evidence) | extra_discoveries[pair], key=lambda e: (e.channel, e.member_ids, e.entity_id or "", e.gap_seconds, e.retrieval_window_seconds, e.effective_window_seconds, e.override or (), e.nomination_rep, e.neighbor_rep, e.hot, e.admission_limit, e.neighbor_rank, e.relation_facts)))
            candidate = CandidatePair(*pair, tuple(sorted({e.channel for e in unique})), unique, rank)
            if db:
                pairs[pair] = candidate
            else:
                pairs.append(candidate)
        if db:
            pairs = DiskPairs(pairs)
        result = CandidateResult(pairs, diagnostics, proposed, len(pairs), lost, lost > 0, self.examined,
            admitted_count=total, resource_truncated_count=lost, admitted_degrees=tuple(admitted_degrees))
        if lost:
            scheduled_keys = pairs.objects if db else {p.support_key for p in pairs}
            def unscheduled():
                for pair in (all_pairs if db else sorted(all_pairs)):
                    if pair in scheduled_keys:
                        continue
                    rank, evidence = all_pairs[pair]
                    unique = sorted(set(evidence) | extra_discoveries[pair], key=lambda e: (
                        e.channel, e.member_ids, e.entity_id or "", e.gap_seconds, e.retrieval_window_seconds,
                        e.effective_window_seconds, e.override or (), e.nomination_rep, e.neighbor_rep,
                        e.hot, e.admission_limit, e.neighbor_rank, e.relation_facts))
                    yield {"stage": "candidate_resource_truncated", "candidate_contract_version": CANDIDATE_CONTRACT_VERSION,
                        "support_key": list(pair), "ranking_key": rank, "channels": sorted({e.channel for e in unique}),
                        "evidence": [e.json_data() for e in unique], "rule_id": "max_candidate_pairs",
                        "admission_reason": "non_time_window_and_deterministic_top_k", "scored": False}
            result.resource_candidates = unscheduled()
        reports = self.audit.finish(result)
        report = reports["candidate_diagnostics"]
        result.policy_pruned_count = report["policy_pruned_count"]
        result.potential_pair_stats = {key: report[key] for key in
            ("raw_potential_discoveries", "unique_potential_pairs", "duplicate_potential_discoveries")}
        result.candidate_admission_stats = {"candidate_contract_version": CANDIDATE_CONTRACT_VERSION,
            "policy_pruned_count": result.policy_pruned_count, "resource_truncated_count": lost,
            "admitted_candidate_count": total, "scheduled_candidate_count": len(pairs),
            "representatives_processed": index.N}
        report.update(potential_pair_stats=result.potential_pair_stats, candidate_admission_stats=result.candidate_admission_stats)
        result.retrieval_seconds = self.retrieval_seconds
        result.admission_seconds = max(0, time.perf_counter()-started-self.retrieval_seconds)
        if callback is not None:
            callback(reports)
        return result


def generate_candidates(index, config, scorer=None):
    return CandidateGenerator(index, config, scorer).generate()

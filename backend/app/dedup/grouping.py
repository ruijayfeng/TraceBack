"""Frozen duplicate score, indexed retrieval and complete-link grouping."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from itertools import combinations
import math

from app.config import MappingConflict, resolve_mapping
from app.models import DedupeGroup, Reason, ReasonCode
from app.utils.stable_id import canonical_json, id_for


@dataclass
class DedupeResult:
    groups: list[DedupeGroup]
    diagnostics: list[dict]
    candidate_count: int | None
    verified_pair_count: int | None
    is_complete: bool = True
    incomplete_reason: str | None = None


class DuplicateScorer:
    def __init__(self, alerts, config, source_settings):
        from app.services.capacity import AlertMap, AlertSequence
        bounded = alerts.mapping if isinstance(alerts, AlertSequence) else getattr(alerts, '_mapping', None)
        self.alerts = bounded if isinstance(bounded, AlertMap) else {a.alert_id: a for a in alerts}
        self.parameters = config.algorithm.duplicate
        self.settings = source_settings
        from app.services.capacity import execution_state, DiskScalarObjects
        state = execution_state()
        self.metadata = DiskScalarObjects(state.database(), 'duplicate_metadata') if state else {}
        self.cache = {}
        mappings = config.mapping_files
        for alert in alerts:
            context = alert.model_dump(mode="json")
            def mapped(kind):
                selected = [m for m in mappings["duplicate." + kind + "_mapping_files"] if m.source_type == alert.source_type.value]
                resolutions = [resolve_mapping(m, context) for m in selected]
                values = {canonical_json(r.output): r for r in resolutions if r.matched_rule_ids}
                if len(values) > 1:
                    raise MappingConflict(kind + ": conflicting mapping files")
                return next(iter(values.values()), None)
            payload = mapped("payload")
            rule = mapped("rule_equivalence")
            settings = source_settings[alert.source_namespace]
            targets = []
            if alert.host is not None:
                targets.append(("HOST", settings.asset_namespace or alert.source_namespace, alert.host))
            if alert.dst_ip is not None and alert.dst_port is not None:
                targets.append(("ENDPOINT", settings.network_namespace or alert.source_namespace, alert.dst_ip, alert.dst_port))
            rule_key = ("equivalent", rule.output["equivalence_key"]) if rule and rule.output else (
                "native", alert.source_namespace, alert.rule_id) if alert.rule_id else None
            origin = (alert.origin_namespace, alert.origin_record_id) if alert.origin_namespace else (
                alert.source_namespace, alert.source_record_id) if alert.source_record_id else None
            self.metadata[alert.alert_id] = {
                "payload": payload.payload_fingerprint if payload else None,
                "rule": rule_key, "targets": set(targets), "origin": origin,
                "time": datetime.fromisoformat(alert.timestamp.replace("Z", "+00:00")),
            }
        self.observation = None
        if config.algorithm.version in {"v3", "v4"}:
            from .observation import ObservationMatcher
            self.observation = ObservationMatcher(self.alerts, self.parameters.observation, self.metadata, source_settings)

    def score(self, left, right):
        key = tuple(sorted((left, right)))
        if key in self.cache:
            return self.cache[key]
        a, b = (self.alerts[i] for i in key)
        x, y = (self.metadata[i] for i in key)
        contradictions = any(getattr(a, name) is not None and getattr(b, name) is not None and
                             getattr(a, name) != getattr(b, name) for name in (
                                 "host", "src_ip", "dst_ip", "src_port", "dst_port", "account", "session",
                                 "process", "parent_process", "url", "file", "command"))
        source_exact = a.source_record_id is not None and (a.source_namespace, a.source_record_id, a.raw_fingerprint) == (
            b.source_namespace, b.source_record_id, b.raw_fingerprint)
        origin_exact = x["origin"] is not None and x["origin"] == y["origin"] and not contradictions
        # Reused native IDs with different raw content are conflicts, not lineage.
        reused_native = a.source_namespace == b.source_namespace and a.source_record_id is not None and a.source_record_id == b.source_record_id and a.raw_fingerprint != b.raw_fingerprint
        if reused_native:
            origin_exact = False
        gap = abs((x["time"] - y["time"]).total_seconds())
        features = {"rule": float(x["rule"] is not None and x["rule"] == y["rule"]),
                    "payload": float(x["payload"] is not None and x["payload"] == y["payload"]),
                    "target": float(bool(x["targets"] & y["targets"])),
                    "time": math.exp(-math.log(2) * gap / self.parameters.half_life_seconds)}
        score = 1.0 if source_exact or origin_exact else sum(getattr(self.parameters.feature_weights, k) * v for k, v in features.items())
        qualifies = source_exact or origin_exact or (not reused_native and not contradictions and gap <= self.parameters.window_seconds and
                     features["payload"] == features["target"] == 1 and score >= self.parameters.threshold)
        result = {"score": score, "qualifies": qualifies, "exact": source_exact or origin_exact,
                  "features": features, "gap_seconds": gap, "record_id_conflict": reused_native}
        if self.observation is not None:
            observed = self.observation.compare(a, b)
            result["observation_identity"] = observed
            if observed["equivalent"] and not reused_native:
                result["score"] = max(score, self.parameters.observation.equivalence_score)
                result["qualifies"] = True
        self.cache[key] = result
        return result

    def candidates(self):
        source_buckets, origin_buckets, approximate_buckets = defaultdict(list), defaultdict(list), defaultdict(list)
        conflicts = []
        observation_buckets = defaultdict(list)
        for identity in sorted(self.alerts):
            alert = self.alerts[identity]
            info = self.metadata[identity]
            if alert.source_record_id is not None:
                source_buckets[(alert.source_namespace, alert.source_record_id)].append(identity)
            if info["origin"]:
                origin_buckets[info["origin"]].append(identity)
            if info["payload"] is not None and info["rule"] is not None:
                for target in sorted(info["targets"]):
                    approximate_buckets[(info["payload"], target, info["rule"])].append(identity)
            if self.observation is not None:
                for key in self.observation.bucket_keys(identity):
                    observation_buckets[key].append(identity)
        pairs = set()
        for key, members in sorted(source_buckets.items()):
            hashes = {self.alerts[i].raw_fingerprint for i in members}
            if len(hashes) > 1:
                conflicts.append({"stage": "dedupe", "code": "source_record_id_conflict", "alert_ids": sorted(members)})
            by_hash = defaultdict(list)
            for identity in members:
                by_hash[self.alerts[identity].raw_fingerprint].append(identity)
            for subgroup in by_hash.values():
                pairs.update(combinations(sorted(subgroup), 2))
        for members in origin_buckets.values():
            pairs.update(combinations(sorted(members), 2))
        for members, window in [(m, self.parameters.window_seconds) for m in approximate_buckets.values()] + [
                (m, self.parameters.observation.window_seconds) for m in observation_buckets.values()]:
            members.sort(key=lambda i: (self.metadata[i]["time"], i))
            start = 0
            for end, current in enumerate(members):
                while (self.metadata[current]["time"] - self.metadata[members[start]]["time"]).total_seconds() > window:
                    start += 1
                for prior in members[start:end]:
                    pairs.add(tuple(sorted((prior, current))))
        return sorted(pairs), conflicts


def _deduplicate(alerts, config, source_settings) -> DedupeResult:
    scorer = DuplicateScorer(alerts, config, source_settings)
    candidates, diagnostics = scorer.candidates()
    ranked = sorted(candidates, key=lambda pair: (-scorer.score(*pair)["score"], pair))
    groups = {i: {i} for i in scorer.alerts}
    owners = {i: i for i in scorer.alerts}
    for left, right in ranked:
        a, b = owners[left], owners[right]
        if a == b:
            continue
        verified = []
        for x in sorted(groups[a]):
            for y in sorted(groups[b]):
                result = scorer.score(x, y)
                verified.append({"alert_ids": sorted((x, y)), **result})
                if not result["qualifies"]:
                    break
            if not verified[-1]["qualifies"]:
                break
        accepted = all(p["qualifies"] for p in verified)
        diagnostics.append({"stage": "dedupe", "pair": [left, right], "decision": "accept" if accepted else "reject", "verified_pairs": verified})
        if accepted:
            merged = groups.pop(a) | groups.pop(b)
            representative = min(merged)
            groups[representative] = merged
            for identity in merged:
                owners[identity] = representative
    output = []
    for members in sorted(groups.values(), key=min):
        if len(members) < 2:
            continue
        reasons, minimum = [], 1.0
        for left, right in combinations(sorted(members), 2):
            result = scorer.score(left, right)
            minimum = min(minimum, result["score"])
            data = {"code": ReasonCode.DUPLICATE, "message": "已核验相同来源事实" if result["exact"] else "已核验声明的请求特征、目标、规则及时间窗口",
                    "alert_ids": [left, right], "params": {"rule_id": "exact_origin" if result["exact"] else "payload_target_rule_time", "similarity": round(result["score"], 6)}}
            if result.get("observation_identity", {}).get("equivalent"):
                data["message"] = "已核验相同网络观测或告警内消息、作用域、极短时间窗及结构化上下文"
                data["params"]["rule_id"] = "observation_identity_v3"
            data["reason_id"] = id_for("Reason", data)
            reasons.append(Reason(**data))
        data = {"alert_ids": sorted(members), "representative_alert_id": min(members),
                "duplicate_score": round(minimum, 6), "reasons": reasons}
        data["group_id"] = id_for("DedupeGroup", data)
        output.append(DedupeGroup(**data))
    diagnostics.sort(key=canonical_json)
    return DedupeResult(sorted(output, key=lambda g: g.group_id), diagnostics, len(candidates), len(scorer.cache))


def deduplicate(alerts, config, source_settings) -> DedupeResult:
    try:
        return _deduplicate(alerts, config, source_settings)
    except MemoryError:
        # No partially verified grouping is published. There is no hidden top-K
        # budget or sampling fallback; the caller must mark the run incomplete.
        return DedupeResult([], [{"stage": "dedupe", "decision": "incomplete", "code": "resource_exhausted"}],
                            None, None, False, "dedupe_resource_exhausted")

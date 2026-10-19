"""Frozen controlled components; connectivity alone never authorizes union."""

from dataclasses import dataclass

from app.chains.nodes import maximum_severity, reason
from app.chains.reconstruction import validate_support
from app.correlation.conflicts import group_targets, pair_conflicts, target_diagnostic, targets
from app.models import Incident
from app.utils.stable_id import id_for


@dataclass
class ClusteringResult:
    incidents: list[Incident]
    support_cache: dict


def cluster_incidents(index, edges, scorer, diagnostic_sink=None):
    sink = diagnostic_sink or (lambda row: None)
    cfg = scorer.algorithm.clustering
    edge_map, cache = {}, {}
    for edge in sorted(edges, key=lambda e: e.edge_id):
        if edge.edge_id in edge_map:
            if edge_map[edge.edge_id] != edge:
                raise ValueError("conflicting_correlation_identity")
            continue
        edge_map[edge.edge_id] = edge
        cache[edge.edge_id] = validate_support(edge, index, scorer)
    eligible = sorted((e for e in edge_map.values() if cache[e.edge_id].score >= cfg.edge_threshold),
                      key=lambda e: (-cache[e.edge_id].score, e.edge_id))
    components = {rep: {rep} for rep in index.representatives}
    owner = {rep: rep for rep in index.representatives}
    target_values = {rep: group_targets(rep, index, scorer.settings) for rep in index.representatives}
    adjacency = {rep: [] for rep in index.representatives}
    for edge in eligible:
        adjacency[edge.source_alert_id].append(edge)
        adjacency[edge.target_alert_id].append(edge)
    hard_cache = {}

    def members(reps):
        return sorted(aid for rep in sorted(reps) for aid in index.groups[rep])

    def cross_edges(left, right):
        scan, other = (left, right) if len(left) <= len(right) else (right, left)
        found = {}
        for rep in sorted(scan):
            for edge in adjacency[rep]:
                endpoint = edge.target_alert_id if edge.source_alert_id == rep else edge.source_alert_id
                if endpoint in other:
                    found[(edge.source_alert_id, edge.target_alert_id)] = edge
        return sorted(found.values(), key=lambda e: (-cache[e.edge_id].score, e.edge_id))

    def hard_conflicts(left_ids, right_ids):
        for aid in left_ids:
            for bid in right_ids:
                a, b = index.alerts[aid], index.alerts[bid]
                # Same namespace cannot trigger cross-namespace isolation. The
                # existing verified session interface still runs for every pair.
                key = tuple(sorted((aid, bid)))
                if key not in hard_cache:
                    shared = sorted(set(a.entity_ids) & set(b.entity_ids))
                    relations, _ = scorer.verify_relations(a, b)
                    hard_cache[key] = pair_conflicts(a, b, index, scorer.algorithm, scorer.settings,
                                                     relations, shared, [])['hard']
                if hard_cache[key]:
                    return {"alert_ids": [aid, bid], "rules": hard_cache[key]}
        return None

    for edge in edge_map.values():
        if cache[edge.edge_id].score < cfg.edge_threshold:
            sink({"stage": "clustering", "edge_id": edge.edge_id, "decision": "reject",
                  "rule_id": "clustering.edge_threshold", "score": cache[edge.edge_id].score,
                  "support_key": [edge.source_alert_id, edge.target_alert_id]})
    # Reevaluate only after an actual union. At most N-1 successful rounds.
    for round_number in range(max(1, index.N)):
        changed, evaluated = False, set()
        for edge in eligible:
            lroot, rroot = owner[edge.source_alert_id], owner[edge.target_alert_id]
            if lroot == rroot:
                continue
            left, right = components[lroot], components[rroot]
            signature = tuple(sorted((tuple(sorted(left)), tuple(sorted(right)))))
            if signature in evaluated:
                continue
            evaluated.add(signature)
            supports = cross_edges(left, right)
            lids, rids = members(left), members(right)
            combined = lids + rids
            left_targets = [t for rep in sorted(left) for t in target_values[rep]]
            right_targets = [t for rep in sorted(right) for t in target_values[rep]]
            lt, rt = {t.key for t in left_targets}, {t.key for t in right_targets}
            propagation = [e for e in supports if cache[e.edge_id].relations]
            target_bridge = []
            for support in propagation:
                a = index.alerts[support.support_pair.alert_id_src]
                b = index.alerts[support.support_pair.alert_id_dst]
                at = {t.key for t in targets(a, index, scorer.settings)}
                bt = {t.key for t in targets(b, index, scorer.settings)}
                if at and bt and at != bt:
                    target_bridge.append(support)
            sizes = sorted((len(left), len(right)))
            needed = (cfg.bridge_min_edges_between_singletons if sizes == [1, 1]
                      else cfg.bridge_min_edges_with_singleton if sizes[0] == 1
                      else cfg.bridge_min_edges_between_non_singletons)
            span = (max(index.times[i] for i in combined) - min(index.times[i] for i in combined)) / 1000000
            rejects = []
            hard = hard_conflicts(lids, rids) if cfg.reject_component_hard_conflict else None
            if hard:
                rejects.append("clustering.component_hard_conflict")
            if span > cfg.max_incident_span_seconds:
                rejects.append("clustering.max_incident_span_seconds")
            if sum(sizes) > cfg.max_representatives:
                rejects.append("clustering.max_representatives")
            if lt and rt and lt != rt and not target_bridge:
                rejects.append("clustering.target_set_without_propagation")
            if len(supports) < needed and not (cfg.permit_explicit_relation_single_bridge and propagation):
                rejects.append("clustering.insufficient_independent_support")
            decision = "reject" if rejects else "accept"
            rule = rejects[0] if rejects else "clustering.controlled_components"
            guard_reason = reason("clustering_guard", combined,
                {"rule_id": rule, "decision": decision, "component_sizes": sizes},
                f"受控分量合并 {decision}；代表数量 {sizes}；规则 {rule}")
            sink({"stage": "clustering", "round": round_number, "edge_id": edge.edge_id,
                  "support_key": [edge.source_alert_id, edge.target_alert_id],
                  "component_representatives": [sorted(left), sorted(right)], "component_sizes": sizes,
                  "support_keys": [[e.source_alert_id, e.target_alert_id] for e in supports],
                  "required_support_count": needed, "span_seconds": span,
                  "left_targets": target_diagnostic(left_targets), "right_targets": target_diagnostic(right_targets),
                  "propagation": [{"edge_id": e.edge_id, "relations": [r.json_data() for r in cache[e.edge_id].relations]}
                                  for e in propagation],
                  "target_bridge_edge_ids": [e.edge_id for e in target_bridge], "hard_conflict": hard,
                  "decision": decision, "rule_id": rule, "rejection_codes": rejects,
                  "reason": guard_reason.model_dump(mode="json")})
            if not rejects:
                root = min(lroot, rroot)
                merged = left | right
                del components[lroot]
                del components[rroot]
                components[root] = merged
                for rep in sorted(merged):
                    owner[rep] = root
                changed = True
        if not changed:
            break
    internal = {root: [] for root in components}
    for edge in edge_map.values():
        root = owner[edge.source_alert_id]
        if root == owner[edge.target_alert_id]:
            internal[root].append(edge.edge_id)
    incidents = []
    for root, reps in sorted(components.items()):
        aids = members(reps)
        alerts = [index.alerts[aid] for aid in aids]
        data = {"alert_ids": aids, "start_time": min(a.timestamp for a in alerts),
                "end_time": max(a.timestamp for a in alerts), "severity": maximum_severity(alerts),
                "entity_ids": sorted({eid for a in alerts for eid in a.entity_ids}),
                "correlation_edge_ids": sorted(internal[root]),
                "summary": f"{len(aids)} 条安全告警，{len(reps)} 个事实组，{len(internal[root])} 条正式关联"}
        data["incident_id"] = id_for("Incident", data)
        incidents.append(Incident.model_validate(data))
    return ClusteringResult(sorted(incidents, key=lambda i: i.incident_id), cache)

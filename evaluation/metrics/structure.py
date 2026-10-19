"""Engineering structure and external temporal context, never quality truth."""

from collections import Counter


def structural_metrics(snapshot, mapping):
    inside = set(mapping["alert_windows"])
    known_alert_ids = set(snapshot.alerts)
    known_entity_ids = set(snapshot.entities)
    incident_sizes, nodes_per_chain, edges_per_chain, node_sizes, categories, sources = (Counter() for _ in range(6))
    incident_members, node_members = {}, {}
    incident_overlap = Counter()
    for inc in snapshot.records("incidents"):
        ids = set(inc["alert_ids"])
        if not ids or not ids <= known_alert_ids:
            raise ValueError("incident_evidence_reference_missing")
        incident_members[inc["incident_id"]] = ids
        incident_sizes[len({snapshot.owner[i] for i in ids})] += 1
        incident_overlap["inside_only" if ids <= inside else "outside_only" if ids.isdisjoint(inside) else "mixed"] += 1
    flattened = [i for ids in incident_members.values() for i in ids]
    if len(flattened) != len(snapshot.alerts) or set(flattened) != set(snapshot.alerts):
        raise ValueError("incident_membership_not_partition")
    traced_nodes = reason_nodes = 0
    node_overlap = Counter()
    for node in snapshot.records("chain_nodes"):
        ids = set(node["alert_ids"])
        if not ids or not ids <= incident_members.get(node["incident_id"], set()) or not set(node["entity_ids"]) <= known_entity_ids:
            raise ValueError("node_evidence_reference_missing")
        node_members[node["node_id"]] = ids
        traced_nodes += 1
        reason_nodes += bool(node["reasons"])
        node_sizes[len(ids)] += 1
        node_overlap["inside_only" if ids <= inside else "outside_only" if ids.isdisjoint(inside) else "mixed"] += 1
    chain_overlap = Counter()
    for chain in snapshot.records("attack_chains"):
        ids = {i for n in chain["nodes"] for i in n["alert_ids"]}
        if ids != incident_members[chain["incident_id"]] or any(set(n["alert_ids"]) != node_members.get(n["node_id"]) for n in chain["nodes"]):
            raise ValueError("chain_membership_mismatch")
        nodes_per_chain[len(chain["nodes"])] += 1
        edges_per_chain[len(chain["edges"])] += 1
        chain_overlap["inside_only" if ids <= inside else "outside_only" if ids.isdisjoint(inside) else "mixed"] += 1
    for a in snapshot.alerts.values():
        categories[a["category"]] += 1
        sources[a["source_type"]] += 1
    n_inc = len(incident_members)
    temporal_sources = Counter(snapshot.alerts[i]["source_type"] for i in inside)
    per_window = []
    for w in mapping["windows"]:
        ids = set(w["alert_ids"])
        per_window.append({"window_id": w["window_id"], "alert_count": len(ids),
            "incident_count_with_timestamp_overlap": sum(bool(m & ids) for m in incident_members.values()),
            "node_count_with_timestamp_overlap": sum(bool(m & ids) for m in node_members.values()),
            "definition": "member alert timestamp overlap only"})
    def fractions(counts):
        total = sum(counts.values())
        return {k: v/total if total else None for k,v in counts.items()}
    return {"diagnostic_kind": "structural_engineering_not_accuracy", "incident_count": n_inc,
            "singleton_incident_count": incident_sizes[1], "singleton_incident_ratio": incident_sizes[1] / n_inc if n_inc else None,
            "incident_representative_size_distribution": dict(sorted(incident_sizes.items())),
            "chain_node_count_distribution": dict(sorted(nodes_per_chain.items())), "chain_edge_count_distribution": dict(sorted(edges_per_chain.items())),
            "node_alert_count_distribution": dict(sorted(node_sizes.items())), "category_distribution": dict(sorted(categories.items())),
            "source_distribution": dict(sorted(sources.items())), "node_traceability_rate": 1.0 if traced_nodes else None,
            "node_reason_coverage": reason_nodes / traced_nodes if traced_nodes else None,
            "raw_fingerprint_schema_validation": "all CanonicalAlerts validated against retained raw_alert during snapshot load",
            "grounding_from_completed_analysis": snapshot.manifest["summary"].get("grounding"),
            "temporal_context": {"incident_overlap": dict(incident_overlap), "chain_overlap": dict(chain_overlap), "node_overlap": dict(node_overlap),
                "incident_overlap_fractions": fractions(incident_overlap), "chain_overlap_fractions": fractions(chain_overlap),
                "node_overlap_fractions": fractions(node_overlap), "window_alert_source_distribution": dict(temporal_sources),
                "per_window_object_counts": per_window,
                "covered_attack_windows": mapping["mapped"], "total_attack_windows": mapping["selected_rows"],
                "window_coverage": mapping["mapped"] / mapping["selected_rows"],
                "definition": "object member alert timestamps in union of selected [start,end); no attack membership assertion"},
            "incident_quality": {"status": "unavailable", "reason": "not_evaluable_from_current_gt: no_gold_incident_membership"},
            "chain_quality": {"status": "unavailable", "reason": "not_evaluable: no_gold_chain_nodes_edges_order_or_direction"},
            "ai_claim_quality": {"status": "unavailable", "reason": "AI outside this Task"}}

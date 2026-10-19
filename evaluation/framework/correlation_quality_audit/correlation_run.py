"""End-to-end read-only audit and artifact generation."""

from collections import Counter, defaultdict
from datetime import datetime
import json
import hashlib
import math
from pathlib import Path
import time

from .correlation_quality import (FAMILIES, SCORE_BOUNDS, TIME_BOUNDS, bucket, capture_integrity,
    classify, compare_integrity, csv_output, digest, distribution, effective_contributions,
    entity_frequency, graph_statistics, hot_entities, offline_evaluation, quantile,
    read_json, records, sampled, source_pair, write_json, observation_proxies)


def dt(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def ratio(count, total):
    return count / total if total else None


def describe_alert(alert, entities):
    fields = ("alert_id", "timestamp", "source_namespace", "source_type", "sensor", "rule_id",
              "signature", "alert_type", "category", "severity", "src_ip", "dst_ip", "src_port",
              "dst_port", "host", "account", "session", "url", "process", "parent_process")
    return {**{f: alert.get(f) for f in fields}, "key_entities": [
        {k: entities[eid][k] for k in ("entity_id", "type", "scope", "value")} for eid in alert["entity_ids"]],
        "field_provenance": alert["field_provenance"]}


def scan_diagnostics(path, edges, alerts):
    """Stream the full file. No sampling of accepted/rejected decision counts."""
    formal = {e["edge_id"]: e for e in edges}
    accepted, decisions, source_decisions, guard_counts = {}, Counter(), Counter(), Counter()
    count, member_count, candidate_count, clustering_count = 0, 0, 0, 0
    processed_bytes, started = 0, time.monotonic()
    bounded = None
    with Path(path).open("rb") as handle:
        for line in handle:
            processed_bytes += len(line)
            if b'"stage":"member_score"' in line:
                member_count += 1
            elif b'"stage":"candidate"' in line:
                candidate_count += 1
            elif b'"stage":"correlation_decision"' in line:
                row = json.loads(line)
                count += 1
                decisions[row["decision"]] += 1
                pair = row["support_key"]
                source_decisions[(source_pair(alerts[pair[0]], alerts[pair[1]]), row["decision"])] += 1
                if row["decision"] == "accept":
                    eid = row["edge_id"]
                    if eid in accepted or eid not in formal:
                        raise ValueError("duplicate_or_unknown_formal_decision")
                    if row["support_pair"] != list(formal[eid]["support_pair"].values()):
                        # JSON key order is not part of support_pair semantics.
                        p = formal[eid]["support_pair"]
                        if row["support_pair"] != [p["alert_id_src"], p["alert_id_dst"]]:
                            raise ValueError("diagnostic_support_pair_mismatch")
                    accepted[eid] = row
                if count % 100000 == 0:
                    print(f"diagnostics decisions={count} bytes={processed_bytes} elapsed={time.monotonic()-started:.1f}s", flush=True)
            elif b'"stage":"clustering"' in line:
                row = json.loads(line)
                clustering_count += 1
                guard_counts[(row["decision"], row["rule_id"])] += 1
            elif b'"stage":"bounded_diagnostics_summary"' in line:
                bounded = json.loads(line)['summary']
    if set(accepted) != set(formal):
        raise ValueError("formal_edge_missing_accepted_diagnostic")
    if bounded is not None:
        # Same edge-quality policy; only the diagnostic storage reader changes.
        assert bounded['exact'] and bounded['counts'].get('accept',0) == len(formal)
        counts = bounded['counts']
        return accepted, dict(scored_candidates=counts['correlation_decision'],
            accepted_candidates=counts.get('accept',0),rejected_candidates=counts.get('reject',0),
            member_scores=counts['member_score'],candidate_records=counts['candidate'],
            clustering_decision_records=counts.get('clustering',0),
            source_candidate_decisions=bounded['source_candidate_decisions'],
            clustering_guards=bounded['clustering_guards'],scan_bytes=processed_bytes,
            scan_seconds=time.monotonic()-started,diagnostic_storage='bounded-diagnostics-v1')
    return accepted, {"scored_candidates": count, "accepted_candidates": decisions["accept"],
        "rejected_candidates": decisions["reject"], "member_scores": member_count,
        "candidate_records": candidate_count, "clustering_decision_records": clustering_count,
        "source_candidate_decisions": [{"source_pair": p, "decision": d, "count": c}
                                       for (p, d), c in sorted(source_decisions.items())],
        "clustering_guards": [{"decision": d, "rule_id": r, "count": c} for (d, r), c in sorted(guard_counts.items())],
        "scan_bytes": processed_bytes, "scan_seconds": time.monotonic() - started}


def aggregate_contributions(edges):
    values, present, combinations, rows = defaultdict(list), Counter(), Counter(), []
    max_error = 0
    for edge in edges:
        families, dims, penalties = effective_contributions(edge)
        legacy = edge["score_breakdown"]["contributions"]
        recomputed = sum(families.values()) + sum(penalties.values())
        max_error = max(max_error, abs(recomputed - edge["score_breakdown"]["raw_total"]))
        if abs(recomputed - edge["score_breakdown"]["raw_total"]) > .00001:
            raise ValueError("v2_additive_attribution_mismatch")
        contributions = {**{f"v2.family.{k}": v for k, v in families.items()},
                         **{f"v2.dimension.{k}": v for k, v in dims.items()},
                         **{f"penalty.{k}": v for k, v in penalties.items()},
                         **{f"legacy.{k}": v for k, v in legacy.items()}}
        # Include absent/zero dimensions for a fair all-edge mean denominator.
        for d in edge["score_breakdown"]["evidence_v2"]["dimensions"]:
            contributions.setdefault("v2.dimension." + d["dimension"], 0)
        for key, value in contributions.items():
            values[key].append(value)
            present[key] += int(value != 0)
        matched = edge["score_breakdown"]["evidence_v2"]["matched_evidence"]
        combinations[" + ".join(matched)] += 1
        rows.append({"edge_id": edge["edge_id"], "score": edge["score"],
                     "v2_family_contributions": families, "v2_dimension_contributions": dims,
                     "penalties": penalties, "legacy_contributions": legacy, "recomputed_raw_total": recomputed,
                     "normalization_amplification": 1 / edge["score_breakdown"]["evidence_v2"]["available_weight"]})
    aggregated = [{"contribution_type": k, "nonzero_count": present[k], "edge_ratio": ratio(present[k], len(edges)),
                   "mean_all_edges": distribution(v)["mean"], "median_all_edges": distribution(v)["median"],
                   "max": max(v), "min": min(v)} for k, v in sorted(values.items())]
    return aggregated, combinations, rows, max_error


def old_comparison(root, record, alerts, edges):
    """Use an immutable historical snapshot only after exact canonical equality."""
    matches = []
    for path in (root / "data/processed").glob("*/analysis.json"):
        previous = read_json(path)
        if previous["analysis_id"] == record["analysis_id"]:
            continue
        if (previous.get("status") == "completed" and previous.get("is_complete")
                and previous.get("dataset_digest") == record["dataset_digest"]
                and previous.get("mapping_digest") == record["mapping_digest"]
                and "v2" not in previous.get("algorithm_version", "")):
            matches.append((previous["analysis_id"], path.parent, previous))
    for identity, directory, previous in sorted(matches):
        canonical = {a["alert_id"]: a for a in records(directory / "alerts.jsonl")}
        if canonical != alerts:
            continue
        old_edges = list(records(directory / "correlation_edges.jsonl"))
        old_pairs = {tuple(sorted((e["source_alert_id"], e["target_alert_id"]))) for e in old_edges}
        new_pairs = {tuple(sorted((e["source_alert_id"], e["target_alert_id"]))) for e in edges}
        old_groups = list(records(directory / "dedupe_groups.jsonl"))
        new_groups = list(records(root / "data/processed" / record["analysis_id"] / "dedupe_groups.jsonl"))
        if old_groups != new_groups:
            continue
        previous_manifest = read_json(root / "outputs/analyses" / identity / "manifest.json")
        if any(digest(directory / name) != expected for name, expected in previous_manifest["files"].items()):
            raise ValueError("historical_snapshot_manifest_mismatch")
        return {"status": "available_frozen_snapshot_comparison", "old_analysis_id": identity,
                "old_algorithm_version": previous["algorithm_version"], "old_config_hash": previous["config_hash"],
                "canonical_alerts_exactly_equal": True, "dedupe_groups_exactly_equal": True,
                "dataset_digest_equal": True, "mapping_digest_equal": True, "old_edge_count": len(old_edges),
                "v2_edge_count": len(edges), "newly_added_edges": len(new_pairs-old_pairs),
                "retained_edges": len(old_pairs & new_pairs), "removed_edges": len(old_pairs-new_pairs),
                "added_pair_ids": sorted(new_pairs-old_pairs),
                "limitation": "Historical production snapshot comparison, no algorithm replay or GT recall claim; candidate sets differ by version."}
    return {"status": "comparison_not_available", "reason": "No completed historical snapshot with exactly equal canonical alerts, groups and dataset/mapping digests."}


def run_audit(root, destination, *, receipt=None):
    root, destination = Path(root), Path(destination)
    before = read_json(destination / "before_hashes.json")
    receipt = read_json(receipt or root / "outputs/correlation_v2/REAL_DATA_RESULT.json")
    aid = receipt["analysis_id"]
    domain, details = root / "data/processed" / aid, root / "outputs/analyses" / aid
    record, run, manifest = [read_json(p) for p in (domain/"analysis.json", domain/"run.json", details/"manifest.json")]
    if record["status"] != "completed" or not record["is_complete"] or record["candidate_truncated"]:
        raise ValueError("audit_requires_completed_snapshot")
    from app.services.storage import parse_analysis_record, restore_config
    from app.services.datasets import load_dataset
    from app.utils.stable_id import content_digest, id_for
    from app.models import CorrelationEdge
    parsed = parse_analysis_record(record, manifest.get("execution"))
    config = record["config_snapshot"]["algorithm"]
    if load_dataset(root, scene_id="russellmitchell", config_version=config["version"]).config.snapshot != config:
        raise ValueError("current_configuration_differs_from_formal_snapshot")
    if restore_config(config).mapping_digest != record["mapping_digest"]:
        raise ValueError("mapping_digest_mismatch")
    for name, expected in manifest["files"].items():
        if before[(domain/name).relative_to(root).as_posix()] != expected:
            raise ValueError("domain_manifest_mismatch:" + name)
    if before[(details/"diagnostics.jsonl").relative_to(root).as_posix()] != manifest["diagnostics_digest"]:
        raise ValueError("detail_manifest_mismatch:diagnostics.jsonl")
    # The production frequency digest hashes canonical JSON content, not bytes.
    if content_digest(read_json(details/"frequency_snapshot.json")) != manifest["frequency_digest"]:
        raise ValueError("detail_manifest_mismatch:frequency_snapshot.json")
    for file in run["input_files"]:
        if before[file["path"]] != file["sha256"]:
            raise ValueError("raw_input_differs_from_snapshot")
    print("snapshot/input/config hashes verified; reading formal objects", flush=True)
    alerts = {a["alert_id"]: a for a in records(domain/"alerts.jsonl")}
    entities = {e["entity_id"]: e for e in records(domain/"entities.jsonl")}
    groups = list(records(domain/"dedupe_groups.jsonl"))
    edges = list(records(domain/"correlation_edges.jsonl"))
    incidents = list(records(domain/"incidents.jsonl"))
    if sorted(alerts) != record["input_alert_ids"] or content_digest([[i, alerts[i]["raw_fingerprint"]] for i in sorted(alerts)]) != record["dataset_digest"]:
        raise ValueError("canonical_input_fingerprint_mismatch")
    owner = {a: a for a in alerts}
    for group in groups:
        for member in group["alert_ids"]:
            owner[member] = group["representative_alert_id"]
    reps = sorted(set(owner.values()))
    for edge in edges:
        CorrelationEdge.model_validate(edge)
        if id_for("CorrelationEdge", edge) != edge["edge_id"]:
            raise ValueError("edge_stable_identity_mismatch")
        pair = edge["support_pair"]
        if owner[pair["alert_id_src"]] != edge["source_alert_id"] or owner[pair["alert_id_dst"]] != edge["target_alert_id"]:
            raise ValueError("support_pair_outside_endpoint_groups")
        if edge["score_breakdown"]["config_hash"] != record["config_hash"]:
            raise ValueError("edge_configuration_mismatch")
        if any(eid not in entities for eid in edge["entity_ids"]):
            raise ValueError("missing_entity")
    frequency = entity_frequency(entities, owner)
    frozen_frequency = read_json(details/"frequency_snapshot.json")
    if frozen_frequency["N"] != len(reps) or frequency != {e["entity_id"]: e["df"] for e in frozen_frequency["entities"]}:
        raise ValueError("frequency_snapshot_recompute_mismatch")
    hot = hot_entities(frequency, len(reps), config["candidate"])
    accepted, diagnostics = scan_diagnostics(details/"diagnostics.jsonl", edges, alerts)
    if diagnostics["scored_candidates"] != run["scored_candidate_count"]:
        raise ValueError("diagnostic_scored_count_mismatch")
    for edge in edges:
        edge["score_unrounded"] = accepted[edge["edge_id"]]["score"]
    pairs = [(e["source_alert_id"], e["target_alert_id"]) for e in edges]
    adjacency, components = graph_statistics(reps, pairs)
    degrees = {n: len(v) for n, v in adjacency.items()}
    active_degrees = [d for d in degrees.values() if d]
    hub_threshold = max(3, math.ceil(quantile(active_degrees, 99)), math.ceil(2 * quantile(active_degrees, 50))) if active_degrees else 3
    hubs = {n for n, degree in degrees.items() if degree >= hub_threshold}
    component_owner = {n: c for c in components for n in c["alert_ids"]}
    score_values = [e["score_unrounded"] for e in edges]
    threshold = config["score"]["correlation_threshold"]
    near = lambda e: threshold <= e["score_unrounded"] < threshold + .05
    rows, annotations, entity_edges, source_edges, rule_edges, signatures = [], {}, defaultdict(set), defaultdict(list), defaultdict(list), defaultdict(list)
    time_counts = Counter({bucket(lo,TIME_BOUNDS):0 for lo in TIME_BOUNDS[:-1]})
    proxy_counts, class_counts, relation_counts, identity_counts = Counter(), Counter(), Counter(), Counter()
    time_dominated, time_largest, time_only = 0, 0, 0
    incidence = {a: i["incident_id"] for i in incidents for a in i["alert_ids"]}
    if len(incidence) != len(alerts) or set(incidence) != set(alerts):
        raise ValueError("incident_membership_not_complete")
    for edge in edges:
        p = edge["support_pair"]
        a, b = alerts[p["alert_id_src"]], alerts[p["alert_id_dst"]]
        observation = observation_proxies(a, b, edge["score_breakdown"]["evidence_v2"])
        component = component_owner[edge["source_alert_id"]]
        annotation = classify(edge, entities, frequency, len(reps), hot, config,
            hub=edge["source_alert_id"] in hubs or edge["target_alert_id"] in hubs,
            dense=component["node_count"] >= 3 and component["density"] > .8,
            giant=component["node_count"] > config["clustering"]["max_representatives"],
            repeated=observation["repeated_observation_proxy"],
            same_endpoint=observation["network_continuity_same_endpoint_proxy"])
        annotations[edge["edge_id"]] = annotation
        class_counts[annotation["classification"]] += 1
        relation_counts[annotation["relation_support"]] += 1
        for flag in annotation["risk_flags"]:
            proxy_counts[flag] += 1
        shared = annotation["matched_entity_ids"]
        for eid in shared:
            entity_edges[eid].add(edge["edge_id"])
        gap = abs((dt(a["timestamp"]) - dt(b["timestamp"])).total_seconds())
        time_counts[bucket(gap, TIME_BOUNDS)] += 1
        families, dims, penalties = effective_contributions(edge)
        largest_time = families["time"] >= max(families.values())
        time_largest += int(largest_time)
        dominated = largest_time and not annotation["discriminative_entity_ids"] and annotation["relation_support"] != "relation_supported"
        time_dominated += int(dominated)
        time_only += int(not shared and annotation["relation_support"] != "relation_supported" and all(v == 0 for k,v in families.items() if k != "time"))
        sp = source_pair(a, b)
        source_edges[sp].append(edge)
        rule_key = tuple((v["source_namespace"], v["rule_id"]) for v in sorted((a,b), key=lambda v: (v["source_namespace"],v["rule_id"] or "")))
        rule_edges[str(rule_key)].append(edge)
        signatures[str(tuple(sorted((a["signature"] or "<missing>",b["signature"] or "<missing>"))))].append(edge)
        same = {}
        for field in ("rule_id", "signature", "alert_type", "category"):
            valid = a[field] is not None and b[field] is not None and (field != "category" or a[field] != "unknown")
            equal = valid and a[field] == b[field]
            same[field] = equal
            identity_counts["same_"+field] += int(equal)
            identity_counts["comparable_"+field] += int(valid)
        identity_counts["same_category_literal_including_unknown"] += int(a["category"] == b["category"])
        rows.append({"edge_id": edge["edge_id"], "alert_a": a["alert_id"], "alert_b": b["alert_id"],
            "representative_a": edge["source_alert_id"], "representative_b": edge["target_alert_id"],
            "timestamp_a": a["timestamp"], "timestamp_b": b["timestamp"], "delta_time_seconds": gap,
            "source_a": a["source_namespace"], "source_b": b["source_namespace"],
            "signature_a": a["signature"], "signature_b": b["signature"], "rule_a": a["rule_id"], "rule_b": b["rule_id"],
            "src_ip_a": a["src_ip"], "dst_ip_a": a["dst_ip"], "src_ip_b": b["src_ip"], "dst_ip_b": b["dst_ip"],
            "score": edge["score"], "score_unrounded": edge["score_unrounded"],
            "score_breakdown": edge["score_breakdown"], "v2_family_contributions": families,
            "v2_dimension_contributions": dims, "evidence_list": edge["reasons"],
            "alert_details": [describe_alert(a,entities), describe_alert(b,entities)],
            "key_entities": [{**{k: entities[eid][k] for k in ("entity_id","type","scope","value")},
                              "df": frequency[eid], "possible_common_entity": eid in hot} for eid in shared],
            "same_fields": same, "source_pair": sp, "cross_source": a["source_namespace"] != b["source_namespace"],
            "same_incident": incidence[edge["source_alert_id"]] == incidence[edge["target_alert_id"]],
            "near_threshold": near(edge), "component_id": component["component_id"],
            "component_size": component["node_count"], "audit_classification": annotation["classification"],
            "relation_support": annotation["relation_support"], "risk_flags": annotation["risk_flags"],
            "observation_proxies": observation,
            "embedded_payload_refs": [{"alert_id":a["alert_id"],"pointer":"/full_log"},
                                      {"alert_id":b["alert_id"],"pointer":"/full_log"}] if observation["identical_embedded_payload"] else [],
            "embedded_payload_sha256": hashlib.sha256(a["raw_alert"]["full_log"].encode()).hexdigest() if observation["identical_embedded_payload"] and isinstance(a["raw_alert"]["full_log"],str) else None,
            "raw_alert_location_a": a["raw_alert"].get("location") if isinstance(a["raw_alert"],dict) else None,
            "raw_alert_location_b": b["raw_alert"].get("location") if isinstance(b["raw_alert"],dict) else None,
            "source_record_id_a": a["source_record_id"], "source_record_id_b": b["source_record_id"],
            "time_dominated": dominated, "reason": annotation["reason"]})
    by_id = {r["edge_id"]: r for r in rows}
    contributions, combinations, decomposition, error = aggregate_contributions(edges)
    csv_output(destination/"edge_contributions.csv", decomposition)
    csv_output(destination/"edge_evidence_distribution.csv", contributions)
    csv_output(destination/"evidence_combinations.csv", [{"combination": k, "count":v, "ratio":ratio(v,len(edges))} for k,v in combinations.most_common()])
    csv_output(destination/"edge_score_distribution.csv", [{"bucket":bucket(lo,SCORE_BOUNDS), "count": sum(bucket(v,SCORE_BOUNDS)==bucket(lo,SCORE_BOUNDS) for v in score_values)} for lo in SCORE_BOUNDS[:-1]])
    csv_output(destination/"edge_time_distribution.csv", [{"bucket":bucket(lo,TIME_BOUNDS),"count":time_counts[bucket(lo,TIME_BOUNDS)]} for lo in TIME_BOUNDS[:-1]])
    source_rows = [{"source_pair":sp,"edge_count":len(es),"percentage":100*len(es)/len(edges),
                    "avg_score":distribution([e["score_unrounded"] for e in es])["mean"],
                    "median_score":distribution([e["score_unrounded"] for e in es])["median"]} for sp,es in sorted(source_edges.items())]
    csv_output(destination/"edge_source_pair_distribution.csv", source_rows)
    for name,predicate in (("near_threshold_edges",lambda r:r["near_threshold"]),
                           ("cross_source_edges",lambda r:r["cross_source"]),
                           ("weak_evidence_edges",lambda r:r["audit_classification"] in {"weak","suspicious"})):
        csv_output(destination/(name+".csv"), (r for r in rows if predicate(r)), fields=list(rows[0]) if rows else None)
    all_entity_rows = []
    for eid, ids in entity_edges.items():
        involved = {n for edge_id in ids for n in (by_id[edge_id]["representative_a"],by_id[edge_id]["representative_b"])}
        gaps = [by_id[edge_id]["delta_time_seconds"] for edge_id in ids]
        observed_times = [dt(alerts[a]["timestamp"]) for a in entities[eid]["alert_ids"]]
        all_entity_rows.append({"entity_id":eid,"type":entities[eid]["type"],"scope":entities[eid]["scope"],"value":entities[eid]["value"],
            "df":frequency[eid],"df_ratio":frequency[eid]/len(reps),"edge_count":len(ids),"unique_alerts":len(involved),
            "avg_graph_degree":sum(degrees[n] for n in involved)/len(involved),"max_graph_degree":max(degrees[n] for n in involved),
            "edge_time_gap":distribution(gaps),"entity_observation_span_seconds":(max(observed_times)-min(observed_times)).total_seconds(),
            "possible_common_entity":eid in hot})
    all_entity_rows.sort(key=lambda r:(-r["edge_count"],r["entity_id"]))
    csv_output(destination/"high_degree_entities.csv",all_entity_rows[:20])
    csv_output(destination/"all_entity_statistics.csv",all_entity_rows)
    type_rows = []
    for kind in sorted(config["entity"]["weights"]):
        ids = {eid for eid in entity_edges if entities[eid]["type"]==kind}
        participating_edges = set().union(*(entity_edges[eid] for eid in ids)) if ids else set()
        involved = {n for eid in ids for a in entities[eid]["alert_ids"] for n in [owner[a]] if degrees[n]}
        type_rows.append({"entity_type":kind,"entity_count":len(ids),"total_entity_count":sum(e["type"]==kind for e in entities.values()),
            "edge_count":len(participating_edges),"unique_alerts":len(involved),
            "avg_degree":sum(degrees[n] for n in involved)/len(involved) if involved else 0,
            "max_degree":max((degrees[n] for n in involved),default=0)})
    csv_output(destination/"edge_entity_distribution.csv",type_rows)
    top_nodes = sorted(reps,key=lambda n:(-degrees[n],n))
    incident_edges = defaultdict(list)
    for r in rows:
        incident_edges[r["representative_a"]].append(r)
        incident_edges[r["representative_b"]].append(r)
    csv_output(destination/"high_degree_alerts.csv", [{**describe_alert(alerts[n],entities),"degree":degrees[n],
        "main_association_reasons":dict(Counter(d["dimension"] for r in incident_edges[n] for d in r["score_breakdown"]["evidence_v2"]["dimensions"] if d["state"]=="AVAILABLE_MATCH"))} for n in top_nodes[:20]])
    component_rows = []
    for c in components:
        member_alerts = [alerts[n] for n in c["alert_ids"]]
        entity_counts = Counter(eid for a in member_alerts for eid in a["entity_ids"])
        component_rows.append({k:v for k,v in c.items() if k!="alert_ids"} | {
            "start_time": min(a["timestamp"] for a in member_alerts),"end_time":max(a["timestamp"] for a in member_alerts),
            "duration_seconds":(max(dt(a["timestamp"]) for a in member_alerts)-min(dt(a["timestamp"]) for a in member_alerts)).total_seconds(),
            "source_distribution":dict(Counter(a["source_namespace"] for a in member_alerts)),
            "rule_distribution":dict(Counter(str((a["source_namespace"],a["rule_id"])) for a in member_alerts)),
            "entity_distribution":dict(Counter(entities[eid]["type"] for eid in entity_counts)),
            "top_entities":[{"entity_id":eid,"value":entities[eid]["value"],"type":entities[eid]["type"],"member_alert_count":n,"df":frequency[eid]} for eid,n in entity_counts.most_common(10)],
            "hub_nodes":sum(n in hubs for n in c["alert_ids"]),
            "exceeds_incident_size_guard":c["node_count"]>config["clustering"]["max_representatives"],
            "exceeds_incident_span_guard":(dt(max(a["timestamp"] for a in member_alerts))-dt(min(a["timestamp"] for a in member_alerts))).total_seconds()>config["clustering"]["max_incident_span_seconds"]})
    csv_output(destination/"component_statistics.csv",component_rows)
    suspicious_components = [c for c in component_rows if c["exceeds_incident_size_guard"] or c["exceeds_incident_span_guard"] or (c["node_count"]>=3 and c["density"]>.8)]
    csv_output(destination/"suspicious_components.csv",suspicious_components)
    dense_components = sorted([c for c in component_rows if c["node_count"]>=3 and c["density"]>.8],key=lambda c:(-c["edge_count"],c["component_id"]))
    csv_output(destination/"high_density_components.csv",dense_components[:20])
    # Same-rule induced components reveal cliques hidden inside larger mixed components.
    rule_cliques = []
    for rule_key, es in rule_edges.items():
        valid = [e for e in es if alerts[e["support_pair"]["alert_id_src"]]["rule_id"] is not None and
                 alerts[e["support_pair"]["alert_id_src"]]["rule_id"]==alerts[e["support_pair"]["alert_id_dst"]]["rule_id"]]
        nodes = {n for e in valid for n in (e["source_alert_id"],e["target_alert_id"])}
        _, subcomponents = graph_statistics(nodes,[(e["source_alert_id"],e["target_alert_id"]) for e in valid])
        for c in subcomponents:
            if c["node_count"]>=3 and c["density"]>.8:
                rule_cliques.append({"rule_pair":rule_key,**{k:v for k,v in c.items() if k!="alert_ids"}})
    rule_cliques.sort(key=lambda c:(-c["edge_count"],c["component_id"]))
    csv_output(destination/"same_rule_cliques.csv",rule_cliques)
    csv_output(destination/"rule_signature_pairs.csv", [{"kind":kind,"pair":key,"edge_count":len(es),"avg_score":sum(e["score_unrounded"] for e in es)/len(es)} for kind,source in (("rule",rule_edges),("signature",signatures)) for key,es in sorted(source.items(),key=lambda kv:(-len(kv[1]),kv[0]))[:20]])
    utility_rows = []
    high_risk = Counter({key:0 for key in ("total","no_admitted_candidate","formal_edge_but_not_clustered",
                                          "candidates_below_threshold_no_formal_edge","candidates_all_fail_evidence_or_guard")})
    for incident in incidents:
        aids, rep_ids = incident["alert_ids"],{owner[a] for a in incident["alert_ids"]}
        if len(aids)>1:
            utility_rows.append({"incident_id":incident["incident_id"],"alert_count":len(aids),"representative_count":len(rep_ids),
                "edge_count":len(incident["correlation_edge_ids"]),"duration_seconds":(dt(incident["end_time"])-dt(incident["start_time"])).total_seconds(),
                "source_diversity":len({alerts[a]["source_namespace"] for a in aids}),"entity_diversity":len(incident["entity_ids"]),
                "rule_diversity":len({(alerts[a]["source_namespace"],alerts[a]["rule_id"]) for a in aids}),
                "dedupe_only":len(rep_ids)==1})
        triage = incident.get("single_alert_triage")
        if triage and triage["risk_level"] in {"high","critical"}:
            high_risk["total"] += 1
            if triage["candidate_count"]==0:
                high_risk["no_admitted_candidate"] += 1
            elif triage["formal_edge_count"]:
                high_risk["formal_edge_but_not_clustered"] += 1
            elif triage["rejection_counts"].get("REJECT_LOW_SCORE",0):
                high_risk["candidates_below_threshold_no_formal_edge"] += 1
            else:
                high_risk["candidates_all_fail_evidence_or_guard"] += 1
    csv_output(destination/"incident_statistics.csv",utility_rows)
    strata = {"high_score":[r for r in rows if r["score_unrounded"]>=.8],
        "medium_score":[r for r in rows if threshold+.05<=r["score_unrounded"]<.8],
        "near_threshold":[r for r in rows if r["near_threshold"]],
        "same_source":[r for r in rows if not r["cross_source"]],"cross_source":[r for r in rows if r["cross_source"]],
        "hub_related":[r for r in rows if "hub_endpoint" in r["risk_flags"]],
        "weak_evidence":[r for r in rows if r["audit_classification"] in {"weak","suspicious"}]}
    selections = defaultdict(list)
    for stratum, population in strata.items():
        for row in sampled(population,42,stratum):
            selections[row["edge_id"]].append(stratum)
    with (destination/"manual_review_samples.jsonl").open("w",encoding="utf-8",newline="\n") as handle:
        for eid in sorted(selections):
            handle.write(json.dumps({**by_id[eid],"sampling_strata":selections[eid],"sampling_seed":42},ensure_ascii=False,sort_keys=True)+"\n")
    top_groups = {"highest_score":sorted(rows,key=lambda r:(-r["score_unrounded"],r["edge_id"]))[:20],
        "near_threshold":sorted(strata["near_threshold"],key=lambda r:(r["score_unrounded"],r["edge_id"]))[:20],
        "weak_evidence":sorted(strata["weak_evidence"],key=lambda r:(r["audit_classification"]!="suspicious",-r["score_unrounded"],r["edge_id"]))[:20],
        "hub_associated":sorted(strata["hub_related"],key=lambda r:(-max(degrees[r["representative_a"]],degrees[r["representative_b"]]),r["edge_id"]))[:20],
        "cross_source":sorted(strata["cross_source"],key=lambda r:(-r["score_unrounded"],r["edge_id"]))[:20]}
    write_json(destination/"representative_edge_samples.json",top_groups)
    with (destination/"all_edge_audit.jsonl").open("w",encoding="utf-8",newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row,ensure_ascii=False,sort_keys=True)+"\n")
    evaluation = offline_evaluation(root,alerts)
    write_json(destination/"offline_evaluation.json",evaluation)
    comparison = old_comparison(root,record,alerts,edges)
    if comparison.get("status")=="available_frozen_snapshot_comparison":
        added = set(tuple(p) for p in comparison.pop("added_pair_ids"))
        comparison["new_edge_classification"] = dict(Counter(r["audit_classification"] for r in rows if tuple(sorted((r["representative_a"],r["representative_b"]))) in added))
        comparison["new_edge_sources"] = dict(Counter(r["source_pair"] for r in rows if tuple(sorted((r["representative_a"],r["representative_b"]))) in added))
        comparison["new_edge_scores"] = distribution([r["score_unrounded"] for r in rows if tuple(sorted((r["representative_a"],r["representative_b"]))) in added])
        comparison["new_edge_evidence_combinations"] = combinations.most_common(10)
        comparison["new_edge_entity_types"] = type_rows
        comparison["component_impact"] = {"v2_nontrivial_components":sum(c["node_count"]>1 for c in components),
            "v2_largest_component":components[0]["node_count"],"old_nontrivial_components":0 if comparison["old_edge_count"]==0 else None}
    write_json(destination/"old_vs_v2_comparison.json",comparison)
    top_share = {}
    for percent in (1,5):
        for population,name in ((top_nodes,"all_representatives"),([n for n in top_nodes if degrees[n]],"participating_nodes")):
            selected = set(population[:math.ceil(len(population)*percent/100)])
            incident_count = sum(a in selected or b in selected for a,b in pairs)
            top_share[f"top_{percent}_percent_{name}_edge_share"] = ratio(incident_count,len(edges))
    proxy_edges = sum(bool(set(r["risk_flags"]) & {"only_high_frequency_entities","no_entity_or_attested_relation","no_high_discrimination_context","hub_endpoint","near_clique_component","component_exceeds_production_size_guard","repeated_observation_inflation","network_continuity_same_endpoint"}) for r in rows)
    suspicious_ratio = ratio(class_counts["suspicious"],len(edges)) or 0
    weak_ratio = ratio(class_counts["weak"]+class_counts["suspicious"],len(edges)) or 0
    # Explicit conservative audit policy, no claim of calibrated quality grades.
    grade = "D" if suspicious_ratio>=.5 else "C" if weak_ratio>=.25 else "B"
    result = "OVER_CORRELATED" if grade=="D" else "QUALITY_NOT_PROVEN" if evaluation["status"]=="evaluation_not_computable" else "HEALTHY_WITH_WEAK_EDGES"
    summary = {"audit_version":"correlation-edge-quality-audit-v1","config_version":config["version"],"analysis_id":aid,
        "snapshot_identity":manifest.get("execution",{}).get("snapshot_identity"),"dataset_digest":record["dataset_digest"],
        "config_hash":record["config_hash"],"mapping_digest":record["mapping_digest"],"algorithm_version":record["algorithm_version"],
        "raw_inputs":run["input_files"],"production_ground_truth_used":False,"production_algorithm_replayed":False,
        "total_alerts":len(alerts),"representative_alerts":len(reps),"total_edges":len(edges),"unique_edge_pairs":len(set(pairs)),
        "duplicate_edges":len(edges)-len(set(pairs)),"self_edges":sum(a==b for a,b in pairs),"accepted_edges":len(edges),
        "total_candidates":diagnostics["scored_candidates"],"rejected_candidates":diagnostics["rejected_candidates"],
        "diagnostics":diagnostics,"edge_density":ratio(2*len(set(pairs)),len(reps)*(len(reps)-1)),
        "degree":distribution(list(degrees.values())),"active_degree":distribution(active_degrees),
        "isolated_alerts":sum(d==0 for d in degrees.values()),"non_isolated_alerts":len(active_degrees),
        "participating_raw_alerts":sum(degrees[owner[a]]>0 for a in alerts),"participating_ratio":ratio(len(active_degrees),len(reps)),
        "score":distribution(score_values),"threshold":threshold,"near_threshold_edges":sum(near(e) for e in edges),
        "near_threshold_ratio":ratio(sum(near(e) for e in edges),len(edges)),
        "score_buckets":{bucket(lo,SCORE_BOUNDS):sum(bucket(v,SCORE_BOUNDS)==bucket(lo,SCORE_BOUNDS) for v in score_values) for lo in SCORE_BOUNDS[:-1]},"contribution_recompute_max_error":error,
        "evidence_combinations":combinations.most_common(20),"family_contributions":[r for r in contributions if r["contribution_type"].startswith("v2.family.")],
        "classification":{k:{"count":class_counts[k],"ratio":ratio(class_counts[k],len(edges))} for k in ("strong","medium","weak","suspicious")},
        "proxy_counts":dict(proxy_counts),"false_positive_risk_proxy":{"edge_count":proxy_edges,"edge_ratio":ratio(proxy_edges,len(edges)),"ground_truth_false_positive":False},
        "hot_entity_count":len(hot),"hot_entity_edge_count":proxy_counts["high_frequency_entity_exposure"],
        "hub_threshold":hub_threshold,"hub_node_count":len(hubs),"hub_edge_count":proxy_counts["hub_endpoint"],
        "top_nodes_edge_share":top_share,"top_entities":all_entity_rows[:20],"entity_type_distribution":type_rows,
        "time_buckets":dict(time_counts),"time_dominated_edges":time_dominated,"time_largest_contribution_edges":time_largest,"time_only_edges":time_only,
        "source_pairs":source_rows,"cross_source_edges":len(strata["cross_source"]),"cross_source_ratio":ratio(len(strata["cross_source"]),len(edges)),
        "same_fields":{k:{"count":v,"ratio":ratio(v,len(edges))} for k,v in identity_counts.items()},
        "components":{"count":len(components),"singleton":sum(c["node_count"]==1 for c in components),
            "two_node":sum(c["node_count"]==2 for c in components),"three_to_five":sum(3<=c["node_count"]<=5 for c in components),
            "six_to_ten":sum(6<=c["node_count"]<=10 for c in components),"eleven_to_fifty":sum(11<=c["node_count"]<=50 for c in components),
            "over_fifty":sum(c["node_count"]>50 for c in components),"largest":component_rows[0],
            "exceed_size_guard":sum(c["exceeds_incident_size_guard"] for c in component_rows),
            "exceed_span_guard":sum(c["exceeds_incident_span_guard"] for c in component_rows),
            "high_density_nontrivial_count":len(dense_components),"same_rule_near_clique_count":len(rule_cliques),
            "top_dense":dense_components[:20],"top_same_rule_cliques":rule_cliques[:20]},
        "relation_support":dict(relation_counts),"incidents":{"total":len(incidents),"literal_singletons":sum(len(i["alert_ids"])==1 for i in incidents),
            "multi_alert":len(utility_rows),"multi_representative":sum(r["representative_count"]>1 for r in utility_rows),
            "dedupe_only_multi_alert":sum(r["dedupe_only"] for r in utility_rows),"largest_representatives":max((r["representative_count"] for r in utility_rows),default=1),
            "internal_edges":sum(r["same_incident"] for r in rows),"external_edges":sum(not r["same_incident"] for r in rows),
            "cluster_eligible_edges":sum(e["score_unrounded"]>=config["clustering"]["edge_threshold"] for e in edges),
            "chain_edges":sum(1 for _ in records(domain/"chain_edges.jsonl"))},
        "high_risk_singleton_breakdown":dict(high_risk),"truly_independent_high_risk_singletons":"not_identifiable_without_GT_and_unpruned_search",
        "sampling":{"seed":42,"sample_per_stratum":20,"unique_sample_count":len(selections),
            "strata":{k:{"population":len(v),"sample_count":min(20,len(v))} for k,v in strata.items()}},
        "offline_evaluation":evaluation,"old_vs_v2":comparison,"quality_grade":grade,"audit_result":result,
        "audit_policy":{"discriminative_rarity_minimum":config["score"]["evidence_v2"]["gate"]["specific_minimum_rarity"],
            "hub_threshold_rule":"max(3,ceil(P99 active degree),ceil(2*median active degree))",
            "giant_threshold":"current production max_representatives; proxy only",
            "near_clique":"component >=3 nodes and density>0.8; 2-node pairs excluded",
            "grade_rule":"D if suspicious>=50%; C if weak+suspicious>=25%; otherwise B; A/F require semantic truth review",
            "classification_is_not_ground_truth":True},"schema_and_identity_checks":"all formal edges; all support membership and entity refs; input and df recomputed"}
    write_json(destination/"audit_summary.json",summary)
    render_report(destination,summary,top_groups)
    print(json.dumps({k:summary[k] for k in ("total_edges","non_isolated_alerts","classification","cross_source_edges","near_threshold_ratio","quality_grade","audit_result")}),flush=True)


def finalize(root,destination):
    before = read_json(destination/"before_hashes.json")
    after = capture_integrity(root)
    result = compare_integrity(before,after)
    write_json(destination/"snapshot_integrity.json",result)
    if not result["unchanged"]:
        raise ValueError("protected_artifacts_changed:"+str(result["changed_paths"]))
    summary = read_json(destination/"audit_summary.json")
    summary["snapshot_integrity"] = {k:v for k,v in result.items() if k!="files"}
    write_json(destination/"audit_summary.json",summary)
    render_report(destination,summary,read_json(destination/"representative_edge_samples.json"))
    print("all protected artifact hashes unchanged",flush=True)


def render_report(destination,s,examples):
    """Human-readable report includes all 20 audits and actual evidence examples."""
    def table(rows,fields):
        escape = lambda v: str(v).replace("|","\\|").replace("\n"," ")
        return "\n".join(["| "+" | ".join(fields)+" |","| "+" | ".join("---" for _ in fields)+" |"]+
            ["| "+" | ".join(escape(row.get(f,"")) for f in fields)+" |" for row in rows])
    pct = lambda v:f"{100*v:.2f}%" if v is not None else "unavailable"
    lines = ["# Correlation v2 关联边质量审计", "", "2026-10-09 · Read-only production snapshot audit + separate offline evaluation.","",
        f"**质量等级 {s['quality_grade']}；结果 {s['audit_result']}。** 关联数量不能证明有效攻击召回。现有边保留可核验的共同上下文，但需结合下述弱证据、同规则重复与事件转化结果判断 SOC 调查价值。", "",
        "## 审计对象与方法", "",f"正式 Analysis：`{s['analysis_id']}`；算法 `{s['algorithm_version']}`。", "",
        table([{"field":k,"sha256":s[k]} for k in ("dataset_digest","config_hash","mapping_digest")],["field","sha256"]),"",
        "真实文件名称映射：请求中的 raw/aminer.json、raw/wazuh.json 对应已有 russellmitchell_aminer.json、russellmitchell_wazuh.json；未复制或改名。", "",
        table(s["raw_inputs"],["path","record_count","sha256"]),"",
        "复用 completed/is_complete 正式快照，不创建 Analysis、不运行评分或聚类、不修改边。检查 manifest/raw/config/frequency 摘要，遍历所有正式边 Schema/Stable ID/support_pair，完整扫描诊断决策；评分/时间/来源语义取实际 support_pair，图度数取代表端点。图统计是无向简单图，包含孤立代表。", "",
        "## Audit 01 · 整体边与覆盖", "",table([{ "metric":k,"value":s[k]} for k in ("total_alerts","representative_alerts","total_edges","unique_edge_pairs","duplicate_edges","self_edges","accepted_edges","total_candidates","rejected_candidates","edge_density","isolated_alerts","non_isolated_alerts","participating_raw_alerts","participating_ratio")],["metric","value"]),"",
        f"18k 边只覆盖 {s['non_isolated_alerts']} 个代表告警（{pct(s['participating_ratio'])}），不能说关联了18k个安全事件。平均/中位/P90/P95/P99/MAX度数：`{s['degree']}`；参与节点口径：`{s['active_degree']}`。", "",
        "## Audit 02 · Score 分布", "",f"未舍入正式边分布：`{s['score']}`。阈值 {s['threshold']}；near-threshold=[threshold,threshold+0.05)：{s['near_threshold_edges']} 条，{pct(s['near_threshold_ratio'])}。", "",
        table([{"bucket":k,"count":v} for k,v in sorted(s["score_buckets"].items())],["bucket","count"]),"",
        "## Audit 03 · 真实贡献与组合", "",
        "v2：raw=qfactor×matched/available + mfactor×matched/total − conflict − duplicate。按家族精确归因：`c_f=w_f*s_f*(qfactor/available+mfactor/total)`。实体/semantic 按已有加权均值拆分；topology 使用 max，平分相同最大项的归因。此拆分仅解释已保存分数，不增评分项。缺失家族提高剩余项的归一化倍率；v0七项贡献保留在CSV并明确标 legacy，不能将其和当作v2总分。", "",
        table(s["family_contributions"],["contribution_type","nonzero_count","edge_ratio","mean_all_edges","median_all_edges","max"]),"",
        f"归因重算与持久化 raw_total 最大误差 {s['contribution_recompute_max_error']}，允许浮点/6位舍入误差≤1e-5。", "",
        table([{"combination":k,"count":v} for k,v in s["evidence_combinations"][:10]],["combination","count"]),"",
        "## Audit 04 · Evidence Strength 分层", "",
        "审计规则为可复算的保守风险代理：稀有度沿用 production df/N公式与0.5特异性界限，限定现有强实体类型/SESSION，并排除production hot。Strong=合法显式关系，或高区分实体+达到已有semantic支持门槛的有效category语义+时间；Medium=高区分实体、分数达到聚类阈值且无hub/超大分量风险；Weak=其余可观察共同上下文；Suspicious=完全相同时间/源/规则及抽取上下文，且已有告警内full_log相等（重复观测膨胀代理），或无合法关系/高区分实体且只有hot实体、缺实体或受hub/超大分量影响。图形本身不否定强证据；强/中分类也不确认攻击。", "",
        "重复观测的两告警很可能应该一起查看；标Suspicious是针对将同一观测包装成新增安全关联数量的风险，**不是证明两端属于不同事件或真实False Positive**。full_log仅比较raw_alert已有字段，不读取或扩展原始运行日志，不新增生产去重组。", "",
        table([{"classification":k,**v} for k,v in s["classification"].items()],["classification","count","ratio"]),"",
        "## Audit 05–06 · Entity / Hub", "",table(s["entity_type_distribution"],["entity_type","entity_count","total_entity_count","edge_count","unique_alerts","avg_degree","max_degree"]),"",
        "Entity edge_count 按该实体实际匹配的唯一边；unique_alerts 按含该实体且参与关联的代表数；avg/max_degree 为这些代表在完整图中的度数，不能当作实体因果贡献。top实体按匹配边数排名，可能共用边，不能相加。", "",
        f"Production hot 实体 {s['hot_entity_count']} 个，暴露边 {s['hot_entity_edge_count']}（不等于仅靠hot）；hub阈值 {s['hub_threshold']}，节点 {s['hub_node_count']}，相连边 {s['hub_edge_count']}。", "",
        table(s["top_entities"][:20],["entity_id","type","value","df","edge_count","possible_common_entity"]),"",
        f"Top节点触边份额（唯一边、不重复计两端）：`{s['top_nodes_edge_share']}`。全代表Top1%可能超过全部有边节点数，因此另给参与节点Top1%/5%份额；不能用全代表份额单独宣称hub explosion。", "",
        "## Audit 07 · 时间质量", "",table([{"bucket_seconds":k,"count":v} for k,v in s["time_buckets"].items()],["bucket_seconds","count"]),"",
        f"Time是最大加分项的边 {s['time_largest_contribution_edges']}；time_dominated={s['time_dominated_edges']}（time最大且无高区分实体/显式关系）；严格time-only={s['time_only_edges']}。时间最大不等于只有时间，不能把它直接叫误报。窗口使用快照配置；未扩大候选或重新打分。", "",
        "## Audit 08 · Source Pair", "",table(s["source_pairs"],["source_pair","edge_count","percentage","avg_score","median_score"]),"",
        f"Cross-source(namespace口径)：{s['cross_source_edges']}，{pct(s['cross_source_ratio'])}。不同product但同namespace（例如Wazuh内Suricata）不算跨源部署；跨来源不证明独立检测。", "",
        "## Audit 09 · Rule / Signature 重复关联", "",table([{"field":k,**v} for k,v in s["same_fields"].items()],["field","count","ratio"]),"",
        f"重复观测膨胀代理={s['proxy_counts'].get('repeated_observation_inflation',0)}条，{pct(ratio(s['proxy_counts'].get('repeated_observation_inflation',0),s['total_edges']))}；network continuity中双方src_ip=dst_ip={s['proxy_counts'].get('network_continuity_same_endpoint',0)}条。这是已有端点相等再次进入topology家族，未提供跨主机传播。典型Dovecot记录full_log、session、timestamp相同，但location为不同mail日志文件、source_record_id不同，形成同一会话的三节点三边。", "",
        "为何未被既有去重消除：Frozen Wazuh payload mapping只覆盖有URL且具备src/dst IP、port、URL的结构化网络请求；Dovecot登录告警无URL，不生成该payload fingerprint。近似去重还要求payload匹配，故这类不同native ID/日志location的重复观测仍保留为不同事实代表。这是只读配置与样本核验发现，未新增payload mapping或去重规则。", "",
        "同category统计排除unknown；另给含unknown字面相等比例。rule/signature缺失不算相等。Top20规则和signature见 rule_signature_pairs.csv；同规则诱导图的密集分量见same_rule_cliques.csv，避免大分量掩盖内部clique。", "",
        "## Audit 10–11 · 图结构 / Clique", "",f"Component统计：`{ {k:v for k,v in s['components'].items() if k not in ('largest','top_dense','top_same_rule_cliques')} }`。", "",
        f"最大分量：{s['components']['largest']['node_count']} nodes、{s['components']['largest']['edge_count']} edges、density={s['components']['largest']['density']:.6f}、跨度{s['components']['largest']['duration_seconds']}秒。", "",
        f"来源：`{s['components']['largest']['source_distribution']}`；规则：`{s['components']['largest']['rule_distribution']}`；实体类型：`{s['components']['largest']['entity_distribution']}`。", "",
        "超500代表/7200秒是沿用生产保护的调查规模风险，非统计学giant-component证明。density>0.8且至少3节点标near-clique；2-node组件天然density=1，单列排除异常clique计数。详见component_statistics/suspicious_components及Top20文件。", "",
        table(s["components"]["top_dense"],["component_id","node_count","edge_count","possible_max_edges","density"]),"",
        "## Audit 12 · Relation Mapping", "",f"`{s['relation_support']}`。仅explicit_relation reasons中的冻结五类关系算relation-supported；endpoint continuity与相同session都是无向上下文，不能冒充已核验传播。unknown relation support=0：完整正式reason可检查。ChainEdge=0不自动代表Correlation失败，但步骤关系价值未得到证明。", "",
        "## Audit 13 · Incident Utility", "",table([{"metric":k,"value":v} for k,v in s["incidents"].items()],["metric","value"]),"",
        "multi-alert包含去重展开；multi-representative才是关联带来的事件组织价值。以上是生产Incident数量，缺GT不能称这些都是正确事件。incident_statistics.csv列出所有multi-alert Incident的告警、边、跨度、来源/实体/规则多样性。低于0.70正式边仅展示，未转为事件不是聚类失效证据。", "",
        "## Audit 14 · 高风险 Singleton", "",f"`{s['high_risk_singleton_breakdown']}`。优先按有正式边、其次有REJECT_LOW_SCORE、最后证据/guard拒绝进行互斥归类；每个singleton可能同时有多类候选，底层triage保留完整拒绝计数。", "",
        "no_admitted_candidate不等于整个数据无相关告警。局部策略剪枝存在，缺GT，确实完全独立与漏召回都不可证明；风险高本身不是关联理由。", "",
        "## Audit 15–16 · 真实样本与确定性分层抽样", "",f"`{s['sampling']}`。固定seed=42，按SHA256(seed,stratum,edge_id)排序抽样，独立于输入顺序；空组明确0条。JSONL合并重复样本但保留所有strata。", "",
        "人工查看：manual_review_samples.jsonl；Top5组完整引用、src/dst、关键实体、评分分解、理由和分类见representative_edge_samples.json；每条正式边审计记录见all_edge_audit.jsonl。下列每组最多20条，详情均可用edge_id定位。", ""]
    for group, sample in examples.items():
        lines += [f"### {group} ({len(sample)} 条)","",table([
            {"edge_id":r["edge_id"],"score":r["score_unrounded"],"delta_s":r["delta_time_seconds"],
             "signature_pair":f"{r['signature_a']} / {r['signature_b']}","classification":r["audit_classification"],
            "reason":r["reason"]} for r in sample],["edge_id","score","delta_s","signature_pair","classification","reason"]),""]
    validation = read_json(destination/"validation.json") if (destination/"validation.json").exists() else {}
    test_rows = [{"check":name,"status":value.get("status"),"passed":value.get("passed","—"),
                  "skipped":value.get("skipped",0)} for name,value in validation.items() if isinstance(value,dict) and "status" in value]
    lines += ["## Audit 17 · Offline Evaluation", "",f"**{s['offline_evaluation']['status']}**。schema={s['offline_evaluation']['label_schema']}；scene rows={s['offline_evaluation']['matching_scene_rows']}；时间={s['offline_evaluation']['time_mapping']}。", "",
        f"告警时间范围：{s['offline_evaluation']['alert_time_range']}；标签区间范围：{s['offline_evaluation']['label_time_range']}。标签缺alert/source身份、恶意成员与pair/incident真值。attack窗口不能按重叠推导pair TP/FP/FN，因此Precision/Recall/F1全部null、coverage=0。读取仅在evaluation/framework/correlation_quality_audit，生产对象先冻结，标签从未反馈算法或AI。", "",
        "## Audit 18 · False Positive Risk Proxy", "",f"去重并集 {s['false_positive_risk_proxy']['edge_count']} 条，{pct(s['false_positive_risk_proxy']['edge_ratio'])}。分项可重叠：`{s['proxy_counts']}`。此数是复核优先级代理，绝不等于真实FP。未依据地址名称推断NAT/gateway角色。", "",
        "## Audit 19 · Old vs v2", "",f"`{ {k:v for k,v in s['old_vs_v2'].items() if k not in ('new_edge_entity_types','new_edge_evidence_combinations','new_edge_classification','new_edge_sources','new_edge_scores')} }`", "",
        "对比仅使用同CanonicalAlert逐对象完全相等、同dedupe组、同dataset/mapping摘要的旧正式快照；不重放生产算法，版本的候选集合不同。新增边的分数/证据/实体/来源/分量影响见old_vs_v2_comparison.json。新增边数证明覆盖变化，无法证明有效关联召回提升。", "",
        "## Audit 20 · 质量评级与十项结论", "",
        f"1. 整体可信性：等级{s['quality_grade']}，共同上下文可追溯，但攻击关联可信性未由GT证实，不可将18k条全部视为高可信事件关系。当前只适合作为待复核上下文；不足以无条件驱动Incident，保留既有0.70/桥/目标保护。",
        "2. 主要证据按真实平均贡献降序：" + "；".join(f"{r['contribution_type']}={r['mean_all_edges']:+.6f}" for r in sorted(s["family_contributions"],key=lambda r:-r["mean_all_edges"])) + "。Topology的原始端点相等不等于传播，见Audit09。",
        f"3. Strong/Medium/Weak/Suspicious：`{s['classification']}`；是审计分层，不是真值准确率。",
        f"4. 高频实体暴露{s['hot_entity_edge_count']}条；hub影响{s['hub_edge_count']}条，可能重叠；不能简单相加或称全部无效。",
        f"5. Near-threshold {pct(s['near_threshold_ratio'])}。",
        f"6. Cross-source {pct(s['cross_source_ratio'])}。跨源碎片化关联能力在本次数据未充分证明。",
        f"7. 最大分量{s['components']['largest']['node_count']}节点；≥3节点density>0.8组件{s['components']['high_density_nontrivial_count']}，同rule密集诱导组件{s['components']['same_rule_near_clique_count']}；hub节点{s['hub_node_count']}。应结合主体与规则分布判断。",
        f"8. 最终{s['incidents']['multi_representative']}个multi-representative Incident；另有{s['incidents']['dedupe_only_multi_alert']}个仅去重展开。真正正确incident数因缺GT未知。",
        "9. 最大风险：重复观测使边数膨胀、同一IP事实的实体/网络连续性重复贡献、同源规则名称的多维语义奖励；其次Relation ambiguity / Dataset limitation。存在少数局部hub，未发现巨型组件失控；真实FP/FN尚不可计算。",
        "10. 下一阶段建议：I先复核重复观测的去重覆盖与SOC分层样本；D评测证据独立性/可靠性（src=dst网络连续性、同一rule对应signature/alert_type）；C在开发划分评测重复证据归一化；F评测rarity floor；E仅按实测局部hub考虑抑制。保留现有聚类保护，不因边少转化就放宽；G调阈值、B候选召回和H聚类变更需要对应真值与漏例依据。此Task不实施任何建议。", "",
        "## Files / 复现", "",
        "新增文件：scripts/correlation_quality_audit.py；evaluation/framework/correlation_quality_audit/{__init__,cli,correlation_quality,correlation_run}.py；evaluation/tests/test_correlation_quality_audit.py；本目录全部审计产物。已有业务文件和测试未修改。", "",
        "根目录运行：`.venv/Scripts/python.exe scripts/correlation_quality_audit.py`；已有before_hashes不得覆盖。首次保护采集用`--capture-before`，完成全部验证后用`--finalize`。脚本仅启动独立evaluation进程，不向生产模块导入GT。SHA256分层抽样固定seed=42；报告与CSV由全量快照计算。", "",
        "## 验证与完整性", "",f"Schema/StableID/support_pair/df/manifest/input/config核验已完成；pytest/frontend/typecheck/build/repository的实际结果见validation.json及对应日志。", "",
        table(test_rows,["check","status","passed","skipped"]),"",
        "4个skipped是既有opt-in全量生产重放，本任务复用已冻结真实快照，未将skip当pass。初次全量回归仅因新audit顶层目录触发仓库固定树断言失败；已将新模块移入framework并完整重跑，未修改/删除既有测试。", "",
        f"运行前后保护：`{s.get('snapshot_integrity','pending final hash comparison')}`。snapshot_integrity.json逐文件列before/after SHA256；覆盖所有既有data/processed、outputs/analyses、配置/映射、backend/app、frontend/src、七份文档、AIT原始数据/标签和历史freeze manifests。", "",
        "未修改生产算法、阈值、权重、映射、Incident、Chain、GT或正式快照。未自动实施下一阶段。", "",f"CORRELATION_V2_AUDIT_RESULT={s['audit_result']}"]
    if s.get("config_version") == "v3":
        # Presentation only: classify(), grade rules, bins and sampling are the
        # original v1 audit policy. Do not reinterpret the repaired population.
        lines = [line.replace("# Correlation v2 关联边质量审计", "# Correlation v3 关联边质量审计")
                     .replace("18k 边只覆盖", f"{s['total_edges']} 边覆盖")
                     .replace("不可将18k条全部视为", "不可将全部边视为")
                     .replace("CORRELATION_V2_AUDIT_RESULT=", "CORRELATION_V3_AUDIT_RESULT=")
                 for line in lines]
        lines = [line for line in lines if not line.startswith(("为何未被既有去重消除：", "新增文件：", "4个skipped是", "10. 下一阶段建议："))]
        lines = [
            line.replace("典型Dovecot记录", "历史v2的典型Dovecot记录")
                .replace("## Audit 19 · Old vs v2", "## Audit 19 · 历史同去重口径对比")
                .replace("9. 最大风险：重复观测使边数膨胀、同一IP事实的实体/网络连续性重复贡献、同源规则名称的多维语义奖励；其次Relation ambiguity / Dataset limitation。存在少数局部hub，未发现巨型组件失控；真实FP/FN尚不可计算。",
                         f"9. 当前风险代理：重复观测{s['proxy_counts'].get('repeated_observation_inflation',0)}条，双方本机端点连续性{s['proxy_counts'].get('network_continuity_same_endpoint',0)}条，hub影响{s['hub_edge_count']}条。上述计数不确认攻击关联；真实FP/FN尚不可计算。")
                .replace("未修改生产算法、阈值、权重、映射、Incident、Chain、GT或正式快照。", "本只读审计未修改生产算法、阈值、权重、映射、Incident、Chain、GT或正式快照；v3实现变更另见主报告。")
            for line in lines]
        lines.insert(4, "沿用原 Correlation Edge Quality Audit v1 分类、阈值、图风险代理与 seed=42；此审计只读取已冻结 v3 快照。v2→v3 修复、对比、完整测试及限制见上一层 CORRELATION_V3_REPORT.md。")
    (destination/"CORRELATION_EDGE_QUALITY_AUDIT.md").write_text("\n".join(lines)+"\n",encoding="utf-8")

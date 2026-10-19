"""Snapshot statistics and documented risk proxies, never a correlation engine.

All scores and evidence are read from production. Classification is an audit
policy, not ground truth, and has no write path back to any production object.
"""

from collections import Counter, defaultdict
import csv
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import statistics


FAMILIES = ("time", "entity", "relation", "behavior", "source")
SCORE_BOUNDS = (.65, .70, .75, .80, .85, .90, .95, 1.000000001)
TIME_BOUNDS = (0, 10, 30, 60, 300, 900, 1800, 3600, math.inf)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def records(path):
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2,
                                   sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def protected_paths(root):
    """Inventory existing snapshots, inputs, implementation and freeze receipts."""
    root = Path(root)
    paths = set()
    for directory in ("data/processed", "outputs/analyses", "configs", "backend/app",
                      "frontend/src", "docs", "data/ait_ads"):
        for path in (root / directory).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                paths.add(path)
    paths.add(root / "AGENTS.md")
    for pattern in ("*freeze*.json", "*manifest*.json"):
        paths.update(p for p in (root / "outputs").rglob(pattern)
                     if "correlation_quality_audit" not in p.parts)
    paths.update((root / "evaluation/configs").rglob("*.json"))
    return sorted(paths, key=lambda p: p.relative_to(root).as_posix())


def capture_integrity(root):
    root = Path(root)
    result = {}
    paths = protected_paths(root)
    for number, path in enumerate(paths, 1):
        result[path.relative_to(root).as_posix()] = digest(path)
        if number % 150 == 0:
            print(f"integrity {number}/{len(paths)}", flush=True)
    return result


def compare_integrity(before, after):
    changed = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
    aggregate = lambda x: hashlib.sha256(json.dumps(x, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"unchanged": not changed, "changed_paths": changed, "file_count": len(before),
            "before_aggregate_sha256": aggregate(before), "after_aggregate_sha256": aggregate(after),
            "files": {p: {"before_sha256": before.get(p), "after_sha256": after.get(p),
                          "equal": before.get(p) == after.get(p)} for p in sorted(before.keys() | after.keys())}}


def quantile(values, percentile):
    if not values:
        return None
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile / 100
    lo, hi = math.floor(rank), math.ceil(rank)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (rank - lo)


def distribution(values):
    return {"count": len(values), "min": min(values) if values else None,
            "max": max(values) if values else None, "mean": statistics.fmean(values) if values else None,
            "median": statistics.median(values) if values else None,
            **{f"P{p}": quantile(values, p) for p in (50, 75, 90, 95, 99)}}


def bucket(value, bounds):
    for lo, hi in zip(bounds, bounds[1:]):
        if lo <= value < hi:
            return f"[{lo:g},{hi:g})" if math.isfinite(hi) else f"[{lo:g},inf)"
    return "outside"


def source_pair(a, b):
    return " ↔ ".join(sorted((a["source_namespace"], b["source_namespace"])))


def sampled(rows, seed, stratum, count=20):
    """Hash ranking is stable under input permutation and independent per stratum."""
    return sorted(rows, key=lambda r: (hashlib.sha256(
        f"{seed}|{stratum}|{r['edge_id']}".encode()).hexdigest(), r["edge_id"]))[:count]


def graph_statistics(nodes, pairs):
    adjacency = {n: set() for n in nodes}
    for a, b in set(tuple(sorted(p)) for p in pairs):
        if a == b:
            continue
        if a not in adjacency or b not in adjacency:
            raise ValueError("edge_endpoint_not_representative")
        adjacency[a].add(b)
        adjacency[b].add(a)
    seen, components = set(), []
    for node in sorted(adjacency):
        if node in seen:
            continue
        stack, members = [node], []
        seen.add(node)
        while stack:
            current = stack.pop()
            members.append(current)
            for neighbor in sorted(adjacency[current], reverse=True):
                if neighbor not in seen:
                    seen.add(neighbor)
                    stack.append(neighbor)
        members.sort()
        size = len(members)
        edges = sum(len(adjacency[n]) for n in members) // 2
        maximum = size * (size - 1) // 2
        components.append({"component_id": members[0], "alert_ids": members,
                           "node_count": size, "edge_count": edges, "possible_max_edges": maximum,
                           "density": edges / maximum if maximum else 0})
    return adjacency, sorted(components, key=lambda c: (-c["node_count"], c["component_id"]))


def entity_frequency(entities, owner):
    return {eid: len({owner.get(a, a) for a in entity["alert_ids"]}) for eid, entity in entities.items()}


def hot_entities(frequency, N, config):
    return {eid for eid, count in frequency.items() if count >= config["hot_entity_min_count"]
            and count / N >= config["hot_entity_ratio"]}


def effective_contributions(edge):
    """Exact additive attribution of the existing v2 formula, not new evidence.

    Family c = w*s*(quality_factor/available_weight + mass_factor/total_weight).
    Entity/semantic families split their existing weighted mean; relation uses
    max and shares ties equally. Penalties retain their production signs.
    """
    breakdown = edge["score_breakdown"]
    evidence = breakdown["evidence_v2"]
    factor = evidence["quality_factor"] / evidence["available_weight"] + evidence["mass_factor"] / evidence["total_configured_weight"]
    families = {family: evidence["family_weights"][family] * evidence["family_strengths"][family] * factor
                for family in FAMILIES}
    dims = {}
    for family in FAMILIES:
        observable = [d for d in evidence["dimensions"] if d["family"] == family and d["state"].startswith("AVAILABLE")]
        if family == "relation":
            winners = [d for d in observable if d["strength"] == evidence["family_strengths"][family] and d["strength"] > 0]
            for d in winners:
                dims[d["dimension"]] = families[family] / len(winners)
        else:
            denominator = sum(d["weight"] for d in observable)
            for d in observable:
                dims[d["dimension"]] = evidence["family_weights"][family] * factor * d["weight"] * d["strength"] / denominator
    penalties = {name: breakdown["contributions"][name] for name in ("conflict", "duplicate")}
    return families, dims, penalties


def observation_proxies(a, b, evidence):
    """Compare existing alert fields only; never parse or fetch additional logs.

    Equal full_log plus identical extracted context is a repeated-observation
    proxy, not a new production duplicate decision or a maliciousness label.
    """
    fields = ("timestamp", "source_namespace", "rule_id", "signature", "host", "account",
              "session", "src_ip", "dst_ip", "src_port", "dst_port", "url", "file",
              "command", "process", "parent_process")
    identical_context = all(a.get(f) == b.get(f) for f in fields)
    raw_a, raw_b = a.get("raw_alert"), b.get("raw_alert")
    identical_payload = (isinstance(raw_a, dict) and isinstance(raw_b, dict)
        and raw_a.get("full_log") is not None and raw_a.get("full_log") == raw_b.get("full_log"))
    continuity = "topology.network_continuity" in evidence["matched_evidence"]
    same_endpoint = (continuity and a.get("src_ip") is not None and b.get("src_ip") is not None
        and a.get("src_ip") == a.get("dst_ip") and b.get("src_ip") == b.get("dst_ip"))
    return {"identical_extracted_context": identical_context, "identical_embedded_payload": identical_payload,
            "repeated_observation_proxy": identical_context and identical_payload,
            "network_continuity_same_endpoint_proxy": same_endpoint}


def classify(edge, entities, frequency, N, hot, config, hub=False, dense=False, giant=False,
             repeated=False, same_endpoint=False):
    """Conservative, evidence-specific SOC review proxies. Not TP/FP labels."""
    evidence = edge["score_breakdown"]["evidence_v2"]
    gate = config["score"]["evidence_v2"]["gate"]
    shared = {eid for d in evidence["dimensions"] if d["state"] == "AVAILABLE_MATCH" for eid in d["entity_ids"]}
    rarity = lambda eid: max(config["entity"]["rarity_floor"], math.log((N + 1) / (frequency[eid] + 1)) / math.log(N + 1))
    discriminative = {eid for eid in shared if eid not in hot and rarity(eid) >= gate["specific_minimum_rarity"]
                      and entities[eid]["type"] in set(gate["strong_entity_types"]) | {"SESSION"}}
    relation = any(r["code"] == "explicit_relation" and r["params"]["relation_type"] in config["chain"]["relation_type_mapping"] for r in edge["reasons"])
    matched = set(evidence["matched_evidence"])
    semantic = evidence["family_strengths"]["behavior"] >= gate["semantic_support_minimum"]
    temporal = evidence["family_strengths"]["time"] >= gate["temporal_support_minimum"]
    flags = []
    if shared & hot:
        flags.append("high_frequency_entity_exposure")
    if shared and shared <= hot and not relation:
        flags.append("only_high_frequency_entities")
    if not shared and not relation:
        flags.append("no_entity_or_attested_relation")
    if not discriminative and not relation:
        flags.append("no_high_discrimination_context")
    if hub:
        flags.append("hub_endpoint")
    if dense:
        flags.append("near_clique_component")
    if giant:
        flags.append("component_exceeds_production_size_guard")
    if repeated:
        flags.append("repeated_observation_inflation")
    if same_endpoint:
        flags.append("network_continuity_same_endpoint")
    if edge["score"] < config["score"]["correlation_threshold"] + .05:
        flags.append("near_threshold")
    if not discriminative and not relation and temporal:
        flags.append("time_supported_low_discrimination_context")
    # Graph shape alone cannot turn a strongly evidenced edge into a fake edge.
    suspicious = repeated or (not relation and not discriminative and (not shared or shared <= hot or hub or giant))
    if suspicious:
        classification = "suspicious"
    elif relation or (discriminative and semantic and temporal and "semantic.category" in matched):
        classification = "strong"
    elif discriminative and not (hub or giant) and edge["score"] >= config["clustering"]["edge_threshold"]:
        classification = "medium"
    else:
        classification = "weak"
    return {"classification": classification, "risk_flags": flags,
            "discriminative_entity_ids": sorted(discriminative), "matched_entity_ids": sorted(shared),
            "relation_support": "relation_supported" if relation else "generic_correlation",
            "reason": f"{classification}: " + (", ".join(flags) if flags else "specific observed context")}


def csv_output(path, rows, fields=None):
    rows = list(rows)
    fields = fields or sorted({key for row in rows for key in row}) or ["edge_id"]
    with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False, sort_keys=True) if isinstance(v, (list, dict, set)) else v for k, v in row.items()})


def offline_evaluation(root, alerts):
    """Only evaluation code loads labels; interval metadata never becomes pair GT."""
    from evaluation.io.ait_ads import load_ait_ads_ground_truth
    gt = load_ait_ads_ground_truth(root)
    scope = [r for r in gt.get("records", []) if r["scene_id"] == "russellmitchell"]
    times = sorted(a["timestamp"] for a in alerts.values())
    return {"status": "evaluation_not_computable", "offline_evaluation_only": True,
            "production_consumed_ground_truth": False, "label_path": gt["path"], "label_sha256": gt.get("sha256"),
            "label_schema": gt.get("columns"), "label_capabilities": gt.get("capabilities"),
            "dataset_scope": "ait_ads/russellmitchell", "matching_scene_rows": len(scope),
            "time_mapping": gt.get("interval_policy"), "alert_time_range": [times[0], times[-1]] if times else [],
            "label_time_range": [min(r["start_time"] for r in scope), max(r["end_time"] for r in scope)] if scope else [],
            "alert_identity_mapping": "unavailable: schema has no alert IDs or source record references",
            "pair_precision": None, "pair_recall": None, "pair_F1": None,
            "incident_precision": None, "incident_recall": None, "incident_F1": None,
            "evaluation_coverage": 0.0,
            "reason": "Official attack intervals provide neither malicious alert membership nor common-incident pair labels; time overlap cannot establish either.",
            "limitations": gt.get("limitations", [])}

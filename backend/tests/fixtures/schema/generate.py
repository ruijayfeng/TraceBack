"""Regenerate synthetic-only v1 contract fixtures. Never read real dataset files.

Run from the repository root: .venv/Scripts/python.exe backend/tests/fixtures/schema/generate.py
"""

from copy import deepcopy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import app.models as models
from app.utils.stable_id import content_digest, id_for, raw_fingerprint


def identified(kind, data):
    from app.utils.stable_id import ID_FIELDS
    result = deepcopy(data)
    result[ID_FIELDS[kind]] = id_for(kind, result)
    return result


def build():
    fixtures = {}
    time = "2026-10-04T02:31:04.123456Z"
    provenance = {"raw_pointer": "/time", "transform": "synthetic/rfc3339-v1"}
    first = identified("CanonicalAlert", {
        "timestamp": time, "source_type": "wazuh", "source_namespace": "synthetic/detector-a",
        "raw_alert": {"time": time, "product": "wazuh", "request": {"trigger": "synthetic-process-instance"},
                      "host": "synthetic-target", "values": [2, 1], "evidence/key": {"~name": 0}},
        "field_provenance": {"timestamp": provenance,
                             "source_type": {"raw_pointer": "/product", "transform": "synthetic/source-v1"}},
    } | {"raw_fingerprint": raw_fingerprint({"time": time, "product": "wazuh",
            "request": {"trigger": "synthetic-process-instance"}, "host": "synthetic-target",
            "values": [2, 1], "evidence/key": {"~name": 0}})})
    second = deepcopy(first)
    second["source_namespace"] = "synthetic/detector-b"
    second = identified("CanonicalAlert", second)
    alerts = sorted([first, second], key=lambda a: a["alert_id"])
    aids = [a["alert_id"] for a in alerts]
    fixtures["CanonicalAlert"] = alerts[0]
    entity = identified("Entity", {"type": "HOST", "value": "synthetic-target", "scope": "synthetic/asset",
                                    "display_value": "synthetic-target", "alert_ids": aids})
    eid = entity["entity_id"]
    fixtures["Entity"] = entity
    fixtures["ProcessRef"] = {"name": "synthetic-process", "pid": 0, "start_time": time}
    fixtures["FieldProvenance"] = provenance
    fixtures["EntityOccurrence"] = {"entity_id": eid, "role": "host", "raw_pointer": "/host"}
    pointers = [{"alert_id": a, "pointer": "/request/trigger", "side": side}
                for a, side in zip(aids, ("src", "dst"), strict=True)]
    fixtures["EvidencePointer"] = pointers[0]
    pair = {"alert_id_src": aids[0], "alert_id_dst": aids[1]}
    fixtures["SupportPair"] = pair
    fixtures["AlertRelation"] = {"relation_type": "target_to_process", "source_entity_id": eid,
                                  "target_entity_id": eid, "raw_pointers": pointers}
    incident = identified("Incident", {"start_time": time, "end_time": time, "severity": "unknown",
                                       "alert_ids": aids, "entity_ids": [eid]})
    fixtures["Incident"] = incident
    iid = incident["incident_id"]
    node_ids = [id_for("ChainNode", {"incident_id": iid, "category": category, "alert_ids": [aid]})
                for category, aid in zip(("web_attack", "process_execution"), aids, strict=True)]
    params = {
        "time_gap": {"gap_seconds": 0, "half_life_seconds": 60},
        "shared_entity": {"entity_type": "HOST", "roles": ["host"], "rarity": 0.5, "contribution": 0.5},
        "explicit_relation": {"relation_type": "target_to_process", "raw_pointers": pointers},
        "behavior_transition": {"from_category": "web_attack", "to_category": "process_execution", "compatibility": 1},
        "source_complement": {"source_types": ["wazuh", "aminer"], "sensor_names": ["synthetic/a", "synthetic/b"],
            "rule_id": "synthetic/source-context", "source_independence": "unknown", "raw_pointers": [], "independence_rule_ids": []},
        "conflict": {"rule_id": "synthetic/conflict", "penalty": 0},
        "duplicate": {"rule_id": "synthetic/duplicate", "similarity": 1},
        "direction": {"rule_id": "synthetic/direction", "source_node_id": node_ids[0], "target_node_id": node_ids[1],
                      "direction_score": 0.8},
        "clustering_guard": {"rule_id": "synthetic/guard", "decision": "accept", "component_sizes": [2, 2]},
        "node_basis": {"rule_id": "synthetic/node", "category": "web_attack", "confidence": 0.7},
    }
    reasons = {}
    for code, value in params.items():
        reasons[code] = identified("Reason", {"code": code, "message": "人工契约边界样例（synthetic）",
            "alert_ids": aids, "entity_ids": [eid] if code in ("shared_entity", "explicit_relation") else [], "params": value})
        fixtures["Reason." + code] = reasons[code]
        fixtures[models.reasons.PARAM_MODELS[models.ReasonCode(code)].__name__] = value
    fixtures["Reason"] = reasons["time_gap"]
    fixtures["DedupeGroup"] = identified("DedupeGroup", {"representative_alert_id": aids[0], "alert_ids": aids,
                                                        "duplicate_score": 1, "reasons": [reasons["duplicate"]]})
    weights = {"time": 0.2, "entity": 0.3, "relation": 0.2, "behavior": 0.2, "source": 0.1, "conflict": 0.45, "duplicate": 0.4}
    contributions = {"time": 0.2, "entity": 0.3, "relation": 0.18, "behavior": 0.2, "source": 0, "conflict": 0, "duplicate": 0}
    breakdown = {"time_score": 1, "entity_score": 1, "relation_score": 0.9, "behavior_score": 1,
        "source_score": 0, "source_independence": "unknown", "conflict_penalty": 0, "duplicate_penalty": 0,
        "weights": weights, "contributions": contributions, "raw_total": 0.88, "final_score": 0.88,
        "config_hash": content_digest({"synthetic": True})}
    fixtures.update(ScoreWeights=weights, ScoreContributions=contributions, ScoreBreakdown=breakdown)
    correlation = identified("CorrelationEdge", {"source_alert_id": aids[0], "target_alert_id": aids[1], "score": 0.88,
        "reasons": [reasons["time_gap"], reasons["explicit_relation"], reasons["source_complement"]],
        "entity_ids": [eid], "score_breakdown": breakdown, "support_pair": pair})
    fixtures["CorrelationEdge"] = correlation
    nodes = []
    for category, aid in zip(("web_attack", "process_execution"), aids, strict=True):
        basis = identified("Reason", {"code": "node_basis", "message": "人工节点依据（synthetic）", "alert_ids": [aid],
            "params": {"rule_id": "synthetic/node", "category": category, "confidence": 0.7}})
        nodes.append(identified("ChainNode", {"incident_id": iid, "alert_ids": [aid], "start_time": time, "end_time": time,
            "category": category, "severity": "unknown", "entity_ids": [eid], "confidence": 0.7, "reasons": [basis]}))
    fixtures["ChainNode"] = nodes[0]
    chain_edge = identified("ChainEdge", {"incident_id": iid, "source_node_id": node_ids[0], "target_node_id": node_ids[1],
        "relation_type": "REQUEST_TO_PROCESS", "confidence": 0.8, "direction_score": 0.8, "alert_ids": aids,
        "entity_ids": [eid], "correlation_edge_ids": [correlation["edge_id"]],
        "reasons": [reasons["direction"], reasons["explicit_relation"]],
        "score_breakdown": breakdown | {"selected_correlation_edge_id": correlation["edge_id"]}})
    fixtures["ChainEdge"] = chain_edge
    chain = identified("AttackChain", {"incident_id": iid, "nodes": nodes, "edges": [chain_edge], "status": "complete"})
    fixtures["AttackChain"] = chain
    proposition = {"subject_type": "alert", "subject_id": aids[0], "field": "severity", "value": "unknown"}
    fixtures["GroundedProposition"] = proposition
    fixtures["AttackMapping"] = {"technique_id": "T1059.001", "technique_name": "synthetic catalog technique",
                                  "catalog_version": "synthetic-v1", "rationale": "仅测试 Schema，不声称观测技术"}
    claim = identified("AIClaim", {"kind": "fact", "section": "summary", "text": "告警等级字段为 unknown。",
                                  "alert_ids": [aids[0]], "propositions": [proposition]})
    fixtures["AIClaim"] = claim
    metrics = {"alert_count": 2, "representative_count": 2, "candidate_pair_count": 1, "candidate_dropped_count": 0,
        "correlation_runtime_seconds": 0, "clustering_runtime_seconds": 0, "chain_runtime_seconds": 0,
        "total_runtime_seconds": 0, "peak_memory_mb": 0}
    fixtures["AnalysisMetrics"] = metrics
    snapshot = {"synthetic": True}
    digest = content_digest(snapshot)
    analysis = identified("AnalysisRecord", {"input_alert_ids": aids, "config_hash": digest,
        "config_snapshot": snapshot, "algorithm_version": "synthetic-v1",
        "dataset_digest": content_digest([{"alert_id": a["alert_id"], "raw_fingerprint": a["raw_fingerprint"]} for a in alerts]),
        "config_digest": digest, "mapping_digest": content_digest([]), "is_complete": False, "incomplete_reason": None,
        "metrics": metrics})
    analysis.update(diagnostics_ref=f"outputs/analyses/{analysis['analysis_id']}/diagnostics.jsonl",
                    frequency_snapshot_ref=f"outputs/analyses/{analysis['analysis_id']}/frequency_snapshot.json")
    fixtures["AnalysisRecord"] = analysis
    fixtures["AIExplanation"] = identified("AIExplanation", {"analysis_id": analysis["analysis_id"], "incident_id": iid,
        "chain_id": chain["chain_id"], "input_digest": content_digest({"synthetic": "projected-facts"}),
        "provider": "synthetic-provider", "model": "synthetic-model", "prompt_version": "synthetic-v1", "claims": [claim]})
    fixtures["EvaluationSummaryExport"] = {"run_id": content_digest({"synthetic": "run"}), "config_hash": digest,
        "algorithm_version": "synthetic-v1", "split": "synthetic-test", "metrics": {"precision": None},
        "metric_status": {"precision": "not_applicable"}, "evaluation_coverage": 0, "counts": {"tp": 0},
        "runtime": {"seconds": 0}, "limitations": ["synthetic：空分母，无真实实验结论"]}
    return fixtures, alerts


if __name__ == "__main__":
    fixtures, alerts = build()
    legal, illegal = [], []
    for label, data in fixtures.items():
        kind = label.split(".")[0]
        model = getattr(models, kind)
        validated = model.model_validate(data)
        legal.append({"name": label, "model": kind, "data": validated.model_dump(mode="json")})
        illegal.append({"name": label + ".extra", "model": kind, "data": data | {"undeclared": "synthetic"}})
    for name, cases in (("valid.json", legal), ("invalid.json", illegal)):
        Path(__file__).with_name(name).write_text(json.dumps({"fixture_kind": "synthetic", "cases": cases},
                                    ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(f"generated {len(legal)} valid and {len(illegal)} invalid synthetic cases")

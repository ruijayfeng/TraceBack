"""Task 04 entry point: controlled incidents → grounded immutable DAG views."""

import argparse
from dataclasses import dataclass
import json
import time

from app.correlation.edges import peak_memory_mb
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.incidents.clustering import cluster_incidents
from app.models import AnalysisRecord, AttackChain
from app.utils.stable_id import canonical_json, content_digest, id_for
from .conflicts import select_dag
from .direction import decide_direction
from .grounding import validate_grounding
from .nodes import build_nodes
from .reconstruction import reconstruct_candidates


ALGORITHM_VERSION = "incident-chain-v1"


@dataclass
class ReconstructionResult:
    record: AnalysisRecord
    incidents: list
    chains: list
    grounding: object
    summary: dict


def assemble_chain(incident, index, scorer, edges, diagnostic_sink=None, support_cache=None):
    sink = diagnostic_sink or (lambda row: None)
    nodes = build_nodes(incident, index, scorer, sink)
    candidates = reconstruct_candidates(incident, nodes, edges, index, scorer, sink, support_cache)
    decisions = [decide_direction(c, scorer) for c in candidates]
    for decision in decisions:
        sink(decision.diagnostic)
    accepted, rejected = select_dag(decisions, nodes, sink)
    covered = {eid for e in accepted for eid in e.correlation_edge_ids}
    unresolved = sorted(set(incident.correlation_edge_ids) - covered | set(rejected))
    data = {"incident_id": incident.incident_id, "nodes": nodes, "edges": accepted,
            "status": "partial" if unresolved else "complete", "unresolved_correlation_edge_ids": unresolved}
    data["chain_id"] = id_for("AttackChain", {**data, "nodes": [n.model_dump(mode="json") for n in nodes],
                                             "edges": [e.model_dump(mode="json") for e in accepted]})
    return AttackChain.model_validate(data)


def run_reconstruction(alerts, groups, entities, edges, config, source_settings, *, upstream_record=None,
                       output_root=None, diagnostic_sink=None, progress=None, existing_index=None):
    """Accept Task 03 formal edges; never rerun candidate generation or tune it.

    An upstream incomplete result stays incomplete even if all retained facts
    were reconstructed and grounded successfully. New version → new partition.
    """
    from app.services.storage import SnapshotStore
    started = time.perf_counter()
    from app.services.capacity import AlertSequence
    alerts = alerts if isinstance(alerts, AlertSequence) else list(alerts)
    groups, entities = sorted(groups, key=lambda g: g.group_id), list(entities)
    edges = sorted(edges, key=lambda e: e.edge_id)
    index = existing_index if existing_index is not None else AlertIndex(alerts, groups, entities)
    if not index.alerts:
        raise ValueError("empty_reconstruction_input")
    snapshot = {"algorithm": config.snapshot, "sources": {k: v.snapshot() for k, v in sorted(source_settings.items())}}
    config_hash = content_digest(snapshot)
    scorer = CorrelationScorer(index, config, source_settings, config_hash)
    analysis_id = id_for("AnalysisRecord", {"input_alert_ids": list(index.alerts), "config_hash": config_hash,
                                           "algorithm_version": ALGORITHM_VERSION, "schema_version": "1.0"})
    if upstream_record is not None:
        if upstream_record.status.value not in {"completed", "incomplete"}:
            raise ValueError("upstream_correlation_not_available")
        if (upstream_record.config_hash != config_hash or upstream_record.config_snapshot != snapshot
                or set(upstream_record.input_alert_ids) != set(index.alerts)
                or upstream_record.dataset_digest != content_digest([[i, a.raw_fingerprint] for i, a in index.alerts.items()])):
            raise ValueError("upstream_snapshot_mismatch")
    store = SnapshotStore(output_root, analysis_id) if output_root is not None else None

    def execute(sink):
        clustering_started = time.perf_counter()
        clustered = cluster_incidents(index, edges, scorer, sink)
        clustering_runtime = time.perf_counter() - clustering_started
        if progress:
            progress({"stage": "clustering", "incident_count": len(clustered.incidents)})
        chain_started = time.perf_counter()
        edge_map = {e.edge_id: e for e in edges}
        chains = []
        for position, incident in enumerate(clustered.incidents, 1):
            chains.append(assemble_chain(incident, index, scorer, [edge_map[i] for i in incident.correlation_edge_ids],
                                         sink, clustered.support_cache))
            if progress and position % 10000 == 0:
                progress({"stage": "chain", "processed_incidents": position})
        chains.sort(key=lambda c: c.chain_id)
        chain_runtime = time.perf_counter() - chain_started
        incomplete = upstream_record is not None and not upstream_record.is_complete
        previous = upstream_record.metrics if upstream_record is not None else None
        record = AnalysisRecord.model_validate({"analysis_id": analysis_id, "input_alert_ids": list(index.alerts),
            "config_hash": config_hash, "config_digest": config_hash, "config_snapshot": snapshot,
            "algorithm_version": ALGORITHM_VERSION, "mapping_digest": config.mapping_digest,
            "dataset_digest": content_digest([[i, a.raw_fingerprint] for i, a in index.alerts.items()]),
            "diagnostics_ref": f"outputs/analyses/{analysis_id}/diagnostics.jsonl",
            "frequency_snapshot_ref": f"outputs/analyses/{analysis_id}/frequency_snapshot.json",
            "status": "incomplete" if incomplete else "completed", "is_complete": not incomplete,
            "candidate_truncated": upstream_record.candidate_truncated if upstream_record is not None else False,
            "incomplete_reason": upstream_record.incomplete_reason if incomplete else None,
            "errors": upstream_record.errors if incomplete else [],
            "metrics": {"alert_count": len(index.alerts), "representative_count": index.N,
                "candidate_pair_count": previous.candidate_pair_count if previous else 0,
                "candidate_dropped_count": previous.candidate_dropped_count if previous else 0,
                "correlation_runtime_seconds": previous.correlation_runtime_seconds if previous else 0,
                "clustering_runtime_seconds": clustering_runtime, "chain_runtime_seconds": chain_runtime,
                "total_runtime_seconds": time.perf_counter() - started, "peak_memory_mb": peak_memory_mb()}})
        grounding = validate_grounding(index, clustered.incidents, chains, edges, scorer, record, clustered.support_cache)
        grounding.require_valid()
        # Counts use representatives (fact groups), not duplicate wrappers.
        sizes = [len({index.owner[aid] for aid in i.alert_ids}) for i in clustered.incidents]
        summary = {"canonical_alert_count": len(index.alerts), "dedupe_group_count": len(groups),
            "representative_count": index.N, "correlation_edge_count": len(edges),
            "incident_count": len(sizes), "singleton_incident_count": sizes.count(1),
            "multi_alert_incident_count": sum(size > 1 for size in sizes), "max_incident_representatives": max(sizes),
            "max_incident_original_alerts": max(len(i.alert_ids) for i in clustered.incidents),
            "chain_node_count": sum(len(c.nodes) for c in chains), "chain_edge_count": sum(len(c.edges) for c in chains),
            "attack_chain_count": len(chains), "partial_chain_count": sum(c.status == "partial" for c in chains),
            "unresolved_chain_count": sum(bool(c.unresolved_correlation_edge_ids) for c in chains),
            "unresolved_correlation_edge_count": sum(len(c.unresolved_correlation_edge_ids) for c in chains),
            "chain_with_observed_edges_count": sum(bool(c.edges) for c in chains),
            "grounding": grounding.json_data(), "status": record.status.value,
            "upstream_analysis_id": upstream_record.analysis_id if upstream_record is not None else None,
            "limitations": ["upstream_correlation_incomplete"] if incomplete else []}
        sink({"stage": "grounding", **grounding.json_data()})
        return ReconstructionResult(record, clustered.incidents, chains, grounding, summary)

    if store is None:
        return execute(diagnostic_sink or (lambda row: None))
    store.create()
    (store.details / "manifest.json").write_text(canonical_json({"analysis_id": analysis_id, "status": "running",
        "is_complete": False, "algorithm_version": ALGORITHM_VERSION, "config_hash": config_hash}) + "\n", encoding="utf-8")
    try:
        with store.diagnostics_writer() as sink:
            result = execute(sink)
        for kind, records in (("alerts", index.alerts.values()), ("entities", index.entities.values()),
            ("dedupe_groups", groups), ("correlation_edges", edges), ("incidents", result.incidents),
            ("chain_nodes", [n for c in result.chains for n in c.nodes]),
            ("chain_edges", [e for c in result.chains for e in c.edges]), ("attack_chains", result.chains)):
            store.write_records(kind, records)
        data = result.record.model_dump()
        data["metrics"]["total_runtime_seconds"] = time.perf_counter() - started
        data["metrics"]["peak_memory_mb"] = peak_memory_mb()
        result.record = AnalysisRecord.model_validate(data)
        result.summary["metrics"] = result.record.metrics.model_dump()
        store.write_metadata(result.record, index.frequency_snapshot(), result.summary)
        return result
    except BaseException as exc:
        (store.details / "manifest.json").write_text(canonical_json({"analysis_id": analysis_id, "status": "failed",
            "is_complete": False, "errors": [type(exc).__name__], "incomplete_reason": "reconstruction_not_published"})
            + "\n", encoding="utf-8")
        raise


def main():
    from app.services.storage import SnapshotStore, restore_config
    from app.adapters.base import AdapterSettings
    parser = argparse.ArgumentParser(description="Task 04 incidents/chains from a frozen Task 03 snapshot")
    parser.add_argument("--root", required=True)
    parser.add_argument("--correlation-analysis-id", required=True)
    args = parser.parse_args()
    upstream = SnapshotStore(args.root, args.correlation_analysis_id)
    record, _, _ = upstream.read_metadata()
    config = restore_config(record.config_snapshot["algorithm"])
    settings = {k: AdapterSettings(**v) for k, v in record.config_snapshot["sources"].items()}
    result = run_reconstruction(list(upstream.read_records("alerts")), list(upstream.read_records("dedupe_groups")),
        list(upstream.read_records("entities")), list(upstream.read_records("correlation_edges")), config, settings,
        upstream_record=record, output_root=args.root, progress=lambda row: print(json.dumps(row), flush=True))
    reloaded = SnapshotStore(args.root, result.record.analysis_id).validate_reconstruction()
    print(canonical_json({"analysis_id": result.record.analysis_id, "summary": result.summary,
                          "reload_grounding": reloaded.json_data()}), flush=True)


if __name__ == "__main__":
    main()

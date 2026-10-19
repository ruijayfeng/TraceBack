"""Truth-free evaluation glue around the existing, unmodified production calls."""

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import time

import duckdb

from app.correlation.edges import run_correlation
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.chains.assembly import run_reconstruction
from app.dedup import deduplicate
from app.entities.extraction import extract_entities
from app.models import CanonicalAlert, EntityType
from app.utils.stable_id import canonical_json, content_digest
from evaluation.io.task_06_5 import distribution
from evaluation.sensitivity.score_reachability import reachability, component_maxima


FIELDS = tuple(k for k in CanonicalAlert.model_fields if k not in {
    "schema_version", "entity_ids", "entity_occurrences", "relations"
})
STAGES = ("adapter", "normalization", "dedupe", "entity_extraction", "candidate_generation",
          "candidate_admission", "scoring", "correlation_edge", "incident", "chain_reconstruction")


def unavailable(reason):
    return {"value": None, "status": "not_computable", "reason": reason}


def entity_coverage(alerts, entities):
    count = sum(bool(a.entity_ids) for a in alerts)
    return {"entity_total": len(entities), "alerts_with_entity": count,
            "alerts_without_entity": len(alerts) - count,
            "entity_coverage_rate": count / len(alerts) if alerts else None,
            "status": "available" if alerts else "not_applicable",
            "reason": None if alerts else "empty_canonical_input",
            "entity_type_distribution": {k.value: sum(e.type == k for e in entities) for k in EntityType}}


def adapter_coverage(batches):
    """Fields use unique accepted alerts; record acceptance includes imports."""
    counts = {k: Counter() for k in FIELDS}
    total = accepted = 0
    rejects, sources, seen = Counter(), [], set()
    for adapter, batch in batches:
        total += batch.input_count
        accepted += batch.accepted_count
        rejects.update(batch.rejection_reasons)
        sources.append({"source_namespace": adapter.settings.source_namespace, "total_records": batch.input_count,
                        "accepted_records": batch.accepted_count, "rejected_records": len(batch.rejected),
                        "rejection_reasons": batch.rejection_reasons})
        for alert in batch.alerts:
            if alert.alert_id in seen:
                continue
            seen.add(alert.alert_id)
            facts, _, context = adapter.extract(alert.raw_alert)
            for field in FIELDS:
                value = getattr(alert, field)
                if value is not None and value != "" and getattr(value, "value", value) != "unknown":
                    outcome = "covered"
                elif field in {"category", "severity"}:
                    source_present = context.get("raw_severity") is not None if field == "severity" else any(
                        facts.get(k) for k in ("rule_id", "alert_type", "signature")) or context.get("vendor_category") is not None
                    outcome = "mapping_failure" if source_present else "missing_by_source"
                else:
                    outcome = "mapping_failure" if facts.get(field) not in (None, "") else "missing_by_source"
                counts[field][outcome] += 1
    n = len(seen)
    rejection_classes = Counter()
    for reason, count in rejects.items():
        outcome = "invalid_value" if reason.startswith("invalid_") or reason == "schema_violation" else "parse_failure"
        if reason.startswith("missing_"):
            outcome = "missing_by_source"
        rejection_classes[outcome] += count
    return {"total_records": total, "accepted_records": accepted, "rejected_records": total - accepted,
            "acceptance_rate": accepted / total if total else None,
            "unique_canonical_alerts": n, "duplicate_imports": accepted - n, "sources": sources,
            "field_denominator": "unique accepted CanonicalAlerts; rejected records are reported separately",
            "canonical_fields": {k: {"covered": c["covered"], "coverage_rate": c["covered"] / n if n else None,
                **{s: c[s] for s in ("missing_by_source", "mapping_failure", "parse_failure", "invalid_value")}}
                for k, c in counts.items()},
            "rejection_reasons": dict(sorted(rejects.items())),
            "rejected_record_outcomes": {k: rejection_classes[k] for k in (
                "missing_by_source", "mapping_failure", "parse_failure", "invalid_value")},
            "limitations": ["Unknown mapped category/severity with vendor input is an uncovered mapping, not a claim that the adapter is defective.",
                            "Rejected records cannot supply field-level coverage; their parser reasons are separate.",
                            "Source namespace, internal identity and evidence digests are contract/deployment coverage, not observed vendor fields."]}


def run_pipeline(inputs, destination):
    """No GT/labels/dataset name parameter; no production artifact is written."""
    started = time.perf_counter()
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    if not inputs or len({a.config.config_hash for a, _ in inputs}) != 1:
        raise ValueError("missing_inputs_or_inconsistent_config")
    config = inputs[0][0].config
    settings = {}
    for adapter, _ in inputs:
        key = adapter.settings.source_namespace
        if key in settings and settings[key] != adapter.settings:
            raise ValueError("conflicting_source_settings")
        settings[key] = adapter.settings
    stages = {}
    def stage(name, before, after, duration, rejected=0, status="completed", **extra):
        stages[name] = {"input_count": before, "output_count": after, "rejected_count": rejected,
                        "runtime_seconds": duration, "status": status, **extra}
    step = time.perf_counter()
    batches = [(a, a.read_file(p)) for a, p in inputs]
    by_id = {}
    for _, batch in batches:
        for alert in batch.alerts:
            if alert.alert_id in by_id and by_id[alert.alert_id].canonical_json() != alert.canonical_json():
                raise ValueError("same_alert_id_conflicting_content")
            by_id[alert.alert_id] = alert
    alerts = [by_id[i] for i in sorted(by_id)]
    coverage = adapter_coverage(batches)
    stage("adapter", coverage["total_records"], len(alerts), time.perf_counter() - step, coverage["rejected_records"])
    stage("normalization", len(alerts), len(alerts), None, status="included_in_adapter",
          reason="existing Adapter.convert performs basic normalization; no separate timing probe")
    if not alerts:
        for name in STAGES[2:]:
            stage(name, 0, 0, None, status="not_applicable", reason="empty_canonical_input")
        result = {"status": "not_applicable", "blocked_stage": "dedupe", "blocked_reason": "empty_canonical_input",
                  "adapter_coverage": coverage, "entity_coverage": entity_coverage([], []), "stages": stages,
                  "counts": {k: 0 for k in ("canonical_alerts", "representatives", "entities", "correlation_edges", "incidents", "chain_nodes", "chain_edges")},
                  "scores": unavailable("empty_canonical_input"), "reachability": unavailable("empty_canonical_input"),
                  "runtime": {"total_seconds": time.perf_counter()-started, "peak_memory": "not_available"},
                  "prediction_digest": content_digest([])}
        return result
    step = time.perf_counter()
    dedupe = deduplicate(alerts, config, settings)
    representative_count = len(alerts) - sum(len(g.alert_ids)-1 for g in dedupe.groups)
    stage("dedupe", len(alerts), representative_count, time.perf_counter()-step,
          status="completed" if dedupe.is_complete else "incomplete")
    step = time.perf_counter()
    extracted = extract_entities(alerts, settings)
    alerts, entities = extracted.alerts, extracted.entities
    stage("entity_extraction", len(alerts), len(entities), time.perf_counter()-step)
    diagnostic_hashes, winners, member_guards, decisions = {}, [], Counter(), Counter()
    def sink(row):
        name = row["stage"]
        # The existing candidate diagnostic contains internal tuple rankings;
        # JSON arrays preserve their order without changing any decision.
        encoded = (canonical_json(json.loads(json.dumps(row)))+"\n").encode("utf-8")
        diagnostic_hashes.setdefault(name, sha256()).update(encoded)
        diagnostic_file.write(encoded)
        if name == "correlation_decision":
            decisions[row["rule_id"]] += 1
            if row["score"] is not None:
                winners.append(row["score"])
        if name == "member_score":
            member_guards.update(row["rejection_codes"])
    with (destination / "pipeline_diagnostics.jsonl").open("wb") as diagnostic_file:
        correlation = run_correlation(alerts, dedupe.groups, entities, config, settings, diagnostic_sink=sink)
        reconstruction = run_reconstruction(alerts, dedupe.groups, entities, correlation.edges, config, settings,
                                            upstream_record=correlation.record, diagnostic_sink=sink)
    c, r = correlation.summary, reconstruction.summary
    potential = c["potential_pair_stats"]["unique_potential_pairs"]
    stage("candidate_generation", representative_count, potential, c["potential_retrieval_seconds"])
    stage("candidate_admission", potential, c["admitted_candidate_count"], c["candidate_admission_seconds"],
          c["policy_pruned_count"], resource_truncated_count=c["resource_truncated_count"])
    stage("scoring", len(correlation.candidates.pairs), c["scored_candidate_count"], c["correlation_scoring_seconds"],
          status=correlation.record.status.value, member_pair_count=c["verified_member_pair_count"])
    stage("correlation_edge", c["scored_candidate_count"], len(correlation.edges), None,
          sum(v for k, v in decisions.items() if k != "score.correlation_threshold"),
          status="included_in_scoring", reason="production edge admission runs inside scoring timer")
    stage("incident", representative_count, len(reconstruction.incidents), reconstruction.record.metrics.clustering_runtime_seconds)
    stage("chain_reconstruction", len(reconstruction.incidents), sum(len(ch.nodes) for ch in reconstruction.chains),
          reconstruction.record.metrics.chain_runtime_seconds, chain_edge_count=r["chain_edge_count"])
    # Reuse Task 06.5's DuckDB population/linear-quantile statistics verbatim.
    db = duckdb.connect()
    try:
        db.execute("CREATE TABLE selected_scores(score DOUBLE)")
        if winners:
            db.execute("INSERT INTO selected_scores SELECT unnest(?::DOUBLE[])", [winners])
        scores = distribution(db)
    finally:
        db.close()
    threshold = config.algorithm.score.correlation_threshold
    scores.update(threshold=threshold, threshold_reachable_pairs=sum(x >= threshold for x in winners),
                  scope="highest valid complete member score per admitted representative pair",
                  blocking_reasons=dict(sorted(decisions.items())), member_guard_rejections=dict(sorted(member_guards.items())))
    index = AlertIndex(alerts, dedupe.groups, entities)
    scorer = CorrelationScorer(index, config, settings)
    try:
        bound = reachability(index, scorer, config, scores["max"] or 0)
    except ValueError as exc:
        # Task 06.5's field proof has explicit prerequisites. General datasets
        # must never inherit its R=S=0 assertion when those gates are present.
        maxima = component_maxima(config)
        bound = {"status": "not_computable", "reason": str(exc),
                 "dataset_constrained_maximum_reachable_score": None,
                 "mathematical_box_upper_bound": min(1, sum(config.algorithm.score.weights.model_dump()[k]*maxima[k]
                     for k in ("time", "entity", "relation", "behavior", "source"))),
                 "classification": "proof_inconclusive", "observed_maximum": scores["max"]}
    objects = {"canonical": alerts, "dedupe": dedupe.groups, "entities": entities, "correlation_edges": correlation.edges,
               "incidents": reconstruction.incidents, "chains": reconstruction.chains}
    digests = {}
    for name, rows in objects.items():
        h = sha256()
        with (destination / (name+".jsonl")).open("wb") as handle:
            for obj in sorted(rows, key=lambda obj: obj.canonical_json()):
                encoded = (obj.canonical_json()+"\n").encode("utf-8")
                handle.write(encoded)
                h.update(encoded)
        digests[name] = h.hexdigest()
    digests.update({k: h.hexdigest() for k, h in sorted(diagnostic_hashes.items())})
    complete = dedupe.is_complete and reconstruction.record.is_complete and not coverage["rejected_records"]
    counts = {"raw_records": coverage["total_records"], "accepted_records": coverage["accepted_records"],
              "canonical_alerts": len(alerts), "representatives": representative_count, "entities": len(entities),
              "potential_pairs": potential, "policy_pruned": c["policy_pruned_count"],
              "admitted": c["admitted_candidate_count"], "scored": c["scored_candidate_count"],
              "resource_truncated": c["resource_truncated_count"], "correlation_edges": len(correlation.edges),
              "incidents": len(reconstruction.incidents), "singleton_incidents": r["singleton_incident_count"],
              "multi_alert_incidents": r["multi_alert_incident_count"], "chain_nodes": r["chain_node_count"], "chain_edges": r["chain_edge_count"]}
    return {"status": "completed" if complete else "incomplete", "adapter_coverage": coverage,
            "entity_coverage": entity_coverage(alerts, entities), "stages": stages, "counts": counts,
            "scores": scores, "reachability": bound, "grounding": reconstruction.grounding.json_data(),
            "runtime": {"stages": {k: v["runtime_seconds"] for k,v in stages.items()},
                        "correlation_index_and_setup_seconds": c["correlation_index_and_setup_seconds"],
                        "total_seconds": time.perf_counter()-started, "peak_memory_mb": reconstruction.record.metrics.peak_memory_mb,
                        "peak_memory_scope": "existing process lifetime high-water mark; includes earlier work in this process"},
            "stage_digests": digests, "prediction_digest": content_digest(digests),
            "effective_config_snapshot": reconstruction.record.config_snapshot,
            "dataset_digest": reconstruction.record.dataset_digest}

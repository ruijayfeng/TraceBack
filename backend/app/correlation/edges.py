"""Candidate → full member scoring → formal undirected CorrelationEdge.

CLI reads an explicitly identified, complete Task 02 snapshot and stops after
correlation. There is no component union, chain construction or AI invocation.
"""

import argparse
from collections import Counter
from array import array
from dataclasses import dataclass
import heapq
import json
import math
import time

from app.models import AnalysisRecord, CorrelationEdge
from app.utils.stable_id import canonical_json, content_digest, id_for
from .candidates import CANDIDATE_CONTRACT_VERSION, generate_candidates
from .conflicts import group_targets, target_diagnostic
from .index import AlertIndex
from .scoring import CorrelationScorer


ALGORITHM_VERSION = "alert-correlation-candidate-v1.1"


def correlation_version(config):
    if config.algorithm.implementation_version == 'v5-evidence-semantics-v1':
        from .formula_v5 import SEMANTICS_VERSION
        return SEMANTICS_VERSION
    if config.algorithm.implementation_version == 'v5-formula-f3-v1':
        from .formula_v5 import ALGORITHM_VERSION as version
        return version
    if config.algorithm.implementation_version == 'v5-preformula-candidate-v1':
        return 'alert-correlation-v5-preformula-candidate-v1'
    if config.algorithm.version == 'v4':
        return 'alert-correlation-v4-role-context-candidate-v1.1'
    if config.algorithm.version == 'v3' and config.algorithm.duplicate.observation.event_pointers:
        return 'alert-correlation-v3-evidence-quality-r2-candidate-v1.1'
    return f"alert-correlation-{config.algorithm.version}-candidate-v1.1" if config.algorithm.version in {"v2", "v3"} else ALGORITHM_VERSION


@dataclass
class CorrelationResult:
    record: AnalysisRecord
    edges: list[CorrelationEdge]
    summary: dict
    candidates: object


def peak_memory_mb():
    import sys
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")
        return counters.PeakWorkingSetSize / (1024 * 1024)
    import resource
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value / (1024 * 1024) if sys.platform == "darwin" else value / 1024


def run_correlation(alerts, groups, entities, config, source_settings, *, output_root=None, diagnostic_sink=None, progress=None):
    from app.services.storage import SnapshotStore
    started = time.perf_counter()
    cpu_started = time.process_time()
    snapshot = {"algorithm": config.snapshot, "sources": {k: v.snapshot() for k, v in sorted(source_settings.items())}}
    config_hash = content_digest(snapshot)
    index = AlertIndex(alerts, groups, entities)
    if not index.alerts:
        raise ValueError("empty_correlation_input")
    analysis_id = id_for("AnalysisRecord", {"input_alert_ids": list(index.alerts), "config_hash": config_hash,
                                           "algorithm_version": correlation_version(config), "schema_version": "1.0"})
    store = SnapshotStore(output_root, analysis_id) if output_root is not None else None
    if store:
        store.create()
        # Prevent an interrupted rerun from leaving an old completed manifest
        # next to a newly truncated diagnostics stream.
        (store.details / "manifest.json").write_text(canonical_json({"analysis_id":analysis_id,"status":"running",
            "is_complete":False,"config_hash":config_hash,"config_snapshot":snapshot,"algorithm_version":correlation_version(config)})+"\n",encoding="utf-8")
        with store.diagnostics_writer(bounded=config.algorithm.version in {'v3', 'v4'} and bool(config.algorithm.duplicate.observation.event_pointers)) as sink:
            try:
                result = _run(index, config, source_settings, snapshot, config_hash, analysis_id, started, sink, progress, cpu_started)
            except MemoryError:
                sink({"stage":"resource","decision":"incomplete","rule_id":"correlation_resource_exhausted"})
                result = resource_incomplete(index,config,snapshot,config_hash,analysis_id,started)
        # Keep every original alert, including zero-degree representatives and
        # nonrepresentative support members. Separate analysis partition.
        for kind, records in (("alerts", index.alerts.values()), ("entities", index.entities.values()),
                              ("dedupe_groups", sorted(groups, key=lambda g: g.group_id)), ("correlation_edges", result.edges)):
            store.write_records(kind, records)
        data = result.record.model_dump()
        data["metrics"]["total_runtime_seconds"] = time.perf_counter() - started
        data["metrics"]["peak_memory_mb"] = peak_memory_mb()
        result.record = AnalysisRecord.model_validate(data)
        result.summary["total_runtime_seconds"] = result.record.metrics.total_runtime_seconds
        result.summary["peak_memory_mb"] = result.record.metrics.peak_memory_mb
        result.summary["process_cpu_seconds"] = time.process_time() - cpu_started
        store.write_metadata(result.record, index.frequency_snapshot(), result.summary)
        return result
    try:
        return _run(index, config, source_settings, snapshot, config_hash, analysis_id, started,
                    diagnostic_sink or (lambda record: None), progress, cpu_started)
    except MemoryError:
        return resource_incomplete(index,config,snapshot,config_hash,analysis_id,started)


def resource_incomplete(index,config,snapshot,config_hash,analysis_id,started):
    """No unverified maximum/partial formal graph is published after exhaustion."""
    runtime=time.perf_counter()-started
    record=AnalysisRecord.model_validate({"analysis_id":analysis_id,"input_alert_ids":list(index.alerts),
        "config_hash":config_hash,"config_digest":config_hash,"config_snapshot":snapshot,"algorithm_version":correlation_version(config),
        "mapping_digest":config.mapping_digest,"dataset_digest":content_digest([[i,a.raw_fingerprint] for i,a in index.alerts.items()]),
        "diagnostics_ref":f"outputs/analyses/{analysis_id}/diagnostics.jsonl",
        "frequency_snapshot_ref":f"outputs/analyses/{analysis_id}/frequency_snapshot.json",
        "status":"incomplete","is_complete":False,"candidate_truncated":False,
        "incomplete_reason":"correlation_resource_exhausted","errors":["correlation_resource_exhausted"],
        "metrics":{"alert_count":len(index.alerts),"representative_count":index.N,"candidate_pair_count":0,
                   "candidate_dropped_count":0,"correlation_runtime_seconds":runtime,"clustering_runtime_seconds":0,
                   "chain_runtime_seconds":0,"total_runtime_seconds":runtime,"peak_memory_mb":peak_memory_mb()}})
    return CorrelationResult(record,[],{"status":"incomplete","verified_maximum_available":False,
                             "resource_error":"correlation_resource_exhausted"},None)


def _run(index, config, source_settings, snapshot, config_hash, analysis_id, started, sink, progress=None, cpu_started=None):
    scorer = CorrelationScorer(index, config, source_settings, config_hash)
    candidate_started = time.perf_counter()
    candidates = generate_candidates(index, config, scorer)
    if hasattr(sink, 'prepare_candidates'):
        sink.prepare_candidates(index, candidates)
    candidate_runtime = time.perf_counter() - candidate_started
    if progress:
        progress({"stage":"candidates", "count":len(candidates.pairs), "elapsed_seconds":time.perf_counter()-started})
    for diagnostic in candidates.diagnostics:
        sink(diagnostic)
    for diagnostic in candidates.resource_candidates:
        sink(diagnostic)
    candidates.resource_candidates = ()
    for rep in index.representatives:
        sink({"stage": "targets", "representative_alert_id": rep, "member_alert_ids": list(index.groups[rep]),
              "targets": target_diagnostic(group_targets(rep, index, source_settings))})
    scoring_started = time.perf_counter()
    edges, rejections, distributions, degree, states = [], Counter(), Counter(), set(), Counter()
    member_count, highest_rejected = 0, []
    context = {"alerts": index.alerts, "groups": index.groups, "config_hash": config_hash,
               "score_weights": scorer.algorithm.score.weights.model_dump(),
               "independence_rule_ids": sorted({rule.id for m in scorer.independence_mappings for rule in m.rules})}
    accepted_samples, cross_samples, same_samples = [], [], []
    # Reporting intervals do not affect scoring, ranking or admission. Include
    # the effective threshold so the distribution exposes its exact boundary.
    interval_bounds = sorted({*(round(i / 10, 2) for i in range(11)), scorer.algorithm.score.correlation_threshold})
    interval_names = [f"[{a:.2f},{b:.2f})" for a, b in zip(interval_bounds, interval_bounds[1:])] + ["{1.00}"]
    member_scores, candidate_scores = dict.fromkeys(interval_names, 0), dict.fromkeys(interval_names, 0)
    candidate_scores["no_valid_member_pair"] = 0
    highest_score, highest_score_pair = -1.0, None
    v2 = scorer.algorithm.version in {"v2", "v3", "v4"}
    measured_scores, top_pairs = array("d"), []
    gate_count, gate_member_count, legacy_highest = 0, 0, -1.0
    alert_diagnostics = {rep: {"candidate_count": 0, "gate_passed_count": 0, "formal_edge_count": 0,
                              "decisions": Counter()} for rep in index.representatives} if v2 else {}
    def interval(score):
        if score == 1.0:
            return "{1.00}"
        return next(name for a, b, name in zip(interval_bounds, interval_bounds[1:], interval_names) if a <= score < b)
    for candidate_number, candidate in enumerate(candidates.pairs, 1):
        pair = candidate.support_key
        sink({"stage": "candidate", "candidate_contract_version": CANDIDATE_CONTRACT_VERSION,
              "admission_reason": "non_time_window_and_deterministic_top_k", "ranking_key": candidate.priority,
              "support_key": list(pair), "channels": list(candidate.channels), "evidence": [e.json_data() for e in candidate.evidence], **({"candidate_reasons": list(candidate.channels)} if v2 else {})})
        winner = None
        observed = None
        for left in index.groups[pair[0]]:
            for right in index.groups[pair[1]]:
                scored = scorer.score_pair(left, right)
                member_count += 1
                member_scores[interval(scored.score)] += 1
                if v2:
                    legacy_highest = max(legacy_highest, min(1, max(0, sum(scored.contributions.values()))))
                    gate_member_count += int(scored.diagnostics["evidence_v2"]["evidence_gate_passed"])
                    observed_key = (-scored.score, index.alerts[left].timestamp, index.alerts[right].timestamp, left, right)
                    if observed is None or observed_key < observed[0]:
                        observed = (observed_key, scored)
                if scored.score > highest_score:
                    highest_score, highest_score_pair = scored.score, [left, right]
                tie = (index.alerts[left].timestamp, index.alerts[right].timestamp, left, right)
                sink({"stage": "member_score", "support_key": list(pair), "support_pair": [left, right],
                      "values": scored.values, "contributions": scored.contributions, "raw_total": scored.raw_total,
                      "score": scored.score, "source_independence": scored.source_independence,
                      "threshold": scorer.algorithm.score.correlation_threshold, "valid": scored.valid,
                      "rejection_codes": scored.rejection_codes, "reasons": [r.model_dump(mode="json") for r in scored.reasons],
                      "evidence": scored.diagnostics})
                if scored.valid and (winner is None or (-scored.score, tie) < winner[0]):
                    winner = ((-scored.score, tie), scored)
        # Every member was verified. A lower-scoring valid pair may win over a
        # high-scoring pair rejected by hard guards; no feature-wise maxima.
        selected = winner[1] if winner else None
        candidate_scores[interval(selected.score) if selected else "no_valid_member_pair"] += 1
        accepted = selected is not None and selected.score >= scorer.algorithm.score.correlation_threshold
        code = None if accepted else "no_valid_member_pair" if selected is None else "below_correlation_threshold"
        decision = {"stage": "correlation_decision", "support_key": list(pair), "decision": "accept" if accepted else "reject",
                    "rule_id": code or "score.correlation_threshold", "score": selected.score if selected else None,
                    "support_pair": [selected.source_member_id, selected.target_member_id] if selected else None,
                    "threshold": scorer.algorithm.score.correlation_threshold}
        if accepted:
            data = {"source_alert_id": pair[0], "target_alert_id": pair[1], "score": round(selected.score, 6),
                    "reasons": selected.reasons, "entity_ids": selected.entity_ids, "score_breakdown": scorer.breakdown(selected),
                    "support_pair": {"alert_id_src": selected.source_member_id, "alert_id_dst": selected.target_member_id}}
            data["edge_id"] = id_for("CorrelationEdge", data)
            edge = CorrelationEdge.model_validate(data, context=context)
            edges.append(edge)
            degree.update(pair)
            states[selected.source_independence] += 1
            types = sorted({r.relation_type for r in selected.relations}, key=scorer.algorithm.chain.relation_priority.index)
            mapped = scorer.algorithm.chain.relation_type_mapping[types[0]] if types else "unresolved"
            distributions[mapped] += 1
            decision.update(edge_id=edge.edge_id, attested_relations=[r.json_data() for r in selected.relations],
                            relation_type_mapping=mapped, causal_chain_edge_published=False)
            sample = {"edge": edge.model_dump(mode="json"), "unrounded_score": selected.score, "evidence": selected.diagnostics,
                      "relation_type_mapping": mapped}
            if len(accepted_samples) < 5:
                accepted_samples.append(sample)
            same_source = index.alerts[selected.source_member_id].source_type == index.alerts[selected.target_member_id].source_type
            destination = same_samples if same_source else cross_samples
            if len(destination) < 5:
                destination.append(sample)
        else:
            rejections[code] += 1
            if selected is not None:
                sample = {**decision, "values": selected.values, "reasons": [r.model_dump(mode="json") for r in selected.reasons],
                          "evidence": selected.diagnostics}
                # Best rejected evidence samples; ID is a deterministic tie-break.
                item = (selected.score, pair, sample)
                if len(highest_rejected) < 8:
                    heapq.heappush(highest_rejected, item)
                elif item[:2] > highest_rejected[0][:2]:
                    heapq.heapreplace(highest_rejected, item)
        if v2:
            evaluated = selected if selected is not None else observed[1]
            audit = evaluated.diagnostics["evidence_v2"]
            measured_scores.append(evaluated.score)
            gate_count += int(audit["evidence_gate_passed"])
            for rep in pair:
                row = alert_diagnostics[rep]
                row["candidate_count"] += 1
                row["gate_passed_count"] += int(audit["evidence_gate_passed"])
                row["formal_edge_count"] += int(accepted)
                row["decisions"][audit["decision"]] += 1
            relation_types = sorted({r.relation_type for r in evaluated.relations}, key=scorer.algorithm.chain.relation_priority.index)
            ranked = {"support_key": list(pair), "alert_ids": [evaluated.source_member_id, evaluated.target_member_id],
                "final_score": evaluated.score, "evidence": audit, "relation_mapping":
                scorer.algorithm.chain.relation_type_mapping[relation_types[0]] if relation_types else None,
                "edge_created": accepted, "chain_mapping_decision": "MAPPED" if relation_types else "REJECT_NO_RELATION"}
            item = (evaluated.score, pair, ranked)
            if len(top_pairs) < 20:
                heapq.heappush(top_pairs, item)
            elif item[:2] > top_pairs[0][:2]:
                heapq.heapreplace(top_pairs, item)
            decision.update(evidence_decision=audit["decision"], evidence_gate_passed=audit["evidence_gate_passed"])
        sink(decision)
        if progress and candidate_number % 50000 == 0:
            progress({"stage":"scoring", "verified_candidates":candidate_number, "accepted_edges":len(edges),
                      "elapsed_seconds":time.perf_counter()-started})
    scoring_runtime = time.perf_counter() - scoring_started
    edges.sort(key=lambda edge: edge.edge_id)
    runtime = time.perf_counter() - started
    incomplete = candidates.candidate_truncated
    record = AnalysisRecord.model_validate({"analysis_id": analysis_id, "input_alert_ids": list(index.alerts), "config_hash": config_hash,
        "config_snapshot": snapshot, "algorithm_version": correlation_version(config),
        "dataset_digest": content_digest([[i, a.raw_fingerprint] for i, a in index.alerts.items()]),
        "config_digest": config_hash, "mapping_digest": config.mapping_digest,
        "diagnostics_ref": f"outputs/analyses/{analysis_id}/diagnostics.jsonl",
        "frequency_snapshot_ref": f"outputs/analyses/{analysis_id}/frequency_snapshot.json",
        "is_complete": not incomplete, "status": "incomplete" if incomplete else "completed",
        "incomplete_reason": "candidate_resource_truncation" if incomplete else None, "candidate_truncated": incomplete,
        "errors": ["candidate_resource_truncation"] if incomplete else [],
        "metrics": {"alert_count": len(index.alerts), "representative_count": index.N,
                    "candidate_pair_count": len(candidates.pairs), "candidate_dropped_count": candidates.dropped_count,
                    "correlation_runtime_seconds": runtime, "clustering_runtime_seconds": 0, "chain_runtime_seconds": 0,
                    "total_runtime_seconds": runtime, "peak_memory_mb": peak_memory_mb()}})
    summary = {"representative_alert_count": index.N, "original_alert_count": len(index.alerts),
               "candidate_pair_count": len(candidates.pairs), "filtered_candidate_count": sum(rejections.values()),
               "accepted_relation_count": len(edges), "zero_degree_alert_count": index.N - len(degree),
               "relation_type_distribution": dict(sorted(distributions.items())), "source_independence_distribution": dict(sorted(states.items())),
               "rejection_distribution": dict(sorted(rejections.items())), "verified_member_pair_count": member_count,
               "member_score_distribution": member_scores, "candidate_score_distribution": candidate_scores,
               "actual_highest_member_score": highest_score, "actual_highest_member_support_pair": highest_score_pair,
               "correlation_threshold": scorer.algorithm.score.correlation_threshold,
               "candidate_contract_version": CANDIDATE_CONTRACT_VERSION,
               "potential_pair_stats": candidates.potential_pair_stats,
               "candidate_admission_stats": {**candidates.candidate_admission_stats, "scored_candidate_count": len(candidates.pairs)},
               "policy_pruned_count": candidates.policy_pruned_count,
               "resource_truncated_count": candidates.resource_truncated_count,
               "admitted_candidate_count": candidates.admitted_count, "scored_candidate_count": len(candidates.pairs),
               "potential_retrieval_seconds": candidates.retrieval_seconds,
               "candidate_admission_seconds": candidates.admission_seconds,
               "correlation_scoring_seconds": scoring_runtime,
               "correlation_index_and_setup_seconds": max(0, candidate_started-started),
               "candidate_truncated": incomplete, "status": record.status.value, "candidate_examined_neighbors": candidates.examined_neighbors,
               "candidate_runtime_seconds": candidate_runtime, "correlation_runtime_seconds": runtime,
               "total_runtime_seconds": runtime, "peak_memory_mb": record.metrics.peak_memory_mb,
               "process_cpu_seconds": time.process_time() - cpu_started if cpu_started is not None else None,
               "verified_incompatible_session": {"status":"unproven", "actual_trigger_count":0,
                                                  "limitation":"no_contract_defined_exclusivity_proof_or_verifiable_positive"},
               "accepted_samples": accepted_samples, "cross_source_samples": cross_samples, "same_source_samples": same_samples,
               "highest_rejected_samples": [r[2] for r in sorted(highest_rejected, key=lambda r: (-r[0], r[1]))],
               "limitations": ["candidate_truncation_recall_unknown"] if incomplete else []}
    if v2:
        ordered_scores = sorted(measured_scores)
        def quantile(q):
            if not ordered_scores:
                return None
            p = (len(ordered_scores)-1)*q
            lo, hi = math.floor(p), math.ceil(p)
            return ordered_scores[lo] + (ordered_scores[hi]-ordered_scores[lo])*(p-lo)
        summary["correlation_v2"] = {"version": scorer.algorithm.version, "gate_passed_candidate_count": gate_count,
            "gate_passed_member_count": gate_member_count, "legacy_highest_member_score": legacy_highest,
            "score_population": "best valid complete member pair per candidate; best rejected pair if none is valid",
            "score_distribution": {"P50": quantile(.5), "P90": quantile(.9), "P95": quantile(.95), "P99": quantile(.99),
                "MAX": ordered_scores[-1] if ordered_scores else None},
            "score_cutoffs": {str(cut): sum(score >= cut for score in measured_scores) for cut in (.4, .5, .6, .65, .7, .8)},
            "top_20": [row[2] for row in sorted(top_pairs, key=lambda row: (-row[0], row[1]))]}
        summary["alert_correlation_diagnostics"] = {rep: {**row, "decisions": dict(sorted(row["decisions"].items()))}
                                                    for rep, row in alert_diagnostics.items()}
    return CorrelationResult(record, edges, summary, candidates)


def main():
    from app.services.storage import read_preprocessing
    parser = argparse.ArgumentParser(description="Task 03 deterministic alert correlation; stops before incidents/chains")
    parser.add_argument("--root", required=True)
    parser.add_argument("--preprocessing-analysis-id", required=True)
    args = parser.parse_args()
    records, config, settings, manifest = read_preprocessing(args.root, args.preprocessing_analysis_id)
    import sys
    result = run_correlation(records["alerts"], records["dedupe_groups"], records["entities"], config, settings, output_root=args.root,
                             progress=lambda item: print(json.dumps(item,sort_keys=True),file=sys.stderr,flush=True))
    print(canonical_json({"analysis_id": result.record.analysis_id, "summary": result.summary}))


if __name__ == "__main__":
    main()

"""LEGACY historical Analysis Service, not the official Stage 1–4 entry.

Retained for existing snapshot/API compatibility. New analysis starts at
app.services.alert_pipeline.load_alert_pipeline; algorithms here are unchanged.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import secrets
import threading
import time
from contextlib import nullcontext

from app.adapters import AMinerAdapter, WazuhAdapter
from app.adapters.base import AlertAdapter
from app.adapters.truth import GROUND_TRUTH_FORBIDDEN_FIELDS, reject_truth
from app.chains.assembly import run_reconstruction
from app.config import EffectiveConfig
from app.correlation.edges import peak_memory_mb, run_correlation
from app.correlation.candidates import CANDIDATE_CONTRACT_VERSION, candidate_diagnosis
from app.correlation.index import AlertIndex
from app.dedup import deduplicate
from app.entities.extraction import extract_entities
from app.services.storage import (MODELS, RunAnalysisRecord, SnapshotStore, atomic_json,
                                  checked_id, file_digest, run_identity)
from app.utils.stable_id import content_digest, id_for


ALGORITHM_VERSION = "analysis-service-candidate-v1.1"
ADAPTERS = {"wazuh": WazuhAdapter, "aminer": AMinerAdapter}
ZERO_METRICS = dict(alert_count=0, representative_count=0, candidate_pair_count=0, candidate_dropped_count=0,
                    correlation_runtime_seconds=0, clustering_runtime_seconds=0, chain_runtime_seconds=0,
                    total_runtime_seconds=0, peak_memory_mb=0)
FORBIDDEN = GROUND_TRUTH_FORBIDDEN_FIELDS
PIPELINE_ROLE = 'LEGACY_HISTORICAL_REPLAY_NOT_OFFICIAL_ANALYSIS_PIPELINE'


class AnalysisInputError(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def owner_alive(pid):
    """Read-only process liveness; never signal/terminate a Windows process."""
    if type(pid) is not int or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return ctypes.get_last_error() == 5  # Access denied is not proof of exit.
        try:
            code = wintypes.DWORD()
            return not kernel.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except ProcessLookupError:
        return False


def reject_annotations(value):
    reject_truth(value)


class MeasuredAdapter:
    """Instrumentation around the existing ingress; no new parsing/mapping rules."""
    def __init__(self, adapter):
        self.adapter = adapter
        self.settings, self.config = adapter.settings, adapter.config
        self.normalization_seconds = 0.0

    def convert(self, raw):
        started = time.perf_counter()
        try:
            reject_annotations(raw)
            return self.adapter.convert(raw)
        finally:
            self.normalization_seconds += time.perf_counter() - started

    def batch(self, records, **kwargs):
        return AlertAdapter.batch(self, records, **kwargs)

    def read_file(self, path, **kwargs):
        return AlertAdapter.read_file(self, path, **kwargs)


class AnalysisService:
    def __init__(self, root, *, configs, sources, allowed_files=(), progress=None, execution_mode='standard', resource_check=None):
        if execution_mode not in {'standard', 'bounded'}:
            raise ValueError('invalid_execution_mode')
        self.execution_mode = execution_mode
        self.resource_check = resource_check
        self.root = Path(root).resolve()
        # Trusted server-side registries, never paths/settings supplied by HTTP.
        self.configs: dict[str, EffectiveConfig] = dict(configs)
        self.sources = dict(sources)
        from app.services.datasets import source_contexts
        self.dataset_sources = source_contexts(self.root)
        self.allowed_files = frozenset(allowed_files)
        self.progress = progress
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="traceback-analysis")
        self.futures = {}
        self.lock = threading.Lock()

    def safe_input(self, reference):
        if not isinstance(reference, str) or not reference or "\\" in reference or "%" in reference or ":" in reference:
            raise AnalysisInputError("input_path_not_allowed")
        relative = PurePosixPath(reference)
        if relative.is_absolute() or PureWindowsPath(reference).is_absolute() or any(p in ("..", ".") for p in reference.split("/")):
            raise AnalysisInputError("input_path_not_allowed")
        if any(p.lower() in {"evaluation", "labels", "ground_truth", "gold_chain"} for p in relative.parts):
            raise AnalysisInputError("input_path_not_allowed")
        if relative.suffix.lower() not in {".json", ".jsonl", ".ndjson"} or relative.stem.lower() in FORBIDDEN:
            raise AnalysisInputError("input_path_not_allowed")
        candidate = self.root / reference
        resolved = candidate.resolve()
        standard = (self.root / "data/input/alerts").resolve()
        # Reject redirected files/directories, including Windows junctions.
        redirected = any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
                         for p in (candidate, *candidate.parents))
        if resolved != candidate.absolute() or redirected:
            raise AnalysisInputError("input_path_not_allowed")
        if not (resolved.is_relative_to(standard) or reference in self.allowed_files):
            raise AnalysisInputError("input_path_not_allowed")
        if not resolved.is_file():
            raise AnalysisInputError("input_reference_missing")
        return resolved

    def prepare(self, request):
        version = request["config_version"]
        if version not in self.configs:
            raise AnalysisInputError("unknown_config_version")
        seen = set()
        prepared = []
        settings = {}
        for value in request["inputs"]:
            source, ref = value["source"], value["source_ref"]
            if source not in ADAPTERS or ref not in self.sources:
                raise AnalysisInputError("unsupported_source_reference")
            declared_source, setting = self.sources[ref]
            if source != declared_source:
                raise AnalysisInputError("source_reference_mismatch")
            self.safe_input(value["path"])
            key = (source, ref, value["path"])
            if key in seen:
                raise AnalysisInputError("duplicate_input_reference")
            seen.add(key)
            namespace = setting.source_namespace
            if namespace in settings and settings[namespace] != setting:
                raise AnalysisInputError("conflicting_source_settings")
            settings[namespace] = setting
            prepared.append((dict(value), setting))
        if not prepared:
            raise AnalysisInputError("empty_inputs")
        contexts = [self.dataset_sources.get(p[1].source_namespace) for p in prepared]
        registered = [c for c in contexts if c is not None]
        if registered:
            if any(not c["enabled"] for c in registered):
                raise AnalysisInputError("scene_disabled")
            if len(registered) != len(contexts) or len({(c["dataset_id"], c["scene_id"]) for c in registered}) != 1:
                raise AnalysisInputError("mixed_dataset_scenes")
            if any(p[0]["path"] != c["path"] for p, c in zip(prepared, contexts)):
                raise AnalysisInputError("dataset_scene_path_mismatch")
        # Prevent using a generic ref to bypass the registered scene boundary.
        known_paths = {c["path"] for c in self.dataset_sources.values()}
        if any(p[0]["path"] in known_paths and c is None for p, c in zip(prepared, contexts)):
            raise AnalysisInputError("dataset_source_reference_required")
        config = self.configs[version]
        snapshot = {"algorithm": config.snapshot, "sources": {k: v.snapshot() for k, v in sorted(settings.items())}}
        return config, settings, snapshot, sorted(prepared, key=lambda p: (p[0]["source_ref"], p[0]["path"]))

    def create(self, request, *, background=True):
        config, settings, snapshot, inputs = self.prepare(request)
        token = secrets.token_hex(32)
        identity = run_identity(token)
        store = SnapshotStore(self.root, identity)
        # Exclusive reservation; repeated runs cannot overwrite a prior partition.
        store.domain.mkdir(parents=True, exist_ok=False)
        store.details.mkdir(parents=True, exist_ok=False)
        run = {"analysis_id": identity, "status": "queued", "is_complete": False, "owner_pid": os.getpid(),
               "pipeline_role": PIPELINE_ROLE,
               "created_at": now(), "started_at": None, "completed_at": None,
               "candidate_contract_version": CANDIDATE_CONTRACT_VERSION,
               "config_version": request["config_version"], "config_snapshot": snapshot,
               "config_hash": content_digest(snapshot), "config_digest": content_digest(snapshot),
               "mapping_digest": config.mapping_digest, "algorithm_version":
                   'analysis-service-v5-evidence-semantics-v1' if config.algorithm.implementation_version == 'v5-evidence-semantics-v1' else
                   'analysis-service-v5-f3-independent-support-v1' if config.algorithm.implementation_version == 'v5-formula-f3-v1' else
                   'analysis-service-correlation-v4-role-context' if config.algorithm.version == 'v4' else
                   'analysis-service-correlation-v3-evidence-quality-r2' if config.algorithm.version == 'v3' and config.algorithm.duplicate.observation.event_pointers else
                   f"analysis-service-correlation-{config.algorithm.version}" if config.algorithm.version in {'v2','v3'} else ALGORITHM_VERSION,
               "inputs": [p[0] for p in inputs], "input_files": [], "dataset_digest": None,
               "counts": {}, "runtime": {}, "metrics": dict(ZERO_METRICS), "errors": [], "warnings": [],
               "incomplete_reason": None, "candidate_truncated": False, "state_history": ["queued"],
               "diagnostics_ref": f"outputs/analyses/{identity}/diagnostics.jsonl",
               "frequency_snapshot_ref": f"outputs/analyses/{identity}/frequency_snapshot.json",
               "manifest_ref": f"outputs/analyses/{identity}/manifest.json"}
        context = self.dataset_sources.get(inputs[0][1].source_namespace)
        if context:
            run["dataset_metadata"] = {"dataset_id": context["dataset_id"], "scene_id": context["scene_id"],
                "source_alert_ownership": {s.source_namespace: context["scene_id"] for _, s in inputs}}
        (store.details / "diagnostics.jsonl").write_text("", encoding="utf-8")
        atomic_json(store.details / "frequency_snapshot.json", {"status": "not_computed"})
        self._checkpoint(store, run)
        args = (store, run, token, config, settings, inputs)
        if background:
            with self.lock:
                self.futures[identity] = self.executor.submit(self._execute, *args)
        else:
            self._execute(*args)
        return identity

    def _checkpoint(self, store, run):
        atomic_json(store.domain / "run.json", run)
        atomic_json(store.details / "manifest.json", {**run, "schema_version": "1.0",
                    "domain_ref": f"data/processed/{store.analysis_id}"})

    def _execute(self, store, run, token, config, settings, inputs):
        from app.services.capacity import bounded_execution, IMPLEMENTATION_VERSION
        if self.execution_mode == 'bounded':
            run['execution_implementation'] = IMPLEMENTATION_VERSION
        context = bounded_execution(store.details/'execution_spill') if self.execution_mode == 'bounded' else nullcontext()
        with context as state:
            if state is not None and self.resource_check is not None:
                state.resource_check = self.resource_check
            if state is not None and self.progress is not None:
                state.progress = self.progress
            self._execute_pipeline(store, run, token, config, settings, inputs)

    def _execute_pipeline(self, store, run, token, config, settings, inputs):
        start = time.perf_counter()
        run.update(status="running", started_at=now())
        run["state_history"].append("running")
        self._checkpoint(store, run)
        stage = "input"
        alerts, groups, entities = [], [], []
        try:
            with store.diagnostics_writer(bounded=config.algorithm.version in {'v3', 'v4'} and bool(config.algorithm.duplicate.observation.event_pointers)) as sink:
                from app.services.capacity import execution_state
                state = execution_state()
                by_id, batches = state.alerts() if state else {}, []
                load_started = time.perf_counter()
                normalize_seconds = 0.0
                for reference, setting in inputs:
                    path = self.safe_input(reference["path"])
                    before = file_digest(path)
                    adapter = MeasuredAdapter(ADAPTERS[reference["source"]](config, setting))
                    batch = adapter.read_file(path, alert_store=state.alerts()) if state else adapter.read_file(path)
                    if self.progress:
                        self.progress({'stage':'input_source', 'source':reference['source'], 'input_count':batch.input_count,
                            'canonical_count':len(batch.alerts)})
                    if file_digest(self.safe_input(reference["path"])) != before:
                        raise ValueError("input_changed_during_read")
                    normalize_seconds += adapter.normalization_seconds
                    batches.append(batch)
                    run["input_files"].append({**reference, "sha256": before, "record_count": batch.input_count,
                        "accepted_count": batch.accepted_count, "rejected_count": len(batch.rejected),
                        "source_namespace": setting.source_namespace})
                    for a in batch.alerts:
                        if a.alert_id in by_id and by_id[a.alert_id].canonical_json() != a.canonical_json():
                            raise ValueError("same_alert_id_conflicting_content")
                        if state:
                            by_id.add(a)
                        else:
                            by_id[a.alert_id] = a
                    for rejection in batch.rejected:
                        sink({"stage": "adapter", "decision": "reject", **asdict(rejection)})
                run["runtime"].update(input_load_seconds=max(0, time.perf_counter()-load_started-normalize_seconds),
                                      normalization_seconds=normalize_seconds)
                alerts = by_id.sequence() if state else [by_id[k] for k in sorted(by_id)]
                run["counts"].update(input_count=sum(b.input_count for b in batches),
                    accepted_count=sum(b.accepted_count for b in batches), rejected_count=sum(len(b.rejected) for b in batches),
                    canonical_alert_count=len(alerts), duplicate_import_count=sum(b.accepted_count for b in batches)-len(alerts))
                run["dataset_digest"] = content_digest([[a.alert_id, a.raw_fingerprint] for a in alerts])
                # Batch containers are no longer needed; avoid retaining a
                # second generation of alerts throughout every later stage.
                del batches, batch, by_id
                if self.progress:
                    self.progress({'stage':'input_complete', **run['counts']})
                if not alerts:
                    raise ValueError("no_accepted_alerts")
                stage = "dedupe"
                stage_start = time.perf_counter()
                dedupe = deduplicate(alerts, config, settings)
                groups = dedupe.groups
                run["runtime"]["dedupe_seconds"] = time.perf_counter() - stage_start
                if self.progress:
                    self.progress({'stage':'dedupe_complete','group_count':len(groups), 'candidate_count':dedupe.candidate_count})
                for diagnostic in dedupe.diagnostics:
                    sink(diagnostic)
                stage = "entities"
                stage_start = time.perf_counter()
                extracted = extract_entities(alerts, settings)
                alerts, entities = extracted.alerts, extracted.entities
                if self.progress:
                    self.progress({'stage':'entities_complete','alert_count':len(alerts),'entity_count':len(entities)})
                run["runtime"]["entity_extraction_seconds"] = time.perf_counter() - stage_start
                run["counts"].update(dedupe_group_count=len(groups), grouped_alert_count=sum(len(g.alert_ids) for g in groups),
                    entity_count=len(entities), dedupe_candidate_count=dedupe.candidate_count,
                    dedupe_verified_pair_count=dedupe.verified_pair_count)
                self._checkpoint(store, run)
                stage = "correlation"
                def save_candidate_diagnosis(reports):
                    references = {}
                    for name, report in reports.items():
                        path = store.details / (name + ".json")
                        atomic_json(path, {"analysis_id": store.analysis_id, "config_hash": run["config_hash"],
                                          "dataset_digest": run["dataset_digest"], **report})
                        references[name] = {"ref": f"outputs/analyses/{store.analysis_id}/{path.name}",
                                            "sha256": file_digest(path)}
                    # Bound to the existing, manifest-hashed diagnostics stream.
                    sink({"stage": "candidate_diagnosis", "analysis_id": store.analysis_id, "reports": references})
                with candidate_diagnosis(save_candidate_diagnosis):
                    correlation = run_correlation(alerts, groups, entities, config, settings,
                                                  diagnostic_sink=sink, progress=self.progress)
                for key in ("potential_pair_stats", "candidate_admission_stats", "policy_pruned_count",
                            "resource_truncated_count", "admitted_candidate_count", "scored_candidate_count"):
                    run[key] = correlation.summary.get(key, 0 if key.endswith("count") else {})
                if correlation.candidates is None:
                    run["resource_truncation_events"] = ["correlation_resource_exhausted"]  # unfinished pair count unknown
                run["candidate_truncated"] = correlation.record.candidate_truncated
                run["metrics"] = correlation.record.metrics.model_dump()
                run["runtime"]["candidate_generation_seconds"] = correlation.summary.get("candidate_runtime_seconds", 0)
                run["runtime"]["correlation_seconds"] = correlation.record.metrics.correlation_runtime_seconds
                for key in ("potential_retrieval_seconds", "candidate_admission_seconds", "correlation_scoring_seconds", "correlation_index_and_setup_seconds"):
                    run["runtime"][key] = correlation.summary.get(key, 0)
                reasons = list(correlation.record.errors)
                if run["counts"]["rejected_count"]:
                    reasons.append("rejected_input_records")
                if not dedupe.is_complete:
                    reasons.append(dedupe.incomplete_reason or "dedupe_incomplete")
                reasons = sorted(set(reasons))
                if reasons:
                    upstream = correlation.record.model_dump()
                    upstream.update(status="incomplete", is_complete=False, errors=reasons, incomplete_reason=";".join(reasons))
                    from app.models import AnalysisRecord
                    correlation.record = AnalysisRecord.model_validate(upstream)
                stage = "reconstruction"
                existing_index = sink.index if state and hasattr(sink, 'index') else None
                reconstruction = run_reconstruction(alerts, groups, entities, correlation.edges, config, settings,
                    upstream_record=correlation.record, diagnostic_sink=sink, progress=self.progress,
                    existing_index=existing_index)
                run["runtime"].update(incident_clustering_seconds=reconstruction.record.metrics.clustering_runtime_seconds,
                                      chain_reconstruction_seconds=reconstruction.record.metrics.chain_runtime_seconds)
                run["counts"].update(representative_count=correlation.record.metrics.representative_count,
                    candidate_pair_count=correlation.record.metrics.candidate_pair_count,
                    candidate_dropped_count=correlation.record.metrics.candidate_dropped_count,
                    policy_pruned_count=run["policy_pruned_count"], resource_truncated_count=run["resource_truncated_count"],
                    admitted_candidate_count=run["admitted_candidate_count"], scored_candidate_count=run["scored_candidate_count"],
                    **run["potential_pair_stats"], correlation_edge_count=len(correlation.edges), incident_count=len(reconstruction.incidents),
                    attack_chain_count=len(reconstruction.chains), chain_node_count=sum(len(c.nodes) for c in reconstruction.chains),
                    chain_edge_count=sum(len(c.edges) for c in reconstruction.chains))
                run["grounding"] = reconstruction.grounding.json_data()
                if config.algorithm.version in {"v2", "v3", "v4"}:
                    from app.incidents.triage import triage_singletons
                    triage_started = time.perf_counter()
                    reconstruction.incidents = triage_singletons(reconstruction.incidents,
                        existing_index or AlertIndex(alerts, groups, entities), config, correlation.summary,
                        search_complete=reconstruction.record.is_complete)
                    run["runtime"]["single_alert_triage_seconds"] = time.perf_counter()-triage_started
                    report = correlation.summary["correlation_v2"]
                    path = store.details / "correlation_v2_scores.json"
                    atomic_json(path, {"analysis_id": store.analysis_id, "config_hash": run["config_hash"],
                                      "dataset_digest": run["dataset_digest"], **report})
                    run["correlation_v2"] = {k: v for k, v in report.items() if k != "top_20"}
                    run["correlation_v2"]["report_ref"] = f"outputs/analyses/{store.analysis_id}/{path.name}"
                    run["correlation_v2"]["sha256"] = file_digest(path)
                    sink({"stage": "single_alert_triage", "triaged_count":
                          sum(i.single_alert_triage is not None for i in reconstruction.incidents),
                          "correlation_report": run["correlation_v2"]["report_ref"]})
                run["candidate_truncated"] = reconstruction.record.candidate_truncated
                sink({"stage": "analysis_publication", "analysis_id": store.analysis_id,
                      "status": reconstruction.record.status.value, "counts": run["counts"]})
            stage = "persistence"
            stage_start = time.perf_counter()
            objects = {"alerts": alerts, "dedupe_groups": groups, "entities": entities,
                       "correlation_edges": correlation.edges, "incidents": reconstruction.incidents,
                       "attack_chains": reconstruction.chains,
                       "chain_nodes": (n for c in reconstruction.chains for n in c.nodes),
                       "chain_edges": (e for c in reconstruction.chains for e in c.edges)}
            for kind in MODELS:
                store.write_records(kind, objects[kind])
            stage_start_frequency = time.perf_counter()
            frequency = (existing_index or AlertIndex(alerts, groups, entities)).frequency_snapshot()
            run["runtime"]["frequency_snapshot_seconds"] = time.perf_counter() - stage_start_frequency
            run["runtime"]["persistence_seconds"] = time.perf_counter() - stage_start
            data = reconstruction.record.model_dump()
            data.update(analysis_id=store.analysis_id, algorithm_version=run["algorithm_version"],
                diagnostics_ref=run["diagnostics_ref"], frequency_snapshot_ref=run["frequency_snapshot_ref"])
            data["metrics"]["total_runtime_seconds"] = time.perf_counter() - start
            data["metrics"]["peak_memory_mb"] = peak_memory_mb()
            record = RunAnalysisRecord.model_validate(data)
            run.update(status=record.status.value, is_complete=record.is_complete, errors=record.errors,
                incomplete_reason=record.incomplete_reason, completed_at=now(), metrics=record.metrics.model_dump())
            run["runtime"]["total_seconds"] = record.metrics.total_runtime_seconds
            run["state_history"].append(run["status"])
            run["warnings"] = ["candidate_truncation_recall_unknown"] if record.candidate_truncated else []
            atomic_json(store.domain / "run.json", run)
            execution = {"token": token, "snapshot_identity": id_for("AnalysisRecord", record)}
            # The manifest is the last, atomic publication marker.
            store.write_metadata(record, frequency, run, execution=execution)
        except Exception as exc:
            code = str(exc) if isinstance(exc, ValueError) and len(str(exc)) < 100 else type(exc).__name__
            run.update(status="incomplete" if isinstance(exc, (MemoryError, TimeoutError)) or run["candidate_truncated"] else "failed", is_complete=False,
                       completed_at=now(), errors=[f"{stage}:{code}"], incomplete_reason=f"{stage}_not_published")
            run["resource_truncation_events"] = [f"{stage}:{code}"] if stage != "input" or isinstance(exc, (MemoryError, TimeoutError)) else []
            run["state_history"].append(run["status"])
            run["runtime"]["total_seconds"] = time.perf_counter() - start
            run["metrics"]["total_runtime_seconds"] = run["runtime"]["total_seconds"]
            with (store.details / "diagnostics.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"stage": stage, "decision": run["status"], "error": code}) + "\n")
            self._checkpoint(store, run)
        if self.progress:
            self.progress({"stage": "finished", "analysis_id": store.analysis_id, "status": run["status"], "counts": run["counts"]})

    def wait(self, identity, timeout=None):
        future = self.futures.get(checked_id(identity))
        if future:
            future.result(timeout=timeout)

    def close(self):
        self.executor.shutdown(wait=True)

    def fail_interrupted_runs(self):
        """Mark interrupted execution honestly; never automatically rerun inputs."""
        directory = self.root / "data/processed"
        if not directory.exists():
            return
        for path in sorted(directory.glob("ana_*/run.json")):
            run = json.loads(path.read_text(encoding="utf-8"))
            # A second reader/server startup cannot fail an execution owned by
            # a still-live local process. Legacy unowned records are not guessed.
            if run["status"] in {"queued", "running"} and "owner_pid" in run and not owner_alive(run["owner_pid"]):
                store = SnapshotStore(self.root, path.parent.name)
                run.update(status="failed", is_complete=False, completed_at=now(),
                           errors=["execution_interrupted"], incomplete_reason="execution_interrupted")
                run["state_history"].append("failed")
                self._checkpoint(store, run)

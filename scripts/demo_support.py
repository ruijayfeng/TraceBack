"""Demo preflight, production-service orchestration, integrity and presentation.

Fixture inputs are accepted only by test-injected contexts, never CLI flags.
The default validates an existing matching production snapshot when available.
Cold rebuild delegates to AnalysisService; no algorithm is implemented here.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen



class DemoError(RuntimeError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def save(path, value):
    from app.services.storage import atomic_json
    atomic_json(path, value)


@contextmanager
def truth_guard(root):
    """Audit actual file opens, including pathlib/io/native Python callers."""
    active = [True]
    root = Path(root).resolve()
    def audit(event, args):
        if event != "open" or not active[0] or not isinstance(args[0], (str, bytes, os.PathLike)):
            return
        path = Path(os.fsdecode(args[0])).resolve()
        if path.is_relative_to(root / "evaluation") or path.name.lower() in {
            "labels.csv", "attacks.log", "gold_chain.json", "ground_truth.json"}:
            raise DemoError("Ground Truth access rejected: " + str(path))
    sys.addaudithook(audit)
    try:
        yield
    finally:
        active[0] = False


def source_registry(root, config, inputs):
    """Same confirmed-registry policy as existing create_app; fail on conflicts."""
    from app.adapters.base import AdapterSettings
    from app.utils.stable_id import content_digest
    sources, origins = {}, []
    needed = {i["source_ref"] for i in inputs}
    for path in sorted((root / "outputs/analyses").glob("ana_*/manifest.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        snapshot = manifest.get("config_snapshot", {})
        if snapshot.get("algorithm") != config.snapshot or content_digest(snapshot) != manifest.get("config_hash"):
            continue
        used = False
        for namespace, data in snapshot.get("sources", {}).items():
            if namespace not in needed:
                continue
            setting = AdapterSettings(**data)
            source = setting.generator.lower()
            if namespace != setting.source_namespace or source not in {"wazuh", "aminer"}:
                raise DemoError("invalid confirmed source registry: " + str(path))
            value = (source, setting)
            if namespace in sources and sources[namespace] != value:
                raise DemoError("conflicting confirmed source registry: " + str(path))
            sources[namespace] = value
            used = True
        if used:
            origins.append({"path": path.relative_to(root).as_posix(), "sha256": digest(path)})
    if set(sources) != needed:
        raise DemoError("confirmed AdapterSettings missing; restore the accepted deployment manifest, do not guess namespace/timezone")
    return sources, origins


def digest(path):
    from app.services.storage import file_digest
    return file_digest(Path(path))


def code_version(root):
    files = sorted([*root.glob("backend/app/**/*.py"), *root.glob("scripts/demo*.py"),
                    *root.glob("scripts/verify_demo.py"), root / "backend/pyproject.toml"])
    hashes = {p.relative_to(root).as_posix(): digest(p) for p in files}
    from app.utils.stable_id import content_digest
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True)
    return {"git_commit": result.stdout.strip() if result.returncode == 0 else None,
            "git_status": "available" if result.returncode == 0 else "unavailable_no_git_metadata",
            "source_digest": content_digest(hashes), "files": hashes}


def preflight(root, dataset_id="ait_ads", scene_id=None):
    root = Path(root).resolve()
    checks = []
    def check(name, action, repair):
        try:
            result = action()
        except Exception as exc:
            raise DemoError(f"preflight [{name}]: {exc}. Repair: {repair}") from exc
        checks.append({"check": name, "status": "passed"})
        print(f"Preflight {name}: passed", flush=True)
        return result
    def environment():
        if sys.version_info[:2] != (3, 11):
            raise ValueError("Python 3.11 required: " + sys.executable)
        project = tomllib.loads((root / "backend/pyproject.toml").read_text(encoding="utf-8"))["project"]
        for requirement in project["dependencies"]:
            package, expected = requirement.split("==")
            if version(package) != expected:
                raise ValueError("package mismatch: " + requirement)
        for module in ("pydantic", "yaml", "duckdb", "fastapi", "uvicorn"):
            importlib.import_module(module)
    check("Python / packages / DuckDB / API dependencies", environment, "install ./backend[test] in the Python 3.11 .venv per README")
    from app.config import load_config, read_yaml
    check("algorithm-v0.yaml", lambda: read_yaml(root / "configs/algorithm-v0.yaml"), "restore configs/algorithm-v0.yaml")
    check("sources.yaml", lambda: read_yaml(root / "configs/sources.yaml"), "restore configs/sources.yaml")
    config = check("effective config / Mapping v1", lambda: load_config(root / "configs/algorithm-v0.yaml", deployment_override=root / "configs/sources.yaml"), "restore valid YAML and every referenced configs/mappings file")
    from app.services.datasets import load_dataset
    loaded = check("Dataset / Scene registry", lambda: load_dataset(root, dataset_id, scene_id), "restore data/<dataset>/dataset.yaml with valid source declarations")
    config, sources, inputs = loaded.config, loaded.sources, loaded.inputs
    origins = [{"path": f"data/{dataset_id}/dataset.yaml", "selection_digest": loaded.metadata["registry_selection_digest"]}]
    from app.services.analysis import AnalysisService
    service = AnalysisService(root, configs={"v0": config}, sources=sources, allowed_files=[i["path"] for i in inputs])
    try:
        for item in inputs:
            check(item["source"] + " real input", lambda item=item: service.safe_input(item["path"]), "restore the original real security alert JSON file " + item["path"])
    finally:
        service.close()
    def storage():
        import duckdb
        for directory in (root / "outputs/demo", root / "outputs/analyses", root / "data/processed"):
            directory.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="demo-preflight-", dir=directory) as tmp:
                path = Path(tmp)
                (path / "write-probe").write_text("probe", encoding="utf-8")
                with duckdb.connect(str(path / "probe.duckdb")) as db:
                    parquet = str(path / "probe.parquet").replace("'", "''")
                    db.execute(f"COPY (SELECT 1 AS n) TO '{parquet}' (FORMAT PARQUET)")
                    if db.execute("SELECT n FROM read_parquet(?)", [str(path / "probe.parquet")]).fetchone() != (1,):
                        raise ValueError("Parquet round-trip failed")
    check("output write / DuckDB / Parquet round-trip", storage, "ensure outputs and data/processed are writable and DuckDB available")
    from app.main import create_app
    app = check("existing application factory", lambda: create_app(root, configs={"v0": config}, sources=sources, allowed_files=[i["path"] for i in inputs]), "check existing FastAPI startup diagnostics")
    app.state.analyses.close()
    return {"root": root, "config": config, "sources": sources, "request": loaded.request,
            "checks": checks, "source_registry_origins": origins, "dataset": loaded.scene_id, "data_kind": "real",
            "dataset_metadata": loaded.metadata}


def collect(context, identity, *, parquet=False):
    from app.services.storage import SnapshotStore, MODELS
    from app.utils.stable_id import content_digest
    store = SnapshotStore(context["root"], identity)
    record, _, manifest = store.read_metadata()
    summary = manifest["summary"]
    if record.status.value != "completed" or not record.is_complete:
        raise DemoError("production pipeline not completed: " + str(summary.get("errors")))
    if record.config_hash != content_digest(record.config_snapshot) or record.mapping_digest != context["config"].mapping_digest:
        raise DemoError("snapshot configuration mismatch")
    used_sources = [context["sources"][item["source_ref"]][1] for item in context["request"]["inputs"]]
    expected = {"algorithm": context["config"].snapshot,
                "sources": {setting.source_namespace: setting.snapshot() for setting in used_sources}}
    if record.config_snapshot != expected or summary["inputs"] != sorted(context["request"]["inputs"], key=lambda i: (i["source_ref"], i["path"])):
        raise DemoError("snapshot input/deployment mismatch")
    for item in summary["input_files"]:
        if digest(context["root"] / item["path"]) != item["sha256"]:
            raise DemoError("snapshot input changed: " + item["path"])
    # Existing verifier checks the entire formal node/edge/evidence closure.
    store.validate_reconstruction(parquet=parquet)
    import duckdb
    identities = {}
    with duckdb.connect(":memory:") as db:
        for kind in MODELS:
            path = store.domain / (kind + ".parquet")
            rows = db.execute("SELECT object_id,payload FROM read_parquet(?) ORDER BY object_id", [str(path)]).fetchall()
            identities[kind] = {"count": len(rows), "identity_digest": content_digest([r[0] for r in rows]),
                                "content_digest": content_digest([json.loads(r[1]) for r in rows])}
    counts = summary["counts"]
    for kind, name in (("alerts", "canonical_alert_count"), ("entities", "entity_count"), ("incidents", "incident_count"),
                       ("correlation_edges", "correlation_edge_count"), ("chain_edges", "chain_edge_count")):
        if identities[kind]["count"] != counts[name]:
            raise DemoError("snapshot count mismatch: " + name)
    representative_ids = set(record.input_alert_ids)
    for group in store.read_records("dedupe_groups", parquet=parquet):
        representative_ids.difference_update(set(group.alert_ids) - {group.representative_alert_id})
    identities["representatives"] = {"count": len(representative_ids), "identity_digest": content_digest(sorted(representative_ids))}
    if len(representative_ids) != counts["representative_count"]:
        raise DemoError("representative count mismatch")
    if context["data_kind"] == "real" and context["dataset"] == "russellmitchell" and (counts["correlation_edge_count"] or counts["chain_edge_count"]):
        raise DemoError("real frozen zero-edge result changed; investigate without tuning")
    return store, record, summary, identities


def http_get(base, path, method="GET"):
    try:
        with urlopen(Request(base + path, method=method), timeout=30) as response:
            return response.status, json.load(response)
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def stop_api(process):
    """Stop only our child and its Windows venv redirector descendants."""
    if process.poll() is None:
        if os.name == "nt" and hasattr(process, "args"):
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=15)


def smoke(get, identity, counts, *, presentation=False):
    """Works with real HTTP or the existing application's TestClient in tests."""
    scope = "?analysis_id=" + identity
    results = {}
    def expect(name, path, expected=200, method="GET"):
        status, body = get(path, method)
        if status != expected:
            raise DemoError(f"API smoke [{name}]: HTTP {status}, expected {expected}: {body}")
        results[name] = {"status": "available", "http_status": status, "path": path}
        return body
    expect("startup / OpenAPI", "/openapi.json")
    analysis = expect("analysis", "/api/v1/analyses/" + identity)
    if analysis["status"] != "completed" or analysis["counts"] != counts:
        raise DemoError("API analysis result mismatch")
    incidents = expect("incidents", "/api/v1/incidents" + scope)
    if incidents["total"] != counts["incident_count"] or not incidents["items"]:
        raise DemoError("API incident result mismatch")
    iid = incidents["items"][0]["incident_id"]
    expect("incident detail", "/api/v1/incidents/" + iid + scope)
    chain = expect("chain", f"/api/v1/incidents/{iid}/chain" + scope)["chain"]
    expect("timeline", f"/api/v1/incidents/{iid}/timeline" + scope)
    alert = expect("node evidence", "/api/v1/alerts/" + chain["nodes"][0]["alert_ids"][0] + scope)
    if not alert["alert"]["raw_alert"]:
        raise DemoError("API raw evidence missing")
    if chain["edges"]:
        edge = expect("edge reasons", "/api/v1/edges/" + chain["edges"][0]["edge_id"] + scope)
        if not edge["edge"]["reasons"] or not edge["correlation_edges"]:
            raise DemoError("API edge grounding missing")
    else:
        expect("edge empty lookup", "/api/v1/edges/che_" + "0"*64 + scope, 404)
        results["edge reasons"] = {"status": "available", "positive_result": "not_applicable_real_zero_edges"}
    if presentation:
        expect("SOC overview", f"/api/v1/analyses/{identity}/overview")
        expect("SOC workbench", f"/api/v1/analyses/{identity}/workbench")
        status, ai = get(f"/api/v1/incidents/{iid}/explain" + scope, "POST")
        if status not in {200, 409} or ai.get("grounding_status") != "validated" or not ai.get("report_json"):
            raise DemoError("Explain did not return a validated formal report")
        results["AI"] = {"status": "available", "http_status": status,
            "generation_status": ai["generation_status"], "result_origin": ai["result_origin"]}
        expect("persisted report", f"/api/v1/incidents/{iid}/explanation" + scope)
        results["UI"] = {"status": "available", "mode": "built frontend at API root"}
    else:
        # Retain the old smoke helper's explicit test-only packaging contract.
        expect("AI availability", f"/api/v1/incidents/{iid}/explain" + scope, 409, "POST")
        results["AI"] = {"status": "not_implemented", "reason": "ai_grounding_unavailable"}
        results["UI"] = {"status": "not_implemented", "components": ["frontend", "Attack Chain UI", "Evidence Drawer", "Edge Reason Drawer"]}
    results["health"] = {"status": "not_implemented", "substitute": "HTTP OpenAPI startup probe"}
    return results


def start_api(context, identity, directory, counts):
    started = time.perf_counter()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    command = [sys.executable, str(context["root"] / "scripts/demo.py"), "--serve", identity, "--port", str(port)]
    log = directory / "api.log"
    with log.open("wb") as handle:
        process = subprocess.Popen(command, cwd=context["root"], stdin=subprocess.DEVNULL, stdout=handle, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0, start_new_session=os.name != "nt")
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 60
        while True:
            if process.poll() is not None:
                raise DemoError("API startup failed; see " + str(log))
            try:
                if http_get(base, "/openapi.json")[0] == 200:
                    break
            except (URLError, TimeoutError, ConnectionError):
                pass
            if time.monotonic() >= deadline:
                raise DemoError("API startup timeout; see " + str(log))
            time.sleep(0.25)
        built = (context["root"] / "frontend/dist/index.html").is_file()
        startup_seconds = time.perf_counter() - started
        results = smoke(lambda path, method="GET": http_get(base, path, method), identity, counts, presentation=True)
        if not built:
            results["UI"] = {"status": "build_required", "command": "npm --prefix frontend run build"}
        context["_api_process"] = process
        return {"url": base, "docs": base + "/docs", "pid": process.pid, "status": "running",
                "startup_seconds": startup_seconds,
                "web": base + "/?analysis_id=" + identity if built else None,
                "command": command, "log": log.relative_to(context["root"]).as_posix(), "smoke": results}
    except BaseException:
        # Preserve cleanup even when the subprocess has already exited.
        if process.poll() is not None:
            process.terminate()
            process.wait(timeout=15)
        else:
            stop_api(process)
        raise


def serve(root, identity, port):
    try:
        with truth_guard(root):
            from app.services.storage import SnapshotStore
            from app.api.workbench import create_workbench_app
            from app.config import load_config
            from app.adapters.base import AdapterSettings
            import uvicorn
            record, _, manifest = SnapshotStore(root, identity).read_metadata()
            from app.services.storage import restore_config
            config = restore_config(record.config_snapshot["algorithm"])
            sources = {namespace: (data["generator"].lower(), AdapterSettings(**data))
                       for namespace, data in record.config_snapshot["sources"].items()}
            app = create_workbench_app(root, configs={"v0": config}, sources=sources, allowed_files=[i["path"] for i in manifest["summary"]["inputs"]])
            uvicorn.run(app, host="127.0.0.1", port=port)
        return 0
    except Exception as exc:
        print("FAILED [API startup]: " + str(exc), file=sys.stderr, flush=True)
        return 1


def execute(context, directory, *, api_launcher=start_api, snapshot_id=None, final=False):
    from app.services.analysis import AnalysisService
    started = time.perf_counter()
    manifest = {"task": "09", "dataset": context["dataset"], "data_kind": context["data_kind"],
                "dataset_metadata": context.get("dataset_metadata"),
                "run_id": directory.name, "status": "running", "started_at": now(), "finished_at": None,
                "ground_truth_used": False, "production_core_modified": False,
                "preflight": context["checks"], "source_registry_origins": context.get("source_registry_origins", []),
                "code_version": code_version(context["root"]), "snapshot_reused": snapshot_id is not None,
                "cross_dataset_evaluation": "blocked_by_missing_dataset",
                "test_status": "not_run_by_demo", "build_status": "existing_build_unverified" if
                (context["root"] / "frontend/dist/index.html").is_file() else "build_required",
                "preflight_duration_seconds": context.get("preflight_duration_seconds")}
    save(directory / "demo_manifest.json", manifest)
    service = None
    try:
        if snapshot_id is None:
            service = AnalysisService(context["root"], configs={"v0": context["config"]}, sources=context["sources"],
                allowed_files=[i["path"] for i in context["request"]["inputs"]],
                progress=lambda value: print("Production: " + json.dumps(value, ensure_ascii=False), flush=True))
            identity = service.create(context["request"], background=False)
        else:
            identity = snapshot_id
        manifest["analysis_id"] = identity
        save(directory / "demo_manifest.json", manifest)
        if final:
            from verify_demo import validate_snapshot
            store, record, summary, identities, validity = validate_snapshot(context, identity)
            manifest["snapshot_validation"] = validity
            manifest["snapshot_identity"] = validity["snapshot_identity"]
        else:
            store, record, summary, identities = collect(context, identity)
        if code_version(context["root"])["source_digest"] != manifest["code_version"]["source_digest"]:
            raise DemoError("code changed during demo execution")
        counts = summary["counts"]
        manifest.update(input={source + "_count": sum(i["record_count"] for i in summary["input_files"] if i["source"] == source)
                              for source in ("wazuh", "aminer")},
                        input_files=summary["input_files"], configuration={"config_hash": record.config_hash, "mapping_digest": record.mapping_digest},
                        analysis=counts, identities=identities, dataset_digest=record.dataset_digest,
                        algorithm_version=record.algorithm_version, candidate_contract_version=summary["candidate_contract_version"],
                        production_runtime=summary["runtime"], peak_memory_mb=record.metrics.peak_memory_mb,
                        artifacts={"analysis_snapshot": (store.domain / "analysis.json").relative_to(context["root"]).as_posix(),
                                   "analysis_manifest": (store.details / "manifest.json").relative_to(context["root"]).as_posix(),
                                   "domain": store.domain.relative_to(context["root"]).as_posix(),
                                   "diagnostics": record.diagnostics_ref, "frequency_snapshot": record.frequency_snapshot_ref,
                                   "demo_manifest": (directory / "demo_manifest.json").relative_to(context["root"]).as_posix(),
                                   "report": (directory / "TASK_09_REPORT.md").relative_to(context["root"]).as_posix()})
        manifest["input"]["total_count"] = counts["input_count"]
        manifest["cold_duration_seconds"] = summary["runtime"].get("total_seconds")
        manifest["cold_measurement_origin"] = "persisted_production_run" if snapshot_id else "current_production_run"
        manifest["warm_duration_seconds"] = time.perf_counter() - started if snapshot_id else None
        # Preserve verified analysis details even if API startup subsequently fails.
        save(directory / "demo_manifest.json", manifest)
        manifest["application"] = api_launcher(context, identity, directory, counts)
        if final:
            from verify_demo import select_incidents, verify_http
            selected = select_incidents(context["root"], identity)
            manifest["demo_incidents"] = selected
            manifest["real_smoke"] = verify_http(context["root"], identity, selected,
                lambda path, method="GET": http_get(manifest["application"]["url"], path, method))
            manifest["AI_status"] = [i["generation_status"] for i in manifest["real_smoke"]["incidents"]]
            manifest["dataset_identity"] = record.dataset_digest
            manifest["schema_version"] = record.schema_version
            manifest["config_hash"] = record.config_hash
            manifest["mapping_digest"] = record.mapping_digest
            manifest["demo_ready_duration_seconds"] = time.perf_counter() - started + context.get("preflight_duration_seconds", 0)
            save(directory / "real_smoke.json", manifest["real_smoke"])
        manifest.update(status="completed", packaging_status="soc_workbench_ready" if
            manifest["application"].get("smoke", {}).get("UI", {}).get("status") == "available" else "packaging_completed_with_product_gaps")
    except BaseException as exc:
        process = context.get("_api_process")
        if process is not None and process.poll() is None:
            stop_api(process)
        manifest.update(status="failed", packaging_status="blocked", error=f"{type(exc).__name__}: {exc}")
    finally:
        if service is not None:
            service.close()
        manifest.update(finished_at=now(), generated_at=now(), runtime_seconds=time.perf_counter() - started)
        save(directory / "demo_manifest.json", manifest)
        write_report(directory, manifest)
    return manifest


def write_report(directory, manifest):
    lines = ["# TASK 09 Demo execution", "", "Production Core Modified: NO", "Ground Truth Used by Production Demo: NO", "",
             "Packaging status: " + manifest["packaging_status"], "Data kind: " + manifest["data_kind"],
             "Cross-dataset: framework_completed / evaluation_blocked_by_missing_dataset", "",
             "Full interactive presentation: " + manifest["packaging_status"], "",
             "Command: `python scripts/demo.py`", "", "Default validates a matching production snapshot; --cold-rebuild runs AnalysisService.", "",
             "Health route is not implemented; startup is checked via HTTP OpenAPI. Real zero edges have no positive edge reason example.", "",
             "## Measured run", "", "```json", json.dumps(manifest, ensure_ascii=False, indent=2), "```", ""]
    (directory / "TASK_09_REPORT.md").write_text("\n".join(lines), encoding="utf-8")


def print_result(root, directory, manifest):
    print("\nTraceBack Demo\n==============")
    print("Dataset       : " + manifest["dataset"])
    print("Status        : " + manifest["status"])
    print("Packaging     : " + manifest["packaging_status"])
    for key, value in manifest.get("input", {}).items():
        print(f"Input {key}: {value:,}")
    for key in ("canonical_alert_count", "representative_count", "entity_count", "unique_potential_pairs",
                "admitted_candidate_count", "scored_candidate_count", "correlation_edge_count", "incident_count", "chain_edge_count"):
        if key in manifest.get("analysis", {}):
            print(f"{key}: {manifest['analysis'][key]:,}")
    print("Runtime seconds: " + str(manifest["runtime_seconds"]))
    print("Demo Manifest: " + str(directory / "demo_manifest.json"))
    print("Analysis Artifact: " + str(root / manifest["artifacts"]["analysis_snapshot"]) if "artifacts" in manifest else "Analysis Artifact: unavailable")
    if "application" in manifest:
        print("API: " + manifest["application"]["url"] + " (running, PID " + str(manifest["application"]["pid"]) + ")")
        print("API Docs: " + manifest["application"]["docs"])
        print("Web: " + str(manifest["application"].get("web") or "Build UI: npm --prefix frontend run build"))
        print("Analysis ID: " + manifest["analysis_id"])
    print("Ground Truth Used: NO\nProduction Core Modified: NO")
    if "error" in manifest:
        print("FAILED: " + manifest["error"], file=sys.stderr)


def demo_output(root, context):
    metadata = context["dataset_metadata"]
    return Path(root) / "outputs/task09" / metadata["dataset_id"] / metadata["scene_id"]


def run_demo(root, *, check_only=False, analysis_id=None, cold_rebuild=False, warm_only=False, dataset_id="ait_ads", scene_id=None):
    root = Path(root).resolve()
    try:
        with truth_guard(root):
            preflight_started = time.perf_counter()
            context = preflight(root, dataset_id, scene_id)
            context["preflight_duration_seconds"] = time.perf_counter() - preflight_started
            if check_only:
                print("Preflight completed; no production analysis executed.")
                return 0
            from verify_demo import choose_snapshot
            identity = None if cold_rebuild else choose_snapshot(context, analysis_id)
            if identity is None and warm_only:
                raise DemoError("snapshot_missing: run --cold-rebuild to create a production snapshot")
            print("Demo mode: " + ("validated warm snapshot" if identity else "cold production analysis"), flush=True)
            directory = Path(tempfile.mkdtemp(prefix="task09-", dir=root / "outputs/demo"))
            manifest = execute(context, directory, snapshot_id=identity, final=True)
            final_output = demo_output(root, context)
            final_output.mkdir(parents=True, exist_ok=True)
            save(final_output / "demo_manifest.json", manifest)
            if context["dataset_metadata"]["scene_id"] == context["dataset_metadata"]["default_scene"]:
                # Retain the default Demo's public receipt path only for its
                # own scene; other scenes never replace that legacy receipt.
                save(root / "outputs/task09/demo_manifest.json", manifest)
            print_result(root, directory, manifest)
            return 0 if manifest["status"] == "completed" else 1
    except Exception as exc:
        print("FAILED [Demo]: " + str(exc), file=sys.stderr, flush=True)
        return 1


def open_analysis(root, identity):
    """Explicit snapshot mode. Never recomputes or modifies production results."""
    return run_demo(root, analysis_id=identity, warm_only=True)

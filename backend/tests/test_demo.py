"""Task 06.7 packaging checks; every fixture run is synthetic/test-only."""

import json
from pathlib import Path
import shutil
import subprocess
import sys

from fastapi.testclient import TestClient
import pytest

from app.main import create_app
from app.services.storage import SnapshotStore, file_digest
from test_analysis_service import deployment, edge_records, write_input, request_for, tripwire
from test_wazuh_adapter import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import demo_support as demo
from app.services.datasets import load_dataset
DEFAULT_INPUTS = load_dataset(ROOT).inputs


@pytest.fixture
def preflight_root(tmp_path):
    shutil.copytree(ROOT / "configs", tmp_path / "configs")
    (tmp_path / "backend").mkdir()
    shutil.copy2(ROOT / "backend/pyproject.toml", tmp_path / "backend/pyproject.toml")
    registry = tmp_path / "data/ait_ads/dataset.yaml"
    registry.parent.mkdir(parents=True)
    shutil.copy2(ROOT / "data/ait_ads/dataset.yaml", registry)
    # Deployment metadata is production-confirmed; input here is test-only.
    source = ROOT / "outputs/analyses/ana_c24111d997ab7a4cc809392ffb0306155ffffc6e1a73f74a0e1e45fab3c413d7/manifest.json"
    manifest_dir = tmp_path / "outputs/analyses" / source.parent.name
    manifest_dir.mkdir(parents=True)
    shutil.copy2(source, manifest_dir / "manifest.json")
    for item in DEFAULT_INPUTS:
        path = tmp_path / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{}\n', encoding='utf-8')
    return tmp_path


def test_preflight_success_and_real_default_identity(preflight_root):
    context = demo.preflight(preflight_root)
    assert context["dataset"] == "russellmitchell"
    assert context["request"]["inputs"] == DEFAULT_INPUTS
    assert all(c["status"] == "passed" for c in context["checks"])
    assert len(context["source_registry_origins"]) == 1


@pytest.mark.parametrize("path", [i["path"] for i in DEFAULT_INPUTS] + ["configs/algorithm-v0.yaml", "configs/sources.yaml"])
def test_preflight_missing_file_fails_fast(preflight_root, path):
    (preflight_root / path).unlink()
    with pytest.raises(demo.DemoError, match="preflight.*Repair"):
        demo.preflight(preflight_root)


@pytest.mark.parametrize("path", ["configs/algorithm-v0.yaml", "configs/mappings/wazuh-category.yaml"])
def test_preflight_invalid_config_or_mapping(preflight_root, path):
    (preflight_root / path).write_text('unknown_key: true\n', encoding='utf-8')
    with pytest.raises(demo.DemoError, match="effective config / Mapping v1"):
        demo.preflight(preflight_root)


def test_preflight_storage_unavailable(preflight_root, monkeypatch):
    import duckdb
    def unavailable(*args, **kwargs):
        raise OSError("synthetic unavailable storage")
    monkeypatch.setattr(duckdb, "connect", unavailable)
    with pytest.raises(demo.DemoError, match="output write / DuckDB / Parquet.*Repair"):
        demo.preflight(preflight_root)


def fixture_context(tmp_path):
    config, sources = deployment(tmp_path, edge=True)
    path = write_input(tmp_path, edge_records())
    return {"root": tmp_path, "config": config, "sources": sources, "request": request_for(path),
            "checks": [{"check": "test-only synthetic deployment", "status": "passed"}],
            "dataset": "synthetic-test-only", "data_kind": "fixture"}


def test_application_smoke_fixture_manifest_determinism_and_gt_isolation(tmp_path, monkeypatch):
    context = fixture_context(tmp_path)
    reads = tripwire(monkeypatch)
    monkeypatch.setattr(demo, "code_version", lambda root: {"git_commit": None, "source_digest": "test-only"})
    def api(context, identity, directory, counts):
        app = create_app(tmp_path, configs={"v0": context["config"]}, sources=context["sources"])
        with TestClient(app) as client:
            def get(path, method="GET"):
                response = client.request(method, path)
                return response.status_code, response.json()
            report = demo.smoke(get, identity, counts)
        assert report["edge reasons"]["http_status"] == 200
        assert report["AI"]["status"] == "not_implemented"
        return {"smoke": report, "status": "test-only", "url": "in-process-test-only"}
    manifests = []
    with demo.truth_guard(tmp_path):
        for name in ("fixture-1", "fixture-2"):
            directory = tmp_path / "outputs/demo-fixtures" / name
            directory.mkdir(parents=True)
            manifests.append(demo.execute(context, directory, api_launcher=api))
    first, second = manifests
    assert first["status"] == second["status"] == "completed"
    assert first["analysis_id"] != second["analysis_id"]
    for field in ("identities", "configuration", "input_files", "dataset_digest", "analysis", "algorithm_version"):
        assert first[field] == second[field]
    assert first["ground_truth_used"] is False and first["snapshot_reused"] is False
    assert first["data_kind"] == "fixture" and first["dataset"] != "russellmitchell"
    assert first["analysis"]["chain_edge_count"] == 1
    for key, relative in first["artifacts"].items():
        assert (tmp_path / relative).exists(), key
    assert first["configuration"]["mapping_digest"] == context["config"].mapping_digest
    for item in first["input_files"]:
        assert item["sha256"] == file_digest(tmp_path / item["path"])
    required = {"dataset", "run_id", "input", "configuration", "analysis", "status", "started_at", "finished_at",
                "runtime_seconds", "artifacts", "application", "code_version", "identities", "peak_memory_mb"}
    assert required <= first.keys()
    assert reads


@pytest.mark.parametrize("filename", ["evaluation/labels.csv", "evaluation/gold.json", "labels.csv", "attacks.log"])
def test_runtime_audit_rejects_truth_open(tmp_path, filename):
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("evaluation-only test sentinel", encoding="utf-8")
    with demo.truth_guard(tmp_path), pytest.raises(demo.DemoError, match="Ground Truth access rejected"):
        path.read_text(encoding="utf-8")


@pytest.mark.parametrize("stage", ["pipeline", "snapshot", "API"])
def test_failure_never_publishes_completed_manifest(tmp_path, monkeypatch, stage):
    context = fixture_context(tmp_path)
    monkeypatch.setattr(demo, "code_version", lambda root: {"source_digest": "test-only"})
    def fail(*args, **kwargs):
        raise demo.DemoError("synthetic " + stage + " failure")
    if stage == "pipeline":
        from app.services.analysis import AnalysisService
        monkeypatch.setattr(AnalysisService, "create", fail)
    elif stage == "snapshot":
        monkeypatch.setattr(SnapshotStore, "read_metadata", fail)
    directory = tmp_path / "outputs/demo-fixtures/failed"
    directory.mkdir(parents=True)
    result = demo.execute(context, directory, api_launcher=fail)
    persisted = json.loads((directory / "demo_manifest.json").read_text(encoding="utf-8"))
    assert result["status"] == persisted["status"] == "failed"
    assert persisted["packaging_status"] == "blocked"
    assert stage in persisted["error"]


def test_check_only_command_and_nonzero_failure(preflight_root):
    # CLI has no dataset/config/fixture escape hatch; ROOT is the real repo.
    result = subprocess.run([sys.executable, str(ROOT / "scripts/demo.py"), "--check-only"], cwd=ROOT,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "no production analysis executed" in result.stdout
    (preflight_root / DEFAULT_INPUTS[0]["path"]).unlink()
    assert demo.run_demo(preflight_root, check_only=True) == 1


def test_packaging_has_no_evaluation_import_or_algorithm_implementation():
    import ast
    for path in (ROOT / "scripts/demo.py", ROOT / "scripts/demo_support.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith(("evaluation", "app.correlation", "app.incidents", "app.chains"))
            if isinstance(node, ast.Import):
                assert all(not a.name.startswith("evaluation") for a in node.names)


def test_actual_corrupted_snapshot_is_rejected(tmp_path):
    from app.services.analysis import AnalysisService
    context = fixture_context(tmp_path)
    service = AnalysisService(tmp_path, configs={"v0": context["config"]}, sources=context["sources"])
    try:
        identity = service.create(context["request"], background=False)
    finally:
        service.close()
    store = SnapshotStore(tmp_path, identity)
    (store.domain / "chain_edges.parquet").write_bytes(b"test-only damaged snapshot")
    with pytest.raises(ValueError, match="domain_digest_mismatch"):
        demo.collect(context, identity)


def test_api_process_exit_fails_startup_and_is_cleaned_up(tmp_path, monkeypatch):
    class FailedProcess:
        pid = 123
        terminated = False
        def poll(self):
            return 1
        def terminate(self):
            self.terminated = True
        def wait(self, timeout):
            return 1
    process = FailedProcess()
    monkeypatch.setattr(demo.subprocess, "Popen", lambda *a, **k: process)
    with pytest.raises(demo.DemoError, match="API startup failed"):
        demo.start_api({"root": tmp_path}, "ana_" + "0"*64, tmp_path, {})
    assert process.terminated

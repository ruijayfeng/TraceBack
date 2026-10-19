"""Task 09 warm identity, failure rejection and formal closure. Synthetic only."""

import json
import sys

import pytest
from fastapi.testclient import TestClient

from app.api.workbench import create_workbench_app
from app.services.analysis import AnalysisService
from app.services.storage import SnapshotStore
from test_demo import fixture_context
from test_wazuh_adapter import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import demo_support as demo
import verify_demo as verify


@pytest.fixture
def published(tmp_path):
    context = fixture_context(tmp_path)
    service = AnalysisService(tmp_path, configs={"v0": context["config"]}, sources=context["sources"])
    try:
        identity = service.create(context["request"], background=False)
    finally:
        service.close()
    return context, identity


def test_warm_rechecks_bytes_and_never_calls_production(published, monkeypatch):
    context, identity = published
    first = verify.validate_snapshot(context, identity)
    assert first[4]["receipt_reused"] is False
    def forbidden(*args, **kwargs):
        pytest.fail("warm snapshot reran production/deep verification")
    monkeypatch.setattr(AnalysisService, "create", forbidden)
    monkeypatch.setattr(SnapshotStore, "validate_reconstruction", forbidden)
    second = verify.validate_snapshot(context, identity)
    assert second[4]["receipt_reused"] is True
    assert first[3] == second[3]
    assert verify.choose_snapshot(context) == identity
    (SnapshotStore(context["root"], identity).domain / "chain_edges.parquet").write_bytes(b"synthetic damaged")
    with pytest.raises(ValueError, match="snapshot_invalid.*domain_digest_mismatch"):
        verify.validate_snapshot(context, identity)


@pytest.mark.parametrize("change", ["input", "mapping", "config", "algorithm", "required_artifact", "receipt", "run"])
def test_critical_mismatch_is_never_silently_reused(published, change):
    context, identity = published
    verify.validate_snapshot(context, identity)
    store = SnapshotStore(context["root"], identity)
    if change == "input":
        (context["root"] / context["request"]["inputs"][0]["path"]).write_text('{}\n', encoding="utf-8")
    elif change == "mapping":
        from dataclasses import replace
        context["config"] = replace(context["config"], mapping_digest="0" * 64)
    elif change == "config":
        from dataclasses import replace
        snapshot = context["config"].snapshot
        snapshot["time"]["clock_skew_seconds"] += 1
        context["config"] = replace(context["config"], _snapshot_json=json.dumps(snapshot))
    elif change == "required_artifact":
        (store.domain / "chain_nodes.parquet").unlink()
    elif change == "receipt":
        receipt = context["root"] / "outputs/task09/validated_snapshots" / (identity + ".json")
        payload = json.loads(receipt.read_text(encoding="utf-8"))
        payload["status"] = "corrupt"
        receipt.write_text(json.dumps(payload), encoding="utf-8")
    elif change == "run":
        payload = json.loads((store.domain / "run.json").read_text(encoding="utf-8"))
        payload["counts"]["incident_count"] += 1
        (store.domain / "run.json").write_text(json.dumps(payload), encoding="utf-8")
    else:
        payload = json.loads((store.details / "manifest.json").read_text(encoding="utf-8"))
        payload["algorithm_version"] = "wrong-version"
        (store.details / "manifest.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="snapshot_invalid"):
        verify.validate_snapshot(context, identity)


def test_missing_snapshot_is_explicit_and_no_rebuild(published):
    context, _ = published
    with pytest.raises(ValueError, match="snapshot_invalid"):
        verify.validate_snapshot(context, "ana_" + "0" * 64)


def test_repeated_runs_keep_stable_objects_and_isolate_reports(published):
    context, identity = published
    service = AnalysisService(context["root"], configs={"v0": context["config"]}, sources=context["sources"])
    try:
        second = service.create(context["request"], background=False)
    finally:
        service.close()
    a, b = verify.validate_snapshot(context, identity), verify.validate_snapshot(context, second)
    assert identity != second
    assert a[3] == b[3]
    assert a[4]["snapshot_identity"] == b[4]["snapshot_identity"]
    app = create_workbench_app(context["root"], configs={"v0": context["config"]}, sources=context["sources"])
    try:
        with demo.truth_guard(context["root"]), TestClient(app) as client:
            selected = verify.select_incidents(context["root"], identity)
            assert selected == verify.select_incidents(context["root"], second)
            result = verify.verify_http(context["root"], identity, selected,
                lambda path, method="GET": (lambda r: (r.status_code, r.json()))(client.request(method, path)))
            assert result["status"] == "passed"
            assert result["claim_statistics"]["unsupported_formal_claims"] == 0
            assert result["claim_statistics"]["broken_evidence_references"] == 0
            iid = next(i["incident_id"] for i in selected if i["incident_id"])
            # Same logical Incident, separate Analysis report publication.
            other = client.get(f"/api/v1/incidents/{iid}/explanation?analysis_id={second}").json()
            assert other["state"] == "not_generated"
    finally:
        app.state.analyses.close()


def test_warm_cli_options_reject_ambiguous_modes():
    import subprocess
    command = [sys.executable, str(ROOT / "scripts/demo.py"), "--cold-rebuild", "--warm-only"]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 2
    assert "cannot be combined" in result.stderr


def test_default_selection_does_not_import_evaluation_or_read_labels():
    import ast
    tree = ast.parse((ROOT / "scripts/verify_demo.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("evaluation")
        if isinstance(node, ast.Import):
            assert all(not a.name.startswith("evaluation") for a in node.names)
    assert "labels.csv" not in ast.get_source_segment((ROOT / "scripts/verify_demo.py").read_text(encoding="utf-8"),
        next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "select_incidents"))

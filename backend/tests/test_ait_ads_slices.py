"""Slice tooling only. All generated source records below are synthetic.

No test calls candidates, scoring, clustering, reconstruction or AI.
"""

import ast
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import stat
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import build_ait_ads_slices as slices
from app.services.datasets import load_dataset, read_registry, source_contexts
from app.services.storage import file_digest
from app.utils.stable_id import utc_text


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("ait-slice-synthetic")
    shutil.copytree(ROOT / "configs", root / "configs")
    registry = root / "data/ait_ads/dataset.yaml"
    registry.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "data/ait_ads/dataset.yaml", registry)
    for dataset in slices.ROLES:
        loaded = load_dataset(root, scene_id=dataset, config_version="v4")
        center = datetime(2022, 1, 22, 12, tzinfo=timezone.utc)
        for item in loaded.inputs:
            source = item["source"]
            rows = []
            # Equal temporal bounds; complete window contains 7600 alerts.
            for index in range(3802):
                stamp = center + timedelta(seconds=(index % 101) - 50)
                if index == 0:
                    stamp = center - timedelta(hours=1)
                elif index == 3801:
                    stamp = center + timedelta(hours=1)
                if source == "aminer":
                    row = {"RecordID": f"synthetic-{index}", "AMiner": {"ID": "synthetic.sensor"},
                        "AnalysisComponent": {"AnalysisComponentIdentifier": 1, "AnalysisComponentName": "Synthetic detector",
                                              "AnalysisComponentType": "NewMatchPathDetector"},
                        "LogData": {"DetectionTimestamp": [stamp.timestamp()], "RawLogData": [], "LogResources": []}}
                else:
                    row = {"id": f"synthetic-{index}", "timestamp": utc_text(stamp),
                        "rule": {"id": "synthetic-rule", "level": 6, "groups": [], "description": "Synthetic alert"},
                        "data": {"host": "synthetic-only"}}
                rows.append(row)
            path = root / item["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            # Exercise both supported input formats.
            content = json.dumps(rows) if source == "aminer" else "\n".join(json.dumps(r) for r in rows) + "\n"
            path.write_text(content, encoding="utf-8")
    hashes = {p.relative_to(root).as_posix(): file_digest(p)
              for dataset in slices.ROLES for p in (root / "data/ait_ads" / dataset / "raw").iterdir()}
    profile = slices.audit(root)
    result = slices.build(root, "russellmitchell", profile)
    yield root, profile, result, hashes
    # Allow pytest to remove its own synthetic read-only derivatives on Windows.
    for p in (root / "data/ait_ads/slices").rglob("*"):
        if p.is_file():
            p.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_time_window_filter(built, tmp_path):
    root, _, _, _ = built
    loaded, paths = slices.selected_inputs(root, "russellmitchell")
    adapter = slices.adapter_for(loaded, "wazuh")
    center = "2022-01-22T12:00:00.000000Z"
    count, ids = slices.write_window(tmp_path / "wazuh.json", paths["wazuh"], "wazuh", adapter, center, center)
    expected = [r for r in slices.records(paths["wazuh"]) if r["timestamp"] == center]
    assert count == len(expected) > 0
    assert list(slices.records(tmp_path / "wazuh.json")) == expected
    assert len(ids) == count


def test_cross_source_same_window(built):
    root, _, result, _ = built
    loaded, _ = slices.selected_inputs(root, "russellmitchell")
    for source in ("aminer", "wazuh"):
        path = root / "data/ait_ads/slices/russellmitchell_dev_small/raw" / (source + ".json")
        stamps = [slices.raw_timestamp(r, source, slices.adapter_for(loaded, source))[0] for r in slices.records(path)]
        assert min(stamps) >= result["start_timestamp"]
        assert max(stamps) <= result["end_timestamp"]
        assert len(stamps) == 3800
    assert result["window_semantics"].startswith("inclusive")


def test_manifest_generation(built):
    root, _, result, _ = built
    manifest = json.loads((root / "data/ait_ads/slices/russellmitchell_dev_small/slice_manifest.json").read_text())
    required = {"slice_version", "source_dataset", "purpose", "selection_method", "selection_rule", "start_timestamp",
                "end_timestamp", "timezone", "raw_counts", "canonical_alert_count", "source_type_counts", "severity_counts",
                "source_files", "source_sha256", "slice_sha256"}
    assert required <= manifest.keys()
    assert manifest["canonical_alert_count"] == 7600
    assert manifest["purpose"] == "correlation_development"
    assert manifest["slice_sha256"] == result["slice_sha256"]
    assert manifest["ground_truth"] == "NOT_USED" and not manifest["correlation_executed"]


def test_deterministic_slice_build(built):
    root, profile, result, _ = built
    assert slices.build(root, "russellmitchell", profile) == result


def test_original_files_unchanged(built):
    root, _, _, before = built
    assert {p: file_digest(root / p) for p in before} == before


def test_adapter_reads_slice(built):
    root, _, result, _ = built
    loaded, _ = slices.selected_inputs(root, "russellmitchell")
    total = 0
    for source in ("aminer", "wazuh"):
        batch = slices.adapter_for(loaded, source).read_file(root / "data/ait_ads/slices/russellmitchell_dev_small/raw" / (source + ".json"))
        assert not batch.rejected
        assert batch.input_count == 3800
        total += len(batch.alerts)
    assert total == result["canonical_alert_count"]


def test_no_out_of_window_records(built):
    assert all(built[2]["validation"][k] == "PASS" for k in ("no_out_of_window_records", "timestamp_parse", "raw_traceability"))
    root, _, result, _ = built
    loaded, paths = slices.selected_inputs(root, "russellmitchell")
    for source, path in paths.items():
        adapter = slices.adapter_for(loaded, source)
        expected = [r for r in slices.records(path) if result["start_timestamp"] <= slices.raw_timestamp(r, source, adapter)[0] <= result["end_timestamp"]]
        actual = list(slices.records(root / "data/ait_ads/slices/russellmitchell_dev_small/raw" / (source + ".json")))
        assert actual == expected  # Also verifies no in-window record was dropped.


def test_source_format_preserved(built):
    root, _, _, _ = built
    _, paths = slices.selected_inputs(root, "russellmitchell")
    assert slices.source_format(paths["aminer"]) == "json_array"
    assert slices.source_format(paths["wazuh"]) == "jsonl"
    for source, path in paths.items():
        assert slices.source_format(path) == slices.source_format(root / "data/ait_ads/slices/russellmitchell_dev_small/raw" / (source + ".json"))


def test_source_namespace_preserved(built):
    root, _, result, _ = built
    loaded, _ = slices.selected_inputs(root, "russellmitchell")
    assert set(result["source_namespace_counts"]) == set(loaded.sources)
    assert result["source_namespace_counts"] == {"ait_ads.russellmitchell.aminer": 3800, "ait_ads.russellmitchell.wazuh": 3800}


def test_slice_not_auto_discovered_as_full_dataset(built):
    root = built[0]
    assert "slices" not in read_registry(root).scenes
    assert not any("/slices/" in c["path"] for c in source_contexts(root).values())
    loaded = load_dataset(root, scene_id="russellmitchell")
    assert len(loaded.inputs) == 2 and all("/slices/" not in i["path"] for i in loaded.inputs)
    with pytest.raises(ValueError, match="unknown_scene"):
        load_dataset(root, scene_id="russellmitchell_dev_small")


def test_full_vs_slice_stable_id_identity(built):
    root, _, result, _ = built
    loaded, paths = slices.selected_inputs(root, "russellmitchell")
    for source, path in paths.items():
        adapter = slices.adapter_for(loaded, source)
        original = [adapter.convert(r) for r in slices.records(path)
                    if result["start_timestamp"] <= slices.raw_timestamp(r, source, adapter)[0] <= result["end_timestamp"]]
        sliced = adapter.read_file(root / "data/ait_ads/slices/russellmitchell_dev_small/raw" / (source + ".json"))
        assert {a.alert_id: a.raw_fingerprint for a in original} == {a.alert_id: a.raw_fingerprint for a in sliced.alerts}


@pytest.mark.parametrize("content", ["[{},]", "[{}] trailing", "{bad", "{}\n[{}]\n"])
def test_malformed_or_mixed_source_rejected(built, tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_text(content)
    loaded, _ = slices.selected_inputs(built[0], "russellmitchell")
    with pytest.raises((ValueError, KeyError, TypeError)):
        slices.audit_source(tmp_path, path, "wazuh", slices.adapter_for(loaded, "wazuh"))


def test_changed_source_receipt_and_existing_slice_refused(built, tmp_path):
    root, profile, _, _ = built
    changed = deepcopy(profile)
    changed["datasets"]["russellmitchell"]["wazuh"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="source_changed_since_audit"):
        slices.build(root, "russellmitchell", changed)
    staged, destination = tmp_path / "staged", tmp_path / "existing"
    staged.mkdir(); destination.mkdir()
    (staged / "raw.json").write_text("[]")
    (destination / "raw.json").write_text("{}")
    with pytest.raises(ValueError, match="refusing_overwrite"):
        slices.publish_immutable(staged, destination)
    assert (destination / "raw.json").read_text() == "{}"


def test_holdout_labels_and_algorithm_independence(built, monkeypatch):
    with pytest.raises(ValueError, match="hold_out_content_access_forbidden"):
        slices.selected_inputs(built[0], "harrison")
    original_open = Path.open
    reads = []
    def guarded(path, *args, **kwargs):
        parts = set(path.parts)
        assert not parts.intersection({"evaluation", "harrison", "santos", "shaw", "wardbeck", "wheeler", "wilson"})
        if path.suffix == ".json" and "raw" in parts:
            reads.append(path)
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", guarded)
    profile = slices.audit(built[0])
    assert profile["ground_truth"] == "NOT_USED" and reads
    assert all(not h["content_read"] for h in profile["hold_out"].values())
    tree = ast.parse(Path(slices.__file__).read_text(encoding="utf-8"))
    imports = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not any(i and any(word in i for word in ("correlation", "chains", "incidents", "ai.", "evaluation")) for i in imports)


def test_window_choice_ignores_physical_order_and_preserves_edges():
    profiles = {s: {"first_timestamp": "2022-01-01T00:00:00.000000Z", "last_timestamp": "2022-01-01T02:00:00.000000Z"} for s in ("aminer", "wazuh")}
    stamps = {s: ["2022-01-01T00:59:00.000000Z", "2022-01-01T01:01:00.000000Z"] for s in profiles}
    window = slices.choose_window(stamps, profiles, target=4)
    assert window[:2] == (stamps["aminer"][0], stamps["aminer"][1])
    assert slices.choose_window(dict(reversed(list(stamps.items()))), profiles, target=4) == window


def test_receipt_verification_refuses_edited_counts(built):
    root, _, result, _ = built
    slices.check_receipt(root, result)
    changed = deepcopy(result)
    changed["canonical_alert_count"] += 1
    with pytest.raises(ValueError, match="receipt_manifest_mismatch"):
        slices.check_receipt(root, changed)


def test_validation_role_cannot_be_used_for_development(monkeypatch):
    assert slices.ROLES == {"russellmitchell": "development", "fox": "validation"}
    monkeypatch.setattr(sys, "argv", ["build_ait_ads_slices.py", "--phase", "build", "--dataset", "fox", "--purpose", "development"])
    with pytest.raises(SystemExit) as exc:
        slices.main()
    assert exc.value.code == 2


def test_no_overlap_or_unreachable_size_fails():
    profiles = {"aminer": {"first_timestamp": "2022-01-01T00:00:00.000000Z", "last_timestamp": "2022-01-01T01:00:00.000000Z"},
                "wazuh": {"first_timestamp": "2022-01-01T02:00:00.000000Z", "last_timestamp": "2022-01-01T03:00:00.000000Z"}}
    with pytest.raises(ValueError, match="no_cross_source_time_overlap"):
        slices.choose_window({"aminer": [], "wazuh": []}, profiles)
    profiles["wazuh"] = deepcopy(profiles["aminer"])
    with pytest.raises(ValueError, match="reaches_target"):
        slices.choose_window({"aminer": [], "wazuh": []}, profiles)

"""Registry and scene isolation; generated raw records here are synthetic only."""

import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

from app.services.analysis import AnalysisInputError, AnalysisService
from app.services.datasets import load_dataset, read_registry
from app.services.storage import SnapshotStore
from app.utils.stable_id import id_for
from test_analysis_service import tripwire
from test_wazuh_adapter import ROOT, synthetic_record
from test_aminer_adapter import aminer_record

sys.path.insert(0, str(ROOT / "scripts"))

SCENES = ("russellmitchell", "fox", "harrison", "santos", "shaw", "wardbeck", "wheeler", "wilson")


@pytest.fixture
def registry_root(tmp_path):
    shutil.copytree(ROOT / "configs", tmp_path / "configs")
    target = tmp_path / "data/ait_ads/dataset.yaml"
    target.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "data/ait_ads/dataset.yaml", target)
    return tmp_path


def synthetic_scene(root, scene):
    loaded = load_dataset(root, scene_id=scene)
    for item in loaded.inputs:
        path = root / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        value = aminer_record() if item["source"] == "aminer" else synthetic_record(data={"host": "synthetic-only"})
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    return load_dataset(root, scene_id=scene)


def test_eight_scenes_paths_namespaces_and_no_ground_truth_projection(registry_root):
    registry = read_registry(registry_root)
    assert tuple(registry.scenes) == SCENES
    refs = set()
    for scene in SCENES:
        loaded = load_dataset(registry_root, scene_id=scene)
        assert loaded.status == "missing_raw_data" and len(loaded.missing_files) == 2
        for item in loaded.inputs:
            assert item["path"] == f"data/ait_ads/{scene}/raw/{scene}_{item['source']}.json"
            assert item["source_ref"] not in refs
            refs.add(item["source_ref"])
        assert loaded.metadata["dataset_id"] == "ait_ads" and loaded.metadata["scene_id"] == scene
        assert "evaluation" not in json.dumps(loaded.metadata)
        assert "labels.csv" not in json.dumps(loaded.config.snapshot)
        assert "official_labels" not in json.dumps(loaded.config.snapshot)
    assert len(refs) == 16


@pytest.mark.parametrize("scene", ["does_not_exist", "../fox", "Fox", "fox/wilson"])
def test_invalid_or_unknown_scene_rejected(registry_root, scene):
    with pytest.raises(ValueError):
        load_dataset(registry_root, scene_id=scene)


@pytest.mark.parametrize("mutation", ["wrong_scene", "traversal", "truth", "namespace", "network", "duplicate_key"])
def test_invalid_registry_rejected(registry_root, mutation):
    path = registry_root / "data/ait_ads/dataset.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if mutation == "wrong_scene":
        raw["scenes"]["fox"]["raw"]["aminer"] = raw["scenes"]["wilson"]["raw"]["aminer"]
    elif mutation == "traversal":
        raw["scenes"]["fox"]["raw"]["aminer"] = "../outside.json"
    elif mutation == "truth":
        raw["scenes"]["fox"]["raw"]["aminer"] = "fox/evaluation/answers.json"
    elif mutation == "namespace":
        raw["scenes"]["fox"]["namespace"] = raw["scenes"]["wilson"]["namespace"]
    elif mutation == "network":
        raw["scenes"]["fox"]["network_namespace"] = raw["scenes"]["wilson"]["network_namespace"]
    path.write_text(yaml.safe_dump(raw) + ("dataset_id: ait_ads\n" if mutation == "duplicate_key" else ""), encoding="utf-8")
    with pytest.raises(ValueError):
        read_registry(registry_root)


def test_production_scene_metadata_identity_output_and_gt_tripwire(registry_root, monkeypatch):
    a, b = synthetic_scene(registry_root, "fox"), synthetic_scene(registry_root, "wilson")
    reads = tripwire(monkeypatch)
    ids, snapshots, counts = [], [], []
    for loaded in (a, b):
        svc = AnalysisService(registry_root, configs={"v0": loaded.config}, sources=loaded.sources,
                              allowed_files=[i["path"] for i in loaded.inputs])
        try:
            identity = svc.create(loaded.request, background=False)
        finally:
            svc.close()
        ids.append(identity)
        store = SnapshotStore(registry_root, identity)
        record, _, manifest = store.read_metadata()
        assert record.status.value == "completed", manifest
        assert manifest["summary"]["dataset_metadata"]["scene_id"] == loaded.scene_id
        assert manifest["summary"]["dataset_metadata"]["dataset_id"] == "ait_ads"
        assert {a.source_namespace for a in store.read_records("alerts")} == set(loaded.sources)
        snapshots.append(id_for("AnalysisRecord", record))
        counts.append(manifest["summary"]["counts"])
    assert ids[0] != ids[1] and snapshots[0] != snapshots[1]
    assert SnapshotStore(registry_root, ids[0]).domain != SnapshotStore(registry_root, ids[1]).domain
    assert counts[0] == counts[1] and reads


def test_mixed_scenes_and_wrong_source_path_rejected_before_candidates(registry_root):
    a, b = synthetic_scene(registry_root, "fox"), synthetic_scene(registry_root, "wilson")
    svc = AnalysisService(registry_root, configs={"v0": a.config}, sources={**a.sources, **b.sources},
                          allowed_files=[i["path"] for i in a.inputs + b.inputs])
    try:
        with pytest.raises(AnalysisInputError, match="mixed_dataset_scenes"):
            svc.create({"config_version": "v0", "inputs": a.inputs + b.inputs}, background=False)
        request = a.request
        request["inputs"][0] = {**a.inputs[0], "path": b.inputs[0]["path"]}
        with pytest.raises(AnalysisInputError, match="dataset_scene_path_mismatch"):
            svc.create(request, background=False)
        svc.sources["alias"] = a.sources[a.inputs[0]["source_ref"]]
        with pytest.raises(AnalysisInputError, match="mixed_dataset_scenes"):
            svc.create({"config_version": "v0", "inputs": [{**a.inputs[0], "source_ref": "alias"}, b.inputs[0]]}, background=False)
    finally:
        svc.close()
    assert not list((registry_root / "data/processed").glob("ana_*"))


def test_disabled_scene_rejected_by_loader_and_service(registry_root):
    loaded = synthetic_scene(registry_root, "fox")
    path = registry_root / "data/ait_ads/dataset.yaml"
    declaration = yaml.safe_load(path.read_text(encoding="utf-8"))
    declaration["scenes"]["fox"]["enabled"] = False
    path.write_text(yaml.safe_dump(declaration), encoding="utf-8")
    with pytest.raises(ValueError, match="scene_disabled"):
        load_dataset(registry_root, scene_id="fox")
    svc = AnalysisService(registry_root, configs={"v0": loaded.config}, sources=loaded.sources,
                          allowed_files=[i["path"] for i in loaded.inputs])
    try:
        with pytest.raises(AnalysisInputError, match="scene_disabled"):
            svc.prepare(loaded.request)
    finally:
        svc.close()


def test_default_config_and_alert_id_baseline_unchanged():
    from app.config import load_config
    from app.adapters import WazuhAdapter
    from demo_support import source_registry
    loaded = load_dataset(ROOT)
    old = load_config(ROOT / "configs/algorithm-v0.yaml", deployment_override=ROOT / "configs/sources.yaml")
    historical, _ = source_registry(ROOT, old, loaded.inputs)
    assert loaded.config.snapshot == old.snapshot and loaded.sources == historical
    setting = loaded.sources["ait_ads.russellmitchell.wazuh"][1]
    raw = synthetic_record()
    assert WazuhAdapter(loaded.config, setting).convert(raw) == WazuhAdapter(old, setting).convert(raw)


def test_demo_receipts_are_scene_partitioned(registry_root):
    from demo_support import demo_output
    paths = [demo_output(registry_root, {"dataset_metadata": load_dataset(registry_root, scene_id=s).metadata}) for s in SCENES]
    assert len(set(paths)) == 8
    assert all(p.is_relative_to(registry_root / "outputs/task09/ait_ads") for p in paths)


@pytest.mark.parametrize("args", [[], ["--dataset", "ait_ads", "--scene", "shaw"]])
def test_cli_default_and_explicit_selection(args):
    result = subprocess.run([sys.executable, str(ROOT / "scripts/demo.py"), "--check-only", *args],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "no production analysis executed" in result.stdout


def test_inventory_missing_empty_malformed_and_contamination(registry_root):
    sys.path.insert(0, str(ROOT / "scripts"))
    from ait_ads_inventory import inspect_file
    loaded = load_dataset(registry_root, scene_id="fox")
    item = next(i for i in loaded.inputs if i["source"] == "wazuh")
    setting = loaded.sources[item["source_ref"]][1]
    assert inspect_file(registry_root, item, loaded.config, setting)["count"] is None
    path = registry_root / item["path"]
    path.parent.mkdir(parents=True)
    for content in ("", "{broken", json.dumps({**synthetic_record(), "time_label": "synthetic-only"})):
        path.write_text(content, encoding="utf-8")
        result = inspect_file(registry_root, item, loaded.config, setting)
        assert result["status"] == "invalid_raw_data" and not result["schema_valid"]
    path.write_text(json.dumps(synthetic_record()), encoding="utf-8")
    result = inspect_file(registry_root, item, loaded.config, setting)
    assert result["status"] == "ready" and result["count"] == 1 and result["sha256"]

"""Task 05 orchestration, deterministic facts and opt-in real API integration."""

import builtins
import json
import os
from pathlib import Path

import pytest
import yaml

from app.adapters.base import AdapterSettings
from app.config import load_config
from app.main import create_app
from app.services.analysis import AnalysisService
from app.services.queries import QueryService
from app.services.storage import MODELS, SnapshotStore, file_digest, restore_config
from app.utils.stable_id import content_digest
from test_aminer_adapter import aminer_record, aminer_settings
from test_wazuh_adapter import ROOT, settings, synthetic_record


def deployment(root, *, edge=False, tiny_budget=False):
    """Explicit synthetic deployment; all experimental values stay in fixtures."""
    directory = root / "data/input/alerts"
    directory.mkdir(parents=True, exist_ok=True)
    configuration = load_config(ROOT / "configs/algorithm-v0.yaml", deployment_override=ROOT / "configs/sources.yaml")
    if edge or tiny_budget:
        override = {"entity": {"rarity_enabled": False}} if edge else {}
        if edge:
            mapping = {"schema_version": "1.0", "mapping_type": "category", "source_type": "wazuh", "default": "unknown",
                "rules": [{"id": name, "match": {"all": [{"field": "rule_id", "op": "eq", "value": name}]}, "output": kind}
                          for name, kind in (("parent", "process_execution"), ("child", "privilege_escalation"))]}
            (root / "category.yaml").write_text(yaml.safe_dump(mapping), encoding="utf-8")
            override["normalization"] = {"category_mapping_files": [str(root / "category.yaml")]}
        if tiny_budget:
            override["candidate"] = {"time_only_neighbors": 1, "per_channel_neighbors": 1,
                                     "max_neighbors_per_alert": 1, "max_candidate_pairs": 1}
        (root / "experiment.yaml").write_text(yaml.safe_dump(override), encoding="utf-8")
        configuration = load_config(ROOT / "configs/algorithm-v0.yaml", deployment_override=ROOT / "configs/sources.yaml",
                                    experiment_override=root / "experiment.yaml")
    sources = {"w": ("wazuh", settings()), "a": ("aminer", aminer_settings())}
    return configuration, sources


def write_input(root, records, name="w.json"):
    relative = "data/input/alerts/" + name
    (root / relative).write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return relative


def request_for(path, source="wazuh", ref="w"):
    return {"config_version": "v0", "inputs": [{"source": source, "source_ref": ref, "path": path}]}


def service(root, **options):
    config, sources = deployment(root, **options)
    return AnalysisService(root, configs={"v0": config}, sources=sources)


def edge_records(tag="x"):
    p = {"pid": 1, "name": "synthetic-process", "start_time": "2022-01-21T00:00:00Z"}
    common = {"host": "synthetic-host", "user": "synthetic-user", "session": "synthetic-session",
              "url": "/synthetic", "file": "/synthetic/file", "command": "synthetic-command"}
    return [synthetic_record(id=tag + "p", rule={"id": "parent", "level": 6}, data={**common, "process": p}),
            synthetic_record(id=tag + "c", timestamp="2022-01-21T00:00:01Z", rule={"id": "child", "level": 10},
                             data={**common, "parent_process": p, "process": {**p, "pid": 2, "start_time": "2022-01-21T00:00:01Z"}})]


def tripwire(monkeypatch):
    original, original_path = builtins.open, Path.open
    reads = []
    def check(path):
        if isinstance(path, (str, Path)):
            value = Path(path)
            assert value.name.lower() not in {"labels.csv", "attacks.log", "gold_chain.json"}
            assert "evaluation" not in {p.lower() for p in value.parts}
            reads.append(str(value))
    def opened(path, *args, **kwargs):
        check(path)
        return original(path, *args, **kwargs)
    def path_opened(path, *args, **kwargs):
        check(path)
        return original_path(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", opened)
    monkeypatch.setattr(Path, "open", path_opened)
    return reads


def test_service_independent_runs_status_snapshot_metrics_and_preprocessing_parity(tmp_path):
    from app.adapters import WazuhAdapter, AMinerAdapter
    from app.services.normalization import preprocess
    svc = service(tmp_path)
    w = write_input(tmp_path, [synthetic_record(data={"host": "synthetic-host"})])
    a = write_input(tmp_path, [aminer_record()], "a.json")
    req = request_for(w)
    req["inputs"].append(request_for(a, "aminer", "a")["inputs"][0])
    first = svc.create(req, background=False)
    second = svc.create(req, background=False)
    assert first != second
    q = QueryService(tmp_path)
    detail = q.analysis(first)
    assert detail["status"] == "completed", detail
    assert detail["state_history"] == ["queued", "running", "completed"]
    assert detail["created_at"] <= detail["started_at"] <= detail["completed_at"]
    assert detail["config_hash"] == detail["config_digest"] == content_digest(detail["config_snapshot"])
    assert detail["mapping_digest"] == svc.configs["v0"].mapping_digest
    assert all(detail["runtime"][k] >= 0 for k in ("input_load_seconds", "normalization_seconds", "dedupe_seconds",
        "entity_extraction_seconds", "candidate_generation_seconds", "correlation_seconds", "incident_clustering_seconds",
        "chain_reconstruction_seconds", "persistence_seconds", "total_seconds"))
    assert detail["counts"]["input_count"] == detail["counts"]["canonical_alert_count"] == 2
    original = preprocess([(WazuhAdapter(svc.configs["v0"], svc.sources["w"][1]), tmp_path/w),
                           (AMinerAdapter(svc.configs["v0"], svc.sources["a"][1]), tmp_path/a)])
    for identity in (first, second):
        store = SnapshotStore(tmp_path, identity)
        record, frequency, manifest = store.read_metadata()
        assert record.analysis_id == identity and frequency["N"] == 2
        assert store.validate_reconstruction().valid
        assert list(store.read_records("alerts")) == original.alerts
        assert list(store.read_records("entities")) == original.entities
        assert list(store.read_records("dedupe_groups")) == original.groups
        assert detail["dataset_digest"] == record.dataset_digest
        assert (tmp_path/record.diagnostics_ref).is_file()
        assert manifest["execution"]["snapshot_identity"] != identity
        candidate_report = json.loads((store.details / "candidate_diagnostics.json").read_text(encoding="utf-8"))
        assert candidate_report["analysis_id"] == identity
        assert candidate_report["config_hash"] == record.config_hash
        assert candidate_report["dataset_digest"] == record.dataset_digest
        assert candidate_report["scheduled_candidate_count"] == record.metrics.candidate_pair_count
        anchors = [json.loads(line) for line in (store.details / "diagnostics.jsonl").read_text(encoding="utf-8").splitlines()
                   if json.loads(line).get("stage") == "candidate_diagnosis"]
        assert len(anchors) == 1
        for item in anchors[0]["reports"].values():
            assert file_digest(tmp_path / item["ref"]) == item["sha256"]
    for kind in MODELS:
        assert list(SnapshotStore(tmp_path, first).read_records(kind)) == list(SnapshotStore(tmp_path, second).read_records(kind))
    svc.close()


def test_failure_is_queryable_and_does_not_publish_empty_domain_record(tmp_path):
    svc = service(tmp_path)
    identity = svc.create(request_for(write_input(tmp_path, [{"malformed": True}])), background=False)
    detail = QueryService(tmp_path).analysis(identity)
    assert detail["status"] == "failed" and not detail["is_complete"] and detail["record"] is None
    assert detail["errors"] == ["input:no_accepted_alerts"]
    assert detail["counts"]["input_count"] == detail["counts"]["rejected_count"] == 1
    assert (tmp_path/detail["diagnostics_ref"]).stat().st_size > 0
    svc.close()


def test_mixed_rejections_and_candidate_truncation_remain_incomplete(tmp_path):
    svc = service(tmp_path, tiny_budget=True)
    records = [synthetic_record(id=f"synthetic-{i}", data={"host":"synthetic-shared"}) for i in range(4)] + [{"bad": True}]
    identity = svc.create(request_for(write_input(tmp_path, records)), background=False)
    detail = QueryService(tmp_path).analysis(identity)
    assert detail["status"] == "incomplete" and detail["candidate_truncated"] and not detail["is_complete"]
    assert detail["record"].errors == ["candidate_resource_truncation", "rejected_input_records"]
    assert detail["counts"]["candidate_dropped_count"] > 0 and detail["counts"]["rejected_count"] == 1
    assert len(QueryService(tmp_path).list(identity, "incidents", page=1, page_size=100, filters={})["items"]) == 4
    svc.close()


def test_configuration_changes_do_not_rewrite_history(tmp_path):
    svc = service(tmp_path)
    identity = svc.create(request_for(write_input(tmp_path, [synthetic_record()])), background=False)
    old = QueryService(tmp_path).analysis(identity)
    svc.configs.clear()
    (tmp_path/"configs").mkdir()
    (tmp_path/"configs/algorithm-v0.yaml").write_text("bad: current-config", encoding="utf-8")
    reloaded = QueryService(tmp_path).analysis(identity)
    assert reloaded == old
    svc.close()


def test_canonical_equivalent_unicode_records_across_files_match_task02(tmp_path):
    from app.adapters import WazuhAdapter
    from app.services.normalization import preprocess
    svc = service(tmp_path)
    paths = [write_input(tmp_path, [synthetic_record(rule={"id": "synthetic-rule", "level": 6,
                 "description": text})], name) for text, name in (("é", "one.json"), ("e\u0301", "two.json"))]
    req = request_for(paths[0])
    req["inputs"].append(request_for(paths[1])["inputs"][0])
    identity = svc.create(req, background=False)
    detail = QueryService(tmp_path).analysis(identity)
    assert detail["status"] == "completed", detail
    assert detail["counts"]["canonical_alert_count"] == detail["counts"]["duplicate_import_count"] == 1
    previous = preprocess([(WazuhAdapter(svc.configs["v0"], svc.sources["w"][1]), tmp_path/p) for p in paths])
    stored = list(SnapshotStore(tmp_path, identity).read_records("alerts"))
    assert [a.canonical_json() for a in stored] == [a.canonical_json() for a in previous.alerts]
    svc.close()


def test_gt_contamination_never_enters_snapshot_and_no_truth_reads(tmp_path, monkeypatch):
    svc = service(tmp_path)
    records = [synthetic_record(), synthetic_record(id="contaminated", ground_truth_path="sensitive-path")]
    path = write_input(tmp_path, records)
    reads = tripwire(monkeypatch)
    identity = svc.create(request_for(path), background=False)
    store = SnapshotStore(tmp_path, identity)
    record, _, _ = store.read_metadata()
    assert record.status.value == "incomplete"
    assert all("ground_truth_path" not in a.raw_alert for a in store.read_records("alerts"))
    assert "sensitive-path" not in (store.details/"diagnostics.jsonl").read_text(encoding="utf-8")
    assert reads
    svc.close()


def test_reconstruction_failure_and_restart_do_not_claim_completed(tmp_path, monkeypatch):
    import app.services.analysis as analysis
    svc = service(tmp_path)
    path = write_input(tmp_path, [synthetic_record()])
    def broken(*args, **kwargs):
        raise RuntimeError("synthetic failure")
    monkeypatch.setattr(analysis, "run_reconstruction", broken)
    identity = svc.create(request_for(path), background=False)
    q = QueryService(tmp_path)
    assert q.analysis(identity)["errors"] == ["reconstruction:RuntimeError"]
    assert q.analysis(identity)["status"] == "failed"
    # Simulate a prior process dying while queued; restart never reopens input.
    store = SnapshotStore(tmp_path, identity)
    run = json.loads((store.domain/"run.json").read_text(encoding="utf-8"))
    run.update(status="running", completed_at=None, owner_pid=-1)
    (store.domain/"run.json").write_text(json.dumps(run), encoding="utf-8")
    svc.fail_interrupted_runs()
    assert q.analysis(identity)["errors"] == ["execution_interrupted"]
    svc.close()


def test_reader_startup_does_not_fail_active_local_execution(tmp_path, monkeypatch):
    import threading
    svc = service(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = svc._execute
    def waiting(*args):
        entered.set()
        release.wait(timeout=10)
        original(*args)
    monkeypatch.setattr(svc, "_execute", waiting)
    identity = svc.create(request_for(write_input(tmp_path, [synthetic_record()])))
    assert entered.wait(timeout=5)
    svc.fail_interrupted_runs()
    assert QueryService(tmp_path).analysis(identity)["status"] == "queued"
    release.set()
    svc.wait(identity, timeout=10)
    assert QueryService(tmp_path).analysis(identity)["status"] == "completed"
    svc.close()


@pytest.mark.skipif(os.environ.get("TRACEBACK_TASK05_FULL_DATASET") != "1", reason="explicit Task 05 real two-source API run")
def test_full_real_two_source_post_analysis_and_snapshot_queries(monkeypatch):
    from fastapi.testclient import TestClient
    wp = "data/ait_ads/russellmitchell/raw/russellmitchell_wazuh.json"
    ap = "data/ait_ads/russellmitchell/raw/russellmitchell_aminer.json"
    tripwire(monkeypatch)
    app = create_app(ROOT, allowed_files={wp, ap}, progress=lambda row: print(json.dumps(row), flush=True))
    req = {"config_version": "v0", "inputs": [{"source": "wazuh", "source_ref": "ait_ads.russellmitchell.wazuh", "path": wp},
           {"source": "aminer", "source_ref": "ait_ads.russellmitchell.aminer", "path": ap}]}
    with TestClient(app) as client:
        response = client.post("/api/v1/analyses", json=req)
        assert response.status_code == 202, response.text
        identity = response.json()["analysis_id"]
        print(json.dumps({"stage": "post_accepted", "analysis_id": identity}), flush=True)
        app.state.analyses.wait(identity)
        response = client.get("/api/v1/analyses/"+identity)
        assert response.status_code == 200, response.text
        detail = response.json()
        counts = detail["counts"]
        assert detail["status"] == "completed" and not detail["candidate_truncated"]
        assert detail["candidate_contract_version"] == "v1.1"
        assert counts["resource_truncated_count"] == 0
        assert counts["admitted_candidate_count"] == counts["scored_candidate_count"]
        assert counts["input_count"] == 45544 and counts["canonical_alert_count"] == 45510
        assert counts["dedupe_group_count"] == 9 and counts["grouped_alert_count"] == 18
        assert counts["representative_count"] == 45501 and counts["entity_count"] == 13752
        assert counts["correlation_edge_count"] == counts["chain_edge_count"] == 0
        assert counts["incident_count"] == counts["attack_chain_count"] == counts["chain_node_count"] == 45501
        scope = {"analysis_id": identity}
        alerts = client.get("/api/v1/alerts", params=scope)
        incidents = client.get("/api/v1/incidents", params=scope)
        assert alerts.status_code == incidents.status_code == 200
        assert alerts.json()["total"] == 45510 and incidents.json()["total"] == 45501
        inc = incidents.json()["items"][0]
        chain_response = client.get(f"/api/v1/incidents/{inc['incident_id']}/chain", params=scope)
        timeline_response = client.get(f"/api/v1/incidents/{inc['incident_id']}/timeline", params=scope)
        assert chain_response.status_code == timeline_response.status_code == 200
        chain = chain_response.json()["chain"]
        assert len(chain["nodes"]) == 1 and not chain["edges"]
        for aid in chain["nodes"][0]["alert_ids"]:
            evidence = client.get("/api/v1/alerts/"+aid, params=scope)
            assert evidence.status_code == 200 and evidence.json()["alert"]["raw_alert"]
        assert client.get("/openapi.json").status_code == 200
        store = SnapshotStore(ROOT, identity)
        assert store.validate_reconstruction(parquet=True).valid
        store.read_metadata()
        from app.services.storage import atomic_json
        atomic_json(ROOT/"outputs/task052/real-acceptance.json",{k:v for k,v in detail.items() if k!="record"})
        print(json.dumps({"stage": "task05_real_acceptance", "analysis_id": identity, "status": detail["status"],
                          "counts": counts, "metrics": detail["metrics"], "runtime": detail["runtime"],
                          "config_hash": detail["config_hash"], "mapping_digest": detail["mapping_digest"],
                          "dataset_digest": detail["dataset_digest"], "grounding": detail["grounding"]}), flush=True)


@pytest.mark.parametrize("resource", [False,True])
def test_api_policy_pruning_and_resource_truncation_v11(tmp_path, monkeypatch, resource):
    from fastapi.testclient import TestClient
    cfg,sources=deployment(tmp_path)
    override={"candidate":{"per_channel_neighbors":20,"max_candidate_pairs":1 if resource else 2000000}}
    (tmp_path/"synthetic-v11.yaml").write_text(yaml.safe_dump(override),encoding="utf-8")
    cfg=load_config(ROOT/"configs/algorithm-v0.yaml",deployment_override=ROOT/"configs/sources.yaml",
        experiment_override=tmp_path/"synthetic-v11.yaml")
    path=write_input(tmp_path,[synthetic_record(id=f"v11-{i}",data={"host":"synthetic-shared"}) for i in range(31)])
    tripwire(monkeypatch)
    app=create_app(tmp_path,configs={"v0":cfg},sources=sources)
    with TestClient(app) as client:
        response=client.post("/api/v1/analyses",json=request_for(path))
        assert response.status_code==202
        identity=response.json()["analysis_id"]
        app.state.analyses.wait(identity)
        detail=client.get("/api/v1/analyses/"+identity).json()
        assert detail["candidate_contract_version"]=="v1.1"
        assert detail["policy_pruned_count"]>0
        assert detail["status"]==("incomplete" if resource else "completed")
        assert detail["candidate_truncated"]==resource
        assert (detail["resource_truncated_count"]>0)==resource
        assert detail["admitted_candidate_count"]==detail["scored_candidate_count"]+detail["resource_truncated_count"]
        store=SnapshotStore(tmp_path,identity)
        record,_,manifest=store.read_metadata()
        assert manifest["candidate_contract_version"]=="v1.1"
        assert record.is_complete== (not resource)


@pytest.mark.parametrize("error", [MemoryError,TimeoutError])
def test_real_resource_execution_error_never_completed(tmp_path,monkeypatch,error):
    import app.services.analysis as module
    svc=service(tmp_path)
    def unfinished(*args,**kwargs):
        raise error()
    monkeypatch.setattr(module,"run_correlation",unfinished)
    identity=svc.create(request_for(write_input(tmp_path,[synthetic_record()])),background=False)
    detail=QueryService(tmp_path).analysis(identity)
    assert detail["status"]=="incomplete" and not detail["is_complete"]
    assert detail["resource_truncation_events"]==[f"correlation:{error.__name__}"]
    assert detail["incomplete_reason"]=="correlation_not_published"
    svc.close()

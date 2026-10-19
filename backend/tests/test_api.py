"""Frozen HTTP/OpenAPI contract, ingress safety and snapshot-only reads."""

import json
import subprocess
import sys
from urllib.request import urlopen
import time

from fastapi.testclient import TestClient
import pytest

from app.main import create_app
from test_analysis_service import deployment, edge_records, request_for, tripwire, write_input
from test_wazuh_adapter import synthetic_record, ROOT


@pytest.fixture
def api(tmp_path):
    config, sources = deployment(tmp_path, edge=True)
    app = create_app(tmp_path, configs={"v0": config}, sources=sources)
    with TestClient(app) as client:
        yield client, app, tmp_path


def create_run(api, records=None, name="w.json"):
    client, app, root = api
    path = write_input(root, records or edge_records(), name)
    response = client.post("/api/v1/analyses", json=request_for(path))
    assert response.status_code == 202, response.text
    assert response.json()["status"] == "queued"
    identity = response.json()["analysis_id"]
    app.state.analyses.wait(identity, timeout=30)
    return identity


def test_registered_routes_openapi_schema_and_all_queries(api, monkeypatch):
    client, app, _ = api
    identity = create_run(api)
    result = client.get("/api/v1/analyses/"+identity)
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "completed"
    counts = result.json()["counts"]
    assert counts["correlation_edge_count"] == counts["chain_edge_count"] == 1
    scope = {"analysis_id": identity}
    incident = client.get("/api/v1/incidents", params=scope).json()["items"][0]
    iid = incident["incident_id"]
    detail = client.get("/api/v1/incidents/"+iid, params=scope)
    assert detail.status_code == 200 and detail.json()["incident"] == incident
    chain = client.get(f"/api/v1/incidents/{iid}/chain", params=scope).json()["chain"]
    assert len(chain["nodes"]) == 2 and len(chain["edges"]) == 1
    edge = client.get("/api/v1/edges/"+chain["edges"][0]["edge_id"], params=scope)
    assert edge.status_code == 200
    assert edge.json()["edge"] == chain["edges"][0]
    cor = edge.json()["correlation_edges"][0]
    assert cor["edge_id"] == edge.json()["edge"]["score_breakdown"]["selected_correlation_edge_id"]
    assert set(cor["score_breakdown"]["contributions"]) == {"time", "entity", "relation", "behavior", "source", "conflict", "duplicate"}
    for node in chain["nodes"]:
        for aid in node["alert_ids"]:
            alert = client.get("/api/v1/alerts/"+aid, params=scope)
            assert alert.status_code == 200 and alert.json()["alert"]["raw_alert"]
            assert {e["entity_id"] for e in alert.json()["entities"]} == set(alert.json()["alert"]["entity_ids"])
    timeline = client.get(f"/api/v1/incidents/{iid}/timeline", params=scope)
    assert timeline.status_code == 200 and timeline.json()["total"] == 4
    items = timeline.json()["items"]
    assert items == sorted(items, key=lambda i: (i["event_time"], i["id"]))
    assert client.post(f"/api/v1/incidents/{iid}/explain", params=scope).status_code == 409
    assert client.get("/api/v1/evaluation/runs/missing", params=scope).status_code == 404
    schema = client.get("/openapi.json").json()
    assert set(schema["paths"]) == {"/api/v1/analyses", "/api/v1/analyses/{analysis_id}", "/api/v1/alerts",
        "/api/v1/alerts/{alert_id}", "/api/v1/incidents", "/api/v1/incidents/{incident_id}",
        "/api/v1/incidents/{incident_id}/chain", "/api/v1/incidents/{incident_id}/timeline", "/api/v1/edges/{edge_id}",
        "/api/v1/incidents/{incident_id}/explain", "/api/v1/evaluation/runs/{run_id}"}
    create_schema = schema["components"]["schemas"]["CreateAnalysis"]
    assert set(create_schema["properties"]) == {"inputs", "config_version"} and create_schema["additionalProperties"] is False
    parameters = schema["paths"]["/api/v1/alerts"]["get"]["parameters"]
    size = next(p["schema"] for p in parameters if p["name"] == "page_size")
    assert size["default"] == 20 and size["minimum"] == 1 and size["maximum"] == 100
    assert all(p["name"] not in {"offset", "limit", "ground_truth_path"} for route in schema["paths"].values()
               for method in route.values() for p in method.get("parameters", []))
    def forbidden(*args, **kwargs):
        raise AssertionError("GET reran an algorithm")
    import app.services.analysis as analysis
    for name in ("deduplicate", "extract_entities", "run_correlation", "run_reconstruction"):
        monkeypatch.setattr(analysis, name, forbidden)
    assert client.get(f"/api/v1/incidents/{iid}/chain", params=scope).json()["chain"] == chain
    assert client.get("/api/v1/edges/"+chain["edges"][0]["edge_id"], params=scope).status_code == 200


@pytest.mark.parametrize("key,value", [("page", "0"), ("page", "-1"), ("page", "no"), ("page", "1.0"),
    ("page_size", "0"), ("page_size", "101"), ("page_size", "no"), ("offset", "0"), ("limit", "20"),
    ("severity", "maximum"), ("category", "bogus"), ("source_type", "bogus"), ("unknown", "value"),
    ("start_time", "2022-01-21T00:00:00"), ("end_time", "not-date")])
def test_invalid_filter_pagination_is_400(api, key, value):
    client, _, _ = api
    identity = create_run(api, [synthetic_record()])
    assert client.get("/api/v1/alerts", params={"analysis_id": identity, key: value}).status_code == 400


def test_pagination_empty_last_page_stable_order_and_half_open_times(api):
    client, _, _ = api
    identity = create_run(api, [synthetic_record(id=str(i), timestamp=f"2022-01-21T00:00:{i:02d}Z") for i in range(5)])
    scope = {"analysis_id": identity, "page_size": 2}
    first = client.get("/api/v1/alerts", params=scope).json()
    assert first == client.get("/api/v1/alerts", params=scope).json()
    assert first["total"] == 5 and first["page"] == 1
    assert len(client.get("/api/v1/alerts", params={**scope, "page": 3}).json()["items"]) == 1
    assert client.get("/api/v1/alerts", params={**scope, "page": 4}).json()["items"] == []
    response = client.get("/api/v1/alerts", params={"analysis_id": identity,
        "start_time": "2022-01-21T01:00:01+01:00", "end_time": "2022-01-21T00:00:03Z"})
    assert response.status_code == 200 and response.json()["total"] == 2
    assert {a["timestamp"] for a in response.json()["items"]} == {"2022-01-21T00:00:01.000000Z", "2022-01-21T00:00:02.000000Z"}
    assert client.get("/api/v1/alerts", params={"analysis_id": identity, "severity": "critical"}).json()["total"] == 0
    assert client.get("/api/v1/alerts", params={"analysis_id": identity, "start_time": "2022-01-21T00:00:01Z",
                                              "end_time": "2022-01-21T00:00:01Z"}).status_code == 400
    same_stamp = create_run(api, [synthetic_record(id=str(i)) for i in range(4)], "same.json")
    ordered = client.get("/api/v1/incidents", params={"analysis_id": same_stamp}).json()["items"]
    assert ordered == sorted(ordered, key=lambda i: i["incident_id"])


@pytest.mark.parametrize("path", ["..", "../", "../alerts.json", "data/input/alerts/../secret.json",
    "D:/secret.json", "/secret.json", "D:\\secret.json", "data/input/alerts\\secret.json",
    "data/unregistered.json", "data/input/alerts/labels.csv", "data/input/alerts/ground_truth.json",
    "data/input/alerts/evaluation/a.json", "data/input/alerts/%2e%2e/secret.json"])
def test_path_safety_never_reads_unapproved_files(api, monkeypatch, path):
    client, _, _ = api
    reads = tripwire(monkeypatch)
    response = client.post("/api/v1/analyses", json=request_for(path))
    assert response.status_code == 400
    assert not reads


@pytest.mark.parametrize("field", ["ground_truth", "ground_truth_path", "labels", "expected_incident", "expected_chain",
    "attack_label", "evaluation_label", "gold_node", "gold_edge", "score", "nodes", "threshold"])
def test_reject_gt_or_derived_request_fields(api, field):
    client, _, root = api
    body = request_for(write_input(root, [synthetic_record()]))
    body[field] = "sensitive-submitted-value"
    response = client.post("/api/v1/analyses", json=body)
    assert response.status_code == 422 and "sensitive-submitted-value" not in response.text
    del body[field]
    body["inputs"][0][field] = "sensitive-submitted-value"
    assert client.post("/api/v1/analyses", json=body).status_code == 422


def test_missing_refs_schema_errors_and_not_ready(api, monkeypatch):
    client, app, root = api
    identity = create_run(api)
    scope = {"analysis_id": identity}
    assert client.get("/api/v1/analyses/ana_"+"0"*64).status_code == 404
    for path, prefix in (("alerts", "alt"), ("incidents", "inc"), ("edges", "che")):
        assert client.get(f"/api/v1/{path}/{prefix}_"+"0"*64, params=scope).status_code == 404
    assert client.get("/api/v1/alerts").status_code == 422
    assert client.post("/api/v1/analyses", json={}).status_code == 422
    body = request_for(write_input(root, [synthetic_record()]))
    body["inputs"][0]["source"] = "edr"
    assert client.post("/api/v1/analyses", json=body).status_code == 422
    body["inputs"][0]["source"] = "wazuh"
    body["config_version"] = "unknown"
    assert client.post("/api/v1/analyses", json=body).status_code == 404
    assert client.post("/api/v1/analyses", json=request_for("data/input/alerts/missing.json")).status_code == 404
    iid = client.get("/api/v1/incidents", params=scope).json()["items"][0]["incident_id"]
    assert client.post(f"/api/v1/incidents/{iid}/explain", params=scope, json={"ground_truth": True}).status_code == 422
    # Pause scheduling to observe the genuine queued snapshot, not a fake API.
    monkeypatch.setattr(app.state.analyses.executor, "submit", lambda *a, **k: None)
    queued = client.post("/api/v1/analyses", json=request_for("data/input/alerts/w.json")).json()["analysis_id"]
    assert client.get("/api/v1/analyses/"+queued).json()["status"] == "queued"
    assert client.get("/api/v1/alerts", params={"analysis_id": queued}).status_code == 409


def test_evaluation_reads_only_valid_export_whitelist(api):
    client, _, root = api
    identity = create_run(api)
    scope = {"analysis_id": identity}
    directory = root/"data/processed/evaluation_exports"
    directory.mkdir()
    export = {"run_id": "synthetic", "config_hash": "0"*64, "algorithm_version": "synthetic-v1", "split": "synthetic-test",
        "metrics": {"precision": None}, "metric_status": {"precision": "not_applicable"}, "evaluation_coverage": 0,
        "counts": {"predictions": 0}, "runtime": {"total": 0}, "limitations": ["empty denominator"]}
    path = directory/"synthetic.json"
    path.write_text(json.dumps(export), encoding="utf-8")
    response = client.get("/api/v1/evaluation/runs/synthetic", params=scope)
    assert response.status_code == 200 and response.json() == export
    export["ground_truth"] = "must never be published"
    path.write_text(json.dumps(export), encoding="utf-8")
    assert client.get("/api/v1/evaluation/runs/synthetic", params=scope).status_code == 409
    assert client.get("/api/v1/evaluation/runs/%2e%2e%5csecret", params=scope).status_code == 404


def test_fastapi_server_startup_and_openapi_smoke():
    # Actual Uvicorn process, bound only to loopback; no visible helper window.
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                                "--port", str(port)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if process.poll() is not None:
                pytest.fail(process.stderr.read().decode())
            try:
                with urlopen(f"http://127.0.0.1:{port}/openapi.json", timeout=1) as response:
                    schema = json.load(response)
                assert len(schema["paths"]) == 11
                return
            except OSError:
                time.sleep(.1)
        pytest.fail("server startup timeout")
    finally:
        process.terminate()
        process.wait(timeout=10)
        process.stderr.close()

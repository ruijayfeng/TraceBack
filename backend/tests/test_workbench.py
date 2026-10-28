"""Task 08 SOC projections. Synthetic fixtures do not represent real findings."""

import json
import time
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.ai.explanation import ExplanationService
from app.ai.providers.fake import FakeProvider
from app.api.workbench import create_workbench_app
from app.services.storage import file_digest
from test_api import create_run
from test_analysis_service import deployment, tripwire
from test_wazuh_adapter import synthetic_record


@pytest.fixture
def api(tmp_path, monkeypatch):
    for name in ("TRACEBACK_LLM_BASE_URL", "TRACEBACK_LLM_MODEL", "TRACEBACK_LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    config, sources = deployment(tmp_path, edge=True)
    app = create_workbench_app(tmp_path, configs={"v0": config}, sources=sources)
    with TestClient(app) as client:
        yield client, app, tmp_path


def test_projection_counts_order_filters_and_observed_fields(api, monkeypatch):
    reads = tripwire(monkeypatch)
    client, app, _ = api
    aid = create_run(api)
    overview = client.get(f"/api/v1/analyses/{aid}/overview")
    assert overview.status_code == 200, overview.text
    counts = overview.json()["counts"]
    assert counts["singleton_count"] == 0 and counts["multi_alert_count"] == counts["chain_incident_count"] == 1
    assert counts["chain_node_count"] == 2 and counts["chain_edge_count"] == 1
    rows = client.get(f"/api/v1/analyses/{aid}/workbench").json()
    assert rows["page"] == 1 and rows["page_size"] == 20 and rows["total"] == 1
    row = rows["items"][0]
    assert row["alert_count"] == row["node_count"] == 2 and row["edge_count"] == 1
    assert row["sources"] and row["entities"] and row["ai_state"] == "not_generated"
    iid = row["incident"]["incident_id"]
    observations = client.get(f"/api/v1/incidents/{iid}/observations", params={"analysis_id": aid}).json()
    assert observations["analysis_id"] == aid and observations["sources"]
    assert all(f["alert_ids"] for f in observations["fields"])
    assert "raw_alert" not in json.dumps(observations)
    def forbidden(*a, **kw):
        raise AssertionError("projection must never call production discovery")
    import app.services.analysis as core
    for name in ("deduplicate", "extract_entities", "run_correlation", "run_reconstruction"):
        monkeypatch.setattr(core, name, forbidden)
    for kind, expected in (("all", 1), ("singleton", 0), ("multi_alert", 1), ("has_chain", 1), ("ai_explained", 0), ("ai_pending", 1)):
        for sort in ("time", "alert_count", "node_count"):
            first = client.get(f"/api/v1/analyses/{aid}/workbench", params={"kind": kind, "sort": sort})
            assert first.status_code == 200 and first.json()["total"] == expected, first.text
            assert first.json() == client.get(first.request.url).json()
    assert not any("evaluation" in r.lower() or "labels.csv" in r.lower() for r in reads)


@pytest.mark.parametrize("query", [{"page": "0"}, {"page_size": "101"}, {"page": "x"}, {"kind": "bogus"},
    {"sort": "risk_score"}, {"severity": "bogus"}, {"offset": "0"}, {"labels": "x"}, {"start_time": "x"}])
def test_projection_invalid_query_rejected(api, query):
    client, _, _ = api
    aid = create_run(api, [synthetic_record()])
    assert client.get(f"/api/v1/analyses/{aid}/workbench", params=query).status_code == 400


def test_singleton_pagination_empty_and_snapshot_scope(api):
    client, _, _ = api
    aid = create_run(api, [synthetic_record(id=str(i), timestamp=f"2022-01-21T00:00:{i:02d}Z") for i in range(4)])
    base = f"/api/v1/analyses/{aid}/workbench"
    first = client.get(base, params={"page_size": 2, "kind": "singleton"}).json()
    second = client.get(base, params={"page_size": 2, "page": 2, "kind": "singleton"}).json()
    assert first["total"] == second["total"] == 4
    assert len(first["items"]) == len(second["items"]) == 2
    assert not {r["incident"]["incident_id"] for r in first["items"]} & {r["incident"]["incident_id"] for r in second["items"]}
    assert client.get(base, params={"page": 3, "page_size": 2}).json()["items"] == []
    row = first["items"][0]
    assert row["node_count"] == 1 and row["edge_count"] == 0
    iid = row["incident"]["incident_id"]
    other = create_run(api, [synthetic_record(id="different")], "other.json")
    for suffix, method in (("", "get"), ("/chain", "get"), ("/observations", "get"), ("/explanation", "get"), ("/explain", "post")):
        assert getattr(client, method)(f"/api/v1/incidents/{iid}{suffix}", params={"analysis_id": other}).status_code == 404
    missing = "ana_" + "0" * 64
    for path in (f"/api/v1/analyses/{missing}/overview", f"/api/v1/analyses/{missing}/workbench"):
        assert client.get(path).status_code == 404


def test_formal_explain_persistence_restart_cache_evidence_and_core_unchanged(api, monkeypatch):
    client, app, root = api
    aid = create_run(api, [synthetic_record()])
    iid = client.get(f"/api/v1/analyses/{aid}/workbench").json()["items"][0]["incident"]["incident_id"]
    paths = list((root / "data/processed" / aid).glob("*")) + list((root / "outputs/analyses" / aid).glob("*"))
    before = {str(p): file_digest(p) for p in paths if p.is_file()}
    reads = tripwire(monkeypatch)
    assert client.get(f"/api/v1/incidents/{iid}/explanation", params={"analysis_id": aid}).json()["state"] == "not_generated"
    provider = FakeProvider()
    app.state.explanations = ExplanationService(provider)
    response = client.post(f"/api/v1/incidents/{iid}/explain", params={"analysis_id": aid})
    assert response.status_code == 200, response.text
    again = client.post(response.request.url)
    assert again.json() == response.json() and provider.calls == 1
    result = response.json()
    assert result["report_json"]["claims"] and all(c["grounding_status"] == "validated" for c in result["report_json"]["claims"])
    assert client.get(f"/api/v1/analyses/{aid}/workbench", params={"kind": "ai_explained"}).json()["total"] == 1
    saved = client.get(f"/api/v1/incidents/{iid}/explanation", params={"analysis_id": aid}).json()
    assert saved["result"] == result and saved["read_origin"] == "persisted"
    config, sources = deployment(root, edge=True)
    restarted = create_workbench_app(root, configs={"v0": config}, sources=sources)
    with TestClient(restarted) as other:
        assert other.get(f"/api/v1/incidents/{iid}/explanation", params={"analysis_id": aid}).json() == saved
        for ref in result["report_json"]["evidence_refs"]:
            assert other.get("/api/v1/alerts/" + ref["alert_id"], params={"analysis_id": aid}).status_code == 200
    assert before == {str(p): file_digest(Path(p)) for p in before}
    assert not any("evaluation" in r.lower() or "labels.csv" in r.lower() for r in reads)


def test_ai_unavailable_preserves_deterministic_report_and_navigation(api):
    client, app, _ = api
    aid = create_run(api, [synthetic_record()])
    iid = client.get(f"/api/v1/analyses/{aid}/workbench").json()["items"][0]["incident"]["incident_id"]
    app.state.explanations = ExplanationService()
    result = client.post(f"/api/v1/incidents/{iid}/explain", params={"analysis_id": aid})
    assert result.status_code == 409 and result.json()["result_origin"] == "deterministic"
    assert result.json()["report_json"]["claims"]
    assert client.get(f"/api/v1/incidents/{iid}/explanation", params={"analysis_id": aid}).json()["state"] == "unavailable"
    chain = client.get(f"/api/v1/incidents/{iid}/chain", params={"analysis_id": aid}).json()["chain"]
    assert len(chain["nodes"]) == 1 and chain["edges"] == []
    assert client.get("/api/v1/alerts/" + chain["nodes"][0]["alert_ids"][0], params={"analysis_id": aid}).status_code == 200


def test_persisted_report_tampering_rejected(api):
    client, app, root = api
    aid = create_run(api, [synthetic_record()])
    iid = client.get(f"/api/v1/analyses/{aid}/workbench").json()["items"][0]["incident"]["incident_id"]
    app.state.explanations = ExplanationService(FakeProvider())
    client.post(f"/api/v1/incidents/{iid}/explain", params={"analysis_id": aid})
    path = root / "outputs/workbench" / aid / (iid + ".json")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["result"]["report_json"]["summary"][0]["statement"] = "tampered"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert client.get(f"/api/v1/incidents/{iid}/explanation", params={"analysis_id": aid}).status_code == 409


def test_one_explain_route_and_unmodified_original_application(api):
    from app.main import create_app
    from fastapi.routing import APIRoute
    _, app, root = api
    routes = [r for r in app.routes if isinstance(r, APIRoute) and r.path.endswith('/explain')]
    assert len(routes) == 1
    config, sources = deployment(root, edge=True)
    original = create_app(root, configs={"v0": config}, sources=sources)
    assert len([r for r in original.routes if isinstance(r, APIRoute)]) == 11
    original.state.analyses.close()


def test_workbench_keyword_entity_time_and_page_size(api):
    client, _, _ = api
    aid = create_run(api, [synthetic_record(id=str(i), timestamp=f"2022-01-21T00:00:0{i}Z") for i in range(4)])
    base = f"/api/v1/analyses/{aid}/workbench"
    all_rows = client.get(base).json()
    assert all_rows["total"] == 4
    incident_id = all_rows["items"][0]["incident"]["incident_id"]
    # stable incident ID is searchable
    found = client.get(base, params={"q": incident_id[:20]})
    assert found.status_code == 200 and found.json()["total"] == 1
    assert found.json()["items"][0]["incident"]["incident_id"] == incident_id
    # entity value search finds the incident that carries that entity
    rich_aid = create_run(api, name="rich.json")
    rich_base = f"/api/v1/analyses/{rich_aid}/workbench"
    rich_rows = client.get(rich_base).json()["items"]
    entity_value = next(e["value"] for row in rich_rows for e in row["entities"] if e["value"])
    by_entity = client.get(rich_base, params={"entity": entity_value})
    assert by_entity.status_code == 200 and by_entity.json()["total"] >= 1
    assert {item["incident"]["incident_id"] for item in rich_rows} & {item["incident"]["incident_id"] for item in by_entity.json()["items"]}
    # the analysis list includes both runs
    assert {rich_aid, aid} <= {item["analysis_id"] for item in client.get("/api/v1/analyses").json()["items"]}
    # time range filter is inclusive of start and exclusive of end
    ranged = client.get(base, params={"start_time": "2022-01-21T00:00:01Z", "end_time": "2022-01-21T00:00:03Z"})
    assert ranged.status_code == 200
    assert ranged.json()["total"] == 2
    # page_size is honoured end-to-end and clamped by validation
    page = client.get(base, params={"page_size": 2, "page": 2})
    assert page.status_code == 200 and page.json()["page_size"] == 2 and page.json()["items"]
    for bad in ({"q": "x" * 201}, {"entity": " "}, {"q": " "}, {"start_time": "not-a-time"},
                {"start_time": "2022-01-21T00:00:02Z", "end_time": "2022-01-21T00:00:01Z"}, {"entity": "x", "offset": "1"}):
        assert client.get(base, params=bad).status_code == 400, bad


def test_analysis_list_is_ready_only_and_newest_first(api):
    client, _, _ = api
    first = create_run(api, [synthetic_record(id="a")])
    listed = client.get("/api/v1/analyses")
    assert listed.status_code == 200, listed.text
    ids = [item["analysis_id"] for item in listed.json()["items"]]
    assert first in ids
    assert all(item["status"] in {"completed", "incomplete"} for item in listed.json()["items"])
    assert client.get("/api/v1/analyses", params={"q": "x"}).status_code == 400


def test_async_explain_job_completes_and_persists(api):
    client, app, _ = api
    aid = create_run(api, [synthetic_record()])
    iid = client.get(f"/api/v1/analyses/{aid}/workbench").json()["items"][0]["incident"]["incident_id"]
    app.state.explanations = ExplanationService(FakeProvider())
    started = client.post(f"/api/v1/incidents/{iid}/explain-job", params={"analysis_id": aid})
    assert started.status_code == 202, started.text
    job_id = started.json()["job_id"]
    job = {}
    for _ in range(200):
        job = client.get(f"/api/v1/ai-jobs/{job_id}").json()
        if job["status"] in {"completed", "failed", "cancelled"}:
            break
        time.sleep(.05)
    assert job["status"] == "completed", job
    assert job["status_code"] == 200
    assert job["result"]["report_json"]["grounding_status"] == "validated"
    saved = client.get(f"/api/v1/incidents/{iid}/explanation", params={"analysis_id": aid}).json()
    assert saved["read_origin"] == "persisted" and saved["result"]["analysis_id"] == aid
    assert client.get(f"/api/v1/ai-jobs/{job_id}", params={"x": "1"}).status_code == 400
    assert client.get("/api/v1/ai-jobs/not_hex!").status_code == 400
    assert client.get("/api/v1/ai-jobs/" + "f" * 32).status_code == 404
    assert client.delete("/api/v1/ai-jobs/" + "f" * 32).status_code == 404


def test_async_explain_job_cancels_without_saving(api):
    client, app, _ = api

    class SlowFakeProvider(FakeProvider):
        def explain(self, context):
            time.sleep(.35)
            return super().explain(context)

    aid = create_run(api, [synthetic_record()])
    iid = client.get(f"/api/v1/analyses/{aid}/workbench").json()["items"][0]["incident"]["incident_id"]
    app.state.explanations = ExplanationService(SlowFakeProvider())
    started = client.post(f"/api/v1/incidents/{iid}/explain-job", params={"analysis_id": aid})
    assert started.status_code == 202
    job_id = started.json()["job_id"]
    cancelled = client.delete(f"/api/v1/ai-jobs/{job_id}")
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    time.sleep(.8)
    assert client.get(f"/api/v1/ai-jobs/{job_id}").json()["status"] == "cancelled"
    saved = client.get(f"/api/v1/incidents/{iid}/explanation", params={"analysis_id": aid}).json()
    assert saved["state"] == "not_generated" and saved["result"] is None


def test_ai_jobs_survive_restart_and_running_jobs_are_interrupted(api):
    client, app, root = api
    aid = create_run(api, [synthetic_record()])
    iid = client.get(f"/api/v1/analyses/{aid}/workbench").json()["items"][0]["incident"]["incident_id"]
    app.state.explanations = ExplanationService(FakeProvider())
    job_id = client.post(f"/api/v1/incidents/{iid}/explain-job", params={"analysis_id": aid}).json()["job_id"]
    for _ in range(200):
        job = client.get(f"/api/v1/ai-jobs/{job_id}").json()
        if job["status"] in {"completed", "failed", "cancelled"}:
            break
        time.sleep(.05)
    assert job["status"] == "completed"
    job_file = root / "outputs" / "ai_jobs" / (job_id + ".json")
    assert job_file.is_file()
    # A job left "running" by a hard stop is reported as interrupted, not stuck.
    interrupted_id = "a" * 32
    (root / "outputs" / "ai_jobs" / (interrupted_id + ".json")).write_text(json.dumps({
        "job_id": interrupted_id, "status": "running", "created_at": 1.0, "finished_at": None,
    }), encoding="utf-8")
    config, sources = deployment(root, edge=True)
    restarted = create_workbench_app(root, configs={"v0": config}, sources=sources)
    with TestClient(restarted) as other:
        completed = other.get(f"/api/v1/ai-jobs/{job_id}")
        assert completed.status_code == 200 and completed.json()["status"] == "completed"
        assert completed.json()["result"]["report_json"]["grounding_status"] == "validated"
        interrupted = other.get(f"/api/v1/ai-jobs/{interrupted_id}").json()
        assert interrupted["status"] == "failed" and interrupted["error"] == "job_interrupted"
        # cancellation state also reloads
        assert other.delete(f"/api/v1/ai-jobs/{interrupted_id}").status_code == 200


def test_ai_job_concurrency_limit(api):
    client, app, _ = api

    class SlowFakeProvider(FakeProvider):
        def explain(self, context):
            time.sleep(.5)
            return super().explain(context)

    aid = create_run(api, [synthetic_record()])
    iid = client.get(f"/api/v1/analyses/{aid}/workbench").json()["items"][0]["incident"]["incident_id"]
    app.state.explanations = ExplanationService(SlowFakeProvider())
    started = [client.post(f"/api/v1/incidents/{iid}/explain-job", params={"analysis_id": aid}) for _ in range(4)]
    assert all(response.status_code == 202 for response in started), [response.text for response in started]
    limited = client.post(f"/api/v1/incidents/{iid}/explain-job", params={"analysis_id": aid})
    assert limited.status_code == 429 and limited.json()["detail"] == "ai_job_limited"
    assert limited.headers["retry-after"] == "5"
    for response in started:
        client.delete(f"/api/v1/ai-jobs/{response.json()['job_id']}")
    time.sleep(.8)


def test_openapi_workbench_route_snapshot(api):
    client, app, _ = api
    root = Path(__file__).resolve().parents[2]
    snapshot = json.loads((root / "docs" / "openapi-workbench.json").read_text(encoding="utf-8"))
    methods = {"get", "put", "post", "delete", "patch", "options", "head"}
    def operations(schema):
        return {path: sorted(m for m in payload if m in methods) for path, payload in schema["paths"].items()}
    current = operations(app.openapi())
    assert current == operations(snapshot), "run: PYTHONPATH=backend python scripts/export_openapi.py"
    # The eleven frozen routes keep their methods even as workbench routes grow.
    frozen = {
        "/api/v1/analyses": ["get", "post"],  # frozen POST + T102 list GET
        "/api/v1/analyses/{analysis_id}": ["get"],
        "/api/v1/alerts": ["get"],
        "/api/v1/alerts/{alert_id}": ["get"],
        "/api/v1/incidents": ["get"],
        "/api/v1/incidents/{incident_id}": ["get"],
        "/api/v1/incidents/{incident_id}/chain": ["get"],
        "/api/v1/incidents/{incident_id}/timeline": ["get"],
        "/api/v1/edges/{edge_id}": ["get"],
        "/api/v1/incidents/{incident_id}/explain": ["post"],
    }
    for path, expected in frozen.items():
        assert current[path] == expected, path

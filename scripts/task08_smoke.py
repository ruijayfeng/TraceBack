"""Read-only real snapshot acceptance. No evaluation imports or label access.

Provider-unavailable and explicit offline FakeProvider checks are reported
separately. Fake responses are stored in test artifacts, never product reports.
"""

import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def run():
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient
    from app.ai.explanation import ExplanationService
    from app.ai.providers.fake import FakeProvider
    from app.api.routes import router
    from app.api.workbench import install_workbench
    from app.models.base import resolve_pointer
    from app.services.queries import QueryError, QueryService
    from app.services.storage import MODELS, file_digest
    from demo_support import truth_guard

    output = ROOT / "outputs/task08"
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    with truth_guard(ROOT):
        runs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "data/processed").glob("ana_*/run.json"))]
        runs = [r for r in runs if r.get("status") == "completed" and r.get("candidate_contract_version") == "v1.1"
            and {"ait_ads.russellmitchell.wazuh", "ait_ads.russellmitchell.aminer"} <=
                {i.get("source_namespace") for i in r.get("input_files", [])}]
        if not runs:
            raise ValueError("real_completed_snapshot_required")
        run_record = max(runs, key=lambda r: (r["created_at"], r["analysis_id"]))
        aid = run_record["analysis_id"]
        q = QueryService(ROOT)
        store = q.ready(aid)
        paths = [store.domain / (k + ".parquet") for k in MODELS]
        paths += [store.domain / "analysis.json", store.domain / "run.json", store.details / "manifest.json",
            store.details / "diagnostics.jsonl", store.details / "frequency_snapshot.json"]
        before = {p.relative_to(ROOT).as_posix(): file_digest(p) for p in paths}
        selected = []
        with q.connection() as db:
            for source in ("aminer", "wazuh", "suricata"):
                row = db.execute("SELECT i.object_id FROM read_parquet(?) i JOIN read_parquet(?) a "
                    "ON json_extract_string(i.payload, '$.alert_ids[0]') = a.object_id "
                    "WHERE json_array_length(i.payload, '$.alert_ids') = 1 AND "
                    "json_extract_string(a.payload, '$.source_type') = ? ORDER BY i.object_id LIMIT 1",
                    [q.table(store, "incidents"), q.table(store, "alerts"), source]).fetchone()
                if row is None:
                    raise ValueError("real_singleton_missing:" + source)
                selected.append((source, row[0]))
        app = FastAPI()
        app.state.queries = q
        @app.exception_handler(QueryError)
        async def query_error(request: Request, exc: QueryError):
            return JSONResponse(status_code=exc.status, content={"detail": exc.code})
        app.include_router(router)
        install_workbench(app, host_ui=False)
        app.state.presentation_reports.root = output / "smoke_report_store"
        measurements = []
        with TestClient(app) as client:
            overview_response = client.get(f"/api/v1/analyses/{aid}/overview")
            assert overview_response.status_code == 200, overview_response.text
            overview = overview_response.json()
            for kind in ("all", "singleton", "multi_alert", "has_chain", "ai_explained", "ai_pending"):
                response = client.get(f"/api/v1/analyses/{aid}/workbench", params={"kind": kind})
                assert response.status_code == 200 and len(response.json()["items"]) <= 20
            for source, iid in selected:
                scope = {"analysis_id": aid}
                detail = client.get(f"/api/v1/incidents/{iid}", params=scope)
                chain = client.get(f"/api/v1/incidents/{iid}/chain", params=scope).json()["chain"]
                assert detail.status_code == 200 and len(chain["nodes"]) == 1 and not chain["edges"]
                node = chain["nodes"][0]
                assert client.get(f"/api/v1/incidents/{iid}/observations", params=scope).status_code == 200
                assert client.get(f"/api/v1/incidents/{iid}/timeline", params=scope).status_code == 200
                for alert_id in node["alert_ids"]:
                    assert client.get("/api/v1/alerts/" + alert_id, params=scope).status_code == 200
                app.state.explanations = ExplanationService()
                fallback_response = client.post(f"/api/v1/incidents/{iid}/explain", params=scope)
                assert fallback_response.status_code == 409
                fallback = fallback_response.json()
                assert fallback["result_origin"] == "deterministic" and fallback["grounding_status"] == "validated"
                assert fallback["report_json"] and fallback["report_markdown"]
                fake = FakeProvider()
                app.state.explanations = ExplanationService(fake)
                response = client.post(f"/api/v1/incidents/{iid}/explain", params=scope)
                assert response.status_code == 200, response.text
                result = response.json()
                assert client.post(response.request.url).json() == result and fake.calls == 1
                report = result["report_json"]
                assert report["analysis_id"] == aid and report["incident_id"] == iid
                assert all(c["grounding_status"] == "validated" for c in report["claims"])
                for ref in report["evidence_refs"]:
                    alert_response = client.get("/api/v1/alerts/" + ref["alert_id"], params=scope)
                    assert alert_response.status_code == 200
                    resolve_pointer(alert_response.json()["alert"]["raw_alert"], ref["pointer"])
                saved = client.get(f"/api/v1/incidents/{iid}/explanation", params=scope)
                assert saved.status_code == 200 and saved.json()["result"] == result
                (output / "reports").mkdir(exist_ok=True)
                for name, value in ((source + "-offline.json", report), (source + "-fallback.json", fallback["report_json"])):
                    (output / "reports" / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
                (output / "reports" / (source + "-offline.md")).write_text(result["report_markdown"], encoding="utf-8")
                measurements.append({"source": source, "incident_id": iid, "nodes": len(chain["nodes"]), "edges": len(chain["edges"]),
                    "node_evidence": True, "singleton_opened": True, "fallback_http": fallback_response.status_code,
                    "fallback_generation_status": fallback["generation_status"], "offline_provider": "explicit test-only FakeProvider",
                    "offline_http": response.status_code, "verified_claims": len(report["claims"]),
                    "rejected_claims": len(result["rejected_claims"]), "rejected_mappings": len(result["rejected_mappings"]),
                    "techniques": len(report["attack_techniques"]), "cache_provider_calls_after_two_requests": fake.calls,
                    "persisted_report_read": True, "claim_evidence_resolved": True})
        after = {p.relative_to(ROOT).as_posix(): file_digest(p) for p in paths}
        assert before == after, "production snapshot modified during Smoke"
        result = {"dataset": "AIT-ADS/russellmitchell", "analysis_id": aid, "status": "passed",
            "counts": overview["counts"], "sources": overview["distributions"]["source_type"], "incidents": measurements,
            "edge_evidence": "not_applicable_real_zero_edges; verified separately using accepted synthetic fixture",
            "attack_mapping_evidence": "not_applicable_selected_real_incidents_zero_techniques",
            "truth_guard_active": True, "production_snapshot_unchanged": True, "before_hashes": before,
            "external_llm_called": False, "runtime_seconds": time.perf_counter()-started}
        (output / "real_smoke.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({k: v for k, v in result.items() if k != "before_hashes"}, ensure_ascii=False, indent=2))
        return 0


if __name__ == "__main__":
    raise SystemExit(run())

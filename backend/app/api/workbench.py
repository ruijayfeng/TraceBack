"""SOC read projections and UI hosting; frozen production modules stay intact.

Use create_workbench_app as an opt-in app factory. Existing eleven routes keep
their schemas. Explain delegates to the existing handler, then saves its
validated response for presentation after refresh or server restart.
"""

import json
from pathlib import Path
from threading import Lock, Thread
from time import time
from types import SimpleNamespace
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles

from app.ai.explanation import GroundedExplanation
from app.models.base import AnalysisID, IncidentID
from app.services.queries import QueryError
from .explanations import explain_incident
from .routes import params
from .schemas import ExplainRequest
from .workbench_store import ReportStore
from .incident_metrics import MEMBERSHIP_SQL, membership_paths
from .score_diagnostics import read_score_diagnostic


class WorkbenchQueries:
    def __init__(self, queries, reports):
        self.q, self.reports = queries, reports

    def overview(self, analysis_id):
        detail = self.q.analysis(analysis_id)
        store = self.q.ready(analysis_id)
        with self.q.connection() as db:
            singleton, multi, expansion = db.execute(MEMBERSHIP_SQL +
                "SELECT count(*) FILTER(WHERE representative_member_count = 1), "
                "count(*) FILTER(WHERE representative_member_count >= 2), "
                "count(*) FILTER(WHERE expanded_member_count > representative_member_count) FROM base",
                membership_paths(self.q, store)).fetchone()
            chain_count = db.execute("SELECT count(*) FROM read_parquet(?) WHERE json_array_length(payload, '$.edges') > 0",
                [self.q.table(store, "attack_chains")]).fetchone()[0]
            distributions = {}
            for field in ("source_type", "severity", "category"):
                rows = db.execute(f"SELECT json_extract_string(payload, '$.{field}') AS value, count(*) AS n "
                    "FROM read_parquet(?) GROUP BY value ORDER BY n DESC, value ASC",
                    [self.q.table(store, "alerts")]).fetchall()
                distributions[field] = [{"value": v, "count": n} for v, n in rows]
        return {"analysis_id": analysis_id, "status": detail["status"], "is_complete": detail["is_complete"],
            "created_at": detail["created_at"], "counts": {**detail["counts"], "singleton_count": singleton,
                "multi_alert_count": multi, "representative_singleton_incident_count": singleton,
                "correlated_multi_alert_incident_count": multi,
                "incidents_with_dedupe_expansion_count": expansion, "chain_incident_count": chain_count},
            "distributions": distributions, "warnings": detail["warnings"], "errors": detail["errors"],
            "incomplete_reason": detail["incomplete_reason"], "algorithm_version": detail["algorithm_version"],
            "config_hash": detail["config_hash"], "diagnostics_ref": detail["diagnostics_ref"],
            "manifest_ref": detail["manifest_ref"], "score_diagnostics": read_score_diagnostic(self.q, analysis_id)}

    def list_analyses(self):
        """List ready frozen analyses for the demo/recent picker; newest first."""
        base = self.q.root / "data" / "processed"
        items = []
        if base.is_dir():
            for child in sorted(base.iterdir()):
                if not child.is_dir() or not (child / "run.json").is_file():
                    continue
                try:
                    detail = self.q.analysis(child.name)
                except QueryError:
                    continue
                if detail.get("record") is None or detail.get("status") not in {"completed", "incomplete"}:
                    continue
                counts = detail.get("counts", {})
                items.append({"analysis_id": detail["analysis_id"], "status": detail["status"],
                    "is_complete": bool(detail.get("is_complete")), "created_at": detail.get("created_at"),
                    "created_count": counts.get("input_count", 0),
                    "incident_count": counts.get("incident_count", 0)})
        items.sort(key=lambda item: item.get("created_at") or "", reverse=True)
        return {"items": items[:20]}

    def incidents(self, analysis_id, page, page_size, kind="all", sort="time", severity=None, q=None, entity=None,
                  start_time=None, end_time=None):
        store = self.q.ready(analysis_id)
        reports = self.reports.index(analysis_id)
        clauses, bindings = [], []
        if kind == "singleton":
            clauses.append("representative_member_count = 1")
        elif kind == "multi_alert":
            clauses.append("representative_member_count >= 2")
        elif kind == "has_chain":
            clauses.append("edge_count > 0")
        elif kind in {"ai_explained", "ai_pending"}:
            ids = sorted(i for i, r in reports.items() if r["state"] in {"completed", "partially_rejected"})
            clauses.append("object_id " + ("IN" if kind == "ai_explained" else "NOT IN") + " (SELECT unnest(?))")
            bindings.append(ids)
        if severity is not None:
            clauses.append("json_extract_string(payload, '$.severity') = ?")
            bindings.append(severity)
        if q is not None:
            # Substring search over stable IDs, summary and other payload text.
            clauses.append("(contains(lower(CAST(object_id AS VARCHAR)), lower(?)) OR contains(lower(CAST(payload AS VARCHAR)), lower(?)))")
            bindings.extend([q, q])
        if entity is not None:
            clauses.append("list_has_any(CAST(json_extract(payload, '$.entity_ids') AS VARCHAR[]), "
                "(SELECT list(json_extract_string(payload, '$.entity_id')) FROM read_parquet(?) "
                "WHERE contains(lower(coalesce(json_extract_string(payload, '$.value'), '')), lower(?)) "
                "OR contains(lower(coalesce(json_extract_string(payload, '$.display_value'), '')), lower(?))))")
            bindings.extend([self.q.table(store, "entities"), entity, entity])
        if start_time is not None:
            clauses.append("epoch(event_time) >= epoch(strptime(?, '%Y-%m-%dT%H:%M:%S.%fZ'))")
            bindings.append(start_time)
        if end_time is not None:
            clauses.append("epoch(event_time) < epoch(strptime(?, '%Y-%m-%dT%H:%M:%S.%fZ'))")
            bindings.append(end_time)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        order = {"time": "event_time DESC", "alert_count": "alert_count DESC, event_time DESC",
            "node_count": "node_count DESC, event_time DESC"}[sort] + ", object_id ASC"
        sql = MEMBERSHIP_SQL
        paths = membership_paths(self.q, store)
        with self.q.connection() as db:
            total = db.execute(sql + "SELECT count(*) FROM base" + where, [*paths, *bindings]).fetchone()[0]
            rows = db.execute(sql + "SELECT payload, alert_count, node_count, edge_count, representative_member_count FROM base" + where +
                " ORDER BY " + order + " LIMIT ? OFFSET ?", [*paths, *bindings, page_size, (page-1)*page_size]).fetchall()
        incidents = [(self.q.parsed("incidents", r[0]), *r[1:]) for r in rows]
        alerts = {a.alert_id: a for a in self.q.by_ids(analysis_id, "alerts", {a for i, *_ in incidents for a in i.alert_ids})}
        entities = {e.entity_id: e for e in self.q.by_ids(analysis_id, "entities", {e for i, *_ in incidents for e in i.entity_ids})}
        items = []
        for incident, ac, nc, ec, rc in incidents:
            meta = reports.get(incident.incident_id, {})
            # Entity labels only; no extra alerts from another Incident.
            items.append({"incident": incident, "alert_count": ac, "node_count": nc, "edge_count": ec,
                "representative_member_count": rc, "expanded_member_count": ac,
                "has_dedupe_expansion": ac > rc,
                "sources": sorted({alerts[a].source_type.value for a in incident.alert_ids}),
                "entities": [{"entity_id": e, "type": entities[e].type.value, "value": entities[e].display_value}
                    for e in incident.entity_ids], "ai_state": meta.get("state", "not_generated"),
                "techniques": meta.get("techniques", [])})
        return {"analysis_id": analysis_id, "items": items, "page": page, "page_size": page_size, "total": total}


def install_workbench(app, *, root=None, host_ui=True):
    q = app.state.queries
    reports = ReportStore(q)
    projection = WorkbenchQueries(q, reports)
    app.state.workbench, app.state.presentation_reports = projection, reports
    router = APIRouter(prefix="/api/v1")

    @router.get("/analyses/{analysis_id}/overview")
    def overview(analysis_id: AnalysisID, request: Request):
        if request.query_params:
            raise HTTPException(400, "unknown_query_parameter")
        return projection.overview(analysis_id)

    @router.get("/analyses")
    def list_analyses(request: Request):
        if request.query_params:
            raise HTTPException(400, "unknown_query_parameter")
        return projection.list_analyses()

    @router.get("/analyses/{analysis_id}/workbench")
    def workbench(analysis_id: AnalysisID, request: Request):
        p = params(request, {"kind", "sort", "severity", "q", "entity", "start_time", "end_time"}, paginated=True)
        kind, sort = p.get("kind", "all"), p.get("sort", "time")
        if kind not in {"all", "singleton", "multi_alert", "has_chain", "ai_explained", "ai_pending"} or sort not in {"time", "alert_count", "node_count"}:
            raise HTTPException(400, "invalid_workbench_filter")
        q, entity = p.get("q"), p.get("entity")
        if (q is not None and (not q.strip() or len(q) > 200)) or (entity is not None and (not entity.strip() or len(entity) > 200)):
            raise HTTPException(400, "invalid_workbench_filter")
        return projection.incidents(analysis_id, p["page"], p["page_size"], kind, sort, p.get("severity"),
                                   q.strip() if q else None, entity.strip() if entity else None,
                                   p.get("start_time"), p.get("end_time"))

    # T103: optional async Explain job API for slow providers. The synchronous
    # endpoint stays the default; jobs never mutate snapshots beyond the same
    # validated presentation report the sync path saves. Cancellation is
    # cooperative: the provider call may finish, but its result is discarded.
    jobs = app.state.ai_jobs = {}
    jobs_lock = app.state.ai_jobs_lock = Lock()
    jobs_dir = q.root / "outputs" / "ai_jobs"

    def public_job(job):
        return {key: job.get(key) for key in ("job_id", "status", "created_at", "finished_at", "status_code", "result", "error")}

    def persist_job(job):
        try:
            jobs_dir.mkdir(parents=True, exist_ok=True)
            path = jobs_dir / (job["job_id"] + ".json")
            temporary = path.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(public_job(job), ensure_ascii=False), encoding="utf-8")
            temporary.replace(path)
        except OSError:
            # Job durability is best-effort; the in-memory registry still serves
            # polling while the process is alive.
            pass

    def remove_job_file(job_id):
        try:
            (jobs_dir / (job_id + ".json")).unlink(missing_ok=True)
        except OSError:
            pass

    # T103/F20: reload completed/cancelled jobs across process restarts; jobs
    # that were running when the process stopped are reported as interrupted.
    if jobs_dir.is_dir():
        for path in sorted(jobs_dir.glob("*.json")):
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                job_id = loaded["job_id"]
                if not isinstance(job_id, str) or not job_id.isalnum() or loaded.get("status") not in {"queued", "running", "completed", "failed", "cancelled"}:
                    continue
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if loaded["status"] in {"queued", "running"}:
                loaded.update(status="failed", error="job_interrupted", finished_at=time())
                persist_job(loaded)
            jobs[job_id] = loaded

    def prune_jobs():
        now = time()
        with jobs_lock:
            finished = [(job_id, job) for job_id, job in jobs.items() if job["status"] in {"completed", "failed", "cancelled"}]
            for job_id, job in finished:
                if now - (job.get("finished_at") or now) > 3600:
                    jobs.pop(job_id, None)
                    remove_job_file(job_id)
            while len(jobs) > 100:
                oldest = min(jobs, key=lambda key: jobs[key]["created_at"])
                jobs.pop(oldest, None)
                remove_job_file(oldest)

    def run_job(job_id, analysis_id, incident_id):
        with jobs_lock:
            job = jobs.get(job_id)
            if not job or job["status"] == "cancelled":
                return
            job["status"] = "running"
            persist_job(job)
        try:
            result = explain_incident(SimpleNamespace(app=app), analysis_id, incident_id)
            with jobs_lock:
                job = jobs.get(job_id)
                if not job or job["status"] == "cancelled":
                    return
            if hasattr(result, "model_dump"):
                payload, status_code = result.model_dump(mode="json"), 200
                reports.save(result)
            else:
                payload, status_code = json.loads(result.body), result.status_code
            with jobs_lock:
                job = jobs.get(job_id)
                if not job or job["status"] == "cancelled":
                    return
                job.update(status="completed", status_code=status_code, result=payload, finished_at=time())
                persist_job(job)
        except Exception as exc:  # provider/query errors stay inside the job
            with jobs_lock:
                job = jobs.get(job_id)
                if job and job["status"] != "cancelled":
                    job.update(status="failed", error=type(exc).__name__, finished_at=time())
                    persist_job(job)

    @router.post("/incidents/{incident_id}/explain-job", status_code=202)
    def start_explain_job(incident_id: IncidentID, request: Request):
        p = params(request)
        analysis_id = p["analysis_id"]
        # Fail fast for unknown incidents instead of surfacing it inside the job.
        q.get(analysis_id, "incidents", incident_id)
        prune_jobs()
        now = time()
        with jobs_lock:
            running = sum(1 for item in jobs.values() if item["status"] in {"queued", "running"})
            recent = sum(1 for item in jobs.values() if now - item["created_at"] < 60)
        if running >= 4 or recent >= 30:
            raise HTTPException(429, "ai_job_limited", headers={"Retry-After": "5"})
        job_id = uuid4().hex
        with jobs_lock:
            jobs[job_id] = {"job_id": job_id, "analysis_id": analysis_id, "incident_id": incident_id,
                            "status": "queued", "created_at": time(), "finished_at": None}
            persist_job(jobs[job_id])
        Thread(target=run_job, args=(job_id, analysis_id, incident_id), daemon=True).start()
        return {"job_id": job_id, "status": "queued"}

    @router.get("/ai-jobs/{job_id}")
    def explain_job(job_id: str, request: Request):
        if request.query_params:
            raise HTTPException(400, "unknown_query_parameter")
        if not job_id.isalnum() or len(job_id) > 64:
            raise HTTPException(400, "invalid_job_id")
        with jobs_lock:
            job = jobs.get(job_id)
            if job is None:
                raise HTTPException(404, "job_not_found")
            return public_job(job)

    @router.delete("/ai-jobs/{job_id}")
    def cancel_explain_job(job_id: str, request: Request):
        if request.query_params:
            raise HTTPException(400, "unknown_query_parameter")
        if not job_id.isalnum() or len(job_id) > 64:
            raise HTTPException(400, "invalid_job_id")
        with jobs_lock:
            job = jobs.get(job_id)
            if job is None:
                raise HTTPException(404, "job_not_found")
            if job["status"] in {"queued", "running"}:
                job.update(status="cancelled", finished_at=time())
                persist_job(job)
        return {key: job.get(key) for key in ("job_id", "status", "created_at", "finished_at")}

    @router.get("/analyses/{analysis_id}/score-diagnostics")
    def score_diagnostics(analysis_id: AnalysisID, request: Request):
        if request.query_params:
            raise HTTPException(400, "unknown_query_parameter")
        return read_score_diagnostic(q, analysis_id)

    @router.get("/incidents/{incident_id}/explanation")
    def read_explanation(incident_id: IncidentID, analysis_id: AnalysisID, request: Request):
        params(request)
        return reports.read(analysis_id, incident_id)

    @router.get("/incidents/{incident_id}/observations")
    def observations(incident_id: IncidentID, analysis_id: AnalysisID, request: Request):
        params(request)
        incident = q.get(analysis_id, "incidents", incident_id)
        with q.connection() as db:
            rc, ac = db.execute(MEMBERSHIP_SQL +
                "SELECT representative_member_count, expanded_member_count FROM base WHERE object_id = ?",
                [*membership_paths(q, q.ready(analysis_id)), incident_id]).fetchone()
        alerts = q.by_ids(analysis_id, "alerts", incident.alert_ids)
        fields = []
        for field in ("src_ip", "dst_ip", "host", "account", "process", "parent_process", "session", "url", "domain", "file", "command"):
            values = {}
            for alert in alerts:
                value = alert.model_dump(mode="json")[field]
                if value is None:
                    continue
                key = json.dumps(value, ensure_ascii=False, sort_keys=True)
                if key not in values:
                    values[key] = {"field": field, "value": value, "alert_ids": [], "pointers": []}
                values[key]["alert_ids"].append(alert.alert_id)
                if field in alert.field_provenance:
                    values[key]["pointers"].append({"alert_id": alert.alert_id,
                        "pointer": alert.field_provenance[field].raw_pointer, "side": "shared"})
            fields.extend(values[k] for k in sorted(values))
        return {"analysis_id": analysis_id, "incident_id": incident_id,
            "representative_member_count": rc, "expanded_member_count": ac, "has_dedupe_expansion": ac > rc,
            "sources": sorted({a.source_type.value for a in alerts}), "fields": fields}

    # One formal Explain route, one existing Explain implementation. Only the
    # app assembled for the workbench adds transport-level report persistence.
    app.router.routes = [r for r in app.router.routes if not (isinstance(r, APIRoute)
        and r.path == "/api/v1/incidents/{incident_id}/explain" and "POST" in r.methods)]

    @router.post("/incidents/{incident_id}/explain", response_model=GroundedExplanation,
        responses={409: {"model": GroundedExplanation}})
    def explain(incident_id: IncidentID, request: Request, analysis_id: AnalysisID, body: ExplainRequest | None = None):
        params(request)
        response = explain_incident(request, analysis_id, incident_id)
        result = (GroundedExplanation.model_validate_json(response.body)
            if isinstance(response, JSONResponse) else response)
        reports.save(result)
        return response

    app.include_router(router)
    if host_ui:
        dist = Path(root or q.root) / "frontend/dist"
        if (dist / "index.html").is_file():
            app.mount("/assets", StaticFiles(directory=dist / "assets"), name="ui_assets")

            @app.get("/", include_in_schema=False)
            def ui():
                return FileResponse(dist / "index.html", headers={"Cache-Control": "no-cache"})
    return app


def create_workbench_app(root=None, **kwargs):
    from app.main import create_app
    return install_workbench(create_app(root, **kwargs), root=root)

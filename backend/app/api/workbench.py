"""SOC read projections and UI hosting; frozen production modules stay intact.

Use create_workbench_app as an opt-in app factory. Existing eleven routes keep
their schemas. Explain delegates to the existing handler, then saves its
validated response for presentation after refresh or server restart.
"""

import json
from pathlib import Path

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

    def incidents(self, analysis_id, page, page_size, kind="all", sort="time", severity=None):
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
    from .stage_workbench import install_stage_workbench
    install_stage_workbench(app, root or q.root)
    reports = ReportStore(q)
    projection = WorkbenchQueries(q, reports)
    app.state.workbench, app.state.presentation_reports = projection, reports
    router = APIRouter(prefix="/api/v1")

    @router.get("/analyses/{analysis_id}/overview")
    def overview(analysis_id: AnalysisID, request: Request):
        if request.query_params:
            raise HTTPException(400, "unknown_query_parameter")
        return projection.overview(analysis_id)

    @router.get("/analyses/{analysis_id}/workbench")
    def workbench(analysis_id: AnalysisID, request: Request):
        p = params(request, {"kind", "sort", "severity"}, paginated=True)
        kind, sort = p.get("kind", "all"), p.get("sort", "time")
        if kind not in {"all", "singleton", "multi_alert", "has_chain", "ai_explained", "ai_pending"} or sort not in {"time", "alert_count", "node_count"}:
            raise HTTPException(400, "invalid_workbench_filter")
        return projection.incidents(analysis_id, p["page"], p["page_size"], kind, sort, p.get("severity"))

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

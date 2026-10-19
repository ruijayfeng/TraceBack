"""Exactly the eleven frozen routes, with explicit snapshot scope."""

from fastapi import APIRouter, HTTPException, Query, Request
from app.models import CanonicalAlert, EvaluationSummaryExport, Incident
from app.models.base import AnalysisID, ChainEdgeID, IncidentID, AlertID
from app.models.enums import AnalysisStatus, Category, IncidentStatus, Severity, SourceType
from app.services.analysis import AnalysisInputError
from app.utils.stable_id import utc_text
from .schemas import (APIError, AlertDetail, AnalysisAccepted, AnalysisDetail, ChainDetail, CreateAnalysis,
                      EdgeDetail, ExplainRequest, IncidentDetail, Page, TimelineItem)
from app.ai.explanation import GroundedExplanation
from .explanations import explain_incident


router = APIRouter(prefix="/api/v1", responses={400: {"model": APIError}, 404: {"model": APIError},
    409: {"model": APIError}, 422: {"model": APIError}})


def params(request, permitted=(), *, paginated=False):
    allowed = {"analysis_id", *permitted} | ({"page", "page_size"} if paginated else set())
    if set(request.query_params) - allowed or any(len(request.query_params.getlist(k)) != 1 for k in request.query_params):
        raise HTTPException(400, "unknown_or_duplicate_query_parameter")
    result = dict(request.query_params)
    if paginated:
        for key, default in (("page", 1), ("page_size", 20)):
            text = result.get(key, str(default))
            if not text.isascii() or not text.isdecimal() or len(text) > 10:
                raise HTTPException(400, "invalid_pagination")
            result[key] = int(text)
        if result["page"] < 1 or not 1 <= result["page_size"] <= 100:
            raise HTTPException(400, "invalid_pagination")
    for key in ("start_time", "end_time"):
        if key in result:
            try:
                result[key] = utc_text(result[key])
            except ValueError:
                raise HTTPException(400, "invalid_time_filter")
    if result.get("start_time") is not None and result.get("end_time") is not None and result["start_time"] >= result["end_time"]:
        raise HTTPException(400, "invalid_time_interval")
    enums = {"source_type": SourceType, "severity": Severity, "category": Category, "status": IncidentStatus}
    for field, enum in enums.items():
        if field in result and result[field] not in {v.value for v in enum}:
            raise HTTPException(400, "invalid_filter:" + field)
    return result


def query(request):
    return request.app.state.queries


@router.post("/analyses", status_code=202, response_model=AnalysisAccepted)
def create_analysis(body: CreateAnalysis, request: Request):
    if request.query_params:
        raise HTTPException(400, "unknown_query_parameter")
    try:
        identity = request.app.state.analyses.create(body.model_dump())
    except AnalysisInputError as exc:
        code = str(exc)
        status = 404 if code in {"input_reference_missing", "unknown_config_version", "unsupported_source_reference"} else 400
        raise HTTPException(status, code)
    return {"analysis_id": identity, "status": AnalysisStatus.QUEUED}


@router.get("/analyses/{analysis_id}", response_model=AnalysisDetail)
def analysis_detail(analysis_id: AnalysisID, request: Request):
    if request.query_params:
        raise HTTPException(400, "unknown_query_parameter")
    result = query(request).analysis(analysis_id)
    result["status"] = AnalysisStatus(result["status"])
    result["state_history"] = [AnalysisStatus(s) for s in result["state_history"]]
    return result


@router.get("/alerts", response_model=Page[CanonicalAlert])
def alerts(request: Request, analysis_id: AnalysisID, page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
           start_time: str | None = None, end_time: str | None = None, source_type: str | None = None,
           category: str | None = None, severity: str | None = None):
    p = params(request, {"start_time", "end_time", "source_type", "category", "severity"}, paginated=True)
    return query(request).list(analysis_id, "alerts", page=p.pop("page"), page_size=p.pop("page_size"),
                               filters={k: v for k, v in p.items() if k != "analysis_id"})


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
def alert_detail(alert_id: AlertID, request: Request, analysis_id: AnalysisID):
    params(request)
    alert = query(request).get(analysis_id, "alerts", alert_id)
    return {"analysis_id": analysis_id, "alert": alert,
            "entities": query(request).by_ids(analysis_id, "entities", alert.entity_ids)}


@router.get("/incidents", response_model=Page[Incident])
def incidents(request: Request, analysis_id: AnalysisID, page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
              start_time: str | None = None, end_time: str | None = None, severity: str | None = None,
              status: str | None = None):
    p = params(request, {"start_time", "end_time", "severity", "status"}, paginated=True)
    return query(request).list(analysis_id, "incidents", page=p.pop("page"), page_size=p.pop("page_size"),
                               filters={k: v for k, v in p.items() if k != "analysis_id"})


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def incident_detail(incident_id: IncidentID, request: Request, analysis_id: AnalysisID):
    params(request)
    incident = query(request).get(analysis_id, "incidents", incident_id)
    return {"analysis_id": analysis_id, "incident": incident,
            "entities": query(request).by_ids(analysis_id, "entities", incident.entity_ids),
            "chain_status": query(request).chain(analysis_id, incident_id).status}


@router.get("/incidents/{incident_id}/chain", response_model=ChainDetail)
def chain_detail(incident_id: IncidentID, request: Request, analysis_id: AnalysisID):
    params(request)
    return {"analysis_id": analysis_id, "chain": query(request).chain(analysis_id, incident_id),
            "diagnostics_ref": f"outputs/analyses/{analysis_id}/diagnostics.jsonl"}


@router.get("/incidents/{incident_id}/timeline", response_model=Page[TimelineItem])
def timeline(incident_id: IncidentID, request: Request, analysis_id: AnalysisID, page: int = Query(1, ge=1),
             page_size: int = Query(20, ge=1, le=100), start_time: str | None = None, end_time: str | None = None):
    p = params(request, {"start_time", "end_time"}, paginated=True)
    result = query(request).timeline(analysis_id, incident_id, page=p["page"], page_size=p["page_size"],
                                     start_time=p.get("start_time"), end_time=p.get("end_time"))
    for item in result["items"]:
        item["source_type"] = SourceType(item["source_type"])
    return result


@router.get("/edges/{edge_id}", response_model=EdgeDetail)
def edge_detail(edge_id: ChainEdgeID, request: Request, analysis_id: AnalysisID):
    params(request)
    edge, correlations = query(request).edge(analysis_id, edge_id)
    return {"analysis_id": analysis_id, "edge": edge, "correlation_edges": correlations}


@router.post("/incidents/{incident_id}/explain", response_model=GroundedExplanation,
             responses={409: {"model": GroundedExplanation | APIError}})
def explain(incident_id: IncidentID, request: Request, analysis_id: AnalysisID, body: ExplainRequest | None = None):
    params(request)
    return explain_incident(request, analysis_id, incident_id)


@router.get("/evaluation/runs/{run_id}", response_model=EvaluationSummaryExport)
def evaluation(run_id: str, request: Request, analysis_id: AnalysisID):
    params(request)
    return query(request).evaluation(analysis_id, run_id)

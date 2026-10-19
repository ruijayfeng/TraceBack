"""Existing Explain endpoint implementation; no new route or algorithm writes."""

from threading import Lock

from fastapi.responses import JSONResponse

from app.ai.explanation import ExplanationService, load_context
from app.ai.provider import load_provider_config
from app.ai.providers.openai_compatible import OpenAICompatibleProvider


_initialization_lock = Lock()


def service_for(app):
    with _initialization_lock:
        if not hasattr(app.state, "explanations"):
            try:
                config = load_provider_config()
                provider = OpenAICompatibleProvider(config) if config.configured else None
                app.state.explanations = ExplanationService(provider)
            except (ValueError, OSError):
                app.state.explanations = ExplanationService(unavailable_reason="provider_configuration_invalid")
        return app.state.explanations


def explain_incident(request, analysis_id, incident_id):
    context = load_context(request.app.state.queries, analysis_id, incident_id)
    result = service_for(request.app).explain(context)
    if result.status != "available":
        # Keep the established 409 contract while returning a separately
        # validated deterministic report. Draft prose/credentials never leave.
        return JSONResponse(status_code=409, content=result.model_dump(mode="json"))
    return result

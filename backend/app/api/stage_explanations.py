"""Opt-in AI sidecar routes for official final Chains, never pipeline hooks."""
from threading import Lock

from fastapi import APIRouter, HTTPException, Request

from app.ai.provider import load_provider_config
from app.ai.providers.openai_compatible import OpenAICompatibleProvider
from app.ai.stage_context import build_stage_context
from app.ai.stage_explanation import StageExplanationService, StageReportStore
from app.models.base import AnalysisID
from app.evidence_trace.snapshot import file_sha256
from app.services.queries import QueryError

_lock = Lock()


def install_stage_explanations(app, root, workbench):
    router = APIRouter(prefix='/api/v1/stage-analyses')
    store = StageReportStore(root)

    def context_for(analysis_id, chain_id, request):
        if request.query_params:
            raise HTTPException(400, 'unknown_query_parameter')
        if not workbench.is_stage9(analysis_id):
            raise QueryError(404, 'stage_ai_requires_official_chain')
        try:
            return build_stage_context(workbench.reader_for(analysis_id), chain_id)
        except LookupError:
            raise QueryError(404, 'stage_chain_not_found') from None
        except (OSError, ValueError, KeyError, TypeError):
            raise QueryError(409, 'stage_ai_evidence_unavailable') from None

    def service():
        with _lock:
            if not hasattr(app.state, 'stage_explanations'):
                try:
                    cfg = load_provider_config(root / 'configs/llm.yaml')
                    provider = OpenAICompatibleProvider(cfg) if cfg.configured else None
                except (OSError, ValueError):
                    provider = None
                app.state.stage_explanations = StageExplanationService(provider)
            return app.state.stage_explanations

    @router.get('/{analysis_id}/chains/{chain_id}/ai-evidence')
    def evidence(analysis_id: AnalysisID, chain_id: str, request: Request):
        ctx = context_for(analysis_id, chain_id, request)
        return dict(analysis_id=analysis_id, input_digest=ctx.input_digest, evidence_package=ctx.model_data)

    @router.post('/{analysis_id}/chains/{chain_id}/explain')
    def explain(analysis_id: AnalysisID, chain_id: str, request: Request):
        ctx = context_for(analysis_id, chain_id, request)
        result = service().explain(ctx)
        try:
            unchanged = all(file_sha256(path) == digest for path, digest in ctx.data['artifact_sha256'].items())
        except OSError:
            unchanged = False
        if not unchanged:
            result = dict(result, status='unavailable', grounding_status='rejected',
                detail='AI 辅助研判暂不可用', report_json=None, report_markdown=None,
                generation_status='grounding_rejected', validation_errors=['ai_source_changed'])
        try:
            store.save(ctx, result)
        except OSError:
            # Storage failure does not invalidate a grounded in-memory report.
            result = dict(result, persistence_status='unavailable')
        return dict(analysis_id=analysis_id, **result)

    @router.get('/{analysis_id}/chains/{chain_id}/explanation')
    def saved(analysis_id: AnalysisID, chain_id: str, request: Request):
        ctx = context_for(analysis_id, chain_id, request)
        result = store.read(ctx)
        return dict(analysis_id=analysis_id, chain_id=chain_id,
                    result=dict(analysis_id=analysis_id, **result) if result else None)

    app.include_router(router)

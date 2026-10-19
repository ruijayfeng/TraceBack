"""FastAPI startup and server-side reference registries; no algorithm logic."""

from contextlib import asynccontextmanager
import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.adapters.base import AdapterSettings
from app.api.routes import router
from app.config import load_config
from app.services.analysis import AnalysisService
from app.services.queries import QueryError, QueryService
from app.utils.stable_id import content_digest


ROOT = Path(__file__).resolve().parents[2]


def create_app(root=None, *, configs=None, sources=None, allowed_files=None, progress=None):
    root = Path(root or ROOT).resolve()
    if configs is None:
        configs = {"v0": load_config(root / "configs/algorithm-v0.yaml", deployment_override=root / "configs/sources.yaml")}
        if (root / "configs/algorithm-v2.yaml").is_file():
            configs["v2"] = load_config(root / "configs/algorithm-v2.yaml", deployment_override=root / "configs/sources.yaml")
        if (root / 'configs/algorithm-v5.yaml').is_file():
            configs['v5'] = load_config(root / 'configs/algorithm-v5.yaml', deployment_override=root / 'configs/sources.yaml')
        if (root / 'configs/algorithm-v4.yaml').is_file():
            configs['v4'] = load_config(root / 'configs/algorithm-v4.yaml', deployment_override=root / 'configs/sources.yaml')
    if sources is None:
        if (root / "configs/algorithm-v3.yaml").is_file():
            configs["v3"] = load_config(root / "configs/algorithm-v3.yaml", deployment_override=root / "configs/sources.yaml")
        # Reuse confirmed source declarations from matching historical snapshots.
        # New deployments supply this registry through create_app. No namespace,
        # timezone, adapter version or dataset filename is guessed from a name.
        sources = {}
        for path in sorted((root / "outputs/analyses").glob("ana_*/manifest.json")):
            manifest = json.loads(path.read_text(encoding="utf-8"))
            snapshot = manifest.get("config_snapshot", {})
            if (snapshot.get("algorithm") not in [c.snapshot for c in configs.values()] or
                    content_digest(snapshot) != manifest.get("config_hash")):
                continue
            for namespace, data in snapshot["sources"].items():
                setting = AdapterSettings(**data)
                source = setting.generator.lower()
                if source not in {"wazuh", "aminer"}:
                    continue
                if namespace != setting.source_namespace or (namespace in sources and sources[namespace] != (source, setting)):
                    raise ValueError("conflicting_confirmed_source_registry")
                sources[namespace] = (source, setting)
    if allowed_files is None:
        allowed_files = ()  # Standard data/input/alerts; extra exact files require server registration.
    service = AnalysisService(root, configs=configs, sources=sources, allowed_files=allowed_files, progress=progress)

    @asynccontextmanager
    async def lifespan(app):
        service.fail_interrupted_runs()
        yield
        service.close()

    app = FastAPI(title="TraceBack", version="1.0", lifespan=lifespan)
    app.state.analyses, app.state.queries = service, QueryService(root)

    @app.exception_handler(QueryError)
    async def query_error(request: Request, exc: QueryError):
        return JSONResponse(status_code=exc.status, content={"detail": exc.code})

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Error responses do not echo submitted raw/GT values.
        errors = exc.errors()
        query_errors = [e for e in errors if e["loc"][0] == "query"]
        invalid_filters = query_errors and all(e["loc"][1] not in {"analysis_id"} for e in query_errors)
        return JSONResponse(status_code=400 if invalid_filters else 422,
                            content={"detail": "invalid_query_parameter" if invalid_filters else "invalid_request_schema"})

    app.include_router(router)
    return app


app = create_app()

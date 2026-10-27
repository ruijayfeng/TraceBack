"""File upload transport and durable task queries; no server path inputs."""
from contextlib import asynccontextmanager
import secrets
from urllib.parse import unquote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool

from app.services.stage_runs import MAX_UPLOAD_BYTES


class StartRun(BaseModel):
    model_config = ConfigDict(extra='forbid')
    upload_id: str


def install_stage_runs(app, service):
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        async with original_lifespan(application):
            service.recover()
            try:
                yield
            finally:
                service.close()

    app.router.lifespan_context = lifespan
    app.state.stage_runs = service
    router = APIRouter(prefix='/api/v1/stage-runs')

    @router.post('/uploads', status_code=201)
    async def upload(request: Request):
        # Raw File body avoids a second multipart parser/dependency; the client
        # supplies the display name only. It is never used as a filesystem path.
        filename = unquote(request.headers.get('x-file-name', ''))
        if not filename or len(filename) > 255 or any(ord(c) < 32 for c in filename) or not filename.lower().endswith('.jsonl'):
            raise HTTPException(415, 'only_native_jsonl_supported')
        upload_id = secrets.token_hex(32)
        directory = service.upload_directory(upload_id)
        directory.mkdir(parents=True, exist_ok=False)
        path = directory / 'alerts.jsonl'
        size = 0
        try:
            with path.open('xb') as stream:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise HTTPException(413, 'stage_upload_too_large')
                    stream.write(chunk)
            return await run_in_threadpool(service.register_upload, upload_id, filename)
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    @router.post('', status_code=202)
    def start(body: StartRun):
        return service.create(body.upload_id)

    @router.get('')
    def history():
        return dict(items=service.history())

    @router.get('/uploads/{upload_id}/errors')
    def errors(upload_id: str):
        import json
        try:
            value = json.loads((service.upload_directory(upload_id) / 'upload.json').read_text(encoding='utf8'))
        except FileNotFoundError:
            raise HTTPException(404, 'stage_upload_not_found') from None
        return JSONResponse(value['validation'], headers={'Content-Disposition': 'attachment; filename="validation-errors.json"'})

    @router.get('/{run_id}')
    def status(run_id: str):
        return service.status(run_id)

    @router.get('/{run_id}/log')
    def log(run_id: str):
        service.read(run_id)
        path = service.directory(run_id) / 'run.log'
        if not path.is_file():
            raise HTTPException(404, 'stage_run_log_not_created')
        return FileResponse(path, media_type='text/plain; charset=utf-8', filename='run.log')

    app.include_router(router)

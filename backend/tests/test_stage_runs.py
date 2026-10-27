"""Upload → actual formal CLI → registered results; isolated from sealed data."""
import json
from pathlib import Path
import sys
import threading
import time
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
import pytest

from app.api.stage_workbench import install_stage_workbench
from app.services.queries import QueryError
from app.services.stage_runs import StageRunService
from test_stage9_pipeline import cli, native


@pytest.fixture
def api(tmp_path):
    app = FastAPI()
    @app.exception_handler(QueryError)
    async def error(request: Request, exc: QueryError):
        return JSONResponse(status_code=exc.status, content={'detail': exc.code})
    install_stage_workbench(app, tmp_path)
    with TestClient(app) as client:
        yield client, app.state.stage_runs, tmp_path


def upload(client, body, name='alerts.jsonl'):
    return client.post('/api/v1/stage-runs/uploads', content=body,
                       headers={'x-file-name': quote(name), 'content-type': 'application/octet-stream'})


def start(client, body, name='alerts.jsonl'):
    response = upload(client, body, name)
    assert response.status_code == 201, response.text
    assert response.json()['validation']['status'] == 'VALID', response.text
    response = client.post('/api/v1/stage-runs', json={'upload_id': response.json()['upload_id']})
    assert response.status_code == 202, response.text
    return response.json()


def finish(client, run_id):
    deadline = time.monotonic()+30
    states = set()
    while time.monotonic() < deadline:
        response = client.get('/api/v1/stage-runs/'+run_id)
        assert response.status_code == 200, response.text
        record = response.json()
        states.add(record['status'])
        if record['status'] in {'SUCCEEDED','FAILED'}:
            return record, states
        time.sleep(.05)
    pytest.fail('real CLI did not finish within 30 seconds')


def test_upload_native_contract_and_precise_error_download(api):
    client, service, root = api
    body = native(root).read_bytes()
    good = upload(client, body, '../../上传.jsonl').json()
    assert good['filename'] == '../../上传.jsonl'
    assert good['validation'] == dict(status='VALID',total_count=3,valid_count=3,invalid_count=0,errors=[])
    assert (service.upload_directory(good['upload_id'])/'alerts.jsonl').read_bytes() == body
    cases = [b'', b'\n', b'[]\n', b'{broken}\n', b'\xff\n', b'{}\n',
             b'{"source_type":"edr"}\n', b'{"source_type":"edr","event":[] }\n',
             json.dumps(dict(source_type='edr',event={'source_type':'edr'})).encode()+b'\n',
             json.dumps(dict(source_type='edr',event={'source_type':'edr','timestamp':123})).encode()+b'\n',
             json.dumps(dict(source_type='edr',event={'source_type':'edr','timestamp':'2026-01-01T00:00:00Z','process_id':[]})).encode()+b'\n',
             body.splitlines()[0]+b'\n{}\n', body.splitlines()[0]+b'\n'+body.splitlines()[0]+b'\n']
    for content in cases:
        response = upload(client, content)
        assert response.status_code == 201
        result = response.json()
        assert result['validation']['status'] == 'INVALID'
        assert result['validation']['errors']
        assert client.post('/api/v1/stage-runs',json={'upload_id':result['upload_id']}).status_code == 422
        assert client.get('/api/v1/stage-runs/uploads/'+result['upload_id']+'/errors').json() == result['validation']
    mixed = upload(client, body.splitlines()[0]+b'\n{}\n').json()['validation']
    assert (mixed['total_count'],mixed['valid_count'],mixed['invalid_count']) == (2,1,1)
    assert mixed['errors'][0]['line'] == 2 and mixed['errors'][0]['field'] == 'source_type'
    assert upload(client, body, 'alerts.json').status_code == 415
    assert client.post('/api/v1/stage-runs',json={'upload_id':'../outside'}).status_code == 404
    assert client.post('/api/v1/stage-runs',json={'upload_id':good['upload_id'],'path':'outside'}).status_code == 422


def test_upload_limit_enforced_on_actual_body(api, monkeypatch):
    import app.api.stage_runs as transport
    client, _, _ = api
    monkeypatch.setattr(transport, 'MAX_UPLOAD_BYTES', 10)
    assert upload(client,b'x'*11).status_code == 413


def test_http_returns_before_background_finishes(api, monkeypatch):
    client, service, root = api
    gate = threading.Event()
    original = service.execute
    monkeypatch.setattr(service,'execute',lambda run_id: (gate.wait(5),original(run_id)))
    started = time.monotonic()
    try:
        run = start(client,native(root).read_bytes())
        assert time.monotonic()-started < 2
        assert client.get('/api/v1/stage-runs/'+run['run_id']).json()['status'] == 'QUEUED'
    finally:
        gate.set()
    assert finish(client,run['run_id'])[0]['status'] == 'SUCCEEDED'


def test_two_real_cli_runs_have_separate_results_and_durable_history(api):
    client, service, root = api
    body = native(root).read_bytes()
    a = start(client,body,'a.jsonl')
    b = start(client,b'\n'.join(body.splitlines()[:2])+b'\n','b.jsonl')
    a, states = finish(client,a['run_id'])
    b, _ = finish(client,b['run_id'])
    assert a['status'] == b['status'] == 'SUCCEEDED', (a,b)
    assert a['run_id'] != b['run_id'] and a['output_path'] != b['output_path']
    assert a['exit_code'] == b['exit_code'] == 0
    assert a['duration_seconds'] > 0 and b['duration_seconds'] > 0
    assert all(stage['status']=='COMPLETED' for stage in a['stages'])
    assert '@@TRACEBACK_PROGRESS' in a['recent_log']
    assert a['command'][0] == sys.executable
    for record, count in [(a,3),(b,2),(a,3)]:
        base = '/api/v1/stage-analyses/'+record['run_id']
        result = client.get(base)
        assert result.status_code == 200,result.text
        result = result.json()
        assert result['analysis_id'] == record['run_id']
        assert result['counts']['input_count'] == count
        assert result['data_source'] == record['output_path']
        summary = client.get(base+'/summary').json()
        assert summary['analysis_id'] == record['run_id']
        assert summary['summary']['counts']['input_count'] == count
        sid = result['stages'][0]['stage_id']
        assert client.get(base+'/traces/'+sid).json()['analysis_id'] == record['run_id']
        aid = result['stages'][0]['alert_ids'][0]
        assert client.get(base+'/alerts/'+aid).status_code == 200
    reopened = StageRunService(root)
    try:
        reopened.recover()
        assert {r['run_id'] for r in reopened.history()} == {a['run_id'],b['run_id']}
    finally:
        reopened.close()
    # Tamper one completed artifact: every read endpoint must fail for A;
    # no endpoint may switch to B or to a sealed baseline.
    (Path(a['output_path'])/'stage9.json').write_text('{}',encoding='utf8')
    for suffix in ['', '/summary','/traces/stg_x','/alerts/alt_'+'0'*64]:
        assert client.get('/api/v1/stage-analyses/'+a['run_id']+suffix).status_code == 409
    assert client.get('/api/v1/stage-runs/'+a['run_id']).json()['result_available'] is False
    assert client.get('/api/v1/stage-analyses/'+b['run_id']).status_code == 200
    Path(b['input_path']).unlink()
    catalog = client.get('/api/v1/stage-analyses')
    assert catalog.status_code == 200
    assert all(item['result_available'] is False for item in catalog.json()['items'])


@pytest.mark.parametrize('mode',['exit','empty','timeout'])
def test_cli_failure_exit_missing_artifacts_and_timeout(api, monkeypatch, mode):
    client, service, root = api
    program = {'exit':"import sys; print('actual test stderr',file=sys.stderr); sys.exit(7)",
               'empty':"print('zero exit but no artifacts')",
               'timeout':"import time; print('started',flush=True); time.sleep(30)"}[mode]
    monkeypatch.setattr(service,'command',lambda record:[sys.executable,'-u','-c',program])
    if mode=='timeout':
        service.timeout_seconds=.1
    record = start(client,native(root).read_bytes())
    result,_ = finish(client,record['run_id'])
    assert result['status']=='FAILED' and result['result_available'] is False
    assert result['failure_reason'] and result['failed_stage']
    assert client.get('/api/v1/stage-analyses/'+record['run_id']).status_code==409
    assert client.get('/api/v1/stage-runs/'+record['run_id']+'/log').status_code==200
    if mode=='exit':
        assert result['exit_code']==7 and 'actual test stderr' in result['recent_log']
    if mode=='empty':
        assert result['exit_code']==0 and 'receipt.json' in result['failure_reason']
    if mode=='timeout':
        assert 'timeout' in result['failure_reason'] and result['exit_code'] is not None


def test_input_changed_after_upload_is_not_executed(api):
    client, service, root = api
    result = upload(client,native(root).read_bytes()).json()
    (service.upload_directory(result['upload_id'])/'alerts.jsonl').write_text('{}\n',encoding='utf8')
    assert client.post('/api/v1/stage-runs',json={'upload_id':result['upload_id']}).status_code==409


def test_interrupted_owner_is_failed_on_restart(api, monkeypatch):
    from app.services.storage import atomic_json
    client, service, root = api
    gate = threading.Event()
    monkeypatch.setattr(service,'execute',lambda run_id:gate.wait(2))
    record = start(client,native(root).read_bytes())
    record['owner_pid'] = -1
    atomic_json(service.directory(record['run_id'])/'run.json',record)
    reopened=StageRunService(root)
    try:
        reopened.recover()
        recovered=reopened.read(record['run_id'])
        assert recovered['status']=='FAILED'
        assert 'interrupted' in recovered['failure_reason']
    finally:
        reopened.close();gate.set()


def test_observation_callbacks_preserve_all_formal_outputs(tmp_path):
    path = native(tmp_path)
    events=[]
    before = cli().execute(path,output=tmp_path/'without')
    after = cli().execute(path,output=tmp_path/'with',progress=events.append)
    for name in ('stage8.json','stage9.json','receipt.json'):
        assert (tmp_path/'without'/name).read_bytes()==(tmp_path/'with'/name).read_bytes()
    assert [(e['stage'],e['status']) for e in events]==[(i,status) for i in range(1,10) for status in ('RUNNING','COMPLETED')]
    assert before.statistics==after.statistics

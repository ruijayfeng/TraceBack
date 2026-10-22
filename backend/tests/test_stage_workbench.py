"""Sealed Stage chains are browsable without rerunning production algorithms."""
import json
import sys

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.api.stage_workbench import install_stage_workbench
from app.services.queries import QueryError
from test_stage_attack_chains import pair, cfg, normalization, write_sealed_sources, ROOT


@pytest.fixture
def stage_api(pair, tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'scripts'))
    import run_attack_chain_reconstruction as runner
    monkeypatch.setattr(runner, 'ROOT', tmp_path)
    relations, evidence = write_sealed_sources(tmp_path, pair)
    output = tmp_path / 'outputs/assembled'
    runner.execute(relations, evidence, output)
    aid = json.loads((output / 'manifest.json').read_text())['analysis_id']
    app = FastAPI()

    @app.exception_handler(QueryError)
    async def error(request: Request, exc: QueryError):
        return JSONResponse(status_code=exc.status, content={'detail': exc.code})

    install_stage_workbench(app, tmp_path)
    with TestClient(app) as client:
        yield client, app, aid, pair, tmp_path


def test_catalog_graph_trace_raw_and_scope_without_algorithm_replay(stage_api, monkeypatch):
    client, app, aid, graph, root = stage_api
    import app.stage_chains.assembly as assembly
    import app.stage_relations.analysis as analysis

    def forbidden(*args, **kwargs):
        raise AssertionError('read endpoint must not run production algorithms')

    monkeypatch.setattr(assembly, 'assemble_attack_chains', forbidden)
    monkeypatch.setattr(analysis, 'analyze_stage_relations', forbidden)
    assert client.get('/api/v1/stage-analyses').json()['default_analysis_id'] == aid
    response = client.get('/api/v1/stage-analyses/' + aid)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['counts']['input_count'] == 2
    assert body['counts']['stage_count'] == 2
    assert body['counts']['chain_count'] == body['counts']['relation_count'] == 1
    assert 'raw_alert' not in response.text
    relation, = graph.relations.values()
    assert body['relations'][0]['relation_type'] == relation.relation_type
    assert body['relations'][0]['from_stage_id'] == relation.from_stage_id
    base = '/api/v1/stage-analyses/' + aid
    trace = client.get(base + '/traces/' + relation.relation_id).json()
    assert trace['trace']['direction_basis'] == relation.direction_basis
    assert trace['resolved_pointers']
    assert trace['trace']['winning_witness_alert_ids'] == relation.primary_evidence.alert_ids
    ref = graph.traces[relation.relation_id].raw_evidence_refs[0]
    raw = client.get(base + '/alerts/' + ref.alert_id)
    assert raw.status_code == 200
    assert raw.json()['raw_alert'] == graph.trace_index.raw_evidence(ref)
    assert client.get(base + '/alerts/alt_' + '0'*64).status_code == 404
    assert client.get(base + '/traces/stg_' + '0'*64).status_code == 404
    assert client.get('/api/v1/stage-analyses/ana_' + '0'*64).status_code == 404
    assert client.get(base + '?labels=forbidden').status_code == 400


def test_cached_source_tamper_is_rejected_and_never_served(stage_api):
    client, app, aid, graph, root = stage_api
    base = '/api/v1/stage-analyses/' + aid
    assert client.get(base).status_code == 200
    path = root / 'data/processed' / aid / 'stage_attack_chains.jsonl'
    path.write_text(path.read_text() + '\n', encoding='utf8')
    for _ in range(2):
        response = client.get(base)
        assert response.status_code == 409
        assert response.json()['detail'] == 'stage_snapshot_integrity_error'


def test_source_paths_cannot_escape_into_truth(stage_api):
    client, app, aid, graph, root = stage_api
    path = root / 'outputs/analyses' / aid / 'manifest.json'
    manifest = json.loads(path.read_text())
    manifest['artifacts']['outputs/ground_truth.json'] = '0'*64
    path.write_text(json.dumps(manifest), encoding='utf8')
    assert client.get('/api/v1/stage-analyses/' + aid).status_code == 409


def test_empty_catalog_does_not_select_legacy_snapshot(tmp_path):
    from app.api.stage_workbench import StageWorkbench
    assert StageWorkbench(tmp_path).catalog() == {'items': [], 'default_analysis_id': None}


def test_official_stage9_summary_is_read_only_aggregation():
    """The overview summary aggregates sealed alerts only; totals must equal
    the official ATTACK125 input count, and no algorithm is re-run."""
    from app.api.stage_workbench import STAGE9_ANALYSIS_ID, StageWorkbench
    service = StageWorkbench(ROOT)
    # If the official artifact is present, verify the summary projection.
    if not (ROOT / 'outputs/stage9_formal_acceptance_20261022/run1/stage9.json').is_file():
        pytest.skip('official stage9 artifact not present')
    summary = service.stage9_reader().summary()
    assert summary['counts']['input_count'] == 125
    assert summary['counts']['stage_count'] == 15
    assert sum(b['count'] for b in summary['time_series']) == 125
    assert sum(r['count'] for r in summary['source_namespace']) == 125
    # Six device namespaces are projected for the multi-source distribution.
    assert len(summary['source_namespace']) == 6
    assert STAGE9_ANALYSIS_ID.startswith('ana_')

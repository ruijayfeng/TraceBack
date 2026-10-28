"""Read-time integrity and input/retained count regressions for real CLI output."""
from hashlib import sha256
import json

import pytest

from app.api.stage_workbench import STAGE9_ARTIFACT, STAGE9_ANALYSIS_ID
from app.stage_chains.stage9_reader import Stage9ArtifactReader
from test_stage9_pipeline import cli, native
from test_stage_runs import api, finish, start
from test_community_builder import record


def write_json(path, value):
    path.write_text(json.dumps(value), encoding='utf8')


@pytest.fixture
def sealed(tmp_path):
    output = tmp_path / STAGE9_ARTIFACT
    path = native(tmp_path)
    path.write_text(''.join(json.dumps(dict(source_type='edr', event=record(
        i+1, time=i*300, hostname='h', session_id='s', operation='ProcessStart')))+'\n'
        for i in range(2)), encoding='utf8')
    run = cli().execute(path, output=output)
    assert len(run.graph.relations) == 1
    manifest = output.parent / 'artifact_manifest.json'
    def seal():
        write_json(manifest, {f'run1\\{name}': sha256((output/name).read_bytes()).hexdigest()
                              for name in ('stage8.json', 'stage9.json', 'receipt.json')})
    seal()
    return tmp_path, output, seal


@pytest.mark.parametrize('name', ['stage8.json', 'stage9.json', 'receipt.json'])
def test_sealed_hashes_reject_changed_bytes(sealed, name):
    root, output, _ = sealed
    with (output/name).open('a', encoding='utf8') as stream:
        stream.write(' ')
    with pytest.raises(ValueError, match='hash_mismatch'):
        Stage9ArtifactReader(root, output).load()


@pytest.mark.parametrize('mutation,reason', [
    ('digest', 'input_digest_mismatch'),
    ('missing', 'stage_partition_mismatch'),
    ('duplicate', 'stage_partition_mismatch'),
    ('missing_relation', 'relation_partition_mismatch'),
])
def test_graph_closure_is_checked_without_reconstruction(sealed, monkeypatch, mutation, reason):
    root, output, seal = sealed
    stage9 = json.loads((output/'stage9.json').read_text(encoding='utf8'))
    if mutation == 'digest':
        stage9['input_digest'] = 'f'*64
    elif mutation == 'missing':
        stage9['chains'].pop()
    elif mutation == 'duplicate':
        stage9['chains'].append(stage9['chains'][0])
    else:
        from app.stage_chains.reconstruction import VERSION
        from app.utils.stable_id import content_digest
        chain = stage9['chains'][0]
        chain['relation_ids'] = []
        chain['chain_id'] = 'sch_' + content_digest(dict(
            version=VERSION, stage_ids=chain['stage_ids'], relation_ids=[]))
    write_json(output/'stage9.json', stage9)
    receipt = json.loads((output/'receipt.json').read_text(encoding='utf8'))
    receipt['stage9_sha256'] = sha256((output/'stage9.json').read_bytes()).hexdigest()
    write_json(output/'receipt.json', receipt)
    seal()
    def forbidden(*args, **kwargs):
        pytest.fail('reader must not reconstruct chains')
    monkeypatch.setattr('app.stage_chains.reconstruction.reconstruct_attack_chains', forbidden)
    with pytest.raises(ValueError, match=reason):
        Stage9ArtifactReader(root, output).load()


def test_unsealed_task_output_still_checks_receipt_hashes(sealed):
    root, output, _ = sealed
    (output.parent/'artifact_manifest.json').unlink()
    with (output/'stage8.json').open('a') as stream:
        stream.write(' ')
    with pytest.raises(ValueError, match='receipt_hash_mismatch'):
        Stage9ArtifactReader(root, output).load()


def test_corrupt_baseline_fails_closed_on_all_result_routes(api):
    client, _, root = api
    output = root / STAGE9_ARTIFACT
    run = cli().execute(native(root), output=output)
    write_json(output.parent/'artifact_manifest.json', {
        f'run1/{name}': sha256((output/name).read_bytes()).hexdigest()
        for name in ('stage8.json', 'stage9.json', 'receipt.json')})
    with (output/'stage9.json').open('a') as stream:
        stream.write(' ')
    stage_id = next(iter(run.graph.stages))
    alert_id = next(iter(run.graph.alerts))
    for suffix in ('', '/summary', '/traces/'+stage_id, '/alerts/'+alert_id):
        response = client.get('/api/v1/stage-analyses/'+STAGE9_ANALYSIS_ID+suffix)
        assert response.status_code == 409, response.text
    assert client.get('/api/v1/stage-analyses').json()['default_analysis_id'] is None


def test_missing_formal_manifest_is_unavailable(sealed):
    from app.api.stage_workbench import StageWorkbench
    from app.services.queries import QueryError
    root, output, _ = sealed
    (output.parent/'artifact_manifest.json').unlink()
    with pytest.raises(QueryError) as error:
        StageWorkbench(root).overview(STAGE9_ANALYSIS_ID)
    assert error.value.status == 409


def test_input_and_retained_counts_after_real_noise_filtering(api):
    client, _, root = api
    body = ''.join(json.dumps(dict(source_type='edr', event=record(
        1, time=i, hostname='h', operation='ProcessStart')))+'\n' for i in range(2)).encode()
    task = start(client, body)
    task, _ = finish(client, task['run_id'])
    assert task['status'] == 'SUCCEEDED', task
    assert task['input_count'] == 2
    url = '/api/v1/stage-analyses/'+task['run_id']
    assert client.get(url).json()['counts']['input_count'] == 2
    summary = client.get(url+'/summary').json()['summary']
    assert summary['counts']['input_count'] == 2
    assert summary['counts']['kept_count'] == 1
    assert sum(bucket['count'] for bucket in summary['time_series']) == 1

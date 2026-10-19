"""Synthetic fault injections; no synthetic progression counted as real GT."""
import builtins
import json
import os
from pathlib import Path
import subprocess

import pytest

from evaluation.framework.v5_truth_guard import reject_truth_fields, truth_guard


@pytest.mark.parametrize('reader', [lambda p: p.read_text(), lambda p: builtins.open(p).read(),
                                   lambda p: os.open(p, os.O_RDONLY)])
@pytest.mark.parametrize('name', ['truth_progressions.json', 'labels.csv', 'campaign_id.json', 'scenario_stage.json'])
def test_truth_reads_fail_during_replay_then_work_after_completion(tmp_path, reader, name):
    truth = tmp_path / name
    truth.write_text('{"synthetic":true}')
    alerts = tmp_path / 'alerts.json'
    alerts.write_text('[]')
    with truth_guard(data_files=[alerts]) as events:
        assert alerts.read_text() == '[]'
        with pytest.raises(PermissionError):
            reader(truth)
    assert events and events[-1]['rejected']
    assert json.loads(truth.read_text()) == {'synthetic':True}


@pytest.mark.parametrize('key', ['truth_progression_id', 'true_edges', 'attack_stage',
    'scenario_step', 'scenario_stage', 'known_campaign_id', 'campaign_id',
    'expected_predecessor', 'expected_successor', 'manual_relation', 'ground_truth_label',
    'time_label', 'event_label'])
def test_nested_truth_features_rejected(key):
    with pytest.raises(PermissionError):
        reject_truth_fields({'raw_alert':{'nested':[{'innocent':1}, {key:'synthetic'}]}})


def test_detector_metadata_is_allowed():
    reject_truth_fields({'category':'web_attack','alert':{'signature':'synthetic attack',
                        'signature_id':1}, 'timestamp':'2026-01-01T00:00:00Z'})


def test_preopened_descriptor_and_child_process_are_rejected(tmp_path):
    path = tmp_path / 'truth.json'
    path.write_text('synthetic')
    descriptor = os.open(path, os.O_RDONLY)
    try:
        with truth_guard(data_files=[]):
            with pytest.raises(PermissionError):
                os.fdopen(descriptor, closefd=False)
            with pytest.raises(PermissionError):
                subprocess.run(['echo', 'synthetic'])
    finally:
        os.close(descriptor)


def test_writes_cannot_be_used_to_read_truth(tmp_path):
    output = tmp_path / 'output'
    output.mkdir()
    truth = tmp_path / 'truth.json'
    truth.write_text('synthetic')
    with truth_guard(data_files=[], write_root=output):
        (output / 'result.json').write_text('{}')
        with pytest.raises(PermissionError):
            truth.open('r+')
        with pytest.raises(PermissionError):
            (output / 'result.json').read_text()


def test_code_root_does_not_authorize_truth_json(tmp_path):
    (tmp_path / 'module.py').write_text('# synthetic')
    (tmp_path / 'truth.json').write_text('{}')
    with truth_guard(data_files=[], code_roots=[tmp_path]):
        assert 'synthetic' in (tmp_path / 'module.py').read_text()
        with pytest.raises(PermissionError):
            (tmp_path / 'truth.json').read_text()


def test_no_witness_artifacts_do_not_claim_replay_or_zero_recall(tmp_path, monkeypatch):
    from evaluation.framework import v5_ground_truth_replay as module
    monkeypatch.setattr(module, 'OUT', tmp_path)
    (tmp_path / 'ground_truth_sources.json').write_text('{"sources":[]}')
    module.write_insufficient([], {'alert_count':10000})
    for filename in ['candidate_recall.json','admission_recall.json']:
        value=json.loads((tmp_path / filename).read_text())
        assert value['value'] is None and value['denominator']==0
        assert value['metric_status']=='not_applicable'
    assert not json.loads((tmp_path / 'summary.json').read_text())['replay_completed']
    assert json.loads((tmp_path / 'failure_taxonomy.json').read_text())['primary_failure_point'] is None
    assert (tmp_path / 'true_edge_reachability.jsonl').read_text()==''


def test_new_truth_readers_have_no_production_import_path():
    import ast
    root=Path(__file__).resolve().parents[2]
    for path in (root/'backend/app').rglob('*.py'):
        tree=ast.parse(path.read_text(encoding='utf8'))
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                assert all(not x.name.startswith('evaluation') for x in node.names)
            if isinstance(node,ast.ImportFrom) and node.module:
                assert not node.module.startswith('evaluation')

"""Evaluator cannot load negative memberships before production is sealed."""
import gzip
import hashlib
import json
from pathlib import Path

import pytest

import evaluation.front_data_check as checker


def test_unsealed_prediction_rejected_before_membership_read(tmp_path):
    output=tmp_path/'out';output.mkdir()
    (output/'manifest.json').write_text(json.dumps({'summary':{'status':'FAIL'}}),encoding='utf8')
    with pytest.raises(ValueError,match='sealed'):
        checker.observe(output,tmp_path/'does-not-exist.jsonl')


@pytest.mark.parametrize('channels,status', [(['IP'],'PASS'),(['URL'],'FAIL')])
def test_only_postseal_candidate_observation(tmp_path,monkeypatch,channels,status):
    monkeypatch.setattr(checker,'ROOT',tmp_path)
    output=tmp_path/'out';output.mkdir()
    domain=tmp_path/'data/processed/analysis';domain.mkdir(parents=True)
    candidates=domain/'front_candidates.jsonl.gz'
    with gzip.open(candidates,'wt',encoding='utf8') as f:
        f.write(json.dumps(dict(alert_ids=['a','b'],channels=channels))+'\n')
    source=tmp_path/'input.jsonl';source.write_text('{}\n')
    negatives=tmp_path/'negatives.jsonl';negatives.write_text('{"event_id":"negative"}\n')
    manifest=dict(summary={'status':'PASS'},analysis_id='analysis',input=str(source),input_sha256=checker.sha(source),
                  artifacts={str(candidates.relative_to(tmp_path)):checker.sha(candidates)})
    (output/'manifest.json').write_text(json.dumps(manifest),encoding='utf8')
    (output/'trace_map.json').write_text(json.dumps([dict(event_id='negative',alert_id='a')]),encoding='utf8')
    report=checker.observe(output,negatives)
    assert report['status']==status
    assert report['negative_alerts_retained']==1
    assert report['candidates_touching_negatives']==1
    assert report['ordinary_field_only_candidates']==int(channels==['URL'])

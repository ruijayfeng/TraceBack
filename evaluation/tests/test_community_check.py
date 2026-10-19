"""Post-seal membership metrics, denominators, input integrity and receipt checks."""
from pathlib import Path
import gzip
import json

import pytest

from evaluation.community_check import evaluate, sha, verify_seal


def save(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value),encoding='utf8')


@pytest.fixture
def sealed(tmp_path):
    output=tmp_path/'outputs/community'
    native=tmp_path/'input/native.jsonl'
    save(native,{'native':'unchanged'})
    save(output/'trace_map.json',[dict(event_id=x,alert_id=x) for x in ('attack','negative','background','unknown')])
    save(output/'implementation_receipt.json',{'config':'frozen'})
    domain=tmp_path/'data/processed/analysis'
    domain.mkdir(parents=True)
    communities=[dict(community_id='c1',alert_ids=['attack','negative','background'],member_count=3,matching_evidence=[]),
                 dict(community_id='c2',alert_ids=['unknown'],member_count=1,matching_evidence=[],
                      membership_decisions=[dict(reason='NO_ADMISSIBLE_CONTEXT')])]
    for name,rows in [('incident_candidates',communities),('community_alerts',[dict(alert_id=x) for x in ('attack','negative','background','unknown')])]:
        with gzip.open(domain/(name+'.jsonl.gz'),'wt',encoding='utf8') as f:
            for row in rows:
                f.write(json.dumps(row)+'\n')
    manifest=dict(status='sealed',contract_version='community-v1',analysis_id='analysis',
        input=str(native),input_sha256=sha(native),
        trace_map_sha256=sha(output/'trace_map.json'),implementation_receipt_sha256=sha(output/'implementation_receipt.json'),
        artifacts={p.relative_to(tmp_path).as_posix():sha(p) for p in domain.iterdir()})
    save(output/'manifest.json',manifest)
    attack=tmp_path/'evaluation/attack.json'
    negative=tmp_path/'evaluation/negative.json'
    bg=tmp_path/'evaluation/background'
    save(attack,dict(observations=[dict(alert_id='attack')]))
    save(negative,dict(observations=[dict(alert_id='negative',negative_reason='unrelated',related_alert_ids=['attack'])]))
    save(bg/'alerts.jsonl',dict(event_id='background'))
    return tmp_path,output,native,attack,negative,bg


def test_unique_contamination_counts_and_unlabelled_exclusion(sealed):
    root,output,_,attack,negative,bg=sealed
    r=evaluate(output,attack,negative,bg,root=root)
    assert r['TASK_RESULT']=='COMMUNITY_BUILDER_PARTIAL'
    assert r['HARD_NEGATIVE_FALSE_MERGE_COUNT']==1
    assert r['BACKGROUND_FALSE_MERGE_COUNT']==1
    assert r['HARD_NEGATIVE_RELATED_ALERT_FALSE_MERGE_COUNT']==1
    assert r['evaluation_coverage']==0.75
    assert r['labelled_counts']==dict(attack=1,hard_negative=1,background=1,unlabelled=1)
    assert r['BACKGROUND_TO_BACKGROUND_ERROR_RATE'] is None
    assert r['truth_input_sha256_unchanged']


@pytest.mark.parametrize('target',['trace_map.json','implementation_receipt.json'])
def test_trace_or_receipt_tamper_refused_before_truth_read(sealed,target):
    root,output,_,attack,negative,bg=sealed
    (output/target).write_text('tampered',encoding='utf8')
    attack.unlink()
    with pytest.raises(ValueError,match='receipt_or_trace_changed'):
        evaluate(output,attack,negative,bg,root=root)


def test_domain_tamper_refused(sealed):
    root,output,_,_,_,_=sealed
    (root/'data/processed/analysis/incident_candidates.jsonl.gz').write_bytes(b'bad')
    with pytest.raises(ValueError,match='sealed_artifact_changed'):
        verify_seal(output,root)


def test_input_changed_refused(sealed):
    root,output,native,_,_,_=sealed
    native.write_text('changed',encoding='utf8')
    with pytest.raises(ValueError,match='native_input_changed'):
        verify_seal(output,root)


def test_no_truth_overlap_or_background_inference(sealed):
    root,output,_,attack,negative,bg=sealed
    save(bg/'alerts.jsonl',dict(event_id='negative'))
    with pytest.raises(ValueError,match='classes_overlap'):
        evaluate(output,attack,negative,bg,root=root)


def test_unsealed_prediction_refused(sealed):
    root,output,_,_,_,_=sealed
    manifest=json.loads((output/'manifest.json').read_text())
    save(output/'manifest.json',{**manifest,'status':'running'})
    with pytest.raises(ValueError,match='sealed_first'):
        verify_seal(output,root)

from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""Diagnostic-only checks: production score fidelity, bounds, and source controls."""
import itertools
import json
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from cptc_diagnostic_12 import native_fixtures, all_pair_bound_search, frozen, OUT
from app.adapters.cptc import load_cptc_dataset
from app.adapters.suricata import SuricataAdapter
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.entities.extraction import extract_entities
from app.models import ScoreBreakdown


@pytest.fixture(scope='module')
def controls():
    cfg,settings,_=development_cptc()
    return native_fixtures(cfg,settings)


def test_native_single_source_counterexample(controls):
    p=controls['sparse_same']
    assert p['adapter_roundtrip'] and p['formal_edge_eligible']
    assert p['score']>=.65 and p['source_independence']=='unknown'
    assert p['family_strengths']['source']==0
    assert not p['relations']


def test_complete_endpoints_do_not_create_propagation(controls):
    p=controls['complete_endpoints_same']
    assert p['score']<.65 and p['family_strengths']['relation']==0
    assert p['mapped_categories']==['web_attack','web_attack']
    assert not p['relations']


@pytest.mark.parametrize('prefix',['complete_endpoints','sparse','unknown_metadata'])
def test_namespace_only_means_identical_raw(controls,prefix):
    a,b=controls[prefix+'_same'],controls[prefix+'_cross']
    assert a['raw_alerts']==b['raw_alerts']
    assert a['family_strengths']['source']==b['family_strengths']['source']==0
    assert a['family_strengths']==b['family_strengths']
    if prefix!='unknown_metadata':
        assert a['score']==b['score']


def test_unknown_metadata_namespace_denominator_effect(controls):
    a,b=controls['unknown_metadata_same'],controls['unknown_metadata_cross']
    assert a['available_weight']==pytest.approx(.54)
    assert b['available_weight']==pytest.approx(.50)
    assert b['score']>a['score']
    assert a['matched_weight']==b['matched_weight']
    assert a['mass']==b['mass']


def test_conditional_flow_keeps_scope_and_is_not_native_support(controls):
    a,b=controls['conditional_flow_same'],controls['conditional_flow_cross']
    assert a['formal_edge_eligible'] and b['formal_edge_eligible']
    assert not a['adapter_roundtrip'] and not b['adapter_roundtrip']
    assert not a['relations'] and not b['relations']
    assert a['score']==b['score']


def test_bound_search_matches_brute_force_on_native_alerts(tmp_path):
    cfg,ss,_=development_cptc()
    setting=next(iter(ss.values()))
    ingress=load_cptc_dataset(ROOT).config
    adapter=SuricataAdapter(ingress,setting)
    aa=[]
    for i in range(16):
        raw=dict(event_type='alert',timestamp=f'2022-01-01T00:00:{i:02d}+0000',
            src_ip='192.0.2.'+str(50+i//2),dest_ip='192.0.2.5',
            src_port=5000+i,dest_port=80,flow_id=i,proto='TCP',
            alert=dict(signature_id=100+i,signature='synthetic '+str(i),severity=1,
                category='Web Application Attack' if i%2 else 'unmapped synthetic'),
            http=dict(hostname='specific.invalid',url='/unique/'+str(i//2)))
        if i==8:
            raw.update(src_ip='192.0.2.5',dest_ip='192.0.2.9',src_port=80)
        if i==10:
            raw['timestamp']='2022-01-01T00:00:09+0000'
        if i==12:
            raw['http']['url']='/'
        aa.append(adapter.convert(raw))
    ex=extract_entities(aa,ss)
    idx=AlertIndex(ex.alerts,(),ex.entities)
    scorer=CorrelationScorer(idx,cfg,ss)
    expected=max(scorer.score_pair(a.alert_id,b.alert_id).score for a,b in itertools.combinations(aa,2))
    assert expected>.4
    actual,_=all_pair_bound_search(idx,scorer,tmp_path,.4)
    assert actual['DATASET_REACHABLE_MAX']==expected
    assert actual['checked_by_production_scorer']>0


def test_delivered_artifacts_and_unrounded_gaps():
    report=json.loads((OUT/'score_reachability.json').read_text(encoding='utf8'))
    assert report['DATASET_REACHABLE_MAX']<.65
    assert report['CONFIG_THEORETICAL_MAX']>=.65
    top=json.loads((OUT/'top100_score_breakdown.json').read_text(encoding='utf8'))
    assert len(top)==100
    for row in top:
        assert row['threshold_gap']==.65-row['final_score']
        assert row['complete_score_breakdown']['status']=='PASS'
        assert abs(sum(row['final_family_contributions'].values())+sum(row['penalties'].values())-row['final_score'])<1e-12
    drills=json.loads((OUT/'pair_drilldown.json').read_text(encoding='utf8'))
    assert len(drills)==10 and all(d['raw_alerts'] for d in drills)


def test_frozen_receipt_and_original_artifact_hashes():
    from app.services.storage import file_digest
    receipt=json.loads((OUT/'frozen_recipe_receipt.json').read_text(encoding='utf8'))
    for flag in ['algorithm_modified','config_modified','mapping_modified','threshold_modified','ground_truth_read','production_snapshot_modified']:
        assert receipt[flag] is False
    assert verify_historical_inventory(receipt['protected_file_hashes'])['status'] == 'PASS'
    for name,digest in receipt['previous_diagnostic_hashes'].items():
        assert file_digest(ROOT/'outputs/cptc_top100_diagnostic'/name)==digest

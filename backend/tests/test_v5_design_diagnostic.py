from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""Safety properties for diagnostic policies; never writes frozen artifacts."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import random
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('v5_diagnostic',ROOT/'scripts/v5_design_diagnostic.py')
diag=importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


def view():
    ds=[dict(dimension=n,family=f,state='SUPPORTED',strength=s,weight=w,entity_ids=[])
        for n,f,s,w in [('time.distance','time',1.,1.),('entity.URL','entity',.9,.85),
                        ('entity.IP','entity',.3,.25),('metadata.detector_identity','behavior',.08,1.)]]
    facts=[dict(dimension=d['dimension'],family=f,fact_key=d['dimension'],strength=d['strength'],
                role='primary' if f=='RESOURCE_CONTEXT' else 'supporting',evidence_refs=[])
           for d,f in zip(ds,['TEMPORAL','RESOURCE_CONTEXT','ENTITY_IDENTITY','RULE_METADATA'])]
    return dict(dimensions=ds,facts=facts,reliability=[],weights={'time':.2,'entity':.3,'relation':.36,'behavior':.04,'source':.1},
        hard=[],duplicate_risk=False,penalty=0.,half_life=300.,pair=['synthetic-a','synthetic-b'])


def test_unobservable_not_positive_or_mismatch():
    original=view();missing=deepcopy(original);conflict=deepcopy(original)
    missing['dimensions'][1].update(state='UNOBSERVABLE',strength=0.)
    conflict['dimensions'][1].update(state='CONTRADICTED',strength=0.)
    a=diag.summarize(missing,diag.design());b=diag.summarize(conflict,diag.design())
    assert a['mismatch_mass']==0 < b['mismatch_mass']
    assert a['relation_score']>b['relation_score']
    assert a['confidence']==b['confidence']<diag.summarize(original,diag.design())['confidence']


def test_absolute_confidence_monotone_under_weak_positive_removal():
    v=view();before=diag.summarize(v,diag.design())
    v['dimensions'][2].update(state='UNOBSERVABLE',strength=0.)
    after=diag.summarize(v,diag.design())
    assert after['relation_score']>before['relation_score']
    assert after['confidence']<before['confidence']


@pytest.mark.parametrize('mask',['host','account','process','destination','transport','behavior_metadata','time_only'])
def test_mask_copies_never_mutate_original(mask):
    v=view();before=deepcopy(v)
    masked,_=diag.mask_copy(v,mask)
    diag.compare(masked,diag.design())
    assert v==before and masked is not v


@pytest.mark.parametrize('kind',['time_only','signature_only','hot_or_no_primary'])
def test_sparse_extremes_cannot_pass_any_candidate(kind):
    v=view()
    if kind=='time_only':v,_=diag.mask_copy(v,'time_only')
    elif kind=='signature_only':
        for d in v['dimensions']:
            if d['family']=='entity':d.update(state='UNOBSERVABLE',strength=0.)
        v['dimensions'][-1]['strength']=.2
    else:
        for f in v['facts']:f['role']='supporting'
    assert all(not r['admitted'] for r in diag.compare(v,diag.design()).values())


@pytest.mark.parametrize('guard',['hard','duplicate_risk'])
def test_hard_and_duplicate_guards_cannot_be_overridden(guard):
    v=view();v[guard]=['verified_conflict'] if guard=='hard' else True
    assert all(not r['admitted'] for r in diag.compare(v,diag.design()).values())


def test_dependent_resource_facts_do_not_add_quorum_votes():
    v=view();before=diag.summarize(v,diag.design())
    v['facts'] += [{**v['facts'][1],'fact_key':'same-resource-other-description'}]*10
    assert diag.summarize(v,diag.design())['independent_groups']==before['independent_groups']


def test_same_source_not_a_gate():
    assert diag.compare(view(),diag.design())['b']['admitted']
    assert 'source' not in diag.summarize(view(),diag.design())['independent_groups']


def test_mismatch_lowers_all_numerical_scores():
    v=view();bad=deepcopy(v)
    bad['dimensions'][1].update(state='CONTRADICTED',strength=0.)
    for k in diag.CANDIDATES:
        assert diag.compare(bad,diag.design())[k]['score']<diag.compare(v,diag.design())[k]['score']


def test_time_shuffle_unsafe_window_rejected():
    v=diag.time_copy(view(),100000.,7200)
    assert v['dimensions'][0]['state']=='CONTRADICTED'
    assert all(not r['admitted'] for r in diag.compare(v,diag.design()).values())


def test_deterministic_scores_and_permutation_invariant_aggregation():
    v=view();expected=diag.compare(v,diag.design())
    random.Random(42).shuffle(v['dimensions']);random.Random(43).shuffle(v['facts'])
    assert diag.compare(v,diag.design())==expected


def test_real_frozen_projection_keeps_evidence_and_no_alert_mutation():
    from test_correlation_score import parent_child,inputs
    from app.correlation.scoring import CorrelationScorer
    cfg,_,_=development_config()
    alerts=parent_child();idx,settings=inputs(alerts)
    scorer=CorrelationScorer(idx,cfg,settings)
    before=[a.canonical_json() for a in alerts]
    pair=scorer.score_pair(*sorted(idx.alerts));v=diag.state_projection(pair,scorer)
    diag.validate_refs(v,scorer)
    assert len(v['dimensions'])==len(pair.diagnostics['evidence_v2']['dimensions'])
    assert any(d['state']=='SUPPORTED' and d['family']=='relation' for d in v['dimensions'])
    assert [a.canonical_json() for a in alerts]==before
    assert pair.score==scorer.score_pair(*sorted(idx.alerts)).score


def test_projection_does_not_call_no_pivot_a_refutation():
    from test_correlation_score import alert,inputs
    from app.correlation.scoring import CorrelationScorer
    cfg,_,_=development_config()
    idx,settings=inputs([alert('one',src_ip='192.0.2.1',dst_ip='192.0.2.2'),
                         alert('two',1,src_ip='192.0.2.1',dst_ip='192.0.2.2')])
    scorer=CorrelationScorer(idx,cfg,settings)
    v=diag.state_projection(scorer.score_pair(*sorted(idx.alerts)),scorer)
    d=next(d for d in v['dimensions'] if d['dimension']=='topology.network_continuity')
    assert d['state']=='UNKNOWN' and d['strength']==0


def test_runtime_truth_guard_blocks_before_read(tmp_path):
    from demo_support import truth_guard,DemoError
    gt=tmp_path/'labels.csv';gt.write_text('synthetic tripwire',encoding='utf8')
    with truth_guard(tmp_path),pytest.raises(DemoError):gt.read_text(encoding='utf8')


def test_no_production_import_of_diagnostic():
    assert all('v5_design_diagnostic' not in p.read_text(encoding='utf8') for p in (ROOT/'backend/app').rglob('*.py'))


def test_score_threshold_kept_and_statistics_exact():
    assert diag.design()['reference_threshold']==.65
    assert diag.quantiles([0.,1.])['P50']==.5
    rows=[dict(score=.65,admitted=True,confidence=.8),dict(score=.6499999999,admitted=False,confidence=.8)]
    assert diag.distribution(rows)['counts_ge']['0.65']==1


def test_all_positive_deletions_never_increase_confidence():
    v=view();before=diag.summarize(v,diag.design())['confidence']
    for bits in range(1<<len(v['dimensions'])):
        changed=deepcopy(v)
        for i,d in enumerate(changed['dimensions']):
            if bits&(1<<i):d.update(state='UNOBSERVABLE',strength=0.)
        assert diag.summarize(changed,diag.design())['confidence']<=before


def test_unknown_never_earns_support_or_confidence():
    v=view()
    for d in v['dimensions']:d.update(state='UNKNOWN',strength=0.)
    s=diag.summarize(v,diag.design())
    assert s['relation_score']==s['confidence']==s['supported_mass']==0
    assert all(not r['admitted'] for r in diag.compare(v,diag.design()).values())


def test_observed_contradiction_not_hidden_by_absence():
    v=view();v['dimensions'][1].update(state='CONTRADICTED',strength=0.)
    s=diag.summarize(v,diag.design())
    assert s['mismatch_mass']>0
    assert 'entity.URL' not in s['primary']


def test_destination_mask_preserves_surviving_source_role():
    v=view()
    v['source_entity_ids']=[['source'],['source']]
    v['reliability']=[dict(type='IP',entity_id='destination',role_factor=.25,reliability=.25,evidence_refs=[]),
                      dict(type='IP',entity_id='source',role_factor=1.,reliability=.1,evidence_refs=[])]
    v['dimensions'][2].update(entity_ids=['destination'],strength=.25)
    masked,removed=diag.mask_copy(v,'destination')
    ip=next(d for d in masked['dimensions'] if d['dimension']=='entity.IP')
    assert ip['state']=='SUPPORTED' and ip['entity_ids']==['source'] and ip['strength']==.1
    assert removed==['entity.IP.destination_component']
    assert diag.summarize(masked,diag.design())['confidence']<diag.summarize(v,diag.design())['confidence']


def test_destination_mask_keeps_observed_source_disagreement():
    v=view();v['source_entity_ids']=[['one'],['two']]
    v['reliability']=[dict(type='IP',entity_id='destination',role_factor=.25,reliability=.25,evidence_refs=[])]
    v['dimensions'][2].update(entity_ids=['destination'],strength=.25)
    masked,_=diag.mask_copy(v,'destination')
    ip=next(d for d in masked['dimensions'] if d['dimension']=='entity.IP')
    assert ip['state']=='CONTRADICTED' and ip['strength']==0


def test_complete_artifact_contract():
    """Real run receipt, conservation, masks and source integrity, without a rerun."""
    out=ROOT/'outputs/v5_design_diagnostic'
    manifest=diag.read(out/'manifest.json')
    required=['V5_DESIGN_DIAGNOSTIC_REPORT.md','evidence_family_inventory.json','source_capability_analysis.json',
        'v4_failure_decomposition.json','candidate_a_results.json','candidate_b_results.json',
        'candidate_c_results.json','candidate_d_results.json','score_distribution.json','score_reachability.json',
        'negative_controls.json','counterfactual_missing_evidence.json','top_pairs.json',
        'recommended_v5_architecture.json','freeze_verification.json','manifest.json']
    assert all((out/p).is_file() for p in required)
    assert manifest['candidate_count']==manifest['scored_candidate_count']
    assert manifest['scored_member_count']>=manifest['scored_candidate_count']
    assert manifest['candidate_resource_truncated_count']==0
    assert manifest['reverse_candidate_replay_equal']
    assert diag.file_digest(diag.DEV)==manifest['dataset_sha256']
    assert diag.file_digest(diag.RAW)==manifest['raw_sha256']
    freeze=diag.read(out/'freeze_verification.json')
    assert not freeze['protected_files_changed'] and freeze['status']=='PASS'
    masks=diag.read(out/'counterfactual_missing_evidence.json')
    assert masks['checks'].get('confidence_increases',0)==0
    assert masks['checks'].get('time_only_admitted',0)==0
    top=diag.read(out/'top_pairs.json')
    assert all(len(top[k])>=100 for k in diag.CANDIDATES)
    for k,rows in top.items():
        assert all(rows[i]['candidates'][k]['score']>=rows[i+1]['candidates'][k]['score'] for i in range(len(rows)-1))
    for k in diag.CANDIDATES:
        result=diag.read(out/f'candidate_{k}_results.json')
        assert result['count']==manifest['candidate_count']
        assert result['observed_maximum']==result['quantiles']['max']
        assert result['admitted']<=result['counts_ge']['0.65']


def test_paper_references_and_required_experiment_fields():
    import re
    folder=ROOT/'docs/paper'
    for name in ('PAPER_OUTLINE.md','PAPER_TECHNICAL_NOTES.md','PAPER_EXPERIMENT_LOG.md',
                 'PAPER_DECISION_LOG.md','PAPER_DRAFT.md'):
        text=(folder/name).read_text(encoding='utf8')
        for target in re.findall(r'\]\(([^)]+)\)',text):
            if '://' not in target:
                assert (folder/target.split('#')[0]).resolve().exists(),target
    log=(folder/'PAPER_EXPERIMENT_LOG.md').read_text(encoding='utf8')
    for field in ('experiment_id','date','dataset','dataset_scope','algorithm_version','config_hash','mapping_digest',
                  'threshold','purpose','input_count','candidate_count','scored_count','edge_count','chain_edge_count',
                  'incident_count','max_score','main_findings','limitations','result_status','artifact_paths'):
        assert field+':' in log


def test_global_bounds_and_top_replay_receipts():
    out=ROOT/'outputs/v5_design_diagnostic'
    bounds=diag.read(out/'global_score_reachability.json')
    oracle=diag.read(out/'bound_oracle.json')
    replay=diag.read(out/'reproducibility.json')
    assert oracle['status']=='PASS' and len(oracle['items'])==128
    for row in oracle['items']:
        assert all(score<=row['upper_c' if k=='c' else 'upper_abd']+1e-10
                   for k,score in row['scores'].items())
    for k in diag.CANDIDATES:
        r=bounds[k]
        assert r['pair_count']==49995000
        assert r['lower_bound']<=r['upper_bound']
        if r['status']=='CERTIFIED':
            assert r['dataset_reachable_maximum']==r['lower_bound']
        else:
            assert r['dataset_reachable_maximum'] is None
    assert replay['top_pair_rows_recomputed']==400
    assert replay['all_candidate_scores_gate_results_equal']
    assert replay['all_evidence_refs_resolved']


def test_conditional_control_selection_is_disclosed():
    r=diag.read(ROOT/'outputs/v5_design_diagnostic/high_information_controls.json')
    assert 'selection bias' in r['selection']
    assert len(r['pair_ids'])==r['sample_count']==100
    assert all(rows[k]['count']==100 for rows in r['populations'].values() for k in diag.CANDIDATES)

from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""Diagnostic tooling contracts; synthetic facts do not enter the CPTC replay."""
from pathlib import Path
import random
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from cptc_top100_diagnostic import TopK,rank_key,load_frozen_config
from cptc_top100_report import score_features,rejection,validate_refs,guards,relationship,expand_pair,feature_stats
from app.correlation.scoring import CorrelationScorer
from app.correlation.edges import run_correlation
from test_correlation_score import alert,inputs,parent_child
from test_correlation_v3 import flow


@pytest.fixture(scope='module')
def preformula_v4_formula():
    return development_config()[0]


def scoring(aa,config):
    index,settings=inputs(aa)
    scorer=CorrelationScorer(index,config,settings)
    a,b=list(index.alerts)[:2]
    return scorer.score_pair(a,b),scorer,index


def test_topk_global_order_and_lexical_ties():
    values=[(i%7/10,f'alt_{i:064x}',f'alt_{i+1:064x}',{}) for i in range(701)]
    expected=sorted(values,key=lambda x:rank_key(*x[:3]))[:100]
    for seed in range(4):
        order=values[:];random.Random(seed).shuffle(order)
        top=TopK()
        for row in order:
            top.add(*row)
        assert [(r['score'],r['alert_a_id'],r['alert_b_id']) for r in top.rows()]==[r[:3] for r in expected]
        assert len(top.heap)==100


def test_guard_rejected_score_not_filtered_by_topk():
    top=TopK(1)
    top.add(.9,'a','b',dict(valid=False))
    top.add(.8,'c','d',dict(valid=True))
    assert top.rows()[0]['valid'] is False


@pytest.mark.parametrize('aa',[parent_child(),[alert('a',src_ip='192.0.2.1',dst_ip='192.0.2.2',dst_port=80,rule_id='same'),
    alert('b',1,src_ip='192.0.2.1',dst_ip='192.0.2.2',dst_port=80,rule_id='same')],
    [alert('a',src_ip='192.0.2.1',dst_ip='192.0.2.2',dst_port=80),alert('b',50,src_ip='192.0.2.1',dst_ip='192.0.2.3',dst_port=80)]])
def test_v4_formula_reconstruction_including_clamp_and_penalties(preformula_v4_formula,aa):
    pair,scorer,_=scoring(aa,preformula_v4_formula)
    expanded=score_features(pair,scorer)
    assert expanded['status']=='PASS'
    assert expanded['reconstructed_score']==pytest.approx(pair.score,abs=1e-12)
    assert sum(r['net_contribution'] for r in expanded['features'])==pytest.approx(pair.raw_total,abs=1e-12)
    assert expanded['penalty_total']>=0
    for name in ('conflict','duplicate'):
        row=next(r for r in expanded['features'] if r['feature_name']=='penalty.'+name)
        assert row['negative_contribution']==pair.contributions[name]


def test_every_dimension_and_zero_contribution_is_preserved(preformula_v4_formula):
    pair,scorer,_=scoring(parent_child(),preformula_v4_formula)
    result=score_features(pair,scorer)
    actual={r['feature_name'] for r in result['features']}
    expected={d['dimension'] for d in pair.diagnostics['evidence_v2']['dimensions']}
    assert actual==expected|{'penalty.conflict','penalty.duplicate'}
    assert any(r['net_contribution']==0 for r in result['features'])
    assert len(feature_stats([dict(scoring=result)])['features'])==len(actual)


def test_rejection_matches_frozen_production_precedence(preformula_v4_formula):
    for aa in (parent_child(),[alert('a',host='same',rule_id='same'),alert('b',1,host='same',rule_id='same')]):
        pair,scorer,_=scoring(aa,preformula_v4_formula)
        r=rejection(pair,scorer.algorithm.score.correlation_threshold)
        assert r['formal_edge_admitted']==(pair.valid and pair.score>=.65)
        assert r['production_evidence_decision']==pair.diagnostics['evidence_v2']['decision']
        if r['production_evidence_decision']=='REJECT_INSUFFICIENT_EVIDENCE':
            assert r['primary_rejection_reason']=='REJECTED_EVIDENCE_REQUIREMENT'


def test_no_relationship_does_not_reject_valid_undirected_edge(preformula_v4_formula):
    pair,scorer,_=scoring(flow(),preformula_v4_formula)
    a,b=[scorer.index.alerts[x] for x in (pair.source_member_id,pair.target_member_id)]
    mapping=relationship(pair,scorer,a,b)
    assert mapping['selected_relationship']=='NONE'
    assert rejection(pair,.65)['formal_edge_admitted']


def test_raw_pointers_are_bound_to_their_actual_alert(preformula_v4_formula):
    pair,scorer,index=scoring(parent_child(),preformula_v4_formula)
    refs=validate_refs(pair,dict(index.alerts))
    assert refs and all(r['resolved'] for r in refs)
    pair.diagnostics['malicious_ref']=dict(alert_id='alt_missing',pointer='/host',side='shared')
    with pytest.raises(AssertionError,match='cross_pair_pointer'):
        validate_refs(pair,dict(index.alerts))


def test_session_guard_not_evaluable_is_not_fabricated(preformula_v4_formula):
    pair,scorer,_=scoring(parent_child(),preformula_v4_formula)
    row=next(g for g in guards(pair,scorer) if g['guard_name']=='verified_incompatible_session')
    assert row['status']=='NOT_EVALUABLE / NOT_TRIGGERED'
    assert row['triggered'] is False and row['evidence_available'] is False


def test_full_expansion_binds_a_and_b_and_does_not_change_results(preformula_v4_formula):
    pair,scorer,index=scoring(parent_child(),preformula_v4_formula)
    a,b=pair.source_member_id,pair.target_member_id
    selected=dict(score=pair.score,alert_a_id=a,alert_b_id=b,support_pair=[a,b],
        candidate=dict(support_key=[a,b],channels=['HOST'],evidence=[dict(channel='HOST',
            effective_window_seconds=3600,alert_ids=[a,b],gap_seconds=pair.diagnostics['gap_seconds'])],priority=[]))
    lookup={x.raw_fingerprint:[dict(outer_record={'_raw':'synthetic'},parsed_suricata_eve=x.raw_alert)] for x in index.alerts.values()}
    before={x.alert_id:x.canonical_json() for x in index.alerts.values()}
    expected=scorer.breakdown(pair).canonical_json()
    p=expand_pair(selected,1,index,scorer,lookup)
    assert p['canonical_alerts']['A']['alert_id']==a
    assert p['temporal']['inside_candidate_window'] is True
    assert p['temporal']['member_window_checks'][0]['nomination_member_ids']==[a,b]
    assert p['canonical_alerts']['B']['alert_id']==b
    assert p['raw_alerts']['A']['alert_id']==a
    assert p['raw_alerts']['B']['alert_id']==b
    assert p['raw_alerts']['A']['records'][0]['parsed_suricata_eve']==index.alerts[a].raw_alert
    assert p['raw_alerts']['B']['records'][0]['parsed_suricata_eve']==index.alerts[b].raw_alert
    assert before=={x.alert_id:x.canonical_json() for x in index.alerts.values()}
    assert scorer.breakdown(scorer.score_pair(a,b)).canonical_json()==expected
    reverse={**selected,'support_pair':[b,a]}
    member=expand_pair(reverse,1,index,scorer,lookup,'all_scored_members')
    assert member['alert_a_id']==min(a,b) and member['alert_b_id']==max(a,b)
    assert member['production_scored_support_pair']==[b,a]
    assert member['pair_id'].startswith('cmp_')
    assert member['raw_alerts']['A']['alert_id']==member['alert_a_id']
    args=(list(index.alerts.values()),[],list(index.entities.values()),preformula_v4_formula,scorer.settings)
    run_a=run_correlation(*args)
    expand_pair(selected,1,index,scorer,lookup)
    run_b=run_correlation(*args)
    assert [e.canonical_json() for e in run_a.edges]==[e.canonical_json() for e in run_b.edges]


def test_disk_distribution_and_independent_sql_ranking(tmp_path,monkeypatch):
    import json
    import cptc_top100_report as report
    from cptc_top100_diagnostic import create_scores
    from cptc_2018_step3a import quantiles
    monkeypatch.setattr(report,'OUT',tmp_path)
    monkeypatch.setattr(report,'RUN',tmp_path)
    ids=[f'alt_{i:064x}' for i in range(1001)]
    db=create_scores(tmp_path/'compact_scores.sqlite',ids)
    scores=[i%101/100 for i in range(1000)]
    rows=[(i,i+1,i,i+1,scores[i],i%2) for i in range(1000)]
    db.executemany('INSERT INTO candidates VALUES (?,?,?,?,?,?)',rows)
    db.executemany('INSERT INTO members VALUES (?,?,?,?,?,?)',rows)
    db.commit();db.close()
    q=quantiles(scores,dict(max=1.,P99=.99,P95=.95,median=.5))
    (tmp_path/'score_distribution.json').write_text(json.dumps(dict(scored_pairs=len(scores),quantiles=q)),encoding='utf8')
    dist=report.distributions()
    assert dist['candidates']['total_scored_pairs']==1000
    assert dist['members']['total_scored_pairs']==1000
    assert dist['candidates']['count_score_ge_0_65']==sum(s>=.65 for s in scores)
    assert dist['candidates']['count_score_0_55_0_60']==sum(.55<=s<.6 for s in scores)
    top=TopK()
    for i,score in enumerate(scores):
        top.add(score,ids[i],ids[i+1],{})
    assert report.verify_disk_selection(top.rows(),top.rows())
    bad=top.rows();bad[0],bad[1]=bad[1],bad[0]
    with pytest.raises(AssertionError,match='global_top100_heap_sql_mismatch'):
        report.verify_disk_selection(bad,top.rows())

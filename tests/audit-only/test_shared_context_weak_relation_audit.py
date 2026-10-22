"""Frozen evidence, diagnostic qualification and temporary graph invariants."""
from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'backend'))
from audit_shared_context_weak_relation import (authority,behavior_observation,classify,distribution,
    graph_statistics,no_production_execution,temporal_observation,validate,what_if)
OUT=ROOT/'outputs/shared_context_weak_relation_audit'


def load(name):return json.loads((OUT/name).read_text(encoding='utf8'))


@pytest.fixture(scope='module')
def audit():
    return load('pairs.json'),{c['context_id']:c for c in load('contexts.json')},load('summary.json'),load('what_if.json')


def test_exact_138_target_partition_and_original_decisions(audit):
    rows,catalog,summary,impact=audit
    assert validate(*audit)
    source=json.loads((ROOT/'outputs/stage2_identity_projection/after.json').read_text(encoding='utf8'))
    expected={d['candidate_id']:d for d in source['evidence']['decisions'] if 'SHARED_CONTEXT_ONLY' in d['diagnostics']}
    assert {r['pair_id'] for r in rows}==expected.keys()
    assert all(r['original_formal_decision']==expected[r['pair_id']] for r in rows)
    assert len(expected)==138


def test_classification_is_exhaustive_and_qualification_is_conservative(audit):
    rows,_,s,_=audit
    assert s['PUBLIC_CONTEXT_ONLY_COUNT']==97
    assert s['MULTIPLE_SUPPORTING_CONTEXTS_COUNT']==41
    assert sum(s['SHARED_CONTEXT_AUDIT_COUNTS'].values())==138
    assert s['CLEAR_NO_RELATION_COUNT']==97 and s['AMBIGUOUS_COUNT']==41
    assert s['POSSIBLE_WEAK_RELATION_COUNT']==s['WEAK_RELATION_CANDIDATE_COUNT']==0
    assert all(r['weak_eligibility']=='NEEDS_CALIBRATION' for r in rows if r['qualification_bucket']=='AMBIGUOUS')


def test_no_official_primary_context_ranking_is_invented(audit):
    assert audit[2]['PRIMARY_CONTEXT_TYPE_COUNTS']=={'UNDEFINED':138}
    assert all(r['PRIMARY_CONTEXT_TYPE']=='UNDEFINED' for r in audit[0])


def test_global_context_fanout_keeps_parent_and_non_target_members(audit):
    _,catalog,s,_=audit
    source=json.loads((ROOT/'outputs/stage2_identity_projection/after.json').read_text(encoding='utf8'))
    contexts={c['context_identity_id']:c for c in source['evidence']['context_postings']}
    assert len(catalog)==10
    for cid,c in catalog.items():
        assert c['original_context']==contexts[cid]
        assert c['stage_fanout']==len(contexts[cid]['stage_ids'])
    assert s['PAIRWISE_CONTEXT_COUNT']==0 and s['MULTI_STAGE_CONTEXT_COUNT']==10
    assert s['FANOUT_DISTRIBUTION']==dict(count=10,min=3,median=7.5,p75=9.75,p90=10,max=10)
    assert s['SHARED_CONTEXT_PAIRS_FROM_HIGH_FANOUT']==138


def test_shared_context_field_counts_are_actual_claim_types(audit):
    s=audit[2]['SHARED_CONTEXT_TYPE_COUNTS']
    assert (s['shared_host'],s['shared_account'],s['shared_process'],s['shared_request'])==(88,42,42,1)
    assert (s['shared_flow'],s['shared_auth_session'],s['shared_network_session'])==(95,42,0)
    assert (s['shared_endpoint'],s['shared_file_path'],s['shared_command'],s['shared_object'])==(95,41,37,0)


def test_flow_endpoint_and_tuple_are_one_identity_family(audit):
    flow=[r for r in audit[0] if r['shared_contexts']['shared_flow']]
    assert len(flow)==95
    assert all(r['anchors']['families']==['FLOW'] and not r['anchors']['multiple_distinct_anchors'] for r in flow)
    assert all(r['audit_category']=='PUBLIC_CONTEXT_ONLY' for r in flow)


def test_multiple_anchors_have_distinct_native_paths_without_causal_claim(audit):
    review=[r for r in audit[0] if r['qualification_bucket']=='AMBIGUOUS']
    assert len(review)==41
    for row in review:
        assert {'PROCESS','AUTH_SESSION'}<=set(row['anchors']['families'])
        evidence=[p for p in row['anchors']['distinct_family_observations'] if p['distinct_native_observation_paths']]
        assert evidence and all(p['exclusive_paths_a'] and p['exclusive_paths_b'] for p in evidence)
        assert all(not p['statistical_or_causal_independence_proven'] for p in evidence)


def test_low_fanout_supporting_facts_do_not_become_exclusive_binding(audit):
    rows,_,s,_=audit
    assert s['EXCLUSIVE_TWO_STAGE_SUPPORTING_FACT_COUNT']==7
    assert s['PAIR_COUNT_WITH_EXCLUSIVE_TWO_STAGE_SUPPORTING_FACT']==6
    assert s['EXCLUSIVE_TWO_STAGE_CONTEXT_PAIR_COUNT']==0
    facts=[f for r in rows for f in r['exclusive_two_stage_supporting_facts']]
    assert facts and all(f['authority_class']=='context only' and not f['native_object_or_session_lifecycle_certified'] for f in facts)
    assert all(not r['WEAK_RELATION_CANDIDATE'] for r in rows if r['exclusive_two_stage_supporting_facts'])


def test_time_statistics_are_bins_and_not_eligibility(audit):
    s=audit[2]
    assert [s[k] for k in ('WITHIN_30S','WITHIN_60S','WITHIN_120S','WITHIN_300S','OVER_300S')]==[27,50,88,135,3]
    assert s['WITHIN_300S']+s['OVER_300S']==138
    assert all(r['weak_temporal_eligibility']=='NEEDS_CALIBRATION' for r in audit[0])


def test_touching_overlapping_and_long_intervals_remain_distinct():
    stage=lambda a,b:dict(start_time='2026-01-01T00:'+a+'Z',end_time='2026-01-01T00:'+b+'Z')
    a=stage('00:00','00:10')
    assert temporal_observation(a,stage('00:10','00:20'))['interval_relation']=='adjacent'
    assert temporal_observation(a,stage('00:05','00:08'))['interval_relation']=='overlap'
    assert temporal_observation(a,stage('00:11','00:12'))['interval_relation']=='forward_gap'
    assert temporal_observation(a,stage('06:00','06:10'))['interval_relation']=='large_gap'


def test_behavior_compatibility_is_not_borrowed_from_same_stage_rules(audit):
    assert audit[2]['BEHAVIOR_COMPATIBILITY_COUNTS']=={'UNDEFINED':35,'unknown':82,'same':21}
    unknown=behavior_observation({'behavior':'UNKNOWN'},{'behavior':'UNKNOWN'})
    different=behavior_observation({'behavior':'EXECUTION'},{'behavior':'FILE_ACTIVITY'})
    assert unknown['state']=='unknown' and unknown['compatibility']=='UNDEFINED'
    assert different['state']=='UNDEFINED' and not different['formal_relation_behavior_conflict']


def test_roles_include_paths_and_do_not_invent_creator_consumer(audit):
    assert audit[2]['SHARED_CONTEXT_PAIR_WITH_ROLE_SEMANTICS_COUNT']==0
    paths=[p for r in audit[0] for p in r['role_semantics']['supporting_path_roles']]
    assert paths and all(p['configured_complementary_role_witness_count']==0 for p in paths)
    assert all(p['original_claim_roles'] in [['executable','executable'],['created_file','created_file']] for p in paths)


def test_mixed_stage_sources_not_misreported_as_native_cross_source_identity(audit):
    s=audit[2]
    assert (s['SHARED_CONTEXT_SAME_SOURCE_COUNT'],s['SHARED_CONTEXT_CROSS_SOURCE_COUNT'])==(100,38)
    assert s['ACTUAL_CONTEXT_WITNESS_CROSS_SOURCE_PAIR_COUNT']==5
    assert s['CONTEXT_SCOPE_UNTRUSTED_COUNT']==0


def test_authority_requires_backing_projection_and_scope(audit):
    catalog=audit[1]
    auth=[c for c in catalog.values() if c['context_type']=='SESSION']
    assert len(auth)==2 and all(c['authority']['authority_binding_ids'] for c in auth)
    flow=deepcopy(next(c['original_context'] for c in catalog.values() if c['context_type']=='FLOW'))
    flow['scoped_identity']['scope']=None
    value=authority(flow,{},dict(auth_session_bindings=[]))
    assert not value['scope_trusted_within_original_identity'] and not value['new_cross_source_identity_projection']


def test_classification_cannot_change_when_graph_benefit_is_added(audit):
    row=deepcopy(audit[0][0]);expected=classify(row)
    row.update(baseline_component_a_size=8,baseline_component_b_size=10,isolated_stages_saved=24,ground_truth_edge=True)
    assert classify(row)==expected


def test_what_if_qualified_candidates_preserve_current_graph(audit):
    s=audit[2];impact=audit[3]
    assert impact['qualified_possible']==impact['baseline']
    assert s['WHAT_IF_WEAK_EDGE_COUNT']==0
    assert s['WHAT_IF_COMPONENT_COUNT']==26 and s['WHAT_IF_ISOLATED_STAGE_COUNT']==24
    assert s['WHAT_IF_COMPONENT_SIZES']==[1]*24+[8,10]


def test_uncalibrated_review_pairs_only_densify_existing_components(audit):
    value=audit[3]['uncalibrated_review_set_sensitivity']
    assert value['extra_pair_count']==41 and value['isolated_stage_count']==24 and value['component_count']==26
    impacts=[p for p in audit[3]['per_pair_bridge_impacts'] if p['audit_category']=='MULTIPLE_SUPPORTING_CONTEXTS']
    assert len(impacts)==41 and all(not p['different_baseline_components'] for p in impacts)


def test_ineligible_all_pairs_stress_is_explicitly_not_admission(audit):
    value=audit[3]['deliberately_ineligible_all_shared_context_stress']
    assert value['extra_pair_count']==138 and value['component_sizes']==[1,1,1,4,10,25]
    assert value['isolated_stage_count']==3
    assert audit[2]['WEAK_RELATION_CANDIDATE_COUNT']==0
    assert audit[3]['all_shared_pairs_between_non_singleton_components']==0


def test_bridge_detection_on_independent_non_singleton_components():
    handoff=dict(stages=dict(stages=[dict(stage_id=s) for s in 'abcd']),evidence=dict(decisions=[
        dict(stage_a_id='a',stage_b_id='b',relation_type='DIRECTED_EDGE'),
        dict(stage_a_id='c',stage_b_id='d',relation_type='UNDIRECTED_EDGE')]))
    row=dict(pair_id='synthetic',stage_a='b',stage_b='c',audit_category='OTHER',
        WEAK_RELATION_CANDIDATE=True,qualification_bucket='POSSIBLE_WEAK_RELATION')
    before=deepcopy(handoff);impact=what_if(handoff,[row])
    assert impact['weak_bridge_candidate_count']==1 and impact['qualified_possible']['component_sizes']==[4]
    assert handoff==before


def test_temporary_graph_keeps_singletons_and_rejects_unknown_nodes():
    assert graph_statistics('abc',[],[])['component_sizes']==[1,1,1]
    with pytest.raises(ValueError,match='endpoint'):graph_statistics('ab',[],[('a','c')])


def test_production_guard_blocks_call_without_executing_body():
    called=[]
    def forbidden():called.append(True)
    # Use a separate globals dictionary so the test module itself is unaffected.
    import types
    fn=types.FunctionType(forbidden.__code__,{'__name__':'app.stage_chains.audit_forbidden'},closure=forbidden.__closure__)
    with pytest.raises(AssertionError,match='production_algorithm'):
        with no_production_execution():fn()
    assert called==[]


def test_percentiles_and_empty_inputs_have_no_invented_values():
    assert distribution([0,10])==dict(count=2,min=0,median=5,p75=7.5,p90=9,max=10)
    assert distribution([])['median'] is None


def test_integrity_protects_prior_audits_data_and_formal_outputs():
    integrity=load('integrity.json')
    assert integrity['EXISTING_FILES_CHANGED']==[]
    assert integrity['PRIOR_AUDITS_AND_STAGE9_ARTIFACTS_UNCHANGED']
    assert integrity['PRODUCTION_STAGE7_CALL_COUNT']==integrity['PRODUCTION_STAGE8_CALL_COUNT']==integrity['PRODUCTION_STAGE9_CALL_COUNT']==0
    assert not integrity['GT_USED_FOR_CLASSIFICATION'] and not integrity['NEW_WEAK_THRESHOLD_DEFINED']

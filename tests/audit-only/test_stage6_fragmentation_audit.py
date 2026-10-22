"""Evidence checks for the frozen Stage6 audit; no production replay or writes."""
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'backend'))
import audit_stage6_fragmentation as audit
import app.community
import app.stages.evidence
OUT=ROOT/'outputs/stage6_fragmentation_audit'


def load(name):return json.loads((OUT/name).read_text(encoding='utf8'))


@pytest.fixture(scope='module')
def frozen():
    return json.loads((ROOT/'outputs/stage2_identity_projection/after.json').read_text(encoding='utf8'))


@pytest.fixture(scope='module')
def computed(frozen):
    before=audit.digest(frozen)
    with audit.prohibit_builders():
        data=audit.prepare(frozen)
        pairs=audit.neighbors(data)
        stages=audit.stage_inventory(data)
        isolated=audit.isolated_inventory(data,pairs)
        communities=audit.community_inventory(data,isolated)
        simulation=audit.merge_simulation(data,pairs,isolated)
        summary=audit.summarize(frozen,data,stages,isolated,pairs,communities,simulation)
    assert audit.digest(frozen)==before
    return data,pairs,stages,isolated,communities,simulation,summary


def test_snapshot_is_exact_and_community_discrepancy_is_disclosed(computed):
    data,_,_,_,communities,_,summary=computed
    assert audit.sha(ROOT/'outputs/stage2_identity_projection/after.json')=='51f9b9a50b55405c6380788f3cdd0d36854ad47f33c2d80554823eb4282464df'
    assert (len(data['alerts']),len(data['stages']),len(data['isolated']))==(125,42,24)
    assert summary['INPUT_COMMUNITY_COUNT']==len(communities)==3
    assert summary['REQUESTED_BACKGROUND_COMMUNITY_COUNT']==5
    assert summary['INPUT_COMMUNITY_COUNT_MATCHES_REQUEST'] is False
    assert sorted((c['alert_count'],c['stage_count'],c['isolated_stage_count']) for c in communities)==[(39,15,5),(39,20,18),(47,7,1)]


def test_membership_and_all_original_aggregation_proofs_are_retained(frozen,computed):
    data,_,rows,*_=computed
    assert sorted(i for row in rows for i in row['member_alert_ids'])==sorted(data['alerts'])
    assert [r['original_stage'] for r in rows]==sorted(frozen['stages']['stages'],key=lambda s:s['stage_id'])
    assert all(r['INTRA_STAGE_SUPPORT']['connected'] for r in rows)
    assert all(not r['internal_member_conflict_audit']['hard_conflicts'] for r in rows)
    assert sum(r['INTRA_STAGE_SUPPORT']['formal_aggregation_edge_count'] for r in rows)==229
    assert data['resolved_pointer_count']==6601


def test_degree_uses_only_frozen_accepted_stage8_endpoints(frozen,computed):
    data=computed[0]
    decisions=frozen['evidence']['decisions']
    accepted=[d for d in decisions if d['relation_type']!='NO_RELATION']
    degree=Counter(i for d in accepted for i in (d['stage_a_id'],d['stage_b_id']))
    assert len(accepted)==23
    assert Counter(d['relation_type'] for d in accepted)=={'DIRECTED_EDGE':22,'UNDIRECTED_EDGE':1}
    assert data['degree']==degree and len(degree)==18
    assert data['isolated']==set(data['stages'])-degree.keys()


def test_size_distribution_and_singleton_counts(computed):
    s=computed[-1]
    assert s['STAGE_ALERT_COUNT_DISTRIBUTION']=={1:27,2:4,4:4,5:1,8:1,10:2,12:1,14:1,15:1}
    assert (s['SINGLE_ALERT_STAGE_COUNT'],s['MULTI_ALERT_STAGE_COUNT'])==(27,15)
    assert (s['ISOLATED_SINGLE_ALERT_STAGE_COUNT'],s['ISOLATED_MULTI_ALERT_STAGE_COUNT'])==(17,7)
    assert sum(r['alert_count'] for r in computed[2] if r['alert_count']>1)==98


def test_neighbor_scope_never_invents_arbitrary_42_stage_merge_pairs(computed):
    data,pairs=computed[:2]
    assert len(pairs)==255
    keys=set()
    for p in pairs:
        a,b=p['stage_a'],p['stage_b']
        assert (a,b) not in keys
        keys.add((a,b))
        assert a in data['isolated'] or b in data['isolated']
        assert data['stages'][a]['community_id']==data['stages'][b]['community_id']
        assert not p['existing_relation_between']
    assert all(r['same_behavior_neighbor_count']>0 for r in computed[3])


def test_unknown_labels_are_frozen_provider_absence_not_aggregation_loss(computed):
    data=computed[0];s=computed[-1]
    unknown=[b for b in data['annotations'].values() if b['behavior']=='UNKNOWN']
    assert len(unknown)==39 and {b['reason'] for b in unknown}=={'mapping_no_reliable_match:provider_not_configured'}
    assert Counter(data['alerts'][b['alert_id']].source_namespace for b in unknown)=={'traceback.lab.ids':20,'traceback.lab.waf':18,'traceback.lab.edr':1}
    assert (s['UNKNOWN_STAGE_COUNT'],s['ISOLATED_UNKNOWN_STAGE_COUNT'])==(19,16)
    assert all(data['stages'][data['owner'][b['alert_id']]]['behavior']==b['behavior'] for b in data['annotations'].values())
    assert s['UNKNOWN_RESTRICTIVE_GATE_REJECTION_COUNT']==0


def test_unknown_only_tuple_blocks_do_not_prove_same_cross_source_action(computed):
    pairs=computed[1];s=computed[-1]
    observed=[p for p in pairs if p['observed_unknown_only_gate_witnesses']]
    assert len(observed)==4
    assert sum(len(p['observed_unknown_only_gate_witnesses']) for p in observed)==11
    assert all(not w['trusted_scoped_instance'] for p in observed for w in p['observed_unknown_only_gate_witnesses'])
    assert s['POTENTIAL_FRAGMENTATION_DUE_TO_UNKNOWN_BEHAVIOR_COUNT']==0
    assert s['UNKNOWN_LABEL_ONLY_BLOCK_WITHOUT_TRUSTED_CROSS_SOURCE_IDENTITY_STAGE_COUNT']==5


def test_frozen_rejections_distinguish_boundary_and_transitive_internal_pairs(frozen,computed):
    s=computed[-1]
    assert len(frozen['stages']['diagnostics'])==1281
    assert sum(s['STAGE_SPLIT_REASON_COUNTS'].values())==1092
    assert s['STAGE_SPLIT_REASON_COUNTS']==dict(semantic_conflict=715,dynamic_time_conflict=106,
        distinct_observed_url=210,distinct_observed_command=55,distinct_strong_context=6)
    assert s['INTRA_STAGE_REJECTION_COUNTS']=={'dynamic_time_conflict':189}
    assert s['ALL_FROZEN_REJECTION_REASON_COUNTS']['dynamic_time_conflict']==295
    assert s['HARD_CONFLICT_FRAGMENTATION_PAIR_COUNT']==81


def test_three_consecutive_time_boundaries_have_original_first_gate_proof(computed):
    data,pairs=computed[:2]
    flagged=[p for p in pairs if p['POTENTIAL_TIME_OVER_FRAGMENTATION']]
    assert len(flagged)==3
    seen=set();history_counts=set()
    for p in flagged:
        seen.update((p['stage_a'],p['stage_b']))
        assert p['behavior_same'] and not p['hard_conflict'] and p['shared_flow']
        assert len(p['consecutive_time_witnesses'])==1
        w=p['consecutive_time_witnesses'][0]
        assert w['original_diagnostic']['reason']=='dynamic_time_conflict'
        assert w['delta_seconds']==42 and w['temporal_snapshot']['dynamic_threshold_seconds']==30
        assert w['temporal_snapshot']['fallback_used']
        history_counts.add(w['temporal_snapshot']['interval_count'])
    assert history_counts=={0,1,2}
    assert len(seen)==4 and seen<=data['isolated']
    assert sorted(data['stages'][s]['alert_count'] for s in seen)==[1,1,1,2]


def test_polling_series_retains_same_original_flow_tuple_url_and_signature(computed):
    data,pairs=computed[:2]
    stages={s for p in pairs if p['POTENTIAL_TIME_OVER_FRAGMENTATION'] for s in (p['stage_a'],p['stage_b'])}
    alerts=[data['alerts'][a] for s in stages for a in data['stages'][s]['alert_ids']]
    assert len(alerts)==5 and {a.source_namespace for a in alerts}=={'traceback.lab.ids'}
    assert {a.url for a in alerts}=={'/health/poll'}
    assert len({a.signature for a in alerts})==1
    assert 'Repeated uncommon outbound polling' in alerts[0].signature
    assert len({(a.src_ip,a.src_port,a.dst_ip,a.dst_port) for a in alerts})==1
    assert len({(r.scope,r.value) for a in alerts for r in a.contexts if r.kind=='flow'})==1
    times=sorted(audit.sec(a.timestamp) for a in alerts)
    assert [b-a for a,b in zip(times,times[1:])]==[42]*4


def test_last_two_polling_alerts_pass_only_after_three_prior_intervals(computed):
    data,pairs=computed[:2]
    stages={s for p in pairs if p['POTENTIAL_TIME_OVER_FRAGMENTATION'] for s in (p['stage_a'],p['stage_b'])}
    stage=next(data['stages'][s] for s in stages if data['stages'][s]['alert_count']==2)
    later=max(stage['alert_ids'],key=lambda i:audit.sec(data['alerts'][i].timestamp))
    snapshot=data['histories'][later]
    assert snapshot==dict(interval_count=3,mean_interval_seconds=42.,interval_std_seconds=0.,dynamic_threshold_seconds=42.,fallback_used=False)
    assert len(stage['aggregation_basis'])==1 and stage['aggregation_basis'][0]['temporal_check']['passed']


def test_distant_pair_combinations_are_not_counted_as_consecutive_cuts(computed):
    pairs=computed[1]
    time_only_clean=[p for p in pairs if p['time_only_trusted_witness_count'] and not p['hard_conflict']]
    assert len(time_only_clean)==6
    assert sum(p['POTENTIAL_TIME_OVER_FRAGMENTATION'] for p in time_only_clean)==3
    assert all(not p['POTENTIAL_TIME_OVER_FRAGMENTATION'] for p in time_only_clean if not p['time_only_consecutive_trusted_witness_count'])


def test_clean_member_witness_cannot_override_a_whole_stage_conflict(computed):
    pairs=computed[1]
    review=[p for p in pairs if p['time_only_trusted_witness_count'] and p['hard_conflict']]
    assert len(review)==1
    p=review[0]
    assert p['hard_conflict_types']=={'distinct_strong_context':1}
    assert not p['POTENTIAL_TIME_OVER_FRAGMENTATION']
    assert p['audit_assessment']=='KEEP_SEPARATE_UNDER_CURRENT_STAGE_CONTRACT'
    trio=[p for p in pairs if all(s.startswith(('stg_64c5','stg_c8ee','stg_f905')) for s in (p['stage_a'],p['stage_b']))]
    assert len(trio)==3 and all(p['hard_conflict'] for p in trio)


def test_bare_cross_source_tuple_is_ambiguous_without_native_scope(computed):
    review=[p for p in computed[1] if p['audit_assessment']=='AMBIGUOUS_CROSS_SOURCE_TUPLE_WITHOUT_NATIVE_SCOPE']
    assert len(review)==2
    assert sorted(p['time_gap_seconds'] for p in review)==[55,286]
    for p in review:
        assert p['behavior_same'] and p['existing_stage6_binding_kinds']==['flow']
        assert not p['shared_strong_identity_kinds'] and not p['hard_conflict']
        assert not p['POTENTIAL_TIME_OVER_FRAGMENTATION'] and not p['potential_cross_source_duplicate']


def test_process_auth_request_object_instances_are_not_inferred_from_context(computed):
    pairs=computed[1];s=computed[-1]
    assert all(not p[k] for p in pairs for k in ('shared_process_instance','parent_child_process','process_descriptor_only',
        'shared_auth_session','shared_request','shared_object','shared_network_session'))
    assert all(p['auth_establish_use_audit']=='NO_SHARED_AUTH_SESSION' for p in pairs)
    assert s['SAME_PROCESS_INSTANCE_STAGE_PAIR_COUNT']==s['PARENT_CHILD_PROCESS_STAGE_PAIR_COUNT']==s['PROCESS_DESCRIPTOR_ONLY_PAIR_COUNT']==0


def test_scoped_flow_reader_does_not_unify_equal_native_ids_across_scopes(computed):
    data=computed[0]
    aid=next(i for i,a in data['alerts'].items() if any(c.kind=='flow' for c in a.contexts))
    alert=data['alerts'][aid];profile=data['profiles'][aid]
    original=audit.native_instances(alert,profile)
    changed=alert.model_copy(update={'contexts':[r.model_copy(update={'scope':r.scope+':other'}) if r.kind=='flow' else r for r in alert.contexts]})
    other=audit.native_instances(changed,profile)
    first={k for k,v in original.items() if v['kind']=='scoped_native_flow'}
    second={k for k,v in other.items() if v['kind']=='scoped_native_flow'}
    assert first and second and first.isdisjoint(second)


def test_parent_process_is_not_read_as_current_process_instance():
    from app.community.evidence import Binding
    binding=Binding(2,'process_instance','process:same',(),role='parent_process',identity='{}')
    assert audit.native_instances(SimpleNamespace(contexts=[]),SimpleNamespace(bindings=[binding]))=={}
    current=Binding(2,'process_instance','process:same',(),role='process',identity='{}')
    assert len(audit.native_instances(SimpleNamespace(contexts=[]),SimpleNamespace(bindings=[current])))==1


def test_web_supporting_fields_keep_explicit_raw_method_pointers(computed):
    from app.models.base import resolve_pointer
    data,pairs=computed[:2]
    assert any(p['shared_method'] and p['shared_endpoint'] for p in pairs)
    for p in pairs:
        for side in p['observed_method_evidence'].values():
            for item in side:
                assert item['field'] in {'native.method','native.http/http_method'}
                assert resolve_pointer(data['alerts'][item['alert_id']].raw_alert,item['pointer'])==item['value']
    assert sum(p['shared_request'] for p in pairs)==0


def test_structural_bridges_are_not_reported_as_deleted_weak_bridges(frozen,computed):
    stats=frozen['stages']['statistics'];s=computed[-1]
    assert stats['BRIDGE_EDGE_COUNT']==34
    assert stats['WEAK_BRIDGE_REMOVED_COUNT']==stats['WEAK_STAGE_EDGE_COUNT']==stats['NORMAL_STAGE_EDGE_COUNT']==0
    assert stats['STRONG_STAGE_EDGE_COUNT']==229
    assert not [d for d in frozen['stages']['diagnostics'] if d['decision']=='remove_weak_bridge']
    assert s['ISOLATED_STAGE_CREATED_BY_WEAK_BRIDGE_REMOVAL_COUNT']==0


def test_duplicate_counts_have_scoped_identity_evidence_screen(computed):
    pairs=computed[1];s=computed[-1]
    assert s['POTENTIAL_DUPLICATE_STAGE_PAIR_COUNT']==sum(p['DUPLICATED_STAGE_OBSERVATION'] for p in pairs)==0
    assert s['POTENTIAL_CROSS_SOURCE_DUPLICATE_STAGE_COUNT']==0
    assert not [w for p in pairs for w in p['cross_source_same_instance_local_witnesses']]


def test_what_if_does_not_fold_time_policy_concerns_or_create_objects(computed):
    data,_,_,_,_,simulation,_=computed
    assert simulation['checks']==[]
    assert (simulation['WHAT_IF_MERGE_PAIR_COUNT'],simulation['WHAT_IF_STAGE_COUNT'],simulation['WHAT_IF_ISOLATED_STAGE_COUNT'])==(0,42,24)
    assert simulation['stage_objects_created']==simulation['relation_objects_created']==0
    assert len(simulation['relation_endpoint_remapping'])==len(data['relations'])==23
    assert all(x['original_endpoints']==x['temporary_endpoints'] for x in simulation['relation_endpoint_remapping'])


def test_classification_is_exhaustive_with_potential_not_confirmed_time_errors(computed):
    _,pairs,stages,isolated,_,simulation,s=computed
    assert s['ISOLATED_STAGE_CLASS_COUNTS']==dict(zip(audit.CLASSES,[14,4,0,4,0,0,2]))
    assert (s['LEGITIMATE_STAGE_COUNT'],s['POTENTIALLY_OVER_FRAGMENTED_STAGE_COUNT'],s['AMBIGUOUS_STAGE_COUNT'])==(36,4,2)
    assert s['FINAL_DIAGNOSIS']=='STAGE6_FRAGMENTATION_PARTIAL'
    assert audit.validate(s,stages,isolated,pairs,simulation)
    assert all('NOT_PROVEN_ERROR' in r['confidence'] for r in isolated if r['fragmentation_class'].startswith('POSSIBLE'))


def test_temporal_nearest_distribution_covers_every_isolate(computed):
    data,_,_,isolated,*_=computed
    assert computed[-1]['NEAREST_STAGE_GAP_DISTRIBUTION']==dict(count=24,min=0,median=21,p75=28,p90=28,max=286)
    for r in isolated:
        neighbor=data['stages'][r['nearest_stage_id']]
        assert neighbor['community_id']==r['community_id']
        for field in ('previous_stage_id','next_stage_id'):
            assert r[field] is None or data['stages'][r[field]]['community_id']==r['community_id']


def test_guard_blocks_production_pair_evidence_before_any_work():
    from app.stages.evidence import pair_evidence
    with pytest.raises(AssertionError,match='must_not_rebuild_or_rejudge'):
        with audit.prohibit_builders():pair_evidence(None,None,None,None,None)
    assert sys.getprofile() is None


def test_duplicate_or_lost_membership_is_rejected(frozen):
    broken=deepcopy(frozen)
    broken['stages']['stages'][0]['alert_ids'].append(broken['stages']['stages'][0]['alert_ids'][0])
    with pytest.raises(ValueError,match='partition_not_exact'):audit.prepare(broken)


def test_behavior_loss_is_rejected_without_remapping(frozen):
    broken=deepcopy(frozen)
    broken['stages']['behaviors'][0]['behavior']='UNEXPECTED_TEST_LABEL'
    with pytest.raises(ValueError,match='behavior_lost'):audit.prepare(broken)


def test_persisted_outputs_match_fresh_read_only_diagnosis(computed):
    _,pairs,stages,isolated,communities,simulation,s=computed
    for name,expected in [('summary.json',s),('neighbor_pairs.json',pairs),('stages.json',stages),
        ('isolated_stages.json',isolated),('communities.json',communities),('what_if_merge.json',simulation)]:
        assert load(name)==json.loads(json.dumps(expected))


def test_original_489_files_including_dataset_gt_and_previous_audits_are_unchanged():
    protected=load('protected_before.json')
    assert len(protected)==489
    assert sum('TraceBack-Dataset' in p for p in protected)==18
    assert all(Path(p).is_file() and audit.sha(p)==expected for p,expected in protected.items())
    assert load('integrity.json')['EXISTING_FILES_CHANGED']==[]

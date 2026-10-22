"""Synthetic ⑦ contracts; forbidden downstream modules never supply fixtures."""
import builtins
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import random
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.community.models import community_id
from app.stage_candidates import generate_stage_pair_candidates, load_candidate_config, StagePairCandidateResult
from app.stages import load_stage_config
from app.stages.behavior import normalize_behavior
from app.stages.models import Stage, StageResult, stage_id
from test_community_builder import cfg, normalization, record, run
from test_source_bound_projection import settings

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def candidate_policy():
    return load_candidate_config(ROOT/'configs/stage-candidates-v1.yaml')


def source(rows, cfg, normalization, *, split=True, overrides=None):
    upstream = run(rows, cfg, normalization, overrides=overrides)
    aa = sorted(upstream.alerts, key=lambda a:a.alert_id)
    ee = {e.entity_id:e for e in upstream.entities}
    behavior_policy = load_stage_config(ROOT/'configs/behavior-stage-v1.yaml')
    common = community_id([a.alert_id for a in aa])
    stages, annotations = [], []
    for alert in aa:
        cid = community_id([alert.alert_id]) if split else common
        annotation = normalize_behavior(alert, behavior_policy).model_copy(update=dict(community_id=cid))
        annotations.append(annotation)
        def eids(kind):
            return sorted({o.entity_id for o in alert.entity_occurrences if ee[o.entity_id].type.value == kind})
        stages.append(Stage(stage_id=stage_id(cid, annotation.behavior, [alert.alert_id]), community_id=cid,
            behavior=annotation.behavior, start_time=alert.timestamp, end_time=alert.timestamp,
            alert_ids=[alert.alert_id], alert_count=1, source_types=[alert.source_type.value],
            host_entities=eids('HOST'), account_entities=eids('ACCOUNT'), process_entities=eids('PROCESS'),
            request_bindings=[], session_bindings=[], flow_bindings=[], task_bindings=[],
            evidence_summary='synthetic singleton; upstream partition only', aggregation_basis=[]))
    ss = {a.source_namespace:replace(settings(a.raw_alert['source_type']), **(overrides or {}).get(a.raw_alert['source_type'], {})) for a in aa}
    return SimpleNamespace(stages=StageResult(config_hash=behavior_policy.digest, behaviors=annotations,
        stages=stages, diagnostics=[], statistics={}), alerts=aa, entities=list(ee.values()), settings=ss)


def generate(data, cfg, policy):
    original = deepcopy(data)
    result = generate_stage_pair_candidates(data.stages, data.alerts, data.entities, data.settings, cfg, policy)
    assert data == original
    assert StagePairCandidateResult.model_validate_json(result.model_dump_json()) == result
    return result


@pytest.mark.parametrize('field,reason', [('request_id','SHARED_SCOPED_REQUEST'),('session_id','SHARED_SCOPED_SESSION'),
    ('connection_id','SHARED_SCOPED_CONNECTION'),('application_session_id','SHARED_SCOPED_APPLICATION_SESSION'),
    ('auth_session_id','SHARED_SCOPED_SESSION'),('task_id','SHARED_SCOPED_TASK'),('flow_id','SHARED_SCOPED_FLOW')])
def test_same_typed_scoped_binding_cross_community(cfg, normalization, candidate_policy, field, reason):
    data = source([record(i,time=i,**{field:'bound'}) for i in (1,2)],cfg,normalization)
    candidate, = generate(data,cfg,candidate_policy).candidates
    assert not candidate.same_community and reason in candidate.candidate_reasons
    for feature in candidate.retrieval_features:
        assert feature.stage_id in {candidate.stage_a_id,candidate.stage_b_id}
        for witness in feature.witnesses:
            for pointer in witness.pointers:
                pointer.resolve({a.alert_id:a for a in data.alerts})


def test_process_parent_child_is_an_undirected_hint(cfg, normalization, candidate_policy):
    data = source([record(1,hostname='h',process_id=1,process_start_time='2026-01-01T00:00:00Z'),
        record(2,time=5,hostname='h',process_id=2,process_start_time='2026-01-01T00:00:02Z',
               parent_process_id=1,parent_process_start_time='2026-01-01T00:00:00Z')],cfg,normalization)
    candidate, = generate(data,cfg,candidate_policy).candidates
    assert 'PARENT_CHILD_PROCESS_HINT' in candidate.candidate_reasons
    assert candidate.stage_a_id < candidate.stage_b_id
    assert not set(candidate.model_dump()) & {'source_stage_id','target_stage_id','relation_type','confidence','direction_basis'}


def test_process_name_alone_does_not_retrieve(cfg, normalization, candidate_policy):
    data = source([record(i,hostname='h',process_name='cmd.exe',time=i) for i in range(30)],cfg,normalization)
    result = generate(data,cfg,candidate_policy)
    assert not result.candidates
    assert not any(f.kind == 'process_instance' for f in result.features)


@pytest.mark.parametrize('split', [True,False])
def test_no_shared_feature_or_community_alone_never_retrieves(cfg, normalization, candidate_policy, split):
    data = source([record(i,time=i) for i in (1,2)],cfg,normalization,split=split)
    assert not generate(data,cfg,candidate_policy).candidates


@pytest.mark.parametrize('fields', [dict(hostname='public-host'),dict(source='waf',uri='https://example.test/common'),
    dict(command_line='common-command'),dict(dst_ip='10.0.1.5')])
def test_public_weak_key_cannot_expand_to_all_pairs(cfg, normalization, candidate_policy, fields):
    data = source([record(i,time=i,**fields) for i in range(30)],cfg,normalization,split=False)
    result = generate(data,cfg,candidate_policy)
    assert not result.candidates
    assert result.statistics['POSTING_PAIR_VISIT_COUNT'] == 0
    assert result.diagnostics


def test_high_frequency_host_uses_independent_account_and_keeps_binding(cfg, normalization, candidate_policy):
    data = source([record(i,hostname='h',user='shared' if i < 2 else f'u{i}',time=i) for i in range(30)],cfg,normalization)
    result = generate(data,cfg,candidate_policy)
    candidate, = result.candidates
    assert candidate.candidate_reasons == ['SHARED_ACCOUNT_AT_HOST']
    assert result.statistics['SUPPRESSED_COMMON_WEAK_KEY_COUNT'] >= 1
    bound = source([record(i,hostname='h',request_id='r',time=i) for i in range(15)],cfg,normalization)
    assert len(generate(bound,cfg,candidate_policy).candidates) == 105


def test_weak_url_needs_independent_host_and_temporal_locality(cfg, normalization, candidate_policy):
    assert not generate(source([record(i,source='waf',uri='/shared',time=i) for i in (1,2)],cfg,normalization),cfg,candidate_policy).candidates
    near = source([record(i,source='waf',server_host='h',uri='/shared',time=i) for i in (1,2)],cfg,normalization)
    pair, = generate(near,cfg,candidate_policy).candidates
    assert 'SHARED_HOST_AND_URL' in pair.candidate_reasons
    far = source([record(1,source='waf',server_host='h',uri='/shared'),record(2,source='waf',server_host='h',uri='/shared',time=1000)],cfg,normalization)
    assert not generate(far,cfg,candidate_policy).candidates


def test_multiple_reasons_merge_no_self_or_duplicate_and_stable_id(cfg, normalization, candidate_policy):
    data = source([record(i,time=i,request_id='r',session_id='s',hostname='h') for i in range(3)],cfg,normalization)
    result = generate(data,cfg,candidate_policy)
    assert len(result.candidates) == 3
    for pair in result.candidates:
        assert {'SHARED_SCOPED_REQUEST','SHARED_SCOPED_SESSION'} <= set(pair.candidate_reasons)
        assert pair.stage_a_id < pair.stage_b_id
    assert result.statistics['SELF_PAIR_COUNT'] == result.statistics['DUPLICATE_PAIR_COUNT'] == 0


def test_input_permutations_preserve_entire_result(cfg, normalization, candidate_policy):
    data = source([record(i,hostname='h',user='u',request_id='r',time=i) for i in range(4)],cfg,normalization)
    expected = generate(data,cfg,candidate_policy)
    rng = random.Random(7)
    for _ in range(3):
        for items in (data.stages.stages,data.stages.behaviors,data.alerts,data.entities):
            rng.shuffle(items)
        assert generate(data,cfg,candidate_policy) == expected


def test_scope_keeps_same_token_on_different_hosts_separate(cfg, normalization, candidate_policy):
    data = source([record(i,hostname=f'h{i}',request_id='r',flow_id='f',time=i) for i in (1,2)],cfg,normalization)
    assert not generate(data,cfg,candidate_policy).candidates


def test_cross_source_requires_declared_shared_binding_scope(cfg, normalization, candidate_policy):
    rows = [record(1,request_id='r'),record(2,source='waf',request_id='r',time=5)]
    data = source(rows,cfg,normalization)
    assert not generate(data,cfg,candidate_policy).candidates
    shared = source(rows,cfg,normalization,overrides={s:dict(session_scope='shared-application') for s in ('edr','waf')})
    pair, = generate(shared,cfg,candidate_policy).candidates
    assert 'SHARED_SCOPED_REQUEST' in pair.candidate_reasons


def test_cross_source_tuple_respects_network_scope(cfg, normalization, candidate_policy):
    network = dict(src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=1234,dst_port=443,protocol='tcp')
    rows = [record(1,**network),record(2,source='firewall',time=5,**network)]
    data = source(rows,cfg,normalization)
    pair, = generate(data,cfg,candidate_policy).candidates
    assert 'SAME_NETWORK_TUPLE' in pair.candidate_reasons
    scoped = source(rows,cfg,normalization,overrides={s:dict(network_namespace=s) for s in ('edr','firewall')})
    assert not generate(scoped,cfg,candidate_policy).candidates


def test_object_hostname_hint_survives_alternative_native_asset_id(cfg, normalization, candidate_policy):
    data = source([record(1,source='waf',server_host='web',request_object_id='ticket'),
                   record(2,source='waf',time=5,server_host='web',asset_id='native-asset',response_object_id='ticket')],cfg,normalization)
    pair, = generate(data,cfg,candidate_policy).candidates
    assert pair.candidate_reasons == ['SHARED_OBJECT_AT_OBSERVED_HOST']
    assert not pair.same_community
    different = source([record(1,source='waf',server_host='a',request_object_id='ticket'),
                        record(2,source='waf',time=5,server_host='b',response_object_id='ticket')],cfg,normalization)
    assert not generate(different,cfg,candidate_policy).candidates


def test_file_and_executable_observations_share_host_scoped_path_only(cfg, normalization, candidate_policy):
    data = source([record(1,hostname='h',file_path='/tmp/object'),
                   record(2,hostname='h',executable='/tmp/object',time=5)],cfg,normalization)
    pair, = generate(data,cfg,candidate_policy).candidates
    assert 'SHARED_FILE_AT_HOST' in pair.candidate_reasons
    other = source([record(1,hostname='a',file_path='/tmp/object'),
                    record(2,hostname='b',executable='/tmp/object',time=5)],cfg,normalization)
    assert not generate(other,cfg,candidate_policy).candidates


def test_host_login_id_retrieval_keeps_original_source_scopes(cfg, normalization, candidate_policy):
    data = source([record(1,hostname='host',logon_id='login'),
                   record(2,source='authentication',host='host',logon_id='login',time=5)],cfg,normalization)
    pair, = generate(data,cfg,candidate_policy).candidates
    assert 'SHARED_HOST_AUTH_SESSION' in pair.candidate_reasons
    witnesses = [w for f in pair.retrieval_features if f.kind == 'host_auth_session' for w in f.witnesses]
    assert len({w.source_namespace for w in witnesses}) == 2
    assert len({w.context_scope for w in witnesses}) == 2
    other = source([record(1,hostname='a',logon_id='login'),
                    record(2,source='authentication',host='b',logon_id='login',time=5)],cfg,normalization)
    assert not generate(other,cfg,candidate_policy).candidates


@pytest.mark.parametrize('right_endpoint,scopes,expected', [
    ('192.0.2.2',None,True),('192.0.2.3',None,False),
    ('192.0.2.2',{'edr':dict(network_namespace='a'),'authentication':dict(network_namespace='b')},False)])
def test_cross_source_connection_requires_both_endpoints_and_compatible_declared_scope(
        cfg, normalization, candidate_policy,right_endpoint,scopes,expected):
    rows = [record(1,src_ip='192.0.2.1',dst_ip='192.0.2.2',connection_id='c'),
            record(2,source='authentication',source_ip='192.0.2.1',host_ip=right_endpoint,connection_id='c',time=5)]
    actual_scopes = scopes if scopes is not None else {s:dict(network_namespace=None) for s in ('edr','authentication')}
    data = source(rows,cfg,normalization,overrides=actual_scopes)
    result = generate(data,cfg,candidate_policy)
    assert bool(result.candidates) == expected
    if expected:
        assert result.candidates[0].candidate_reasons == ['SHARED_CONNECTION_TOKEN_AND_ENDPOINT_PAIR']


def test_production_uses_no_files_truth_or_downstream(cfg, normalization, candidate_policy, monkeypatch):
    data = source([record(i,request_id='r',time=i) for i in (1,2)],cfg,normalization)
    def forbidden(*args,**kwargs):
        raise AssertionError('candidate generation must not open files')
    original_import = builtins.__import__
    def guarded(name,*args,**kwargs):
        assert not name.startswith(('evaluation','app.stage_relations','app.stage_chains','app.evidence_trace','app.api','app.ai'))
        return original_import(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',guarded)
    monkeypatch.setattr(builtins,'open',forbidden)
    monkeypatch.setattr(Path,'open',forbidden)
    result = generate(data,cfg,candidate_policy)
    assert len(result.candidates) == 1


def test_connection_locality_uses_binding_window_including_boundary(cfg, normalization, candidate_policy):
    window = cfg.windows_seconds[candidate_policy.connection_context_window_tier]
    for gap, expected in [(window,True),(window+1,False)]:
        rows = [record(1,src_ip='192.0.2.1',dst_ip='192.0.2.2',connection_id='c'),
                record(2,source='authentication',source_ip='192.0.2.1',host_ip='192.0.2.2',connection_id='c',time=gap)]
        data = source(rows,cfg,normalization,overrides={s:dict(network_namespace=None) for s in ('edr','authentication')})
        result = generate(data,cfg,candidate_policy)
        assert bool(result.candidates) == expected


def test_current_official_stage_object_directly_feeds_generator_and_returns(tmp_path, monkeypatch):
    import app.services.stage_pipeline as pipeline
    import app.stages.aggregation as aggregation
    original_aggregate, original_generate = aggregation.aggregate_stages, pipeline.generate_stage_pair_candidates
    seen = {}
    def aggregate(*args,**kwargs):
        seen['stages'] = original_aggregate(*args,**kwargs)
        return seen['stages']
    def candidates(stages,*args,**kwargs):
        assert stages is seen['stages']
        seen['candidates'] = original_generate(stages,*args,**kwargs)
        return seen['candidates']
    monkeypatch.setattr(aggregation,'aggregate_stages',aggregate)
    monkeypatch.setattr(pipeline,'generate_stage_pair_candidates',candidates)
    path = tmp_path/'native.jsonl'
    rows = [record(1,hostname='h',request_id='r',operation='HTTPRequest'),
            record(2,time=5,hostname='h',request_id='r',operation='ProcessStart')]
    path.write_text(''.join(json.dumps(dict(source_type='edr',event=row))+'\n' for row in rows),encoding='utf8')
    original_import = builtins.__import__
    def guarded(name,*args,**kwargs):
        assert not name.startswith(('evaluation','app.stage_relations','app.stage_chains','app.evidence_trace','app.api','app.ai'))
        return original_import(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',guarded)
    result = pipeline.load_stage_pipeline(path)
    assert result.stages is seen['stages'] and result.candidate_result is seen['candidates']
    assert len(result.candidates) == 1 and not result.statistics['NEXT_STAGE_STARTED']
    assert list(tmp_path.iterdir()) == [path]


def test_corrupt_partition_duplicate_ids_and_disabled_features(cfg, normalization, candidate_policy):
    data = source([record(i,request_id='r',time=i) for i in (1,2)],cfg,normalization)
    off = candidate_policy.model_copy(update=dict(enabled_feature_kinds=[]))
    assert not generate(data,cfg,off).candidates
    with pytest.raises(ValueError,match='unique'):
        generate_stage_pair_candidates(data.stages,data.alerts+data.alerts[:1],data.entities,data.settings,cfg,candidate_policy)
    with pytest.raises((ValueError,ValidationError),match='partition|annotation'):
        generate_stage_pair_candidates(data.stages.model_copy(update=dict(stages=data.stages.stages[:1])),
            data.alerts,data.entities,data.settings,cfg,candidate_policy)

"""Behavior fallback, conservative membership, provenance and isolation checks."""
import builtins
from dataclasses import replace
import json
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.ai.provider import ProviderConfig
from app.community import prepare_communities
from app.stages import aggregate_stages, load_stage_config, normalize_behavior, Stage, StageResult, VOCABULARY
from app.stages.config import StageConfig
from app.stages.resolver import AISemanticResolver
from app.utils.stable_id import canonical_json
from test_community_builder import cfg, normalization, record, run
from test_source_bound_projection import settings

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def policy():
    return load_stage_config(ROOT/'configs/behavior-stage-v1.yaml')


class Resolver:
    def __init__(self, behavior='DISCOVERY', confidence=0.95, **extras):
        self.answer = dict(behavior=behavior, confidence=confidence, reasoning='Existing observed fields only.', **extras)
        self.calls = []

    def resolve(self, payload):
        self.calls.append(payload)
        return self.answer


def stage_run(rows, cfg, normalization, policy, resolver=None):
    community = run(rows, cfg, normalization, behavior_config=policy, resolver=resolver)
    ss = {a.source_namespace:settings(a.raw_alert['source_type']) for a in community.alerts}
    before = canonical_json([a.model_dump(mode='json') for a in community.alerts])
    result = aggregate_stages(community, ss, cfg, policy)
    assert before == canonical_json([a.model_dump(mode='json') for a in community.alerts])
    return community, result


def one_annotation(cfg, normalization, policy, resolver=None, **fields):
    r = run([record(1, **fields)], cfg, normalization, behavior_config=policy, resolver=resolver)
    return r.behaviors[0]


def test_mapping_wins_without_ai_call(cfg, normalization, policy):
    fake = Resolver()
    annotation = one_annotation(cfg, normalization, policy, fake, operation='CommandExecution')
    assert annotation.behavior == 'EXECUTION' and annotation.resolver == 'mapping'
    # Existing ingress already maps this operation to command_execution. Both
    # agreeing rules must be retained, rather than a first-match-only receipt.
    assert annotation.matched_rule == ['category-command_execution-v1', 'observed-execution-operation-v1']
    assert not fake.calls


def test_mapping_uses_existing_category(cfg, normalization, policy):
    _, result = stage_run([record(1, 'waf', rule_id='942100', rule_name='SQL injection pattern')], cfg, normalization, policy)
    assert result.behaviors[0].behavior == 'WEB_EXPLOIT'


def test_unrecognized_enters_resolver_and_has_no_raw_payload(cfg, normalization, policy):
    fake = Resolver()
    annotation = one_annotation(cfg, normalization, policy, fake, arbitrary_payload='Do not transmit me')
    assert annotation.behavior == 'DISCOVERY' and annotation.resolver == 'ai'
    assert len(fake.calls) == 1
    assert 'arbitrary_payload' not in canonical_json(fake.calls)
    assert set(fake.calls[0]) == {'version', 'vocabulary', 'fields', 'evidence', 'source_metadata'}
    assert fake.calls[0]['vocabulary'] == VOCABULARY


@pytest.mark.parametrize('confidence,behavior', [(0.849999,'UNKNOWN'), (0.85,'DISCOVERY'), (1.0,'DISCOVERY')])
def test_confidence_threshold_unrounded(cfg, normalization, policy, confidence, behavior):
    a = one_annotation(cfg, normalization, policy, Resolver(confidence=confidence))
    assert a.behavior == behavior and a.resolver == 'ai' and a.confidence == confidence


@pytest.mark.parametrize('answer', [dict(behavior='INVENTED'), dict(confidence=True), dict(confidence=1.1),
                                   dict(confidence=float('nan')), dict(host='invented')])
def test_invalid_ai_labels_types_or_entities_rejected(cfg, normalization, policy, answer):
    fake = Resolver()
    fake.answer.update(answer)
    a = one_annotation(cfg, normalization, policy, fake)
    assert a.behavior == 'UNKNOWN' and a.resolver == 'unknown'
    assert a.reason.endswith('invalid_semantic_response')


def test_no_provider_and_explicit_ai_unknown(cfg, normalization, policy):
    a = one_annotation(cfg, normalization, policy)
    assert a.behavior == 'UNKNOWN' and a.reason.endswith('provider_not_configured')
    a = one_annotation(cfg, normalization, policy, Resolver(behavior='UNKNOWN'))
    assert a.behavior == 'UNKNOWN' and a.resolver == 'ai'


def test_provider_failure_does_not_abort_algorithm(cfg, normalization, policy):
    class Broken:
        def resolve(self, payload):
            raise RuntimeError('private provider body')
    a = one_annotation(cfg, normalization, policy, Broken())
    assert a.behavior == 'UNKNOWN' and 'private' not in a.reason


def test_mapping_conflict_falls_back_instead_of_first_rule(cfg, normalization, policy):
    raw = policy.model_dump()
    extra = dict(raw['rules'][0], id='contradiction', all=[dict(field='alert_type',op='in',values=['CommandExecution'])], behavior='IMPACT')
    raw['rules'].append(extra)
    conflict = StageConfig.model_validate(raw)
    fake = Resolver(behavior='EXECUTION')
    a = one_annotation(cfg, normalization, conflict, fake, operation='CommandExecution')
    assert a.resolver == 'ai' and a.reason.startswith('mapping_conflict:')


def test_same_behavior_binding_can_aggregate_and_keep_all_ids_and_times(cfg, normalization, policy):
    rows = [record(i, time=i*4, operation='CommandExecution', request_id='request') for i in range(5)]
    community, result = stage_run(rows, cfg, normalization, policy)
    assert len(result.stages) == 1
    s = result.stages[0]
    assert s.alert_ids == sorted(a.alert_id for a in community.alerts)
    assert s.start_time == min(a.timestamp for a in community.alerts)
    assert s.end_time == max(a.timestamp for a in community.alerts)
    assert len(s.aggregation_basis) >= s.alert_count - 1
    alerts = {a.alert_id:a for a in community.alerts}
    for proof in s.aggregation_basis:
        assert any(pointer.resolve(alerts) == 'request' for pointer in proof.evidence)
        for pointer in proof.evidence:
            assert pointer.resolve(alerts) is not None
    assert Stage.model_validate_json(s.model_dump_json(), context=dict(alerts=alerts)) == s
    assert StageResult.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize('changes', [dict(hostname='different'), dict(session_id='different'),
    dict(process_id=8), dict(process_start_time='2026-01-01T00:00:02Z'),
    dict(command_line='different command'), dict(file_path='/different')])
def test_shared_binding_cannot_override_core_or_session_conflicts(cfg, normalization, policy, changes):
    first = record(1, operation='CommandExecution', request_id='r', session_id='same', hostname='host',
        process_id=7, process_start_time='2026-01-01T00:00:00Z', command_line='command', file_path='/file')
    second = dict(first, event_id='2', **changes)
    _, result = stage_run([first, second], cfg, normalization, policy)
    assert len(result.stages) == 2


def test_unknown_is_conservative_with_binding_and_without(cfg, normalization, policy):
    _, result = stage_run([record(i, time=i) for i in range(5)], cfg, normalization, policy)
    assert len(result.stages) == 5
    _, result = stage_run([record(i, time=i, request_id='known') for i in range(3)], cfg, normalization, policy)
    assert len(result.stages) == 1 and result.stages[0].behavior == 'UNKNOWN'
    _, result = stage_run([record(1,request_id='r'),record(2,time=31,request_id='r')], cfg, normalization, policy)
    assert len(result.stages) == 2


def test_time_alone_or_behavior_alone_cannot_aggregate(cfg, normalization, policy):
    _, result = stage_run([record(i,operation='ProcessStart',hostname='same') for i in range(4)], cfg, normalization, policy)
    assert len(result.stages) == 4


def test_behavior_and_two_entity_contexts_form_normal_edges(cfg, normalization, policy):
    _, result = stage_run([record(i,operation='ProcessStart',hostname='same',user='Alice') for i in range(4)], cfg, normalization, policy)
    assert len(result.stages) == 1
    assert all(e.edge_strength == 'NORMAL' for e in result.stages[0].aggregation_basis)


def test_core_instance_without_binding_can_group(cfg, normalization, policy):
    first = record(1, operation='ProcessStart', hostname='h', process_id=7, process_start_time='2026-01-01T00:00:00Z')
    _, result = stage_run([first,dict(first,event_id='2')], cfg, normalization, policy)
    assert len(result.stages) == 1
    assert result.stages[0].aggregation_basis[0].rule == 'consistent_core_context'


def test_dynamic_time_and_component_conflict_prevent_chaining(cfg, normalization, policy):
    rows = [record(i,time=i*100,operation='ProcessStart',request_id='r') for i in range(3)]
    community, result = stage_run(rows,cfg,normalization,policy)
    assert len(community.result.incident_candidates) == 1
    assert sorted(s.alert_count for s in result.stages) == [1,1,1]
    rows = [record(1,operation='ProcessStart',request_id='r',session_id='s1'),
            record(2,operation='ProcessStart',request_id='r'),
            record(3,operation='ProcessStart',request_id='r',session_id='s2')]
    _, result = stage_run(rows,cfg,normalization,policy)
    assert sorted(s.alert_count for s in result.stages) == [1,2]


def test_different_behavior_does_not_merge_on_shared_binding(cfg, normalization, policy):
    _, result = stage_run([record(1,request_id='r',operation='ProcessStart'),
                          record(2,request_id='r',operation='FileRead')],cfg,normalization,policy)
    assert len(result.stages) == 2


def test_never_crosses_community_and_is_order_deterministic(cfg, normalization, policy):
    small = cfg.model_copy(update=dict(max_community_members=2,max_weak_members=2))
    rows = [record(i,time=i,operation='ProcessStart',request_id='r') for i in range(4)]
    community, result = stage_run(rows,small,normalization,policy)
    assert len(community.result.incident_candidates) == 2
    assert len(result.stages) == 2 and result.statistics['CROSS_COMMUNITY_STAGE_MERGES'] == 0
    _, reverse = stage_run(rows[::-1],small,normalization,policy)
    assert result == reverse


def test_partition_schema_and_identity_tampering_rejected(cfg, normalization, policy):
    community, result = stage_run([record(1,request_id='r'),record(2,request_id='r')],cfg,normalization,policy)
    for change in (dict(alert_count=3),dict(stage_id='stg_'+'0'*64),dict(aggregation_basis=[]),dict(invented=True)):
        with pytest.raises(ValidationError):
            Stage.model_validate({**result.stages[0].model_dump(),**change})
    with pytest.raises(ValidationError):
        StageResult.model_validate({**result.model_dump(), 'stages':[]})
    broken = replace(community, alerts=community.alerts[:1])
    with pytest.raises(ValueError, match='community_partition'):
        aggregate_stages(broken,{},cfg,policy)


def test_empty_input(cfg, policy):
    result = aggregate_stages(prepare_communities([],{},cfg),{},cfg,policy)
    assert not result.stages and not result.behaviors


def test_configuration_fail_fast_and_rule_reordering_stable(policy):
    assert StageConfig.model_validate({**policy.model_dump(), 'rules':list(reversed(policy.model_dump()['rules']))}).digest == policy.digest
    for change in (dict(ai_confidence_threshold=True),dict(unknown_max_stage_span_seconds=99999), dict(extra='bad')):
        with pytest.raises(ValidationError):
            StageConfig.model_validate({**policy.model_dump(),**change})


def test_evidence_trace_to_raw_and_entity_union(cfg, normalization, policy):
    first = record(1,operation='ProcessStart',request_id='r',hostname='h',user='Alice',
        process_id=7,process_start_time='2026-01-01T00:00:00Z',parent_process_id=6,
        parent_process_start_time='2025-12-31T23:59:00Z')
    community, result = stage_run([first,dict(first,event_id='2')],cfg,normalization,policy)
    stage = result.stages[0]
    entities = {e.entity_id:e for e in community.entities}
    assert len(stage.process_entities) == 2  # Preserve current AND parent process references.
    alerts = {a.alert_id:a for a in community.alerts}
    expected = {eid for a in community.alerts for eid in a.entity_ids if entities[eid].type.value == 'PROCESS'}
    assert set(stage.process_entities) == expected
    for annotation in result.behaviors:
        for pointer in annotation.evidence:
            assert pointer.resolve(alerts) is not None
    context = dict(alerts=alerts,entities=entities)
    for change in (dict(process_entities=[]),dict(source_types=['other']),dict(start_time='2025-01-01T00:00:00Z')):
        with pytest.raises(ValidationError):
            Stage.model_validate({**stage.model_dump(),**change},context=context)


def test_distinct_flow_and_request_block_even_shared_session(cfg, normalization, policy):
    first=record(1,operation='NetworkConnection',session_id='s',request_id='r',
        src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=1111,dst_port=443,protocol='TCP')
    for changes in (dict(src_port=2222),dict(request_id='different')):
        _,result=stage_run([first,dict(first,event_id='2',**changes)],cfg,normalization,policy)
        assert len(result.stages)==2


def test_runtime_no_truth_reads_no_chain_import_and_label_rejection(cfg, normalization, policy, monkeypatch):
    original_import, original_open = builtins.__import__, Path.open
    def guarded_import(name,*args,**kwargs):
        assert not name.startswith(('evaluation','app.chains','app.correlation.scoring','app.ai.explanation','app.ai.report'))
        return original_import(name,*args,**kwargs)
    def guarded_open(path,*args,**kwargs):
        assert not any(part.lower() in {'ground_truth','evaluation','archive'} for part in path.parts)
        return original_open(path,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',guarded_import)
    monkeypatch.setattr(Path,'open',guarded_open)
    _, result = stage_run([record(1,request_id='r')],cfg,normalization,policy)
    assert result.stages
    with pytest.raises(ValueError,match='annotation_contamination'):
        stage_run([record(1,label='ATTACK')],cfg,normalization,policy)


def test_real_semantic_transport_prompt_schema_cache_and_failure(tmp_path):
    config = ProviderConfig(base_url='https://provider.test/v1',model='test-model',api_key=SecretStr('private'),max_retries=0)
    payload = dict(version='behavior-stage-v1',vocabulary=VOCABULARY,fields=dict(alert_type='ambiguous'),evidence=[])
    calls = []
    def handler(request):
        body=json.loads(request.content)
        calls.append(body)
        assert 'UNKNOWN' in body['messages'][0]['content']
        assert json.loads(body['messages'][1]['content']) == payload
        return httpx.Response(200,json=dict(choices=[dict(message=dict(content=json.dumps(dict(behavior='UNKNOWN',confidence=0.0,reasoning='Insufficient evidence.'))),finish_reason='stop')]))
    resolver = AISemanticResolver(config,cache_dir=tmp_path,transport=httpx.MockTransport(handler))
    first = resolver.resolve(payload)
    assert resolver.resolve(payload) == first and len(calls) == 1
    def invalid(request):
        return httpx.Response(200,json=dict(choices=[dict(message=dict(content='{"behavior":"INVENTED","confidence":1.0,"reasoning":"bad"}'))]))
    resolver = AISemanticResolver(config,cache_dir=tmp_path/'invalid',transport=httpx.MockTransport(invalid))
    with pytest.raises(ValidationError):
        resolver.resolve(payload)

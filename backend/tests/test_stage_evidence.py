"""Official ⑧ semantics. Fixtures are synthetic, never ATTACK125/GT edits."""
import builtins
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.models.alerts import EvidencePointer
from app.stage_candidates import generate_stage_pair_candidates, load_candidate_config
from app.stage_candidates.models import (FeatureWitness, StageCandidateFeature, StagePairCandidate,
    candidate_id)
from app.stage_evidence import load_evidence_config, validate_stage_pair_candidates, CrossStageEvidenceResult
from app.utils.stable_id import content_digest
from test_community_builder import cfg, normalization, record
from test_stage_candidates import source

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def evidence_policy():
    return load_evidence_config(ROOT/'configs/stage-evidence-v1.yaml')


def handoff(data,cfg):
    result = generate_stage_pair_candidates(data.stages,data.alerts,data.entities,data.settings,cfg,
        load_candidate_config(ROOT/'configs/stage-candidates-v1.yaml'))
    if result.candidates or len(data.stages.stages) != 2:
        return result
    # Isolate ⑧'s contract with a formal synthetic recalled candidate, including
    # no-evidence cases that ⑦ normally prunes. No production recall changes.
    a,b = sorted(data.stages.stages,key=lambda s:s.stage_id)
    identity = dict(synthetic_recall_fixture=True)
    key = 'fixture:'+content_digest(identity)
    features = [StageCandidateFeature(stage_id=s.stage_id,key=key,kind='fixture',identity=identity,
        retrieval_hint='WEAK_RETRIEVAL_HINT',mode='DIRECT',witnesses=[FeatureWitness(
            alert_id=s.alert_ids[0],source_namespace=next(x.source_namespace for x in data.alerts if x.alert_id == s.alert_ids[0]),
            role='fixture',pointers=[EvidencePointer(alert_id=s.alert_ids[0],pointer='/timestamp',side='shared')])]) for s in (a,b)]
    candidate = StagePairCandidate(candidate_id=candidate_id(a.stage_id,b.stage_id),stage_a_id=a.stage_id,stage_b_id=b.stage_id,
        same_community=a.community_id == b.community_id,community_a_id=a.community_id,community_b_id=b.community_id,
        candidate_reasons=['SYNTHETIC_RECALLED_PAIR'],retrieval_keys=[key],candidate_sources=['fixture'],retrieval_features=features,metadata={})
    return result.model_copy(update=dict(candidates=[candidate]))


def verify(data,cfg,policy,candidates=None):
    candidates = candidates if candidates is not None else handoff(data,cfg)
    before = deepcopy((data,candidates))
    result = validate_stage_pair_candidates(candidates,data.stages,data.alerts,data.entities,data.settings,cfg,policy)
    assert (data,candidates) == before
    assert len(result.decisions) == len(candidates.candidates)
    aa = {a.alert_id:a for a in data.alerts}
    ss = {s.stage_id:s for s in data.stages.stages}
    observations={o.observation_id:o for o in result.trace.observations}
    for e in result.claims:
        for oid in e.observation_ids:
            observation=observations[oid]
            assert observation.alert_a_id in ss[e.stage_a_id].alert_ids
            assert observation.alert_b_id in ss[e.stage_b_id].alert_ids
            result.trace.resolve_observation(oid,aa)
    assert CrossStageEvidenceResult.model_validate_json(result.model_dump_json()) == result
    assert result.statistics['RELATIONS_WITHOUT_EVIDENCE'] == result.statistics['DANGLING_CLAIM_REFERENCE_COUNT'] == 0
    return result


@pytest.mark.parametrize('fields,gap', [({},1),({},86400),({'hostname':'h'},1),
    ({'uri':'/login'},1),({'user':'alice'},0),({'src_ip':'192.0.2.1'},1),
    ({'command':'whoami','hostname':'h'},1),({'process_name':'sh','hostname':'h'},1),
    ({'operation':'ProcessStart'},1)])
def test_time_and_supporting_context_cannot_create_edges(cfg,normalization,evidence_policy,fields,gap):
    data = source([record(1,**fields),record(2,time=gap,**fields)],cfg,normalization)
    result = verify(data,cfg,evidence_policy)
    d, = result.decisions
    assert d.relation_type == 'NO_RELATION' and d.direction_claim == 'NONE'
    assert d.diagnostics and not result.statistics['TIME_CAN_CREATE_DIRECTION']


@pytest.mark.parametrize('field', ['session_id','request_id','connection_id','application_session_id','task_id'])
def test_scoped_identity_is_strong_but_undirected(cfg,normalization,evidence_policy,field):
    data = source([record(1,**{field:'x'}),record(2,time=7200,**{field:'x'})],cfg,normalization)
    d, = verify(data,cfg,evidence_policy).decisions
    assert d.relation_type == 'UNDIRECTED_EDGE'
    assert d.relation_claim_count and not d.context_claim_count


def test_same_complete_process_is_undirected_even_with_different_other_context(cfg,normalization,evidence_policy):
    fields = dict(hostname='h',process_id=9,process_start_time='2025-12-01T00:00:00Z')
    data = source([record(1,uri='/a',request_id='a',**fields),record(2,time=4000,uri='/b',request_id='b',**fields)],cfg,normalization)
    result = verify(data,cfg,evidence_policy)
    assert result.decisions[0].relation_type == 'UNDIRECTED_EDGE'
    assert any(e.evidence_type == 'SAME_PROCESS_INSTANCE' and e.valid for e in result.claims)


@pytest.mark.parametrize('native,expected',[(True,'UNDIRECTED_EDGE'),(False,'NO_RELATION')])
def test_flow_requires_native_identity_and_complete_tuple(cfg,normalization,evidence_policy,native,expected):
    fields = dict(src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=123,dst_port=443,protocol='TCP')
    if native:
        fields['flow_id'] = 'flow'
    data = source([record(1,**fields),record(2,time=5000,**fields)],cfg,normalization)
    assert verify(data,cfg,evidence_policy).decisions[0].relation_type == expected


def test_native_flow_id_alone_is_insufficient(cfg,normalization,evidence_policy):
    data = source([record(1,flow_id='f'),record(2,flow_id='f',time=1)],cfg,normalization)
    assert verify(data,cfg,evidence_policy).decisions[0].relation_type == 'NO_RELATION'


def test_scoped_object_identity_undirected(cfg,normalization,evidence_policy):
    data = source([record(1,hostname='h',object_id='object'),record(2,hostname='h',object_id='object',time=2)],cfg,normalization)
    result = verify(data,cfg,evidence_policy)
    assert result.decisions[0].relation_type == 'UNDIRECTED_EDGE'
    assert any(e.evidence_type == 'SAME_SCOPED_OBJECT' for e in result.claims)


def lineage(parent_observed=0,child_observed=5,child_birth='2026-01-01T00:00:02Z'):
    return [record('p',time=parent_observed,hostname='h',process_id=1,process_start_time='2026-01-01T00:00:00Z'),
        record('c',time=child_observed,hostname='h',process_id=2,process_start_time=child_birth,
            parent_process_id=1,parent_process_start_time='2026-01-01T00:00:00Z')]


@pytest.mark.parametrize('later_observation',[False,True])
def test_lineage_direction_uses_instance_semantics_not_alert_time(cfg,normalization,evidence_policy,later_observation):
    data = source(lineage(9000 if later_observation else 0,5),cfg,normalization)
    result = verify(data,cfg,evidence_policy)
    d, = result.decisions
    assert d.relation_type == 'DIRECTED_EDGE'
    e = next(e for e in result.claims if e.claim_id == d.primary_claim_id)
    assert e.evidence_type == 'PARENT_CHILD_PROCESS'
    assert e.temporal_check['rule'] == 'parent_birth_must_not_follow_child_birth'


@pytest.mark.parametrize('kind,rows', [
    ('REQUEST_RESPONSE',[record(1,operation='HTTPRequest',request_id='r'),record(2,time=5,operation='HTTPResponse',request_id='r')]),
    ('OBJECT_CREATE_EXECUTE',[record(1,hostname='h',operation='FileCreate',file_path='/tmp/x'),record(2,time=5,hostname='h',operation='ProcessStart',executable='/tmp/x')]),
    ('AUTH_ESTABLISH_USE',[record(1,operation='AUTH_SUCCESS',session_id='s'),record(2,time=3600,operation='FileRead',session_id='s')]),
    ('EXPLICIT_ATTESTED_RELATION',[record('p'),record('c',time=5,parent_event_id='p')]),
    ('OBJECT_HANDOFF',[record(1,hostname='h',response_object_id='x'),record(2,time=5,hostname='h',request_object_id='x')]),
])
def test_directional_semantic_families(cfg,normalization,evidence_policy,kind,rows):
    data = source(rows,cfg,normalization)
    result = verify(data,cfg,evidence_policy)
    assert result.decisions[0].relation_type == 'DIRECTED_EDGE'
    assert any(e.evidence_type == kind and e.valid for e in result.claims)


def test_session_unknown_or_failed_operation_is_not_certified_use(cfg,normalization,evidence_policy):
    data = source([record(1,operation='AUTH_SUCCESS',session_id='s'),record(2,time=1,operation='login_failed',session_id='s')],cfg,normalization)
    d, = verify(data,cfg,evidence_policy).decisions
    assert d.relation_type == 'UNDIRECTED_EDGE' and not any(c.semantic_class=='DIRECTIONAL_RELATION' for c in verify(data,cfg,evidence_policy).claims)


@pytest.mark.parametrize('field',['parent_event_id','caused_by','triggered_by','related_event'])
def test_declared_native_reference_semantics(cfg,normalization,evidence_policy,field):
    data = source([record('p'),record('c',time=1,**{field:'p'})],cfg,normalization)
    d, = verify(data,cfg,evidence_policy).decisions
    assert d.relation_type == ('UNDIRECTED_EDGE' if field == 'related_event' else 'DIRECTED_EDGE')


def test_only_file_name_never_attests_create_execute(cfg,normalization,evidence_policy):
    data = source([record(1,hostname='h',operation='FileCreate',file_path='x'),
        record(2,time=1,hostname='h',operation='ProcessStart',executable='x')],cfg,normalization)
    assert verify(data,cfg,evidence_policy).decisions[0].relation_type == 'NO_RELATION'


def test_temporal_conflict_vetoes_direction_without_reversing_it(cfg,normalization,evidence_policy):
    data = source([record(1,time=5,operation='HTTPRequest',request_id='r'),
        record(2,operation='HTTPResponse',request_id='r')],cfg,normalization)
    result = verify(data,cfg,evidence_policy)
    assert result.decisions[0].relation_type == 'UNDIRECTED_EDGE'
    assert 'TEMPORAL_CONFLICT' in result.decisions[0].diagnostics
    assert any(not e.valid and e.evidence_type == 'REQUEST_RESPONSE' for e in result.claims)


def test_impossible_child_birth_invalidates_lineage(cfg,normalization,evidence_policy):
    data = source(lineage(child_birth='2025-12-31T23:59:00Z'),cfg,normalization)
    result = verify(data,cfg,evidence_policy)
    assert result.decisions[0].relation_type == 'NO_RELATION'
    assert 'TEMPORAL_CONFLICT' in result.decisions[0].diagnostics


@pytest.mark.parametrize('fallback',[False,True])
def test_bad_process_witness_does_not_veto_other_valid_witness(cfg,normalization,evidence_policy,fallback):
    fields = dict(hostname='h',process_guid='same-guid',process_id=3)
    if fallback:
        fields['session_id'] = 'valid-independent-session'
    data = source([record(1,process_start_time='2026-01-01T00:00:00Z',**fields),
        record(2,time=10,process_start_time='2026-01-01T00:00:05Z',**fields)],cfg,normalization)
    result = verify(data,cfg,evidence_policy)
    assert result.decisions[0].relation_type == ('UNDIRECTED_EDGE' if fallback else 'NO_RELATION')
    assert any('PROCESS_IDENTITY_CONFLICT' in e.conflict_status for e in result.claims)


def test_opposing_directions_are_not_resolved_by_order(cfg,normalization,evidence_policy):
    data = source([record('a',parent_event_id='b'),record('b',parent_event_id='a')],cfg,normalization)
    result = verify(data,cfg,evidence_policy)
    d, = result.decisions
    assert d.relation_type == 'UNDIRECTED_EDGE' and 'DIRECTION_CONFLICT' in d.diagnostics
    assert d.from_stage_id is d.to_stage_id is None
    reverse = deepcopy(data)
    reverse.stages = data.stages.model_copy(update=dict(stages=list(reversed(data.stages.stages))))
    reverse.alerts.reverse()
    assert verify(reverse,cfg,evidence_policy) == result


def test_no_cross_scope_short_id_collision(cfg,normalization,evidence_policy):
    data = source([record(1,source='waf',request_id='r'),record(2,request_id='r',time=1)],cfg,normalization)
    assert verify(data,cfg,evidence_policy).decisions[0].relation_type == 'NO_RELATION'


@pytest.mark.parametrize('kind,field,value,diagnostic',[
    ('request','scope','independent-environment','SCOPE_CONFLICT'),
    ('request','value','different-request','IDENTITY_CONFLICT'),
    ('object','value','different-object','IDENTITY_CONFLICT')])
def test_witness_identity_collision_is_rejected_locally(cfg,normalization,evidence_policy,monkeypatch,kind,field,value,diagnostic):
    from dataclasses import replace
    import json
    import app.stage_evidence.validation as validation
    fields = dict(request_id='r',hostname='h') if kind == 'request' else dict(object_id='o',hostname='h')
    data = source([record(1,**fields),record(2,time=1,**fields)],cfg,normalization)
    original = validation.project_witnesses
    def bad_bucket(*args,**kwargs):
        indexes = original(*args,**kwargs)
        # Simulate an upstream projection/key collision. Actual identity/scope
        # facts differ despite the matching posting key, so the claim must fail.
        last = sorted(indexes)[-1]
        for key,values in indexes[last].items():
            if key[0] == kind:
                modified = []
                for item in values:
                    identity = json.loads(item.identity)
                    identity[field] = value
                    modified.append(replace(item,identity=json.dumps(identity,sort_keys=True,separators=(',',':'))))
                indexes[last][key] = modified
        return indexes
    monkeypatch.setattr(validation,'project_witnesses',bad_bucket)
    result = verify(data,cfg,evidence_policy)
    assert result.decisions[0].relation_type == 'NO_RELATION'
    assert diagnostic in result.decisions[0].diagnostics


def test_only_passed_candidates_are_verified(cfg,normalization,evidence_policy):
    data = source([record(i,session_id='s',time=i) for i in range(3)],cfg,normalization)
    candidates = handoff(data,cfg)
    assert len(candidates.candidates) == 3
    subset = candidates.model_copy(update=dict(candidates=candidates.candidates[:1]))
    assert len(verify(data,cfg,evidence_policy,subset).decisions) == 1
    empty = candidates.model_copy(update=dict(candidates=[]))
    assert verify(data,cfg,evidence_policy,empty).claims == []


def test_config_can_disable_evidence_without_changing_candidates(cfg,normalization,evidence_policy):
    data = source([record(1,session_id='s'),record(2,time=1,session_id='s')],cfg,normalization)
    policy = evidence_policy.model_copy(update=dict(enabled_evidence_types=[]))
    assert verify(data,cfg,policy).decisions[0].relation_type == 'NO_RELATION'


def test_result_rejects_dangling_and_semantically_forged_decisions(cfg,normalization,evidence_policy):
    result = verify(source([record(1,session_id='s'),record(2,time=1,session_id='s')],cfg,normalization),cfg,evidence_policy)
    raw = result.model_dump(mode='json')
    raw['decisions'][0]['primary_claim_id'] = 'ecl_'+'0'*64
    with pytest.raises(ValidationError,match='dangling'):
        CrossStageEvidenceResult.model_validate(raw)
    raw = result.model_dump(mode='json')
    raw['decisions'][0].update(relation_type='DIRECTED_EDGE',direction_claim='A_TO_B',
        from_stage_id=raw['decisions'][0]['stage_a_id'],to_stage_id=raw['decisions'][0]['stage_b_id'])
    with pytest.raises(ValidationError,match='aggregate'):
        CrossStageEvidenceResult.model_validate(raw)


def test_validator_reads_no_truth_snapshots_scorer_or_downstream(cfg,normalization,evidence_policy,monkeypatch):
    data = source([record(1,session_id='s'),record(2,time=1,session_id='s')],cfg,normalization)
    candidates = handoff(data,cfg)
    original = builtins.__import__
    def guarded(name,*args,**kwargs):
        assert not name.startswith(('evaluation','app.correlation','app.stage_relations','app.stage_chains','app.chains','app.api','app.ai'))
        return original(name,*args,**kwargs)
    def forbidden(*args,**kwargs):
        raise AssertionError('⑧ must consume existing in-memory facts only')
    monkeypatch.setattr(builtins,'__import__',guarded)
    monkeypatch.setattr(builtins,'open',forbidden)
    monkeypatch.setattr(Path,'open',forbidden)
    verify(data,cfg,evidence_policy,candidates)


def test_official_candidate_object_directly_enters_stage8(tmp_path,monkeypatch):
    import json
    import app.services.stage_pipeline as pipeline
    seen = {}
    generate,validate = pipeline.generate_stage_pair_candidates,pipeline.validate_stage_pair_candidates
    def candidates(*args,**kwargs):
        seen['stages'] = args[0]
        seen['candidates'] = generate(*args,**kwargs)
        return seen['candidates']
    def evidence(candidates,stages,*args,**kwargs):
        assert candidates is seen['candidates'] and stages is seen['stages']
        seen['calls'] = seen.get('calls',0)+1
        return validate(candidates,stages,*args,**kwargs)
    monkeypatch.setattr(pipeline,'generate_stage_pair_candidates',candidates)
    monkeypatch.setattr(pipeline,'validate_stage_pair_candidates',evidence)
    path = tmp_path/'native.jsonl'
    path.write_text(''.join(json.dumps(dict(source_type='edr',event=r))+'\n' for r in lineage()),encoding='utf8')
    result = pipeline.load_stage_pipeline(path)
    assert seen['calls'] == 1 and result.candidate_result is seen['candidates']
    assert result.statistics['STAGE8_INPUT_PAIR_COUNT'] == len(result.candidates)
    assert result.statistics['CURRENT_PIPELINE_STAGE'] == 'STAGE_8_RELATION_SEMANTICS_REPAIRED'
    assert not result.statistics['STAGE_9_STARTED'] and list(tmp_path.iterdir()) == [path]

"""⑧ context/relation separation, claim deduplication and complete trace tests."""
from pathlib import Path
from copy import deepcopy
import random
import pytest
from pydantic import ValidationError

from app.stage_evidence import load_evidence_config, validate_stage_pair_candidates, CrossStageEvidenceResult
from app.community.models import community_id
from app.stages.models import Stage, StageResult, AggregationBasis, stage_id
from app.models.alerts import EvidencePointer
from test_community_builder import cfg, normalization, record
from test_stage_candidates import source
from test_stage_evidence import handoff

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def policy():
    return load_evidence_config(ROOT/'configs/stage-evidence-v1.yaml')


def validate(data,cfg,policy,candidates=None):
    return validate_stage_pair_candidates(candidates if candidates is not None else handoff(data,cfg),
        data.stages,data.alerts,data.entities,data.settings,cfg,policy)


@pytest.mark.parametrize('count,kind',[ (3,'flow'),(10,'flow'),(3,'session'),(3,'process') ])
def test_regression_context_membership_never_expands_to_pairwise_relations(cfg,normalization,policy,count,kind):
    fields = dict(flow_id='f',src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=123,dst_port=443,protocol='TCP') if kind=='flow' else (
        dict(session_id='s') if kind=='session' else dict(hostname='h',process_id=7,process_start_time='2025-12-31T00:00:00Z'))
    data=source([record(i,time=i,**fields) for i in range(count)],cfg,normalization)
    result=validate(data,cfg,policy)
    assert len(result.decisions)==count*(count-1)//2
    assert all(d.relation_type=='NO_RELATION' for d in result.decisions)
    assert all('SHARED_CONTEXT_ONLY' in d.diagnostics for d in result.decisions)
    assert any(len(p.stage_ids)==count for p in result.context_postings)
    assert {s.stage_id for s in data.stages.stages}<={m.stage_id for p in result.context_postings for m in p.memberships}


def grouped(data,native_groups):
    """Valid consumed-Stage fixture, without running/changing ⑥ aggregation.

    Timestamp links establish synthetic fixture membership only; they never
    enter ⑧'s evidence postings or relation rules.
    """
    result=deepcopy(data)
    by_native={a.raw_alert['event_id']:a for a in data.alerts}
    old_annotations={b.alert_id:b for b in data.stages.behaviors}
    entities={e.entity_id:e for e in data.entities}
    stages,annotations=[],[]
    for native_ids in native_groups:
        alerts=[by_native[str(i)] for i in native_ids]
        aids=sorted(a.alert_id for a in alerts)
        cid=community_id(aids)
        behavior=old_annotations[aids[0]].behavior
        assert all(old_annotations[aid].behavior==behavior for aid in aids)
        annotations.extend(old_annotations[aid].model_copy(update=dict(community_id=cid)) for aid in aids)
        def ids(kind):
            return sorted({o.entity_id for a in alerts for o in a.entity_occurrences if entities[o.entity_id].type.value==kind})
        proof=[AggregationBasis(alert_ids=sorted([aids[0],aid]),rule='consistent_core_context',shared_keys=['synthetic_fixture_only'],
            evidence=[EvidencePointer(alert_id=i,pointer='/timestamp',side='shared') for i in (aids[0],aid)]) for aid in aids[1:]]
        stages.append(Stage(stage_id=stage_id(cid,behavior,aids),community_id=cid,behavior=behavior,
            start_time=min(a.timestamp for a in alerts),end_time=max(a.timestamp for a in alerts),alert_ids=aids,alert_count=len(aids),
            source_types=sorted({a.source_type.value for a in alerts}),host_entities=ids('HOST'),account_entities=ids('ACCOUNT'),
            process_entities=ids('PROCESS'),request_bindings=[],flow_bindings=[],session_bindings=[],task_bindings=[],
            evidence_summary='synthetic consumed Stage fixture',aggregation_basis=proof))
    result.stages=StageResult(config_hash=data.stages.config_hash,stages=stages,behaviors=annotations,diagnostics=[],statistics={})
    return result


def test_15_by_14_parent_child_is_one_claim_with_all_210_observations(cfg,normalization,policy):
    parent=dict(hostname='h',operation='ProcessStart',process_id=1,process_start_time='2025-12-31T00:00:00Z')
    child=dict(hostname='h',operation='ProcessStart',process_id=2,process_start_time='2026-01-01T00:01:00Z',
        parent_process_id=1,parent_process_start_time='2025-12-31T00:00:00Z')
    data=source([record('p'+str(i),time=i,**parent) for i in range(15)]+[record('c'+str(i),time=100+i,**child) for i in range(14)],cfg,normalization)
    data=grouped(data,[[f'p{i}' for i in range(15)],[f'c{i}' for i in range(14)]])
    result=validate(data,cfg,policy)
    claims=[c for c in result.claims if c.evidence_type=='PARENT_CHILD_PROCESS']
    assert len(claims)==1 and claims[0].observation_count==210
    assert {claims[0].role_a,claims[0].role_b}=={'PARENT','CHILD'}
    assert result.decisions[0].relation_type=='DIRECTED_EDGE'
    observations={o.observation_id:o for o in result.trace.observations}
    pairs={(observations[i].alert_a_id,observations[i].alert_b_id) for i in claims[0].observation_ids}
    assert len(pairs)==210
    aa={a.alert_id:a for a in data.alerts}
    for oid in claims[0].observation_ids:
        assert result.trace.resolve_observation(oid,aa)


def test_10_by_8_same_host_is_one_supporting_claim(cfg,normalization,policy):
    data=source([record(i,time=i,hostname='h') for i in range(18)],cfg,normalization)
    data=grouped(data,[list(range(10)),list(range(10,18))])
    result=validate(data,cfg,policy)
    claim,=[c for c in result.claims if c.evidence_type=='SAME_HOST']
    assert claim.observation_count==80 and claim.semantic_class=='SUPPORTING'
    assert result.decisions[0].relation_type=='NO_RELATION'


def test_distinct_children_of_one_parent_remain_distinct_logical_claims(cfg,normalization,policy):
    parent=dict(hostname='h',operation='ProcessStart',process_id=1,process_start_time='2025-12-31T00:00:00Z')
    rows=[record('p',**parent)]+[record('c'+str(i),time=10+i,hostname='h',operation='ProcessStart',process_id=i,
        process_start_time='2026-01-01T00:00:10Z',parent_process_id=1,parent_process_start_time='2025-12-31T00:00:00Z') for i in (2,3)]
    data=grouped(source(rows,cfg,normalization),[['p'],['c2','c3']])
    result=validate(data,cfg,policy)
    claims=[c for c in result.claims if c.evidence_type=='PARENT_CHILD_PROCESS']
    assert len(claims)==2 and len({c.claim_id for c in claims})==2
    assert len({str(c.identity['child_process_entities']) for c in claims})==2


def test_child_instance_must_have_a_scoped_identity_not_just_pid_start(cfg,normalization,policy):
    rows=[record('p',process_guid='parent-guid'),record('c',time=10,parent_process_guid='parent-guid',
        process_id=2,process_start_time='2026-01-01T00:00:05Z')]
    result=validate(source(rows,cfg,normalization),cfg,policy)
    lineage,=[c for c in result.claims if c.evidence_type=='PARENT_CHILD_PROCESS']
    assert not lineage.valid and 'CHILD_SCOPED_PROCESS_IDENTITY_MISSING' in lineage.conflict_status
    assert result.decisions[0].relation_type=='NO_RELATION'


def test_opposing_directions_are_separate_claims(cfg,normalization,policy):
    data=source([record('a',parent_event_id='b'),record('b',parent_event_id='a')],cfg,normalization)
    result=validate(data,cfg,policy)
    claims=[c for c in result.claims if c.evidence_type=='EXPLICIT_ATTESTED_RELATION']
    assert len(claims)==2 and {c.direction_claim for c in claims}=={'A_TO_B','B_TO_A'}
    assert result.decisions[0].relation_type=='UNDIRECTED_EDGE'
    assert 'DIRECTION_CONFLICT' in result.decisions[0].diagnostics


def test_same_token_different_scopes_never_deduplicates(cfg,normalization,policy):
    rows=[record('e1',request_id='same'),record('e2',time=1,request_id='same'),
        record('w1',source='waf',request_id='same'),record('w2',source='waf',time=1,request_id='same')]
    data=grouped(source(rows,cfg,normalization),[['e1','w1'],['e2','w2']])
    claims=[c for c in validate(data,cfg,policy).claims if c.evidence_type=='SAME_SCOPED_REQUEST']
    assert len(claims)==2 and len({c.identity['scope'] for c in claims})==2


def test_large_flow_context_does_not_veto_independent_lineage(cfg,normalization,policy):
    flow=dict(flow_id='f',src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=10,dst_port=20,protocol='TCP')
    rows=[record('p',hostname='h',process_id=1,process_start_time='2025-12-31T00:00:00Z',**flow),
        record('c',time=10,hostname='h',process_id=2,process_start_time='2026-01-01T00:00:05Z',parent_process_id=1,parent_process_start_time='2025-12-31T00:00:00Z',**flow),
        record('third',time=20,hostname='h',**flow)]
    result=validate(source(rows,cfg,normalization),cfg,policy)
    assert sum(d.relation_type=='DIRECTED_EDGE' for d in result.decisions)==1
    assert sum(d.relation_type=='NO_RELATION' for d in result.decisions)==2
    assert all(c.semantic_class=='CONTEXT' for c in result.claims if c.evidence_type=='SAME_SCOPED_FLOW')


def test_large_session_context_does_not_veto_explicit_pair_association(cfg,normalization,policy):
    rows=[record('a',session_id='s'),record('b',time=1,session_id='s',related_event='a'),record('c',time=2,session_id='s')]
    result=validate(source(rows,cfg,normalization),cfg,policy)
    assert sum(d.relation_type=='UNDIRECTED_EDGE' for d in result.decisions)==1
    assert sum(d.relation_type=='NO_RELATION' for d in result.decisions)==2
    assert any(c.evidence_type=='EXPLICIT_RELATED_EVENT' and c.semantic_class=='DIRECT_ASSOCIATIVE_RELATION' for c in result.claims)


def test_exclusivity_uses_all_stage_memberships_even_if_only_one_candidate(cfg,normalization,policy):
    data=source([record(i,time=i,session_id='s') for i in range(3)],cfg,normalization)
    candidates=handoff(data,cfg)
    subset=candidates.model_copy(update=dict(candidates=candidates.candidates[:1]))
    result=validate(data,cfg,policy,subset)
    assert result.decisions[0].relation_type=='NO_RELATION'
    assert any(len(p.stage_ids)==3 for p in result.context_postings)


def test_process_parent_role_counts_in_global_identity_footprint(cfg,normalization,policy):
    instance=dict(hostname='h',process_id=1,process_start_time='2025-12-31T00:00:00Z')
    rows=[record('a',**instance),record('b',time=2,**instance),record('c',time=5,hostname='h',process_id=2,
        process_start_time='2026-01-01T00:00:04Z',parent_process_id=1,parent_process_start_time='2025-12-31T00:00:00Z')]
    data=source(rows,cfg,normalization)
    result=validate(data,cfg,policy)
    same,=[c for c in result.claims if c.evidence_type=='SAME_PROCESS_INSTANCE']
    # Keep the parent mention in the global footprint, while exclusivity of
    # current-process usage is measured over the two actual current roles.
    assert same.semantic_class=='DIRECT_ASSOCIATIVE_RELATION'
    posting=next(p for p in result.context_postings if p.context_identity_id==same.context_identity_id)
    assert len(posting.stage_ids)==3 and any(m.role=='parent_process' for m in posting.memberships)
    assert sum(d.relation_type=='DIRECTED_EDGE' for d in result.decisions)==2
    assert sum(d.relation_type=='UNDIRECTED_EDGE' for d in result.decisions)==1


def test_public_or_conflicting_identity_is_not_promoted(cfg,normalization,policy):
    fields=dict(hostname='h',process_guid='g')
    rows=[record(1,process_id=1,process_start_time='2026-01-01T00:00:00Z',**fields),
        record(2,time=1,process_id=2,process_start_time='2026-01-01T00:00:01Z',**fields)]
    result=validate(source(rows,cfg,normalization),cfg,policy)
    posting,=[p for p in result.context_postings if p.context_type=='PROCESS']
    assert posting.metadata['identity_polluted'] and not posting.metadata['exclusive_direct_eligible']
    assert result.decisions[0].relation_type=='NO_RELATION'


def test_claim_observation_trace_and_context_raw_links_are_closed(cfg,normalization,policy):
    data=source([record(i,time=i,session_id='s') for i in range(3)],cfg,normalization)
    result=validate(data,cfg,policy)
    raw=result.model_dump(mode='json')
    assert CrossStageEvidenceResult.model_validate(raw)==result
    raw['claims'][0]['observation_ids'][0]='obs_'+'0'*64
    raw['claims'][0]['observation_ids'].sort()
    with pytest.raises(ValidationError,match='dangling'):
        CrossStageEvidenceResult.model_validate(raw)
    raw=result.model_dump(mode='json')
    raw['trace']['observations'].pop()
    with pytest.raises(ValidationError,match='dangling'):
        CrossStageEvidenceResult.model_validate(raw)
    raw=result.model_dump(mode='json')
    raw['trace']['raw_pointers'].pop()
    with pytest.raises(ValidationError,match='dangling'):
        CrossStageEvidenceResult.model_validate(raw)
    raw=result.model_dump(mode='json')
    raw['context_postings'][0]['evidence_claim_ids']=['ecl_'+'0'*64]
    with pytest.raises(ValidationError,match='dangling'):
        CrossStageEvidenceResult.model_validate(raw)


def test_shuffle_alert_stage_candidate_and_extraction_order_is_deterministic(cfg,normalization,policy,monkeypatch):
    import app.stage_evidence.validation as validation
    rows=[record(i,time=i,hostname='h',session_id='s',process_id=7,process_start_time='2025-12-31T00:00:00Z') for i in range(4)]
    data=source(rows,cfg,normalization)
    candidates=handoff(data,cfg)
    original=validate(data,cfg,policy,candidates)
    before=deepcopy(data)
    rng=random.Random(28)
    shuffled=deepcopy(data)
    rng.shuffle(shuffled.alerts)
    rng.shuffle(shuffled.entities)
    shuffled.stages=shuffled.stages.model_copy(update=dict(stages=list(reversed(shuffled.stages.stages)),behaviors=list(reversed(shuffled.stages.behaviors))))
    changed=candidates.model_copy(update=dict(candidates=list(reversed(candidates.candidates)),features=list(reversed(candidates.features))))
    project=validation.project_witnesses
    def permuted(*args,**kwargs):
        indexes=project(*args,**kwargs)
        for buckets in indexes.values():
            for observations in buckets.values():
                rng.shuffle(observations)
        return dict(reversed(list(indexes.items())))
    monkeypatch.setattr(validation,'project_witnesses',permuted)
    assert validate(shuffled,cfg,policy,changed)==original
    assert data==before

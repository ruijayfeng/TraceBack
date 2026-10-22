"""Historical v1 compatibility tests; NOT the official ⑧ semantic contract.

WEAK_DIRECTED expectations here cover sealed snapshot consumers only. The
official entry uses app.stage_evidence and test_stage_evidence.py exclusively.
All generated records are synthetic.
"""
import builtins
import io
import json
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

from app.community.models import IncidentCandidate, MatchingEvidence, MembershipDecision, community_id
from app.models.alerts import EvidencePointer
from app.stage_relations import analyze_stage_relations, load_relation_config, StageRelation
from app.stage_relations.config import RelationConfig
from app.stages import load_stage_config
from app.stages.behavior import normalize_behavior
from app.stages.models import Stage, StageResult, stage_id
from app.utils.stable_id import canonical_json, content_digest
from test_community_builder import cfg, normalization, record, run
from test_source_bound_projection import settings

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def policy():
    return load_relation_config(ROOT/'configs/stage-relations-v1.yaml')


def snapshot(rows, cfg, normalization, *, split=False):
    """Provide a structurally valid upstream scope, not a new membership rule.

    Scope alone must never serve as Stage relation evidence; the synthetic
    membership witness is intentionally not passed as a relation candidate.
    """
    upstream = run(rows, cfg, normalization)
    aa = sorted(upstream.alerts, key=lambda a:a.alert_id)
    entities = {e.entity_id:e for e in upstream.entities}
    groups = [[a] for a in aa] if split else [aa]
    communities, stages, behaviors = [], [], []
    behavior_policy = load_stage_config(ROOT/'configs/behavior-stage-v1.yaml')
    for group in groups:
        aids = sorted(a.alert_id for a in group)
        cid = community_id(aids)
        proof = [MatchingEvidence(match_reason='synthetic_upstream_scope_only', match_level=1,
            alert_ids=sorted([group[0].alert_id,a.alert_id]), identity_kind='fixture_scope',
            identity_key='synthetic', time_delta_seconds=0.0,
            supporting_evidence=[EvidencePointer(alert_id=x.alert_id,pointer='/timestamp',side='shared') for x in (group[0],a)])
            for a in group[1:]]
        decisions = [MembershipDecision(alert_id=group[0].alert_id,action='CREATE',prior_community_ids=[],matching_evidence=[],reason='synthetic')]
        for alert, evidence in zip(group[1:],proof):
            decisions.append(MembershipDecision(alert_id=alert.alert_id,action='JOIN',prior_community_ids=[cid],matching_evidence=[evidence],reason='synthetic'))
        communities.append(IncidentCandidate(community_id=cid,
            incident_candidate_id='icd_'+content_digest(dict(id_version='v1',kind='IncidentCandidate',identity=dict(alert_ids=aids))),
            alert_ids=aids,start_time=min(a.timestamp for a in group),end_time=max(a.timestamp for a in group),
            sources=sorted({a.source_namespace for a in group}),entity_ids=sorted({eid for a in group for eid in a.entity_ids}),
            contexts={},member_count=len(group),matching_evidence=proof,membership_decisions=decisions))
        for alert in group:
            behavior = normalize_behavior(alert,behavior_policy).model_copy(update={'community_id': cid})
            behaviors.append(behavior)
            def ids(kind):
                return sorted({o.entity_id for o in alert.entity_occurrences if entities[o.entity_id].type.value == kind})
            stages.append(Stage(stage_id=stage_id(cid,behavior.behavior,[alert.alert_id]),community_id=cid,
                behavior=behavior.behavior,start_time=alert.timestamp,end_time=alert.timestamp,
                alert_ids=[alert.alert_id],alert_count=1,source_types=[alert.source_type.value],
                host_entities=ids('HOST'),account_entities=ids('ACCOUNT'),process_entities=ids('PROCESS'),
                request_bindings=[],session_bindings=[],flow_bindings=[],task_bindings=[],
                evidence_summary='synthetic singleton snapshot',aggregation_basis=[]))
    stage_result = StageResult(config_hash=behavior_policy.digest,behaviors=behaviors,stages=stages,diagnostics=[],statistics={})
    ss = {a.source_namespace:settings(a.raw_alert['source_type']) for a in aa}
    return stage_result, aa, list(entities.values()), communities, ss


def analyze(data,cfg,policy):
    s,a,e,c,ss = data
    before = canonical_json(dict(stages=s.model_dump(mode='json'),alerts=[x.model_dump(mode='json') for x in a],
        entities=[x.model_dump(mode='json') for x in e],communities=[x.model_dump(mode='json') for x in c]))
    result = analyze_stage_relations(s,a,e,c,ss,cfg,policy)
    assert before == canonical_json(dict(stages=s.model_dump(mode='json'),alerts=[x.model_dump(mode='json') for x in a],
        entities=[x.model_dump(mode='json') for x in e],communities=[x.model_dump(mode='json') for x in c]))
    assert result.statistics['STAGE_PAIRS_CONSIDERED'] == len(result.relations)+result.statistics['NO_RELATION_COUNT']
    return result


def lineage(parent_time=0, child_time=5):
    return [record('p',time=parent_time,hostname='host',operation='ProcessStart',process_id=1,
                   process_start_time='2026-01-01T00:00:00Z'),
            record('c',time=child_time,hostname='host',operation='FileRead',process_id=2,
                   process_start_time='2026-01-01T00:00:02Z',parent_process_id=1,
                   parent_process_start_time='2026-01-01T00:00:00Z')]


@pytest.mark.parametrize('parent,child,expected',[(0,5,'STRONG_DIRECTED'),(100,0,'STRONG_UNDIRECTED'),
    (5,0,'STRONG_DIRECTED'),(30,0,'STRONG_DIRECTED'),(30.000001,0,'STRONG_UNDIRECTED')])
def test_semantic_lineage_and_independent_time_conflict(cfg,normalization,policy,parent,child,expected):
    data = snapshot(lineage(parent,child),cfg,normalization)
    r, = analyze(data,cfg,policy).relations
    assert r.relation_type == expected
    assert r.evidence_type == 'parent_child_process'
    assert r.time_conflict == (expected == 'STRONG_UNDIRECTED')
    assert r.direction_basis == ('unresolved' if expected == 'STRONG_UNDIRECTED' else 'evidence_semantics')
    aa = {a.alert_id:a for a in data[1]}
    assert aa[r.semantic_direction.from_alert_id].process.pid == 1
    assert aa[r.semantic_direction.to_alert_id].process.pid == 2
    if r.time_conflict:
        assert r.from_stage_id is r.to_stage_id is None
        assert not r.direction_reliable and r.confidence_basis.direction_reliability == 0
    for e in [r.primary_evidence,*r.supporting_evidence]:
        for p in e.pointers:
            p.resolve(aa)
    assert StageRelation.model_validate_json(r.model_dump_json(),context=dict(alerts=aa,stages={s.stage_id:s for s in data[0].stages})) == r


@pytest.mark.parametrize('earlier', [1, 2])
def test_weak_evidence_with_observed_order(cfg,normalization,policy,earlier):
    data = snapshot([record(i,time=0 if i == earlier else 5,hostname='host') for i in (1,2)],cfg,normalization)
    r, = analyze(data,cfg,policy).relations
    assert r.relation_type == 'WEAK_DIRECTED' and r.semantic_direction is None
    expected_source = next(s.stage_id for s in data[0].stages if s.start_time == min(a.timestamp for a in data[1]))
    expected_target = next(s.stage_id for s in data[0].stages if s.stage_id != expected_source)
    assert (r.from_stage_id,r.to_stage_id) == (expected_source,expected_target)
    assert r.direction_reliable and r.direction_basis == 'temporal_order'
    assert r.direction_basis != 'evidence_semantics'
    assert not r.primary_evidence.strong
    assert r.confidence == r.evidence_strength == r.primary_evidence.evidence_strength
    assert r.confidence == policy.evidence[r.evidence_type].strength
    assert 'does not prove causation' in r.reason


@pytest.mark.parametrize('fields',[{},dict(operation='ProcessStart'),dict(protocol='TCP'),dict(signature='same')])
def test_time_same_community_behavior_and_vendor_text_do_not_create_edges(cfg,normalization,policy,fields):
    result = analyze(snapshot([record(1,**fields),record(2,time=1,**fields)],cfg,normalization),cfg,policy)
    assert not result.relations and result.statistics['NO_RELATION_COUNT'] == 1


def test_strongest_single_evidence_wins_without_and_or_quantity_bonus(cfg,normalization,policy):
    rows = lineage()
    rows = [dict(r,request_id='r',session_id='s',user='Alice',src_ip='192.0.2.1') for r in rows]
    r, = analyze(snapshot(rows,cfg,normalization),cfg,policy).relations
    assert r.primary_evidence.evidence_type == 'parent_child_process'
    assert len(r.supporting_evidence) >= 3
    assert r.confidence == policy.evidence['parent_child_process'].strength
    assert len(r.witness_alert_ids) == 2


def test_request_response_direction_is_semantic(cfg,normalization,policy):
    data = snapshot([record(1,time=5,operation='HTTPRequest',request_id='r'),
                     record(2,time=0,operation='HTTPResponse',request_id='r')],cfg,normalization)
    r, = analyze(data,cfg,policy).relations
    aa = {a.alert_id:a for a in data[1]}
    assert r.relation_type == 'STRONG_DIRECTED' and r.evidence_type == 'request_response'
    assert aa[r.semantic_direction.from_alert_id].alert_type == 'HTTPRequest'


def test_session_opener_to_operation(cfg,normalization,policy):
    rows = [record(1,operation='session_open',session_id='s'),record(2,time=5,operation='FileRead',session_id='s')]
    r, = analyze(snapshot(rows,cfg,normalization),cfg,policy).relations
    assert r.relation_type == 'STRONG_DIRECTED' and r.evidence_type == 'session_followup'


def test_create_to_execute_object(cfg,normalization,policy):
    rows = [record(1,hostname='h',operation='FileCreate',file_path='/tmp/object'),
            record(2,time=5,hostname='h',operation='ProcessStart',executable='/tmp/object')]
    r, = analyze(snapshot(rows,cfg,normalization),cfg,policy).relations
    assert r.relation_type == 'STRONG_DIRECTED' and r.evidence_type == 'object_create_execute'


def test_scopes_do_not_compare_globally(cfg,normalization,policy):
    rows = [record(i,hostname='h',time=i) for i in range(8)]
    result = analyze(snapshot(rows,cfg,normalization,split=True),cfg,policy)
    assert result.statistics['STAGE_PAIRS_CONSIDERED'] == 0 and not result.relations


def test_weak_equal_time_does_not_use_id_as_direction(cfg,normalization,policy):
    result = analyze(snapshot([record(1,hostname='h'),record(2,hostname='h')],cfg,normalization),cfg,policy)
    assert not result.relations
    assert result.diagnostics[0]['reason'] == 'WEAK_EVIDENCE_WITHOUT_UNAMBIGUOUS_TIME_ORDER'


def test_equal_time_allows_strong_semantics(cfg,normalization,policy):
    r, = analyze(snapshot(lineage(0,0),cfg,normalization),cfg,policy).relations
    assert r.relation_type == 'STRONG_DIRECTED' and r.overlap


def test_overlapping_multi_alert_stage_windows_keep_strong_direction(cfg,normalization,policy):
    from test_stage_aggregation import stage_run
    base = lineage()
    rows = [dict(base[0],event_id='p0'),dict(base[0],event_id='p20',timestamp=record(0,time=20)['timestamp']),
            dict(base[1],event_id='c10',timestamp=record(0,time=10)['timestamp']),
            dict(base[1],event_id='c30',timestamp=record(0,time=30)['timestamp'])]
    community, stages = stage_run(rows,cfg,normalization,load_stage_config(ROOT/'configs/behavior-stage-v1.yaml'))
    assert len(stages.stages) == 2 and all(s.alert_count == 2 for s in stages.stages)
    ss = {a.source_namespace:settings(a.raw_alert['source_type']) for a in community.alerts}
    r, = analyze((stages,community.alerts,community.entities,community.result.incident_candidates,ss),cfg,policy).relations
    assert r.overlap and r.relation_type == 'STRONG_DIRECTED'


def test_network_context_is_weak_and_namespace_bound(cfg,normalization,policy):
    rows = [record(1,src_ip='192.0.2.1'),record(2,time=2,dst_ip='192.0.2.1')]
    r, = analyze(snapshot(rows,cfg,normalization),cfg,policy).relations
    assert r.relation_type == 'WEAK_DIRECTED' and r.evidence_type == 'network_context'


def test_opposing_equally_ranked_semantics_are_retained_without_fake_direction(cfg,normalization,policy):
    rows = [record('a',time=0,parent_event_id='b'),record('b',time=5,parent_event_id='a')]
    r, = analyze(snapshot(rows,cfg,normalization),cfg,policy).relations
    assert r.relation_type == 'STRONG_UNDIRECTED'
    assert r.direction_basis == 'unresolved'
    assert r.direction_conflict and not r.time_conflict and r.from_stage_id is r.to_stage_id is None


def test_reversed_inputs_and_stable_ids(cfg,normalization,policy):
    data = snapshot(lineage(),cfg,normalization)
    first = analyze(data,cfg,policy)
    s,a,e,c,ss = data
    second = analyze((s.model_copy(update=dict(stages=list(reversed(s.stages)),behaviors=list(reversed(s.behaviors)))),list(reversed(a)),list(reversed(e)),list(reversed(c)),ss),cfg,policy)
    assert first == second


def test_invalid_undirected_endpoints_and_forged_confidence_rejected(cfg,normalization,policy):
    r, = analyze(snapshot(lineage(100,0),cfg,normalization),cfg,policy).relations
    for updates in (dict(from_stage_id=r.stage_a_id),dict(direction_reliable=True),dict(confidence=0.99),dict(witness_alert_ids=[])):
        with pytest.raises(ValidationError):
            StageRelation.model_validate(dict(r.model_dump(),**updates))


@pytest.mark.parametrize('kind', ['STRONG_DIRECTED','STRONG_UNDIRECTED','WEAK_DIRECTED'])
def test_direction_basis_schema_serialization_and_legacy_reads(cfg,normalization,policy,kind):
    from fastapi.encoders import jsonable_encoder
    rows = ([record(1,hostname='h'),record(2,time=5,hostname='h')] if kind == 'WEAK_DIRECTED'
            else lineage(100 if kind == 'STRONG_UNDIRECTED' else 0,5))
    r, = analyze(snapshot(rows,cfg,normalization),cfg,policy).relations
    expected = dict(STRONG_DIRECTED='evidence_semantics',STRONG_UNDIRECTED='unresolved',WEAK_DIRECTED='temporal_order')[kind]
    assert r.direction_basis == expected
    assert json.loads(r.canonical_json())['direction_basis'] == expected
    assert jsonable_encoder(r)['direction_basis'] == expected
    assert StageRelation.model_validate_json(r.model_dump_json()) == r
    schema = StageRelation.model_json_schema()
    assert 'direction_basis' in schema['required']
    assert set(schema['properties']['direction_basis']['enum']) == {'evidence_semantics','temporal_order','unresolved'}
    legacy = r.model_dump()
    legacy.pop('direction_basis')
    assert StageRelation.model_validate(legacy) == r
    for invalid in ({'evidence_semantics','temporal_order','unresolved'}-{expected}) | {None,'causal'}:
        with pytest.raises(ValidationError):
            StageRelation.model_validate(dict(r.model_dump(),direction_basis=invalid))


def test_weak_endpoints_must_follow_observed_time_order(cfg,normalization,policy):
    r, = analyze(snapshot([record(1,hostname='h'),record(2,time=5,hostname='h')],cfg,normalization),cfg,policy).relations
    for updates in (dict(from_stage_id=r.to_stage_id,to_stage_id=r.from_stage_id),
                    dict(observed_time_order='OVERLAP_OR_EQUAL')):
        with pytest.raises(ValidationError):
            StageRelation.model_validate(dict(r.model_dump(),**updates))


def test_policy_rejects_missing_and_inverted_ranking(policy):
    raw = policy.model_dump()
    raw['evidence']['parent_child_process']['rank'] = 10
    with pytest.raises(ValidationError):
        RelationConfig.model_validate(raw)


def test_gt_and_downstream_unavailable_production_still_runs(cfg,normalization,policy,monkeypatch):
    data = snapshot(lineage(),cfg,normalization)
    original_import = builtins.__import__
    def denied_open(*args,**kwargs):
        raise AssertionError('pure_stage_algorithm_must_not_read_files')
    def guarded_import(name,*args,**kwargs):
        assert not name.startswith(('evaluation','app.chains','app.ai.'))
        return original_import(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'open',denied_open)
    monkeypatch.setattr(io,'open',denied_open)
    monkeypatch.setattr(builtins,'__import__',guarded_import)
    assert analyze(data,cfg,policy).relations


def test_runner_traps_gt_reads_and_protected_writes(tmp_path):
    sys.path.insert(0,str(ROOT/'scripts'))
    from run_stage_level_analysis import production_guard
    output = tmp_path/'new_output'
    with production_guard([output]):
        with pytest.raises(AssertionError,match='truth_access'):
            (tmp_path/'ground_truth.json').read_text()
        with pytest.raises(AssertionError,match='outside_new_relation_outputs'):
            (tmp_path/'attack125_final.jsonl').write_text('forbidden')


@pytest.mark.parametrize('kind', ['STRONG_DIRECTED','STRONG_UNDIRECTED','WEAK_DIRECTED'])
def test_runner_consumes_only_sealed_snapshot_and_rejects_overwrite(cfg,normalization,policy,tmp_path,monkeypatch,kind):
    import gzip
    import shutil
    sys.path.insert(0,str(ROOT/'scripts'))
    import run_stage_level_analysis as runner
    rows = ([record(1,hostname='h'),record(2,time=5,hostname='h')] if kind == 'WEAK_DIRECTED'
            else lineage(100 if kind == 'STRONG_UNDIRECTED' else 0,5))
    data = snapshot(rows,cfg,normalization)
    s,aa,ee,cc,ss = data
    monkeypatch.setattr(runner,'ROOT',tmp_path)
    source_id = 'ana_'+'0'*64
    domain = tmp_path/'data/processed'/source_id
    domain.mkdir(parents=True)
    (tmp_path/'configs').mkdir()
    shutil.copyfile(ROOT/'configs/stage-relations-v1.yaml',tmp_path/'configs/stage-relations-v1.yaml')
    # Receipt hashes runner code relative to its effective workspace.
    (tmp_path/'scripts').mkdir()
    shutil.copyfile(ROOT/'scripts/run_stage_level_analysis.py',tmp_path/'scripts/run_stage_level_analysis.py')
    monkeypatch.setattr(runner,'__file__',str(tmp_path/'scripts/run_stage_level_analysis.py'))
    files = {}
    for name,objects in (('stage_source_alerts.jsonl.gz',aa),('stage_source_entities.jsonl.gz',ee),
                         ('stage_source_communities.jsonl.gz',cc),('behaviors.jsonl.gz',s.behaviors),('stages.jsonl.gz',s.stages)):
        path = domain/name
        with gzip.open(path,'wt',encoding='utf8') as stream:
            stream.write(''.join(x.canonical_json()+'\n' for x in objects))
        files[path.relative_to(tmp_path).as_posix()] = runner.sha(path)
    native = tmp_path/'alerts.jsonl'
    native.write_text(''.join(canonical_json(a.raw_alert)+'\n' for a in aa),encoding='utf8')
    manifest = tmp_path/'outputs/baseline/manifest.json'
    manifest.parent.mkdir(parents=True)
    manifest.write_text(canonical_json(dict(status='sealed',algorithm_version='behavior-stage-v1',analysis_id=source_id,
        input_sha256=runner.sha(native),artifacts=files,config_snapshot=dict(
            behavior_stage=load_stage_config(ROOT/'configs/behavior-stage-v1.yaml').model_dump(mode='json'),
            community=cfg.model_dump(mode='json'),sources={k:v.snapshot() for k,v in ss.items()}))),encoding='utf8')
    old_convert = __import__('app.adapters.multisource',fromlist=['MultiSourceAdapter']).MultiSourceAdapter
    def no_ingress(*args,**kwargs):
        raise AssertionError('must_not_repeat_adapter')
    monkeypatch.setattr(old_convert,'convert_record',no_ingress)
    result = runner.execute(manifest,native,tmp_path/'outputs/new_relations')
    assert len(result.relations) == 1
    relation, = result.relations
    assert relation.relation_type == kind
    exported = relation.model_dump(mode='json')
    output = tmp_path/'outputs/new_relations'
    assert json.loads((output/'relations.json').read_text()) == [exported]
    assert json.loads((output/'result.json').read_text())['relations'] == [exported]
    stored, = list((tmp_path/'data/processed').glob('*/stage_relations.jsonl'))
    assert json.loads(stored.read_text()) == exported
    assert 'direction_basis' in json.loads((output/'contracts.json').read_text())['StageRelation']['required']
    assert all(runner.sha(tmp_path/p) == h for p,h in files.items())
    summary = json.loads((tmp_path/'outputs/new_relations/summary.json').read_text())
    assert summary['prohibited_reads'] == summary['prohibited_imports'] == 0
    assert summary['GROUND_TRUTH_USED_BY_PRODUCTION'] is summary['DATA_MUTATED'] is False
    # Synthetic receipts exercise rendering only, not a real experiment report.
    from report_stage_level_analysis import report
    audit = tmp_path/'synthetic_integrity.json'
    audit.write_text('{}')
    tests = tmp_path/'synthetic_tests.xml'
    tests.write_text('<testsuites><testsuite tests="0" failures="0" errors="0" skipped="0"/></testsuites>')
    for legacy in (False,True):
        payload = result.model_dump(mode='json')
        if legacy:
            payload['relations'][0].pop('direction_basis')
        (output/'result.json').write_text(json.dumps(payload),encoding='utf8')
        report(output,audit,audit,tests)
        rendered = (output/'REPORT.md').read_text(encoding='utf8')
        assert '"direction_basis": "'+relation.direction_basis+'"' in rendered
        assert '箭头只表示较早 Stage → 较晚 Stage 的展示顺序' in rendered
    with pytest.raises(ValueError,match='new_directory'):
        runner.execute(manifest,native,tmp_path/'outputs/new_relations')


def test_pid_or_name_without_instance_never_becomes_strong_lineage(cfg,normalization,policy):
    rows = [record(1,hostname='h',process_name='same',process_id=1),
            record(2,time=5,hostname='h',process_name='same',process_id=2,parent_process_id=1)]
    result = analyze(snapshot(rows,cfg,normalization),cfg,policy)
    assert all(r.relation_type == 'WEAK_DIRECTED' for r in result.relations)


def test_weak_binding_never_upgrades_by_quantity(cfg,normalization,policy):
    rows = [record(1,hostname='h',user='Alice',request_id='r',session_id='s'),
            record(2,time=5,hostname='h',user='Alice',request_id='r',session_id='s')]
    r, = analyze(snapshot(rows,cfg,normalization),cfg,policy).relations
    assert r.relation_type == 'WEAK_DIRECTED' and r.confidence == policy.evidence['shared_binding'].strength


@pytest.mark.parametrize('time', [0, 5])
def test_same_complete_current_process_is_strong_without_inventing_direction(cfg,normalization,policy,time):
    rows = [record(1,hostname='h',operation='ProcessStart',process_id=42,
                   process_start_time='2026-01-01T00:00:00Z'),
            record(2,time=time,hostname='h',operation='FileRead',process_id=42,
                   process_start_time='2026-01-01T00:00:00Z')]
    data = snapshot(rows,cfg,normalization)
    r, = analyze(data,cfg,policy).relations
    assert r.relation_type == 'STRONG_UNDIRECTED'
    assert r.evidence_type == 'same_instance'
    assert r.semantic_direction is None
    assert r.from_stage_id is r.to_stage_id is None
    assert not r.time_conflict and not r.direction_conflict and not r.direction_reliable
    from app.evidence_trace.trace import EvidenceTraceIndex
    index = EvidenceTraceIndex('ana_'+'0'*64,data[1],data[0].stages,data[0].behaviors,[r])
    assert index.relation_trace(r.relation_id).direction_basis == 'unresolved'
    assert index.validate()['dangling_reference_count'] == 0
    assert StageRelation.model_validate_json(r.model_dump_json(),context=dict(
        alerts={a.alert_id:a for a in data[1]},stages={s.stage_id:s for s in data[0].stages})) == r


@pytest.mark.parametrize('native_id,same_tuple,same_source,expected', [
    (True,True,True,'STRONG_UNDIRECTED'), (False,True,True,'WEAK_DIRECTED'),
    (True,False,True,'WEAK_DIRECTED'), (True,True,False,'WEAK_DIRECTED')])
def test_flow_requires_native_identity_complete_tuple_and_scope(cfg,normalization,policy,
        native_id,same_tuple,same_source,expected):
    fields = dict(src_ip='192.0.2.1',src_port=12345,dst_ip='192.0.2.2',dst_port=443,protocol='TCP')
    if native_id:
        fields['flow_id'] = 100
    rows = [record(1,**fields), record(2,time=5,source='edr' if same_source else 'firewall',
        **dict(fields,dst_port=443 if same_tuple else 22))]
    r, = analyze(snapshot(rows,cfg,normalization),cfg,policy).relations
    assert r.relation_type == expected
    if expected == 'STRONG_UNDIRECTED':
        assert r.evidence_type == 'same_instance' and r.semantic_direction is None
        aa = {a.alert_id:a for a in snapshot(rows,cfg,normalization)[1]}
        assert sum(p.pointer == '/flow_id' for p in r.primary_evidence.pointers) == 2
        for p in r.primary_evidence.pointers:
            p.resolve(aa)


@pytest.mark.parametrize('host,start', [('other','2026-01-01T00:00:00Z'),('h','2026-01-01T00:00:01Z')])
def test_pid_reuse_or_different_host_is_not_same_instance(cfg,normalization,policy,host,start):
    rows = [record(1,hostname='h',process_id=42,process_start_time='2026-01-01T00:00:00Z'),
            record(2,time=5,hostname=host,process_id=42,process_start_time=start)]
    result = analyze(snapshot(rows,cfg,normalization),cfg,policy)
    assert all(not r.primary_evidence.strong for r in result.relations)


def test_legacy_policy_stays_readable_and_replays_legacy_process_decision(cfg,normalization,policy):
    raw = policy.model_dump()
    raw['evidence'].pop('same_instance')
    legacy = RelationConfig.model_validate(raw)
    rows = [record(i,time=i,hostname='h',process_id=42,process_start_time='2026-01-01T00:00:00Z')
            for i in (1,2)]
    r, = analyze(snapshot(rows,cfg,normalization),cfg,legacy).relations
    assert r.relation_type == 'WEAK_DIRECTED' and r.evidence_type == 'shared_process_instance'


def test_semantic_network_attestation_supported_without_promoting_endpoint_match(cfg,normalization,policy):
    from app.models import Entity, EntityOccurrence, AlertRelation
    from app.utils.stable_id import id_for
    rows = [record(1,hostname='a',dst_ip='192.0.2.2',request_object_id='observed-link'),
            record(2,time=5,hostname='b',src_ip='192.0.2.2',response_object_id='observed-link')]
    s,aa,ee,cc,ss = snapshot(rows,cfg,normalization)
    by_native = {a.raw_alert['event_id']:a for a in aa}
    left,right = by_native['1'],by_native['2']
    # Simulate an existing upstream attestation; no production extraction changes.
    entity_data = dict(type='IP',scope='network',value='192.0.2.2')
    eid = id_for('Entity',entity_data)
    entity = Entity(entity_id=eid,**entity_data,display_value='192.0.2.2',alert_ids=sorted([left.alert_id,right.alert_id]))
    ee = [*ee,entity]
    relation = AlertRelation(relation_type='network_pivot',source_entity_id=eid,target_entity_id=eid,
        raw_pointers=[EvidencePointer(alert_id=left.alert_id,pointer='/dst_ip',side='src'),
                      EvidencePointer(alert_id=left.alert_id,pointer='/request_object_id',side='src'),
                      EvidencePointer(alert_id=right.alert_id,pointer='/src_ip',side='dst'),
                      EvidencePointer(alert_id=right.alert_id,pointer='/response_object_id',side='dst')])
    updated = []
    for a in aa:
        source = a.alert_id == left.alert_id
        updated.append(type(a).model_validate(dict(a.model_dump(),entity_ids=sorted([*a.entity_ids,eid]),
            entity_occurrences=[*a.entity_occurrences,EntityOccurrence(entity_id=eid,role='dst_ip' if source else 'src_ip',raw_pointer='/dst_ip' if source else '/src_ip')],
            relations=[relation] if source else [])))
    community = IncidentCandidate.model_validate(dict(cc[0].model_dump(),entity_ids=sorted([*cc[0].entity_ids,eid])))
    r, = analyze((s,updated,ee,[community],ss),cfg,policy).relations
    assert r.relation_type == 'STRONG_DIRECTED' and r.evidence_type == 'attested_relation'

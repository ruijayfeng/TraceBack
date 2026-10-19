"""Independent evidence acceptance and observation repair fixtures; no labels."""

from pathlib import Path
import random

import pytest

from app.adapters.base import AdapterSettings
from app.config import load_config
from app.correlation.edges import run_correlation
from app.correlation.scoring import CorrelationScorer
from app.dedup.grouping import deduplicate, DuplicateScorer
from app.models import CanonicalAlert, ScoreBreakdown, CorrelationEdge
from app.services.storage import restore_config, SnapshotStore
from app.utils.stable_id import id_for, raw_fingerprint
from test_correlation_score import alert, inputs, parent_child, process


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def v3():
    return load_config(ROOT/'configs/algorithm-v3.yaml')


def message(a, value):
    data = a.model_dump()
    data['raw_alert']['full_log'] = value
    data['raw_fingerprint'] = raw_fingerprint(data['raw_alert'])
    data['alert_id'] = id_for('CanonicalAlert', data)
    return CanonicalAlert.model_validate(data)


def score(alerts, cfg, settings=None):
    idx, settings = inputs(alerts, settings)
    scorer = CorrelationScorer(idx, cfg, settings)
    pair = scorer.score_pair(alerts[0].alert_id, alerts[1].alert_id)
    return pair, scorer


def repeated(seconds=0, rule='b', account='u'):
    return [message(alert('a',host='mail',account='u',rule_id='a'), 'same embedded authentication message'),
            message(alert('b',seconds,host='mail',account=account,rule_id=rule), 'same embedded authentication message')]


def test_same_observation_multi_detector(v3):
    aa = repeated()
    idx, settings = inputs(aa)
    result = deduplicate(aa, v3, settings)
    assert len(result.groups) == 1 and len(result.groups[0].alert_ids) == 2
    assert result.groups[0].representative_alert_id == min(a.alert_id for a in aa)
    assert result.groups[0].reasons[0].params['rule_id'] == 'observation_identity_v3'


def test_near_duplicate_conservative_window_and_complete_link(v3):
    aa = repeated(1)
    _, settings = inputs(aa)
    assert len(deduplicate(aa,v3,settings).groups) == 1
    far = repeated(3)
    assert not deduplicate(far,v3,settings).groups
    conflict = repeated(1,account='other')
    assert not deduplicate(conflict,v3,settings).groups


def test_duplicate_vs_correlation(v3):
    pair, _ = score(repeated(),v3)
    assert not pair.valid and pair.diagnostics['evidence_v2']['duplicate_observation_risk']
    pair, _ = score(parent_child(),v3)
    assert pair.valid and pair.score >= .65 and pair.relations


def test_bounded_storage_does_not_change_edges_or_exact_counts(v3,tmp_path):
    import json
    import duckdb
    aa = parent_child()+[alert('noise',12,host='other',rule_id='noise')]
    idx,settings = inputs(aa)
    full_rows=[]
    full=run_correlation(idx.alerts.values(),(),idx.entities.values(),v3,settings,diagnostic_sink=full_rows.append)
    bounded=run_correlation(idx.alerts.values(),(),idx.entities.values(),v3,settings,output_root=tmp_path)
    assert [e.canonical_json() for e in full.edges] == [e.canonical_json() for e in bounded.edges]
    assert full.summary['verified_member_pair_count']==bounded.summary['verified_member_pair_count']
    details=SnapshotStore(tmp_path,bounded.record.analysis_id).details
    stats=json.loads((details/'bounded_diagnostics.json').read_text(encoding='utf8'))
    assert stats['counts'].get('candidate',0)==len(full.candidates.pairs)
    assert stats['counts'].get('member_score',0)==full.summary['verified_member_pair_count']
    assert stats['counts'].get('accept',0)==len(full.edges)
    assert all(c <= (2000 if k=='near_threshold' else 500) for k,c in stats['sample_counts'].items())
    assert not any(json.loads(line)['stage'] in ('candidate','member_score') for line in (details/'diagnostics.jsonl').read_text(encoding='utf8').splitlines())
    db=duckdb.connect(':memory:')
    try:
        actual=db.execute('SELECT count(*) FROM read_parquet(?)',[str(details/'candidate_decisions/*.parquet')]).fetchone()[0]
        assert actual==len(full.candidates.pairs)
    finally:
        db.close()
    SnapshotStore(tmp_path,bounded.record.analysis_id).read_metadata()


def test_rejected_diagnostics_caps_and_size_guard(v3,tmp_path,monkeypatch):
    import io,json
    from app.services import bounded_diagnostics as mod
    aa=repeated()
    pair,scorer=score(aa,v3)
    member=dict(stage='member_score',support_pair=[a.alert_id for a in aa],score=pair.score,
        valid=pair.valid,evidence=pair.diagnostics)
    sink=mod.BoundedDiagnostics(tmp_path,io.StringIO());sink.index=scorer.index
    for n in range(510):
        key=[a.alert_id for a in aa]
        sink(dict(stage='candidate',support_key=key))
        sink(member)
        sink(dict(stage='correlation_decision',support_key=key,decision='reject',rule_id='no_valid_member_pair',
            evidence_decision='REJECT_INSUFFICIENT_EVIDENCE',score=None))
    assert sink.sample_counts['duplicate_observation']==500
    assert all(c <= (2000 if k=='near_threshold' else 500) for k,c in sink.sample_counts.items())
    sink.close()
    stats=json.loads((tmp_path/'bounded_diagnostics.json').read_text(encoding='utf8'))
    assert stats['counts']['correlation_decision']==510 and stats['counts']['duplicate_observation_member']==510
    assert sum(r['count'] for r in stats['score_histogram'] if r['population']=='member')==510
    other=tmp_path/'guard';other.mkdir()
    sink=mod.BoundedDiagnostics(other,io.StringIO());sink.index=scorer.index
    monkeypatch.setattr(mod,'FILE_LIMIT',100)
    sink(dict(stage='candidate',support_key=key));sink(member)
    sink(dict(stage='correlation_decision',support_key=key,decision='reject',rule_id='x',score=None))
    assert sink.sample_guard and not sink.sample_counts
    monkeypatch.undo();sink.close()


def test_columnar_batch_preserves_sql_characters_and_nulls(tmp_path):
    import duckdb
    from app.services.bounded_diagnostics import ColumnarStream,sql_literal
    value="中文 '); DROP TABLE batch; --\n\\literal"
    stream=ColumnarStream(tmp_path/'quoted', 'ordinal BIGINT, payload VARCHAR, score DOUBLE')
    stream.add((0,value,None));stream.add((1,"'quoted'",.65));stream.close()
    db=duckdb.connect(':memory:')
    try:
        rows=db.execute('SELECT * FROM read_parquet('+sql_literal(str(stream.directory/'000000.parquet'))+') ORDER BY ordinal').fetchall()
        assert rows==[(0,value,None),(1,"'quoted'",.65)]
    finally:
        db.close()


def test_signature_time_does_not_dedupe(v3):
    aa = [alert('a',host='h',signature='s'),alert('b',1,host='h',signature='s')]
    _, settings = inputs(aa)
    assert not deduplicate(aa,v3,settings).groups


def test_cross_detector_observation_requires_declared_scope(v3):
    aa=[message(alert('a',namespace='one',host='h',account='u'), 'embedded auth message')]
    data=alert('b',namespace='two',source_type='aminer',host='h',account='u').model_dump()
    data['raw_alert']['LogData']={'RawLogData':['embedded auth message']}
    data['raw_fingerprint']=raw_fingerprint(data['raw_alert'])
    data['alert_id']=id_for('CanonicalAlert',data)
    aa.append(CanonicalAlert.model_validate(data))
    settings={n:AdapterSettings(n,'synthetic','synthetic',asset_namespace='assets',account_realm='realm') for n in ('one','two')}
    assert len(deduplicate(aa,v3,settings).groups)==1
    isolated={n:AdapterSettings(n,'synthetic','synthetic') for n in ('one','two')}
    assert not deduplicate(aa,v3,isolated).groups
    data['raw_alert']['LogData']['RawLogData'].append('other observation')
    data['raw_fingerprint']=raw_fingerprint(data['raw_alert']);data['alert_id']=id_for('CanonicalAlert',data)
    aa[1]=CanonicalAlert.model_validate(data)
    assert not deduplicate(aa,v3,settings).groups


def test_family_fact_keys_are_unique(v3):
    pair, scorer = score(parent_child(),v3)
    evidence = scorer.breakdown(pair).evidence_v2
    assert len({f.fact_key for f in evidence.evidence}) == len(evidence.evidence)
    assert 'entity.PROCESS' in evidence.suppressed_dimensions
    data = scorer.breakdown(pair).model_dump()
    data['evidence_v2']['evidence'].append(data['evidence_v2']['evidence'][0])
    with pytest.raises(ValueError):
        ScoreBreakdown.model_validate(data)


def flow(valid=True):
    return [network_event(alert('a',category='initial_access',src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=1000,dst_port=80),'f1'),
            network_event(alert('b',5,category='lateral_movement' if valid else 'unknown',src_ip='192.0.2.2',dst_ip='192.0.2.3',src_port=1001,dst_port=80),'f2')]


def test_same_ip_derived_feature_consumed_once(v3):
    pair, _ = score(flow(),v3)
    ev = pair.diagnostics['evidence_v2']
    assert ev['network_continuity_valid']
    assert 'entity.IP' in ev['suppressed_dimensions']
    assert 'entity.IP' not in ev['matched_evidence']
    assert sum(f['family']=='NETWORK_FLOW' for f in ev['evidence']) == 1


def test_local_observation_never_flow(v3):
    aa = [alert(n,i,host='h',account='u',src_ip='192.0.2.1',dst_ip='192.0.2.1') for i,n in enumerate(('a','b'))]
    pair, _ = score(aa,v3)
    assert not pair.diagnostics['evidence_v2']['network_continuity_valid']
    assert pair.diagnostics['evidence_v2']['network_diagnostic'] == 'local_host_observation'


def test_invalid_continuity_equality_only(v3):
    pair, _ = score(flow(False),v3)
    assert not pair.valid
    assert pair.diagnostics['evidence_v2']['network_diagnostic'] == 'endpoint_equality_without_direction_context'


def test_valid_ordered_network_continuity(v3):
    pair, scorer = score(flow(),v3)
    assert pair.valid and pair.score >= .65 and not pair.relations
    assert scorer.breakdown(pair).evidence_v2.primary_evidence


def test_multiple_shared_ips_flow_reference_closure(v3):
    aa=flow()
    aa[1]=network_event(alert('b',5,category='lateral_movement',src_ip='192.0.2.2',dst_ip='192.0.2.1',src_port=1001,dst_port=80),'f2')
    idx,settings=inputs(aa)
    result=run_correlation(idx.alerts.values(),(),idx.entities.values(),v3,settings)
    assert len(result.edges)==1
    edge=result.edges[0]
    flow_ids={eid for f in edge.score_breakdown.evidence_v2.evidence if f.family=='NETWORK_FLOW' for eid in f.entity_ids}
    assert flow_ids <= set(edge.entity_ids)
    assert CorrelationEdge.model_validate(edge.model_dump(),context={'alerts':idx.alerts})==edge


def test_equal_timestamp_has_no_network_order(v3):
    aa = flow(); aa[1] = alert('c',category='lateral_movement',src_ip='192.0.2.2',dst_ip='192.0.2.3')
    pair, _ = score(aa,v3)
    assert not pair.diagnostics['evidence_v2']['network_continuity_valid']


def test_metadata_counts_as_one_supporting_fact(v3):
    aa = [alert(n,rule_id='r',signature='s',alert_type='t',category='authentication') for n in ('a','b')]
    pair, _ = score(aa,v3)
    ev = pair.diagnostics['evidence_v2']
    assert len([d for d in ev['dimensions'] if d['family']=='behavior']) == 1
    assert ev['family_strengths']['behavior'] <= .2
    assert not ev['primary_evidence'] and not pair.valid


def test_metadata_only_candidate_diagnostic(v3):
    aa = [alert(n,i,rule_id='r',signature='s') for i,n in enumerate(('a','b'))]
    idx, settings = inputs(aa)
    result = run_correlation(idx.alerts.values(),(),idx.entities.values(),v3,settings)
    assert result.candidates.pairs and not result.edges
    pair, _ = score(aa,v3)
    assert pair.diagnostics['evidence_v2']['gate_reason']=='metadata_dominated_candidate'


def test_hot_entity_reliability_retains_nonzero_support(v3):
    aa = [alert(str(i),i,host='public',rule_id=str(i)) for i in range(105)]
    pair, _ = score(aa,v3)
    row = pair.diagnostics['evidence_v2']['entity_reliability'][0]
    assert row['hot'] and 0 < row['reliability'] < .6 and not pair.valid


def test_rare_entity_reliability(v3):
    aa = [alert('a',host='rare',rule_id='a'),alert('b',1,host='rare',rule_id='b')]
    aa += [alert(str(i),host='other'+str(i)) for i in range(100)]
    pair, _ = score(aa,v3)
    assert pair.diagnostics['evidence_v2']['entity_reliability'][0]['reliability'] > .6
    assert pair.valid and pair.score >= .65


def test_missing_family_not_mismatch(v3):
    pair, _ = score([alert('a',host='h',account='u'),alert('b',1,host='h')],v3)
    ev=pair.diagnostics['evidence_v2']
    assert 'entity.ACCOUNT' in ev['unavailable_evidence']
    assert 'entity.PROCESS' in ev['not_applicable_evidence']


def test_known_different_family_is_mismatch(v3):
    pair, _ = score([alert('a',host='h',account='u'),alert('b',1,host='h',account='v')],v3)
    assert 'entity.ACCOUNT' in pair.diagnostics['evidence_v2']['mismatched_evidence']
    assert 'verified_incompatible_session' not in pair.rejection_codes


def test_applicable_normalization(v3):
    pair, _ = score(parent_child(),v3)
    ev=pair.diagnostics['evidence_v2']
    assert ev['normalized_quality']==pytest.approx(ev['matched_weight']/ev['available_weight'])
    assert 'RESOURCE_CONTEXT' not in ev['applicable_evidence_families']


def test_primary_requirement_prevents_same_rule_host_clique(v3):
    aa=[alert(n,i,host='h',rule_id='r',signature='s') for i,n in enumerate(('a','b'))]
    pair, _ = score(aa,v3)
    assert not pair.valid and not pair.diagnostics['evidence_v2']['primary_evidence']


def test_cross_source_valid_fixture_no_source_bonus(v3):
    aa=[network_event(alert('a',namespace='one',category='initial_access',src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=1000,dst_port=80),'f1'),
        network_event(alert('b',5,namespace='two',category='lateral_movement',src_ip='192.0.2.2',dst_ip='192.0.2.3',src_port=1001,dst_port=80),'f2')]
    settings={n:AdapterSettings(n,'synthetic','synthetic',network_namespace='shared') for n in ('one','two')}
    pair, _ = score(aa,v3,settings)
    assert pair.valid and pair.score >= .65 and pair.values['source']==0


def test_singleton_preserved(v3):
    from app.chains.assembly import run_reconstruction
    aa=[alert('a',rule_id='r'),alert('b',1,rule_id='r')]
    idx,settings=inputs(aa)
    c=run_correlation(idx.alerts.values(),(),idx.entities.values(),v3,settings)
    result=run_reconstruction(idx.alerts.values(),(),idx.entities.values(),c.edges,v3,settings,upstream_record=c.record)
    assert len(result.incidents)==2 and all(len(i.alert_ids)==1 for i in result.incidents)


def test_deterministic_score_and_snapshot_roundtrip(v3,tmp_path):
    aa=parent_child()
    pair,scorer=score(aa,v3)
    expected=scorer.breakdown(pair)
    assert restore_config(v3.snapshot).config_hash==v3.config_hash
    assert ScoreBreakdown.model_validate_json(expected.canonical_json())==expected
    idx,settings=inputs(aa)
    c=run_correlation(idx.alerts.values(),(),idx.entities.values(),v3,settings)
    store=SnapshotStore(tmp_path,c.record.analysis_id)
    store.write_records('correlation_edges',c.edges)
    assert list(store.read_records('correlation_edges'))==c.edges
    for seed in range(3):
        order=aa[:];random.Random(seed).shuffle(order)
        p,s=score(order,v3)
        assert s.breakdown(p).evidence_v2==expected.evidence_v2


def test_legacy_versions_hash_unchanged(v3):
    for version in ('v0','v2'):
        cfg=load_config(ROOT/f'configs/algorithm-{version}.yaml')
        assert 'evidence_v3' not in cfg.snapshot['score'] and 'observation' not in cfg.snapshot['duplicate']
        assert restore_config(cfg.snapshot).config_hash==cfg.config_hash


def network_event(a, flow_id, tx='0', proto='TCP'):
    data=a.model_dump()
    data['raw_alert'].update(flow_id=flow_id, tx_id=tx, proto=proto)
    data['raw_fingerprint']=raw_fingerprint(data['raw_alert'])
    data['alert_id']=id_for('CanonicalAlert',data)
    return CanonicalAlert.model_validate(data)


@pytest.mark.parametrize('seconds',[5,30])
def test_same_observation_outside_dedupe_window_cannot_be_formal_edge(v3,seconds):
    fields=dict(host='h',url='https://rare.example.invalid/specific',
        src_ip='192.0.2.1',dst_ip='192.0.2.1',src_port=1000,dst_port=80)
    aa=[network_event(alert('a',rule_id='one',**fields),'same'),
        network_event(alert('b',seconds,rule_id='two',**fields),'same')]
    pair,scorer=score(aa,v3)
    assert not scorer.duplicate.observation.compare(*aa)['equivalent']
    assert len(scorer.duplicate.observation.compare(*aa)['observation_ids'])==1
    assert not pair.valid and pair.diagnostics['evidence_v2']['duplicate_observation_risk']
    assert pair.diagnostics['evidence_v2']['gate_reason']=='duplicate_observation_only'


def test_same_flow_different_detection_and_source_type(v3):
    fields=dict(src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=1000,dst_port=80)
    aa=[network_event(alert('a',namespace='one',rule_id='r1',signature='one',**fields),'123.000000'),
        network_event(alert('b',namespace='two',source_type='suricata',rule_id='r2',signature='two',**fields),'123')]
    settings={n:AdapterSettings(n,'synthetic','synthetic',network_namespace='shared') for n in ('one','two')}
    dedup=deduplicate(aa,v3,settings)
    assert len(dedup.groups)==1 and len(dedup.groups[0].alert_ids)==2
    pair,scorer=score(aa,v3,settings)
    assert not pair.valid and pair.diagnostics['evidence_v2']['duplicate_observation_risk']
    assert len(scorer.duplicate.observation.compare(*aa)['observation_ids'])==1
    isolated={n:AdapterSettings(n,'synthetic','synthetic') for n in ('one','two')}
    assert not deduplicate(aa,v3,isolated).groups


def test_flow_does_not_merge_distinct_transactions(v3):
    fields=dict(src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=1000,dst_port=80)
    aa=[message(network_event(alert('a',**fields),'f',tx='1'),'same text'),
        message(network_event(alert('b',**fields),'f',tx='2'),'same text')]
    _,settings=inputs(aa)
    assert not deduplicate(aa,v3,settings).groups


@pytest.mark.parametrize('role',['src_ip','dst_ip'])
def test_same_role_endpoint_is_not_succession(v3,role):
    fields=dict(src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=1000,dst_port=80)
    other={**fields, 'dst_ip' if role=='src_ip' else 'src_ip':'192.0.2.3'}
    aa=[network_event(alert('a',category='initial_access',**fields),'f1'),
        network_event(alert('b',1,category='lateral_movement',**other),'f2')]
    pair,_=score(aa,v3)
    assert not pair.valid and not pair.diagnostics['evidence_v2']['network_continuity_valid']


def test_category_transition_does_not_confirm_network_context(v3):
    aa=[alert('a',category='initial_access',src_ip='192.0.2.1',dst_ip='192.0.2.2'),
        alert('b',1,category='lateral_movement',src_ip='192.0.2.2',dst_ip='192.0.2.3')]
    pair,_=score(aa,v3)
    assert not pair.valid
    assert pair.diagnostics['evidence_v2']['network_diagnostic']=='endpoint_bridge_without_independent_flow_context'


@pytest.mark.parametrize('url',['/','/rare-path','https://example.test/'])
def test_weak_resource_is_supporting_even_if_rare(v3,url):
    aa=[alert('a',url=url,rule_id='r'),alert('b',1,url=url,rule_id='r')]
    pair,_=score(aa,v3)
    ev=pair.diagnostics['evidence_v2']
    assert not pair.valid and not ev['primary_evidence']
    assert all(r['descriptor_factor']==.25 for r in ev['entity_reliability'])


def test_specific_target_scoped_resource_remains_primary(v3):
    aa=[alert('a',url='https://example.test/rare-object',rule_id='r'),
        alert('b',1,url='https://example.test/rare-object',rule_id='r')]
    pair,scorer=score(aa,v3)
    assert pair.valid and pair.score >= .65
    ev=scorer.breakdown(pair).evidence_v2
    assert any(f.family=='RESOURCE_CONTEXT' and f.role=='primary' for f in ev.evidence)
    assert all(set(f.source_alert_ids)=={a.alert_id for a in aa} and f.observation_ids for f in ev.evidence)


def test_multiple_independent_facts_have_disjoint_consumed_entities(v3):
    pair,scorer=score(parent_child(),v3)
    ev=scorer.breakdown(pair).evidence_v2
    primary=[f for f in ev.evidence if f.role=='primary']
    assert pair.valid and len(primary)>1
    for i,left in enumerate(primary):
        for right in primary[i+1:]:
            assert not set(left.entity_ids)&set(right.entity_ids)


def test_historical_v3_config_and_edge_serialization_unchanged(v3):
    import json
    receipt=json.loads((ROOT/'outputs/correlation_v3/REAL_DATA_RESULT.json').read_text())
    record=json.loads((ROOT/'data/processed'/receipt['analysis_id']/'analysis.json').read_text(encoding='utf-8'))
    cfg=restore_config(record['config_snapshot']['algorithm'])
    assert not cfg.algorithm.duplicate.observation.event_pointers
    from app.utils.stable_id import content_digest
    assert content_digest({'algorithm':cfg.snapshot,'sources':record['config_snapshot']['sources']})==record['config_hash']
    for line in (ROOT/'data/processed'/receipt['analysis_id']/'correlation_edges.jsonl').read_text(encoding='utf-8').splitlines():
        assert CorrelationEdge.model_validate_json(line).canonical_json()==line


def test_shared_public_ip_and_metadata_do_not_create_clique(v3):
    aa=[alert(str(i),i,src_ip='192.0.2.53',rule_id='dns',signature='same rule',category='authentication') for i in range(105)]
    idx,settings=inputs(aa)
    result=run_correlation(idx.alerts.values(),(),idx.entities.values(),v3,settings)
    assert result.candidates.pairs and not result.edges


def test_fact_provenance_cannot_borrow_an_unrelated_alert(v3):
    pair,scorer=score(parent_child(),v3)
    data=scorer.breakdown(pair).model_dump()
    data['evidence_v2']['evidence'][0]['source_alert_ids']=[alert('unrelated').alert_id]
    with pytest.raises(ValueError,match='fact pointers outside source alerts'):
        ScoreBreakdown.model_validate(data)

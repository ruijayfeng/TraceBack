"""Synthetic v4 adversarial, backward compatibility and integration fixtures."""
from pathlib import Path
import random
import pytest
from app.config import load_config
from app.correlation.edges import run_correlation
from app.correlation.scoring import CorrelationScorer
from app.services.storage import restore_config, SnapshotStore
from app.models import ScoreBreakdown, CorrelationEdge
from test_correlation_score import alert, inputs, parent_child
from test_correlation_v3 import score, flow, network_event

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def v4(): return load_config(ROOT/'configs/algorithm-v4.yaml')


def test_generic_type_does_not_reinforce_metadata(v4):
    aa = [alert(n, host='h', account='u', rule_id=n, alert_type='generic') for n in ('a', 'b')]
    old, _ = score(aa, load_config(ROOT/'configs/algorithm-v3.yaml'))
    new, scorer = score(aa, v4)
    assert old.diagnostics['evidence_v2']['family_strengths']['behavior'] == .2
    assert new.diagnostics['evidence_v2']['family_strengths']['behavior'] == 0
    assert new.score < old.score
    assert scorer.breakdown(new).evidence_v2.version == 'v4'


def test_type_difference_cannot_promote_shared_host(v4):
    aa = [alert('a', host='rare', rule_id='same', alert_type='x'),
          alert('b', 1, host='rare', rule_id='same', alert_type='y')]
    old, _ = score(aa, load_config(ROOT/'configs/algorithm-v3.yaml'))
    new, _ = score(aa, v4)
    assert old.valid and not new.valid
    assert not new.diagnostics['evidence_v2']['primary_evidence']


@pytest.mark.parametrize('roles,factor', [('destination', .25), ('source', 1.), ('bridge', .8)])
def test_ip_role_informativeness(v4, roles, factor):
    shared = '192.0.2.9'
    fields = [{'src_ip': '192.0.2.1', 'dst_ip': shared}, {'src_ip': '192.0.2.2', 'dst_ip': shared}] if roles == 'destination' else (
        [{'src_ip': shared}, {'src_ip': shared}] if roles == 'source' else [{'src_ip': shared}, {'dst_ip': shared}])
    pair, scorer = score([alert('a', **fields[0]), alert('b', 1, **fields[1])], v4)
    row = pair.diagnostics['evidence_v2']['entity_reliability'][0]
    assert row['role_factor'] == factor
    assert row['reliability'] == pytest.approx((.1+.9*row['rarity'])*factor)
    assert not pair.valid
    scorer.breakdown(pair)


@pytest.mark.parametrize('category,diagnostic', [('unknown', 'network_behavior_context_unavailable'),
                                                ('authentication', 'network_behavior_context_incompatible')])
def test_port_only_flow_cannot_be_primary(v4, category, diagnostic):
    aa = [network_event(alert('a', category=category, src_ip='192.0.2.1', dst_ip='192.0.2.2', src_port=1000, dst_port=80), 'f1'),
          network_event(alert('b', 1, category=category, src_ip='192.0.2.2', dst_ip='192.0.2.3', src_port=80, dst_port=1001), 'f2')]
    pair, _ = score(aa, v4)
    ev = pair.diagnostics['evidence_v2']
    assert not pair.valid and not ev['network_continuity_valid']
    assert ev['network_diagnostic'] == diagnostic
    assert not any(r.startswith('hard_guard:') for r in pair.rejection_codes)
    partition = 'unavailable_evidence' if category == 'unknown' else 'mismatched_evidence'
    assert 'topology.network_continuity' in ev[partition]


def test_compatible_network_keeps_undirected_evidence(v4):
    pair, scorer = score(flow(), v4)
    assert pair.valid and pair.score >= .65 and not pair.relations
    assert scorer.breakdown(pair).evidence_v2.network_continuity_valid


def test_protocol_contradiction_cannot_supply_network_support(v4):
    aa = flow()
    aa[1] = network_event(alert('b', 5, category='lateral_movement', src_ip='192.0.2.2', dst_ip='192.0.2.3', src_port=1001, dst_port=80), 'f2', proto='UDP')
    pair, _ = score(aa, v4)
    assert not pair.diagnostics['evidence_v2']['network_continuity_valid']


def test_hot_public_infrastructure_not_primary(v4):
    aa = [alert(str(i), i, host='shared-service', src_ip='192.0.2.1', dst_ip='192.0.2.2', dst_port=53, rule_id=str(i)) for i in range(105)]
    pair, _ = score(aa, v4)
    assert all(r['hot'] for r in pair.diagnostics['evidence_v2']['entity_reliability'])
    assert not pair.valid


def test_rare_context_and_identifiers_retained(v4):
    pair, scorer = score(parent_child(), v4)
    assert pair.valid and pair.score >= .65 and pair.relations
    expected = scorer.breakdown(pair)
    assert ScoreBreakdown.model_validate_json(expected.canonical_json()) == expected
    aa = [alert('a', host='rare', rule_id='a'), alert('b', 1, host='rare', rule_id='b')]
    aa += [alert(str(i), host='noise'+str(i)) for i in range(100)]
    pair, _ = score(aa, v4)
    assert pair.valid and pair.score >= .65


def test_missing_account_not_conflict_and_sessions_not_exclusive(v4):
    aa = [alert('a', host='h', account='u', session='one'), alert('b', 1, host='h', session='two')]
    pair, _ = score(aa, v4)
    assert 'entity.ACCOUNT' in pair.diagnostics['evidence_v2']['unavailable_evidence']
    assert 'verified_incompatible_session' not in pair.rejection_codes


@pytest.mark.parametrize('fields', [dict(signature='same'), dict(rule_id='same', signature='same', alert_type='same'), dict(category='authentication')])
def test_metadata_only_never_primary(v4, fields):
    pair, _ = score([alert('a', **fields), alert('b', 1, **fields)], v4)
    assert not pair.valid and not pair.diagnostics['evidence_v2']['primary_evidence']


def test_temporal_model_unchanged(v4):
    aa = [alert('a', host='h'), alert('b', 300, host='h')]
    pair, _ = score(aa, v4)
    assert pair.values['time'] == pytest.approx(.5)
    aa = [alert('a', category='web_attack', host='h'), alert('b', 60, category='process_execution', host='h')]
    assert score(aa, v4)[0].values['time'] == pytest.approx(.5)


def test_candidates_are_independent_of_v4_scoring(v4):
    aa = parent_child()+[alert('noise', 1, host='h', rule_id='same')]
    idx, settings = inputs(aa)
    results = [run_correlation(idx.alerts.values(), (), idx.entities.values(), cfg, settings)
               for cfg in (load_config(ROOT/'configs/algorithm-v3.yaml'), v4)]
    assert [(p.support_key, p.channels, p.priority, p.evidence) for p in results[0].candidates.pairs] == [
            (p.support_key, p.channels, p.priority, p.evidence) for p in results[1].candidates.pairs]
    assert results[1].record.algorithm_version == 'alert-correlation-v4-role-context-candidate-v1.1'


def test_stable_order_snapshot_and_grounding(v4, tmp_path):
    aa = parent_child()
    expected = score(aa, v4)[1].breakdown(score(aa, v4)[0]).evidence_v2
    for seed in range(3):
        order = aa[:]; random.Random(seed).shuffle(order)
        pair, scorer = score(order, v4)
        assert scorer.breakdown(pair).evidence_v2 == expected
    idx, settings = inputs(aa)
    result = run_correlation(idx.alerts.values(), (), idx.entities.values(), v4, settings, output_root=tmp_path)
    store = SnapshotStore(tmp_path, result.record.analysis_id)
    store.read_metadata()
    assert list(store.read_records('correlation_edges')) == result.edges
    assert CorrelationEdge.model_validate(result.edges[0].model_dump(), context={'alerts': idx.alerts}) == result.edges[0]


def test_legacy_config_and_v4_restore(v4):
    for version in ('v0', 'v2', 'v3'):
        cfg = load_config(ROOT/f'configs/algorithm-{version}.yaml')
        assert 'evidence_v4' not in cfg.snapshot['score']
        assert restore_config(cfg.snapshot).config_hash == cfg.config_hash
    assert restore_config(v4.snapshot).config_hash == v4.config_hash


def test_singletons_and_triage_formula_retained(v4):
    from app.chains.assembly import run_reconstruction
    from app.incidents.triage import triage_singletons
    aa = [alert('a', rule_id='same'), alert('b', 1, rule_id='same')]
    idx, settings = inputs(aa)
    c = run_correlation(idx.alerts.values(), (), idx.entities.values(), v4, settings)
    r = run_reconstruction(idx.alerts.values(), (), idx.entities.values(), c.edges, v4, settings, upstream_record=c.record)
    assert len(r.incidents) == 2 and not c.edges and r.grounding.valid
    triaged = triage_singletons(r.incidents, idx, v4, c.summary, search_complete=True)
    assert all(i.single_alert_triage is not None for i in triaged)
    assert v4.algorithm.single_alert_triage == load_config(ROOT/'configs/algorithm-v3.yaml').algorithm.single_alert_triage


def test_confirmed_cross_source_needs_complementary_context(v4):
    from test_correlation_score import process
    snapshot = v4.snapshot
    snapshot['source']['independence_mapping_files'] = [{
        'schema_version': '1.0', 'mapping_type': 'source_independence', 'source_type': 'waf', 'default': 'unknown',
        'rules': [{'id': 'synthetic-topology-confirmation', 'match': {'all': [
            {'field': 'left.sensor', 'op': 'eq', 'value': 'web-detector'},
            {'field': 'right.sensor', 'op': 'eq', 'value': 'process-detector'}]}, 'output': 'confirmed_independent'}]}]
    cfg = restore_config(snapshot)
    a = alert('w', source_type='waf', sensor='web-detector', category='web_attack', host='h', src_ip='192.0.2.1')
    b = alert('e', 1, source_type='edr', sensor='process-detector', category='process_execution', host='h', process=process(1))
    pair, _ = score([a, b], cfg)
    assert pair.source_independence == 'confirmed_independent' and pair.values['source'] == 1
    b = alert('e', 1, source_type='edr', sensor='process-detector', host='h', process=process(1))
    pair, _ = score([a, b], cfg)
    assert pair.source_independence == 'confirmed_independent' and pair.values['source'] == 0
    assert score([a, b], v4)[0].source_independence == 'unknown'


def test_incremental_population_change_matches_full(v4, tmp_path):
    from app.services.incremental import IncrementalService
    from test_incremental_correlation import assert_equivalent, settings
    base = parent_child()+[alert('noise', 86400)]
    delta = [alert('new', 172800)]
    source = settings(base+delta)
    service = IncrementalService(tmp_path/'workspace.duckdb', v4, source)
    try:
        service.bootstrap(base)
        service.increment(delta)
        assert_equivalent(service, base+delta, v4, source)
    finally:
        service.close()


def test_v4_api_ingress_storage_and_query(v4, tmp_path):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from test_analysis_service import deployment, edge_records, write_input
    _, sources = deployment(tmp_path, edge=True)
    # Synthetic schema mapping belongs only to this temporary deployment.
    cfg = load_config(ROOT/'configs/algorithm-v4.yaml', deployment_override=ROOT/'configs/sources.yaml',
                      experiment_override=tmp_path/'experiment.yaml')
    with TestClient(create_app(tmp_path, configs={'v4': cfg}, sources=sources)) as client:
        path = write_input(tmp_path, edge_records())
        response = client.post('/api/v1/analyses', json={'config_version': 'v4',
            'inputs': [{'source': 'wazuh', 'source_ref': 'w', 'path': path}]})
        assert response.status_code == 202
        identity = response.json()['analysis_id']
        client.app.state.analyses.wait(identity, timeout=30)
        record = client.get('/api/v1/analyses/'+identity).json()
        assert record['status'] == 'completed' and record['correlation_v2']['version'] == 'v4'
        incidents = client.get('/api/v1/incidents', params={'analysis_id': identity}).json()['items']
        assert sum(len(i['alert_ids']) for i in incidents) == 2
        chain = client.get('/api/v1/incidents/'+incidents[0]['incident_id']+'/chain', params={'analysis_id': identity}).json()['chain']
        assert chain['nodes']
        if chain['edges']:
            detail = client.get('/api/v1/edges/'+chain['edges'][0]['edge_id'], params={'analysis_id': identity}).json()
            assert detail['correlation_edges'][0]['score_breakdown']['evidence_v2']['version'] == 'v4'

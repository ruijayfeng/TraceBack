"""Action-level admission and cadence isolation; synthetic native records only."""
import pytest

from test_community_builder import cfg, normalization, record
from test_stage_aggregation import policy, stage_run
from test_stage6_fragmentation_repair import action, flow
from test_source_bound_projection import settings
from app.community.evidence import profile
from app.stages.aggregation import community_graph


def members(run, result):
    native = {a.alert_id: a.raw_alert['event_id'] for a in run.alerts}
    return {frozenset(native[i] for i in s.alert_ids) for s in result.stages}


def graph_checks(rows, cfg, normalization, policy):
    # Isolate ⑥ from ⑤'s earlier temporal admission. All supplied observations
    # are deliberately put in the same candidate recall partition.
    run, _ = stage_run(rows, cfg, normalization, policy)
    entities = {e.entity_id: e for e in run.entities}
    profiles = {a.alert_id: profile(a, entities, settings(a.raw_alert['source_type']), cfg) for a in run.alerts}
    annotations = {b.alert_id: b for b in run.behaviors}
    edges, diagnostics, _ = community_graph(list(profiles), profiles, annotations, cfg, policy)
    return run, edges, diagnostics


def test_shared_process_request_is_not_an_application_action(cfg, normalization, policy):
    web = record('web', 'waf', server_host='worker', server_host_id='asset',
        worker_process_id=700, worker_process_start_time='2026-01-01T00:00:00Z',
        request_id='req', uri='/upload', method='POST', **flow())
    app = record('app', time=2, hostname='worker', host_id='asset', process_id=700,
        process_start_time='2026-01-01T00:00:00Z', request_id='req', operation='ApplicationRequest')
    run, result = stage_run([web, app], cfg, normalization, policy)
    current = [{o.entity_id for o in a.entity_occurrences if o.role.value == 'process'} for a in run.alerts]
    assert all(current) and current[0] == current[1]
    assert len(run.result.incident_candidates) == 1
    assert len(result.stages) == 2
    assert any(d['reason'] == 'distinct_action_roles_without_action_proof' for d in result.diagnostics)


@pytest.mark.parametrize('count', [1, 4])
def test_sparse_record_cannot_transmit_an_observed_role_boundary(cfg, normalization, policy, count):
    fields = dict(hostname='worker', host_id='asset', process_id=700,
                  process_start_time='2026-01-01T00:00:00Z', request_id='req')
    rows = [record('web'+str(i), 'waf', time=i, server_host='worker', server_host_id='asset', request_id='req',
                   worker_process_id=700, worker_process_start_time='2026-01-01T00:00:00Z',
                   uri='/upload', method='POST', **flow()) for i in range(count)]
    rows += [record('sparse', time=8, **fields)]
    rows += [record('app'+str(i), time=10+i, operation='ApplicationRequest', **fields) for i in range(count)]
    run, result = stage_run(rows, cfg, normalization, policy)
    owner = {i: group for group in members(run, result) for i in group}
    assert owner['web0'] != owner['app0']
    assert sorted(s.alert_count for s in result.stages) == [count, count+1]
    assert any(d['reason'] == 'component_hard_conflict' and
               d['conflict_reason'] == 'distinct_action_roles_without_action_proof' for d in result.diagnostics)


@pytest.mark.parametrize('operation', ['ApplicationRequest', 'NetworkConnection'])
def test_explicit_common_action_object_preserves_cross_role_aggregation(cfg, normalization, policy, operation):
    rows = [action('start', operation='ProcessStart'),
            action('observed', 'host_audit', time=2, operation=operation)]
    run, result = stage_run(rows, cfg, normalization, policy)
    assert members(run, result) == {frozenset({'start', 'observed'})}
    refs = {p.pointer for p in result.stages[0].aggregation_basis[0].evidence}
    assert {'/command_line', '/command', '/file_path', '/operation'} <= refs
    for basis in result.stages[0].aggregation_basis:
        for pointer in basis.evidence:
            pointer.resolve({a.alert_id: a for a in run.alerts})


def connection_rows(delay):
    network = dict(src_ip='192.0.2.1', dst_ip='192.0.2.2', src_port=32100, dst_port=22, protocol='TCP')
    return [record('connect', hostname='worker', process_id=8,
                   process_start_time='2025-12-31T00:00:00Z', operation='NetworkConnection',
                   connection_id='conn', **network),
            record('snapshot', 'firewall', time=delay, connection_id='conn', action='allow', **network)]


def test_cross_source_connection_coobservation_retains_identity_and_trace(cfg, normalization, policy):
    from test_context_identity_handoff import extract
    from app.services.alert_pipeline import prepare_alerts
    from app.services.stage_pipeline import prepare_stage_pipeline
    bound, ss = extract(connection_rows(2), normalization)
    pipeline = prepare_stage_pipeline(prepare_alerts(bound.alerts, source_settings=ss, entities=bound.entities,
                                                    identity_projection=bound.identity_projection))
    run, result = pipeline.community, pipeline.stages
    bound.identity_projection.validate_trace(bound.alerts, bound.entities)
    assert members(run, result) == {frozenset({'connect', 'snapshot'})}
    basis = result.stages[0].aggregation_basis[0]
    assert {'connection', 'flow'} <= set(basis.evidence_types)
    assert basis.temporal_check['cadence_scope'].startswith('connection:')
    assert basis.temporal_check['fallback_used']
    for pointer in basis.evidence:
        pointer.resolve({a.alert_id: a for a in run.alerts})


def test_unrelated_network_history_cannot_expand_connection_cadence(cfg, normalization, policy):
    rows = connection_rows(223)
    noise = [record('noise-'+str(i), time=t, hostname='worker', process_id=8,
        process_start_time='2025-12-31T00:00:00Z', operation='NetworkConnection',
        connection_id='other-'+str(i), src_ip='192.0.2.1', dst_ip='192.0.2.2',
        src_port=32200+i, dst_port=22, protocol='TCP') for i,t in enumerate([-950,-900,-400,-50])]
    checks = []
    for records in (rows, noise+rows):
        run, edges, diagnostics = graph_checks(records, cfg, normalization, policy)
        pair = sorted(a.alert_id for a in run.alerts if a.raw_alert['event_id'] in {'connect','snapshot'})
        assert not any(e.alert_ids == pair for e in edges)
        rejection = next(d for d in diagnostics if d['alert_ids'] == pair)
        assert rejection['reason'] == 'dynamic_time_conflict'
        checks.append(rejection['temporal_check'])
    assert checks[0] == checks[1]
    assert checks[0]['effective_threshold_seconds'] == cfg.temporal.fallback_seconds


def test_other_roles_on_same_connection_cannot_train_snapshot_cadence(cfg, normalization, policy):
    rows = connection_rows(223)
    noise = [dict(rows[0], event_id='n'+str(i), timestamp=record(i,time=t)['timestamp'])
             for i,t in enumerate([-950,-900,-400,-50])]
    run, _, diagnostics = graph_checks(noise+rows, cfg, normalization, policy)
    pair = sorted(a.alert_id for a in run.alerts if a.raw_alert['event_id'] in {'connect','snapshot'})
    rejection = next(d for d in diagnostics if d['alert_ids'] == pair)
    assert rejection['reason'] == 'dynamic_time_conflict'
    assert rejection['temporal_check']['effective_threshold_seconds'] == cfg.temporal.fallback_seconds

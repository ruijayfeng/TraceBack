"""Field direction, type mapping, chronology and unrounded admission."""

import math

import pytest

from app.chains.direction import chronology, decide_direction
from app.chains.nodes import build_nodes
from app.chains.reconstruction import reconstruct_candidates
from app.incidents.clustering import cluster_incidents
from fixtures.chains.synthetic import attested_fixture, linear_fixture, scorer_for
from test_chain_reconstruction import run_fixture
from test_correlation_score import alert, config, configured, inputs, process


@pytest.mark.parametrize("kind,mapped,src,dst", [
    ("target_to_process", "REQUEST_TO_PROCESS", "web_attack", "process_execution"),
    ("account_host_pivot", "ACCOUNT_PIVOT", "authentication", "lateral_movement"),
    ("network_pivot", "NETWORK_PIVOT", "initial_access", "lateral_movement"),
    ("session_continuity", "SESSION_FLOW", "authentication", "process_execution")])
def test_four_attested_mappings_direction_and_evidence(config, kind, mapped, src, dst):
    index, settings, values, correlation = attested_fixture(config, kind, src, dst)
    assert len(correlation.edges) == 1 and correlation.edges[0].score >= .7
    result = run_fixture(index, settings, config, correlation)
    chain = next(c for c in result.chains if len(c.nodes) == 2)
    assert len(chain.edges) == 1 and chain.edges[0].relation_type.value == mapped
    edge = chain.edges[0]
    nodes = {n.node_id: n for n in chain.nodes}
    assert values[0].alert_id in nodes[edge.source_node_id].alert_ids
    assert values[1].alert_id in nodes[edge.target_node_id].alert_ids
    reasons = [r for r in edge.reasons if r.code.value == "explicit_relation"]
    assert any(r.params["relation_type"] == kind for r in reasons)
    for r in reasons:
        for p in r.params["raw_pointers"]:
            from app.models import EvidencePointer
            assert EvidencePointer.model_validate(p).resolve(index.alerts)
    assert result.grounding.valid


def test_parent_priority_preserves_other_attested_relations(config):
    index, settings, _, correlation = attested_fixture(config, "target_to_process", "web_attack", "process_execution",
                                                     dual_parent=True)
    result = run_fixture(index, settings, config, correlation)
    edge = next(e for c in result.chains for e in c.edges)
    assert edge.relation_type.value == "PROCESS_CAUSAL"
    assert {r.params["relation_type"] for r in edge.reasons if r.code.value == "explicit_relation"} == {
        "parent_child_process", "target_to_process"}


def test_equal_time_parent_child_below_direction_threshold_unresolved(config):
    from app.correlation.edges import run_correlation
    values = [alert("equal-parent", category="process_execution", host="h", account="u", session="s", process=process(1)),
              alert("equal-child", category="privilege_escalation", host="h", account="u", session="s",
                    parent_process=process(1), process=process(2))]
    index, settings = inputs(values + [alert("equal-bg-" + str(i), 20000 + i * 9000, host="bg-" + str(i)) for i in range(32)])
    correlation = run_correlation(list(index.alerts.values()), [], list(index.entities.values()), config, settings)
    result = run_fixture(index, settings, config, correlation)
    chain = next(c for c in result.chains if len(c.nodes) == 2)
    assert chain.status == "partial" and not chain.edges
    assert len(chain.unresolved_correlation_edge_ids) == 1


def test_host_time_category_without_trigger_never_creates_chain(config):
    from app.correlation.edges import run_correlation
    values = [alert("weak-web", category="web_attack", host="h", account="u", session="s", file="/f", command="c"),
              alert("weak-process", 1, category="process_execution", host="h", account="u", session="s", file="/f",
                    command="c", process=process(1))]
    index, settings = inputs(values + [alert("weak-bg-" + str(i), 20000 + i * 9000, host="bg-" + str(i)) for i in range(64)])
    correlation = run_correlation(list(index.alerts.values()), [], list(index.entities.values()), config, settings)
    assert len(correlation.edges) == 1
    result = run_fixture(index, settings, config, correlation)
    assert all(not c.edges for c in result.chains)
    assert all(r.code.value != "explicit_relation" for r in correlation.edges[0].reasons)


@pytest.mark.parametrize("gap,expected", [(-3, 0.0), (-2.000001, 0.0), (-2, .5), (-1, .5), (0, .5), (1, 1.0)])
def test_chronology_skew_boundary(gap, expected):
    from types import SimpleNamespace
    a, b = alert("clock-a"), alert("clock-b", gap)
    source = SimpleNamespace(start_time=a.timestamp, end_time=a.timestamp)
    target = SimpleNamespace(start_time=b.timestamp, end_time=b.timestamp)
    assert chronology(source, target, 2) == expected


def direction_candidate(config):
    index, settings, _, correlation = linear_fixture(config)
    scorer = scorer_for(index, settings, config)
    clustered = cluster_incidents(index, correlation.edges, scorer)
    incident = next(i for i in clustered.incidents if len(i.alert_ids) == 3)
    nodes = build_nodes(incident, index, scorer)
    candidates = reconstruct_candidates(incident, nodes, correlation.edges, index, scorer,
                                        support_cache=clustered.support_cache)
    return scorer, candidates[0]


def test_direction_unrounded_threshold_and_margin(tmp_path, config):
    scorer, candidate = direction_candidate(config)
    original = decide_direction(candidate, scorer)
    raw = original.diagnostic["directions"][0]["score"]
    margin = original.diagnostic["margin"]
    equal = configured(tmp_path, chain={"direction_threshold": raw, "direction_margin": margin})
    scorer, candidate = direction_candidate(equal)
    assert decide_direction(candidate, scorer).edge is not None
    above = configured(tmp_path, chain={"direction_threshold": math.nextafter(raw, math.inf)})
    scorer, candidate = direction_candidate(above)
    assert decide_direction(candidate, scorer).edge is None
    above_margin = configured(tmp_path, chain={"direction_margin": math.nextafter(margin, math.inf)})
    scorer, candidate = direction_candidate(above_margin)
    assert decide_direction(candidate, scorer).edge is None


def test_high_numeric_direction_never_replaces_field_propagation(tmp_path):
    from dataclasses import replace
    cfg = configured(tmp_path, chain={"direction_weights": {"chronology": 1.0, "relation": 0.0,
                                                           "behavior": 0.0, "source": 0.0}})
    scorer, candidate = direction_candidate(cfg)
    # Remove the attestation through a unit-only seam. High numeric direction
    # remains insufficient even with a legitimate high-scoring support edge.
    candidate = replace(candidate, selected_score=replace(candidate.selected_score, relations=[]))
    answer = decide_direction(candidate, scorer)
    assert answer.diagnostic["directions"][0]["score"] == 1.0
    assert answer.edge is None and "chain.explicit_propagation" in answer.diagnostic["rejection_codes"]

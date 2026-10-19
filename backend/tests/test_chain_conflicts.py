"""Direction conflict, time guards and deterministic cycle rejection."""

from dataclasses import replace

import pytest

from app.chains.conflicts import select_dag
from app.chains.direction import DirectionDecision, decide_direction
from fixtures.chains.synthetic import linear_fixture
from test_chain_direction import direction_candidate
from test_chain_reconstruction import run_fixture
from test_correlation_score import config


def test_opposing_attested_relations_do_not_choose_id_as_direction(config):
    scorer, candidate = direction_candidate(config)
    rel = candidate.selected_score.relations[0]
    reverse = replace(rel, source_alert_id=rel.target_alert_id, target_alert_id=rel.source_alert_id,
                      source_entity_id=rel.target_entity_id, target_entity_id=rel.source_entity_id)
    # Unit-only inconsistent evidence seam: both directions have explicit facts
    # and identical chronology/behavior, so margin—not ID—must reject.
    scored = replace(candidate.selected_score, relations=[rel, reverse])
    candidate = replace(candidate, selected_score=scored)
    from unittest.mock import patch
    with patch("app.chains.direction.chronology", return_value=1.0), patch.object(scorer, "behavior_value", return_value=.9):
        decision = decide_direction(candidate, scorer)
    assert decision.edge is None and "chain.direction_margin" in decision.diagnostic["rejection_codes"]


@pytest.mark.parametrize("rule", ["beyond_behavior_window", "reversed_explicit_relation"])
def test_time_conflict_cannot_be_overridden_by_high_scores(config, rule):
    scorer, candidate = direction_candidate(config)
    diagnostic = {**candidate.selected_score.diagnostics, "conflicts": {
        **candidate.selected_score.diagnostics["conflicts"], "soft": [(rule, 1.0)]}}
    candidate = replace(candidate, selected_score=replace(candidate.selected_score, diagnostics=diagnostic))
    result = decide_direction(candidate, scorer)
    assert result.edge is None and "chain.time_conflict" in result.diagnostic["rejection_codes"]


def test_component_guard_checks_all_members_not_only_bridge(config, monkeypatch):
    from app.incidents.clustering import cluster_incidents
    from fixtures.chains.synthetic import scorer_for
    index, settings, values, correlation = linear_fixture(config)
    import app.correlation.conflicts as guards
    original = guards.verified_incompatible_session
    blocked = {values[0].alert_id, values[2].alert_id}
    def seam(a, b):
        answer = original(a, b)
        if {a.alert_id, b.alert_id} == blocked:
            answer = {**answer, "verified": True, "status": "synthetic-test-seam"}
        return answer
    monkeypatch.setattr(guards, "verified_incompatible_session", seam)
    diagnostics = []
    result = cluster_incidents(index, correlation.edges, scorer_for(index, settings, config), diagnostics.append)
    assert all(len(i.alert_ids) <= 2 for i in result.incidents)
    assert any("clustering.component_hard_conflict" in d.get("rejection_codes", []) for d in diagnostics)


def test_dag_cycle_stable_confidence_then_id_and_evidence_unchanged(config):
    index, settings, _, correlation = linear_fixture(config, extra_context=True)
    result = run_fixture(index, settings, config, correlation)
    chain = next(c for c in result.chains if len(c.nodes) == 3)
    first, second = chain.edges
    # Unit-only directed candidates build a cycle; they are never submitted as
    # grounded production edges. This tests DAG selection independently of the
    # standard v0 direction gate, which is deliberately conservative.
    by_source = {e.source_node_id: e for e in chain.edges}
    start = next(n.node_id for n in chain.nodes if n.node_id not in {e.target_node_id for e in chain.edges})
    end = next(n.node_id for n in chain.nodes if n.node_id not in by_source)
    back = first.model_copy(update={"source_node_id": end, "target_node_id": start, "edge_id": "che_" + "f" * 64})
    decisions = [DirectionDecision(first, {}, .9), DirectionDecision(second, {}, .9), DirectionDecision(back, {}, .9)]
    original = [e.canonical_json() for e in correlation.edges]
    diagnostics = []
    accepted, rejected = select_dag(decisions, chain.nodes, diagnostics.append)
    assert accepted == chain.edges and rejected == back.correlation_edge_ids
    assert any(d["decision"] == "reject" for d in diagnostics)
    assert select_dag(list(reversed(decisions)), list(reversed(chain.nodes))) == (accepted, rejected)
    stronger_back = [*decisions[:2], DirectionDecision(back, {}, .95)]
    preferred, refused = select_dag(stronger_back, chain.nodes)
    assert back in preferred and len(preferred) == 2 and refused
    assert [e.canonical_json() for e in correlation.edges] == original


def test_undirected_evidence_cycle_kept_and_chain_view_partial(config):
    index, settings, _, correlation = linear_fixture(config, extra_context=True)
    assert len(correlation.edges) == 3
    result = run_fixture(index, settings, config, correlation)
    chain = next(c for c in result.chains if len(c.nodes) == 3)
    assert len(chain.edges) == 2 and chain.status == "partial"
    assert len(chain.unresolved_correlation_edge_ids) == 1
    assert len(next(i for i in result.incidents if len(i.alert_ids) == 3).correlation_edge_ids) == 3
    assert result.grounding.valid

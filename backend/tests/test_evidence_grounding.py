"""Negative evidence tests reject plausible-looking, closed but false results."""

from dataclasses import replace

import pytest

from app.chains.grounding import validate_grounding
from app.models import Category, EvidencePointer
from fixtures.chains.synthetic import linear_fixture, scorer_for
from test_chain_reconstruction import run_fixture
from test_correlation_score import config


def snapshot(config):
    index, settings, _, correlation = linear_fixture(config)
    result = run_fixture(index, settings, config, correlation)
    return index, scorer_for(index, settings, config), correlation, result


def report(index, scorer, correlation, result, **changes):
    return validate_grounding(index, changes.get("incidents", result.incidents), changes.get("chains", result.chains),
        changes.get("edges", correlation.edges), scorer, changes.get("record", result.record))


def test_valid_grounding_partial_and_no_edge(config):
    index, scorer, correlation, result = snapshot(config)
    validated = report(index, scorer, correlation, result)
    assert validated.valid and validated.node_count == 35 and validated.edge_count == 2
    assert validated.json_data()["node_traceability"] == 1.0
    assert validated.json_data()["edge_traceability"] == 1.0


@pytest.mark.parametrize("mutation", ["missing_alert", "unknown_entity", "confidence", "time", "category", "reason"])
def test_node_grounding_rejects_tampering(config, mutation):
    index, scorer, correlation, result = snapshot(config)
    chain = next(c for c in result.chains if len(c.nodes) == 3)
    node = chain.nodes[0]
    updates = {"missing_alert": {"alert_ids": ["alt_" + "f" * 64]},
               "unknown_entity": {"entity_ids": ["ent_" + "f" * 64]}, "confidence": {"confidence": .99},
               "time": {"end_time": "2023-01-01T00:00:00.000000Z"},
               "category": {"category": Category.IMPACT}, "reason": {"reasons": []}}[mutation]
    broken = chain.model_copy(update={"nodes": [node.model_copy(update=updates), *chain.nodes[1:]]})
    chains = [broken if c.chain_id == chain.chain_id else c for c in result.chains]
    answer = report(index, scorer, correlation, result, chains=chains)
    assert not answer.valid and answer.errors


@pytest.mark.parametrize("mutation", ["missing_support", "direction", "score", "pointer", "borrow_member", "reason"])
def test_chain_edge_grounding_rejects_tampering(config, mutation):
    index, scorer, correlation, result = snapshot(config)
    chain = next(c for c in result.chains if len(c.nodes) == 3)
    edge = chain.edges[0]
    if mutation == "missing_support":
        updates = {"correlation_edge_ids": ["cor_" + "f" * 64]}
    elif mutation == "direction":
        updates = {"source_node_id": edge.target_node_id, "target_node_id": edge.source_node_id}
    elif mutation == "score":
        updates = {"score_breakdown": edge.score_breakdown.model_copy(update={"entity_score": 1.0})}
    elif mutation == "reason":
        updates = {"reasons": []}
    else:
        relation = next(r for r in edge.reasons if r.code.value == "explicit_relation")
        params = {**relation.params, "raw_pointers": [dict(p) for p in relation.params["raw_pointers"]]}
        if mutation == "pointer":
            params["raw_pointers"][0]["pointer"] = "/absent"
        else:
            params["raw_pointers"][0]["alert_id"] = next(aid for aid in index.alerts if aid not in edge.alert_ids)
        malformed = relation.model_copy(update={"params": params})
        updates = {"reasons": [malformed if r.reason_id == relation.reason_id else r for r in edge.reasons]}
    broken_edge = edge.model_copy(update=updates)
    broken = chain.model_copy(update={"edges": [broken_edge, *chain.edges[1:]]})
    chains = [broken if c.chain_id == chain.chain_id else c for c in result.chains]
    assert not report(index, scorer, correlation, result, chains=chains).valid


def test_correlation_score_and_source_independence_tampering_rejected(config):
    index, scorer, correlation, result = snapshot(config)
    original = correlation.edges[0]
    for updates in ({"score": .99}, {"score_breakdown": original.score_breakdown.model_copy(update={"source_score": .1})}):
        altered = original.model_copy(update=updates)
        assert not report(index, scorer, correlation, result, edges=[altered, *correlation.edges[1:]]).valid


def test_incident_unique_membership_missing_chain_and_wrong_analysis_rejected(config):
    index, scorer, correlation, result = snapshot(config)
    assert not report(index, scorer, correlation, result, incidents=result.incidents + [result.incidents[0]]).valid
    assert not report(index, scorer, correlation, result, chains=result.chains[1:]).valid
    record = result.record.model_copy(update={"analysis_id": "ana_" + "f" * 64})
    assert not report(index, scorer, correlation, result, record=record).valid


def test_pointer_binds_only_its_own_alert_and_bare_pointer_rejected(config):
    index, _, _, _ = snapshot(config)
    # A pointer existing on some other alert is never searched as a fallback.
    aid = next(aid for aid, a in index.alerts.items() if a.process is None)
    with pytest.raises(ValueError):
        EvidencePointer(alert_id=aid, pointer="/process", side="shared").resolve(index.alerts)
    with pytest.raises(ValueError):
        EvidencePointer.model_validate("/process")

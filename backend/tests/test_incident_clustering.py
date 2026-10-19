"""Frozen component guards, original membership and stable boundaries."""

import math

import pytest

from app.chains.assembly import run_reconstruction
from app.correlation.scoring import CorrelationScorer
from app.incidents.clustering import cluster_incidents
from fixtures.chains.synthetic import edge_for, linear_fixture, scorer_for
from test_correlation_score import alert, config, configured, group, inputs, parent_child, process


def cluster(index, settings, config, edges, sink=None):
    return cluster_incidents(index, edges, scorer_for(index, settings, config), sink)


def test_three_singletons_zero_edges_and_dedupe_expansion(config):
    index, settings = inputs([alert("one"), alert("two"), alert("three")])
    result = cluster(index, settings, config, [])
    assert len(result.incidents) == 3
    assert all(len(i.alert_ids) == 1 and not i.correlation_edge_ids for i in result.incidents)
    values = [alert("dup-one"), alert("dup-two", 1), alert("isolated", 2)]
    g = group(values[:2])
    index, settings = inputs(values, groups=[g])
    result = cluster(index, settings, config, [])
    assert len(result.incidents) == 2
    assert sorted(len(i.alert_ids) for i in result.incidents) == [1, 2]
    assert sorted(aid for i in result.incidents for aid in i.alert_ids) == sorted(a.alert_id for a in values)


def test_legal_explicit_a_b_c_same_incident_unchanged_v0(config):
    index, settings, foreground, correlation = linear_fixture(config)
    assert len(correlation.edges) == 2 and all(e.score >= .70 for e in correlation.edges)
    diagnostics = []
    result = cluster(index, settings, config, correlation.edges, diagnostics.append)
    multi = [i for i in result.incidents if len(i.alert_ids) > 1]
    assert len(multi) == 1 and set(multi[0].alert_ids) == {a.alert_id for a in foreground}
    assert any(row.get("required_support_count") == 2 and row["decision"] == "accept"
               and len(row["support_keys"]) == 1 and row["propagation"] for row in diagnostics)
    reverse = cluster(index, settings, config, list(reversed(correlation.edges)))
    assert result.incidents == reverse.incidents


def ordinary_chain(tmp_path):
    # Controlled synthetic threshold override exercises bridge semantics in
    # isolation. The positive linear_fixture uses untouched production v0.
    cfg = configured(tmp_path, entity={"rarity_enabled": False}, score={"correlation_threshold": .3},
                     clustering={"edge_threshold": .3})
    values = [alert("ordinary-A", host="h", account="u"), alert("ordinary-B", 1, host="h", account="u"),
              alert("ordinary-C", 2, host="h", account="u"), alert("ordinary-D", 3, host="h", account="u")]
    index, settings = inputs(values)
    edges = [edge_for(index, settings, cfg, a, b)[0] for a, b in zip(values, values[1:])]
    return cfg, index, settings, values, edges


def test_plain_single_bridge_cannot_swallow_path(tmp_path):
    cfg, index, settings, values, edges = ordinary_chain(tmp_path)
    diagnostics = []
    result = cluster(index, settings, cfg, edges[:2], diagnostics.append)
    assert sorted(len(i.alert_ids) for i in result.incidents) == [1, 1, 2]
    assert all(len(i.alert_ids) <= 2 for i in cluster(index, settings, cfg, edges).incidents)
    assert any("clustering.insufficient_independent_support" in d.get("rejection_codes", []) for d in diagnostics)
    assert all(not CorrelationScorer(index, cfg, settings).score_pair(
        e.support_pair.alert_id_src, e.support_pair.alert_id_dst).relations for e in edges)


def test_two_independent_bridges_accept_singleton_and_duplicate_pair_not_counted(tmp_path):
    cfg, index, settings, values, edges = ordinary_chain(tmp_path)
    ac = edge_for(index, settings, cfg, values[0], values[2])[0]
    result = cluster(index, settings, cfg, edges[:2] + [ac])
    assert sorted(len(i.alert_ids) for i in result.incidents) == [1, 3]
    assert sorted(len(i.alert_ids) for i in cluster(index, settings, cfg, edges[:2] * 3).incidents) == [1, 1, 2]


def test_non_singleton_components_one_bridge_rejected_two_accepted(tmp_path):
    cfg, index, settings, values, edges = ordinary_chain(tmp_path)
    # Force both initial pairs before the cross-component edge with timestamps:
    # time gaps for AB/CD=0, cross edges=1; all ordinary supports remain legal.
    values = [alert("pair-A", host="h", account="u"), alert("pair-B", host="h", account="u"),
              alert("pair-C", 1, host="h", account="u"), alert("pair-D", 1, host="h", account="u")]
    index, settings = inputs(values)
    pairs = [(0, 1), (2, 3), (1, 2)]
    edges = [edge_for(index, settings, cfg, values[a], values[b])[0] for a, b in pairs]
    assert sorted(len(i.alert_ids) for i in cluster(index, settings, cfg, edges).incidents) == [2, 2]
    extra = edge_for(index, settings, cfg, values[0], values[2])[0]
    assert len(cluster(index, settings, cfg, edges + [extra]).incidents) == 1


def test_clustering_unrounded_exact_threshold_and_display_only(tmp_path):
    cfg = configured(tmp_path, entity={"rarity_enabled": False})
    index, settings = inputs(parent_child())
    edge, score = edge_for(index, settings, cfg, *parent_child())
    equal = configured(tmp_path, entity={"rarity_enabled": False}, clustering={"edge_threshold": score.score})
    # Only clustering threshold differs; regenerate edge with matching config hash.
    edge, _ = edge_for(index, settings, equal, *parent_child())
    assert len(cluster(index, settings, equal, [edge]).incidents) == 1
    above = configured(tmp_path, entity={"rarity_enabled": False}, clustering={"edge_threshold": math.nextafter(score.score, math.inf)})
    edge, _ = edge_for(index, settings, above, *parent_child())
    assert len(cluster(index, settings, above, [edge]).incidents) == 2


@pytest.mark.parametrize("guard", ["max_representatives", "max_incident_span_seconds"])
def test_explicit_single_bridge_never_exempts_limits(tmp_path, guard):
    changes = {guard: 2 if guard == "max_representatives" else 1}
    cfg = configured(tmp_path, clustering=changes)
    index, settings, foreground, correlation = linear_fixture(cfg)
    result = cluster(index, settings, cfg, correlation.edges)
    assert all(len(i.alert_ids) <= 2 for i in result.incidents)


def test_target_sets_differ_even_with_intersection_require_cross_target_proof(tmp_path):
    cfg, _, _, _, _ = ordinary_chain(tmp_path)
    values = [alert("target-A", host="one", account="u"), alert("target-B", 1, host="one", account="u"),
              alert("target-C", 2, host="two", account="u")]
    index, settings = inputs(values)
    edges = [edge_for(index, settings, cfg, values[a], values[b])[0] for a, b in [(0, 1), (0, 2), (1, 2)]]
    # Cross-host account context can score, but does not attest an operation.
    result = cluster(index, settings, cfg, edges)
    assert sorted(len(i.alert_ids) for i in result.incidents) == [1, 2]


def test_empty_clustering_is_well_defined(config):
    index, settings = inputs([])
    assert cluster(index, settings, config, []).incidents == []

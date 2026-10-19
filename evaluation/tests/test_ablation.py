import pytest

from evaluation.ablation.experiments import COMPONENTS, ablated_score, run_ablation
from evaluation.io.diagnostics import extract_scores


def test_ablation_is_one_component_without_renormalizing():
    contributions = {"entity":.1,"relation":.2,"behavior":.1,"source":.1,"time":.2,"conflict":-.05,"duplicate":-.1}
    raw = sum(contributions.values())
    assert ablated_score(raw, contributions, "relation") == pytest.approx(raw-.2)
    assert ablated_score(raw, contributions, "conflict") == pytest.approx(raw+.05)
    assert ablated_score(raw, contributions, "entity_rarity", entity_without_rarity=1, entity_weight=.3) == pytest.approx(raw+.2)


def test_six_ablation_snapshot_scores_preserve_configuration(production_snapshot, tmp_path):
    s = production_snapshot
    before = s.config.canonical_snapshot if hasattr(s.config,"canonical_snapshot") else s.config.snapshot
    destination = tmp_path/"outputs/evaluation/ablation"
    destination.mkdir(parents=True)
    db, _ = extract_scores(s,destination)
    rows = run_ablation(db, s.config.algorithm.score.correlation_threshold)
    assert len(rows) == len(COMPONENTS) == 6
    assert all(r["hard_guard_preserved"] and not r["positive_weights_renormalized"] for r in rows)
    assert before == (s.config.canonical_snapshot if hasattr(s.config,"canonical_snapshot") else s.config.snapshot)
    s.assert_unchanged()
    db.close()
    cached, cached_summary = extract_scores(s,destination)
    assert cached_summary["candidate_count"] == s.record.metrics.candidate_pair_count
    assert cached.execute("SELECT count(*) FROM member_scores WHERE ground_truth IS NOT NULL").fetchone()[0] == 0
    cached.close()

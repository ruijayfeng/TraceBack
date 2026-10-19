"""Score-only ablation; original member guard decisions remain mandatory."""

from types import SimpleNamespace

from app.correlation.scoring import CorrelationScorer


COMPONENTS = ("entity_rarity", "relation", "behavior", "source", "conflict", "duplicate")


def rarity_disabled_evaluator(snapshot):
    """Reuse the production entity component, including re-selection of top 3."""
    entities = {eid: SimpleNamespace(type=SimpleNamespace(value=e["type"])) for eid, e in snapshot.entities.items()}
    roles = {aid: {eid: set(rs) for eid, rs in a["entity_roles"].items()} for aid, a in snapshot.alerts.items()}
    instances = {eid for a in snapshot.alerts.values() for eid in a["process_instance_entities"]}
    cfg = snapshot.config.algorithm.entity.model_copy(update={"rarity_enabled": False})
    index = SimpleNamespace(entities=entities, roles=roles, rarity=lambda eid, cfg: 1.0)
    scorer = SimpleNamespace(index=index, algorithm=SimpleNamespace(entity=cfg), is_instance=lambda eid: eid in instances)
    alerts = {aid: SimpleNamespace(alert_id=aid, entity_ids=a["entity_ids"]) for aid, a in snapshot.alerts.items()}
    return lambda left, right: CorrelationScorer.entity_features(scorer, alerts[left], alerts[right])[0]


def ablated_score(raw_total, contributions, component, *, entity_without_rarity=None, entity_weight=None):
    if component not in COMPONENTS:
        raise ValueError("unknown_ablation_component")
    if component == "entity_rarity":
        if entity_without_rarity is None or entity_weight is None:
            raise ValueError("rarity_ablation_needs_recomputed_entity_score")
        raw = raw_total - contributions["entity"] + entity_weight * entity_without_rarity
    else:
        raw = raw_total - contributions[component]
    return min(1.0, max(0.0, raw))


def run_ablation(db, threshold):
    from evaluation.metrics.classification import unavailable_quality
    rows = []
    for component in COMPONENTS:
        expression = "no_rarity_score" if component == "entity_rarity" else f"greatest(0.0,least(1.0,raw_total-c_{component}))"
        maximum, count = db.execute(f"SELECT max(s),count(*) FILTER(WHERE s>=?) FROM "
            f"(SELECT max({expression}) s FROM member_scores WHERE valid GROUP BY rep_left,rep_right)", [threshold]).fetchone()
        rows.append({"experiment": "without_" + component, "scope": "score-only, fixed admitted pairs; complete member maximum",
            "threshold": threshold, "max_valid_score": maximum, "predicted_edge_count": count,
            "positive_weights_renormalized": False, "hard_guard_preserved": True,
            "quality": unavailable_quality(), "candidate_recall": None,
            "limitation": "not end-to-end; candidate admission and direction are unchanged; no incident/chain quality GT"})
    return rows

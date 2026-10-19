"""Score both directions independently; explicit field propagation is mandatory."""

from dataclasses import dataclass

from app.models import ChainEdge
from app.correlation.index import event_microseconds
from app.utils.stable_id import id_for
from .nodes import reason


@dataclass
class DirectionDecision:
    edge: ChainEdge | None
    diagnostic: dict
    confidence: float = 0.0


def chronology(source, target, skew):
    # Equal instants receive 0.5, never an ID-based chronological advantage.
    end, start = event_microseconds(source.end_time), event_microseconds(target.start_time)
    if end < start:
        return 1.0
    if end == start:
        if source.start_time == source.end_time == target.start_time == target.end_time:
            return .5
        return 1.0
    return .5 if end - start <= skew * 1000000 else 0.0


def decide_direction(candidate, scorer):
    index, cfg = scorer.index, scorer.algorithm.chain
    selected, scored = candidate.selected_edge, candidate.selected_score
    left, right = candidate.source_node, candidate.target_node
    pair = selected.support_pair.alert_ids()
    evaluations = []
    for source, target in ((left, right), (right, left)):
        src = next(index.alerts[i] for i in sorted(pair) if i in source.alert_ids)
        dst = next(index.alerts[i] for i in sorted(pair) if i in target.alert_ids)
        relations = [r for r in scored.relations
                     if r.source_alert_id == src.alert_id and r.target_alert_id == dst.alert_id]
        relation_value = max((scorer.algorithm.relation.scores[r.relation_type] for r in relations), default=0.0)
        values = {"chronology": chronology(source, target, scorer.algorithm.time.clock_skew_seconds),
                  "relation": relation_value, "behavior": scorer.behavior_value(src, dst),
                  "source": scored.values["source"]}
        total = sum(getattr(cfg.direction_weights, key) * value for key, value in values.items())
        rejects = []
        if scored.score < cfg.edge_threshold:
            rejects.append("chain.edge_threshold")
        if not relations or relation_value < cfg.explicit_relation_minimum:
            rejects.append("chain.explicit_propagation")
        if values["chronology"] == 0:
            rejects.append("chain.chronology")
        if index.times[src.alert_id] > index.times[dst.alert_id] + scorer.algorithm.time.clock_skew_seconds * 1000000:
            rejects.append("chain.reversed_time")
        if scored.diagnostics["conflicts"]["hard"]:
            rejects.append("chain.hard_conflict")
        if any(rule in {"beyond_behavior_window", "reversed_explicit_relation"}
               for rule, _ in scored.diagnostics["conflicts"]["soft"]):
            rejects.append("chain.time_conflict")
        if total < cfg.direction_threshold:
            rejects.append("chain.direction_threshold")
        evaluations.append({"source_node_id": source.node_id, "target_node_id": target.node_id,
                            "source_alert_id": src.alert_id, "target_alert_id": dst.alert_id,
                            "values": values, "score": total, "relations": relations, "rejections": rejects})
    # A tie remains unresolved. Node/alert IDs never settle causal direction.
    evaluations.sort(key=lambda row: -row["score"])
    winner, other = evaluations
    margin = winner["score"] - other["score"]
    rejects = list(winner["rejections"])
    if margin < cfg.direction_margin:
        rejects.append("chain.direction_margin")
    diagnostic = {"stage": "chain_direction", "correlation_edge_id": selected.edge_id,
                  "support_key": [selected.source_alert_id, selected.target_alert_id],
                  "support_pair": sorted(pair), "margin": margin,
                  "directions": [{**r, "relations": [v.json_data() for v in r["relations"]]} for r in evaluations],
                  "decision": "reject" if rejects else "accept", "rejection_codes": rejects}
    if rejects:
        return DirectionDecision(None, diagnostic)
    relation = min(winner["relations"], key=lambda r: cfg.relation_priority.index(r.relation_type))
    relation_type = cfg.relation_type_mapping[relation.relation_type]
    direction_score = round(winner["score"], 6)
    entities = sorted(set(selected.entity_ids) | {r.source_entity_id for r in scored.relations}
                      | {r.target_entity_id for r in scored.relations})
    direction_reason = reason("direction", pair,
        {"rule_id": "chain.direction_weights", "source_node_id": winner["source_node_id"],
         "target_node_id": winner["target_node_id"], "direction_score": direction_score},
        f"字段传播支持方向；配置方向分 {direction_score}", entities)
    breakdown = selected.score_breakdown.model_copy(update={"selected_correlation_edge_id": selected.edge_id})
    data = {"incident_id": left.incident_id, "source_node_id": winner["source_node_id"],
            "target_node_id": winner["target_node_id"], "relation_type": relation_type,
            "confidence": round(min(scored.score, winner["score"]), 6), "direction_score": direction_score,
            "alert_ids": sorted(pair), "entity_ids": entities,
            "correlation_edge_ids": [e.edge_id for e in candidate.correlation_edges],
            "reasons": [*selected.reasons, direction_reason], "score_breakdown": breakdown}
    data["edge_id"] = id_for("ChainEdge", data)
    edge = ChainEdge.model_validate(data, context={"alerts": index.alerts,
                                   "correlation_edges": {selected.edge_id: selected}})
    diagnostic.update(edge_id=edge.edge_id, relation_type=relation_type,
                      selected_relation=relation.json_data(), confidence=min(scored.score, winner["score"]))
    return DirectionDecision(edge, diagnostic, min(scored.score, winner["score"]))

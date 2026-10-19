"""One evidence-backed node per immutable dedupe fact group."""

from itertools import combinations

from app.models import ChainNode, Reason
from app.models.enums import Severity
from app.utils.stable_id import id_for


def reason(code, alert_ids, params, message, entity_ids=(), context=None):
    data = {"code": code, "alert_ids": sorted(alert_ids), "entity_ids": sorted(set(entity_ids)),
            "params": params, "message": message}
    data["reason_id"] = id_for("Reason", data)
    return Reason.model_validate(data, context=context)


def maximum_severity(alerts):
    rank = {value: position for position, value in enumerate(Severity)}
    return max((a.severity for a in alerts), key=rank.__getitem__)


def build_nodes(incident, index, scorer, diagnostic_sink=None):
    """All original members survive; confidence is an uncalibrated heuristic.

    Category choice uses configured priority then member ID. Independent-source
    confirmation is checked inside this fact group, never inferred from names.
    """
    sink = diagnostic_sink or (lambda row: None)
    members = set(incident.alert_ids)
    if members - index.alerts.keys():
        raise ValueError("node_missing_alert")
    representatives = sorted({index.owner[aid] for aid in members})
    cfg = scorer.algorithm.chain
    priority = scorer.algorithm.normalization.category_priority
    result = []
    for rep in representatives:
        aids = index.groups[rep]
        if set(aids) - members:
            raise ValueError("incident_splits_dedupe_group")
        alerts = [index.alerts[aid] for aid in aids]
        category = min(alerts, key=lambda a: (priority.index(a.category.value), a.alert_id)).category
        known = category.value != scorer.algorithm.normalization.unknown_category
        context = any(a.host is not None or any(
            index.entities[eid].type.value == "SESSION" or scorer.is_instance(eid)
            for eid in a.entity_ids) for a in alerts)
        independent = any(scorer.independence(a, b)[0] == "confirmed_independent"
                          for a, b in combinations(alerts, 2))
        additions = {"base": cfg.node_confidence_base,
                     "category": cfg.node_confidence_category_bonus if known else 0.0,
                     "context": cfg.node_confidence_context_bonus if context else 0.0,
                     "independent_source": cfg.node_confidence_independent_source_bonus if independent else 0.0}
        confidence = round(min(cfg.node_confidence_cap, sum(additions.values())), 6)
        entities = sorted({eid for a in alerts for eid in a.entity_ids})
        basis = reason("node_basis", aids,
                       {"rule_id": "chain.node_confidence", "category": category.value, "confidence": confidence},
                       f"事实组保留 {len(aids)} 条告警；类别 {category.value}；配置节点置信分 {confidence}", entities)
        data = {"incident_id": incident.incident_id, "alert_ids": list(aids),
                "start_time": min(a.timestamp for a in alerts), "end_time": max(a.timestamp for a in alerts),
                "category": category, "severity": maximum_severity(alerts), "entity_ids": entities,
                "confidence": confidence, "reasons": [basis]}
        data["node_id"] = id_for("ChainNode", data)
        node = ChainNode.model_validate(data, context={"alerts": index.alerts})
        result.append(node)
        sink({"stage": "chain_node", "node_id": node.node_id, "representative_alert_id": rep,
              "alert_ids": list(aids), "categories": sorted({a.category.value for a in alerts}),
              "selected_category": category.value, "confidence_components": additions,
              "confidence_cap": cfg.node_confidence_cap, "confidence": confidence,
              "decision": "accept", "rule_id": "chain.node_confidence"})
    return sorted(result, key=lambda node: node.node_id)

"""Cross-node candidates retain one actual strongest member-pair support."""

from dataclasses import dataclass

from app.models import CorrelationEdge
from app.utils.stable_id import id_for


@dataclass
class ChainCandidate:
    source_node: object
    target_node: object
    correlation_edges: tuple
    selected_edge: CorrelationEdge
    selected_score: object


def validate_support(edge, index, scorer):
    """Reuse Task 03 scoring to recover unrounded values and verify evidence.

    No new candidates, thresholds or features are introduced. The immutable
    support_pair remains the only source of every downstream direction fact.
    """
    context = {"alerts": index.alerts, "groups": index.groups, "config_hash": scorer.config_hash,
               "score_weights": scorer.algorithm.score.weights.model_dump(),
               "independence_rule_ids": sorted({r.id for m in scorer.independence_mappings for r in m.rules})}
    edge = CorrelationEdge.model_validate(edge.model_dump(), context=context)
    if id_for("CorrelationEdge", edge) != edge.edge_id:
        raise ValueError("correlation_identity_mismatch")
    if edge.source_alert_id not in index.groups or edge.target_alert_id not in index.groups:
        raise ValueError("correlation_endpoint_not_representative")
    scored = scorer.score_pair(edge.support_pair.alert_id_src, edge.support_pair.alert_id_dst)
    if not scored.valid or scored.score < scorer.algorithm.score.correlation_threshold:
        raise ValueError("correlation_support_fails_guard_or_threshold")
    if scorer.breakdown(scored).model_dump() != edge.score_breakdown.model_dump():
        raise ValueError("correlation_breakdown_mismatch")
    if [r.canonical_json() for r in scored.reasons] != [r.canonical_json() for r in edge.reasons]:
        raise ValueError("correlation_reason_mismatch")
    if scored.entity_ids != edge.entity_ids:
        raise ValueError("correlation_entities_mismatch")
    # Verify the selected original-member pair remains the unique full-score
    # winner. Reuse the existing scorer and tie-break; never splice features.
    if len(index.groups[edge.source_alert_id]) * len(index.groups[edge.target_alert_id]) > 1:
        best = None
        for aid in index.groups[edge.source_alert_id]:
            for bid in index.groups[edge.target_alert_id]:
                item = scored if (aid, bid) == (scored.source_member_id, scored.target_member_id) else scorer.score_pair(aid, bid)
                if item.valid:
                    key = (-item.score, index.alerts[aid].timestamp, index.alerts[bid].timestamp, aid, bid)
                    if best is None or key < best[0]:
                        best = (key, aid, bid)
        if best is None or (best[1], best[2]) != (scored.source_member_id, scored.target_member_id):
            raise ValueError("correlation_support_pair_not_full_score_winner")
    return scored


def reconstruct_candidates(incident, nodes, edges, index, scorer, diagnostic_sink=None, support_cache=None):
    sink = diagnostic_sink or (lambda row: None)
    cache = support_cache if support_cache is not None else {}
    owner = {}
    for node in nodes:
        if node.incident_id != incident.incident_id:
            raise ValueError("node_cross_incident")
        for aid in node.alert_ids:
            if aid in owner:
                raise ValueError("overlapping_chain_nodes")
            owner[aid] = node
    if set(owner) != set(incident.alert_ids):
        raise ValueError("chain_node_member_coverage")
    by_pair = {}
    for edge in sorted(edges, key=lambda e: e.edge_id):
        if edge.edge_id not in incident.correlation_edge_ids:
            raise ValueError("correlation_outside_incident")
        left, right = owner.get(edge.source_alert_id), owner.get(edge.target_alert_id)
        if left is None or right is None:
            raise ValueError("correlation_cross_incident")
        if edge.edge_id not in cache:
            cache[edge.edge_id] = validate_support(edge, index, scorer)
        if left.node_id == right.node_id:
            sink({"stage": "chain_candidate", "edge_id": edge.edge_id, "decision": "reject",
                  "rule_id": "same_fact_node"})
            continue
        pair = tuple(sorted((left.node_id, right.node_id)))
        by_pair.setdefault(pair, []).append((edge, left, right))
    result = []
    for pair, supports in sorted(by_pair.items()):
        supports.sort(key=lambda value: (-cache[value[0].edge_id].score, value[0].edge_id))
        selected, left, right = supports[0]
        candidate = ChainCandidate(left, right, tuple(sorted((s[0] for s in supports), key=lambda e: e.edge_id)),
                                   selected, cache[selected.edge_id])
        result.append(candidate)
    return result

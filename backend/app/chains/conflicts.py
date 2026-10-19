"""Stable DAG view selection; rejected relations remain in the evidence graph."""

def select_dag(decisions, nodes, diagnostic_sink=None):
    sink = diagnostic_sink or (lambda row: None)
    outgoing = {n.node_id: set() for n in nodes}
    def reachable(start, target):
        pending, visited = [start], set()
        while pending:
            current = pending.pop()
            if current == target:
                return True
            if current not in visited:
                visited.add(current)
                pending.extend(sorted(outgoing[current] - visited, reverse=True))
        return False
    accepted, rejected = [], []
    for decision in sorted((d for d in decisions if d.edge is not None),
                           key=lambda d: (-d.confidence, d.edge.edge_id)):
        edge = decision.edge
        if reachable(edge.target_node_id, edge.source_node_id):
            rejected.extend(edge.correlation_edge_ids)
            sink({"stage": "chain_dag", "edge_id": edge.edge_id, "decision": "reject",
                  "rule_id": "chain.cycle_policy", "confidence": decision.confidence,
                  "correlation_edge_ids": edge.correlation_edge_ids})
            continue
        outgoing[edge.source_node_id].add(edge.target_node_id)
        accepted.append(edge)
        sink({"stage": "chain_dag", "edge_id": edge.edge_id, "decision": "accept",
              "rule_id": "chain.cycle_policy", "confidence": decision.confidence})
    return sorted(accepted, key=lambda e: e.edge_id), sorted(set(rejected))

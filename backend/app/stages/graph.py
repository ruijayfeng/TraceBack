"""Undirected Alert membership graphs; no Stage-to-Stage analysis."""
def adjacency(nodes, edges):
    graph = {node: set() for node in nodes}
    for edge in edges:
        a, b = edge.alert_ids
        graph[a].add(b)
        graph[b].add(a)
    return graph


def connected_components(nodes, edges):
    graph = adjacency(nodes, edges)
    unseen, components = set(graph), []
    while unseen:
        stack, members = [min(unseen)], set()
        while stack:
            node = stack.pop()
            if node in members:
                continue
            members.add(node)
            stack.extend(sorted(graph[node] - members, reverse=True))
        unseen.difference_update(members)
        components.append(sorted(members))
    return sorted(components)


def bridge_pairs(nodes, edges):
    """Iterative Tarjan DFS, including disconnected graphs and isolated nodes."""
    graph = adjacency(nodes, edges)
    discovery, low, parent, bridges = {}, {}, {}, set()
    for root in sorted(graph):
        if root in discovery:
            continue
        discovery[root] = low[root] = len(discovery)
        parent[root] = None
        stack = [(root, iter(sorted(graph[root])))]
        while stack:
            node, neighbors = stack[-1]
            other = next(neighbors, None)
            if other is None:
                stack.pop()
                prior = parent[node]
                if prior is not None:
                    low[prior] = min(low[prior], low[node])
                    if low[node] > discovery[prior]:
                        bridges.add(tuple(sorted((node, prior))))
            elif other not in discovery:
                parent[other] = node
                discovery[other] = low[other] = len(discovery)
                stack.append((other, iter(sorted(graph[other]))))
            elif other != parent[node]:
                low[node] = min(low[node], discovery[other])
    return bridges


def weak_bridge_check(nodes, edges, *, pair_support=None, checks=None):
    """Cut unsupported WEAK bridges before final connected components.

    A local weak pair remains admissible. For a bridge joining larger regions,
    every cross-cut pair must satisfy the existing Stage eligibility gates.
    This prevents descriptor/time chains without deleting all weak evidence.
    Strong/normal graph edges are never removed by this filter.
    """
    bridges = bridge_pairs(nodes, edges)
    graph = adjacency(nodes, edges)
    proofs = {tuple(e.alert_ids): e for e in edges}
    removed = []
    for edge in sorted(edges, key=lambda e: e.alert_ids):
        pair = tuple(edge.alert_ids)
        if pair not in bridges or edge.edge_strength != 'WEAK' or edge.binding_evidence:
            continue
        a, b = pair
        graph[a].remove(b)
        graph[b].remove(a)

        def reachable(start):
            reached, stack = set(), [start]
            while stack:
                node = stack.pop()
                if node not in reached:
                    reached.add(node)
                    stack.extend(graph[node] - reached)
            return reached

        left, right = reachable(a), reachable(b)
        failure = None
        for x in sorted(left):
            for y in sorted(right):
                if pair_support is not None:
                    supported, reason = pair_support(x, y)
                else:
                    proof = proofs.get(tuple(sorted((x, y))))
                    supported = proof is not None and proof.behavior_compatible
                    reason = 'no_cross_component_proof'
                if not supported:
                    failure = dict(alert_ids=sorted((x, y)), reason=reason,
                                   left_count=len(left), right_count=len(right))
                    break
            if failure:
                break
        if failure:
            removed.append(edge)
            if checks is not None:
                checks.append(dict(bridge_alert_ids=edge.alert_ids, **failure))
        else:
            graph[a].add(b)
            graph[b].add(a)
    removed_pairs = {tuple(e.alert_ids) for e in removed}
    return [e for e in edges if tuple(e.alert_ids) not in removed_pairs], bridges, removed

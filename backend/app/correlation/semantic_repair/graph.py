"""Controlled components with an independent, evidence-bound progression route."""
from itertools import product
from app.correlation.conflicts import group_targets, targets, pair_conflicts
from app.chains.nodes import maximum_severity, build_nodes
from app.correlation.index import event_microseconds
from app.models import Incident
from app.utils.stable_id import id_for
from .formula import chain_admission
from . import SCHEMA_VERSION


def reconstruct(index, edges, scorer, policy, variant):
    cfg = scorer.algorithm.clustering
    edges = sorted(edges, key=lambda e: e.edge_id)
    def admission(e):
        return chain_admission(e.score, e.support.direction.model_dump(mode='json'),
                               e.support.hierarchy, e.support.baseline['gate'], policy, variant)
    admitted = {e.edge_id: admission(e) for e in edges}
    ordered = sorted((e for e in edges if e.score >= cfg.edge_threshold or admitted[e.edge_id]['accepted']),
                     key=lambda e: (-e.score, e.edge_id))
    components = {r: {r} for r in index.representatives}
    owners = {r: r for r in components}
    target_sets = {r: {t.key for t in group_targets(r, index, scorer.settings)} for r in components}
    diagnostics = []; hard_cache = {}
    def raw_members(reps):
        return sorted(a for r in sorted(reps) for a in index.groups[r])
    def propagation(e):
        # Numeric direct support cannot bypass field proof or two-bridge guards.
        return e.support.hierarchy['level'] == 3 and e.support.direction.status == 'DERIVED_VERIFIED_DIRECTION'
    def cross_target(e):
        if not propagation(e): return False
        d = e.support.direction
        channels = {c['channel'] for c in d.forward_evidence+d.reverse_evidence}
        # A receive observation on the same destination is not a cross-target
        # operation. Explicit, verified relations and host-login pivots can be.
        return bool(channels & {'host_to_login_source', 'explicit_operation'})
    def hard(left, right):
        for a, b in product(raw_members(left), raw_members(right)):
            key = tuple(sorted((a, b)))
            if key not in hard_cache:
                x, y = index.alerts[a], index.alerts[b]
                relations, _ = scorer.verify_relations(x, y)
                hard_cache[key] = pair_conflicts(x, y, index, scorer.algorithm, scorer.settings, relations,
                                                 sorted(set(x.entity_ids)&set(y.entity_ids)), [])['hard']
            if hard_cache[key]: return True
        return False
    while True:
        changed = False; seen = set()
        for edge in ordered:
            l, r = owners[edge.source_alert_id], owners[edge.target_alert_id]
            if l == r: continue
            left, right = components[l], components[r]
            signature = tuple(sorted((l, r)))
            if signature in seen: continue
            seen.add(signature)
            supports = [e for e in ordered if (e.source_alert_id in left and e.target_alert_id in right or
                                               e.source_alert_id in right and e.target_alert_id in left)]
            count = len({tuple(e.support.support_key) for e in supports})
            explicit = any(propagation(e) for e in supports)
            sizes = sorted((len(left), len(right)))
            needed = cfg.bridge_min_edges_between_singletons if sizes == [1, 1] else (
                cfg.bridge_min_edges_with_singleton if sizes[0] == 1 else cfg.bridge_min_edges_between_non_singletons)
            members = raw_members(left | right)
            span = (max(index.times[a] for a in members)-min(index.times[a] for a in members))/1e6
            lt = set().union(*(target_sets[a] for a in left)); rt = set().union(*(target_sets[a] for a in right))
            bridge = False
            for e in supports:
                if not cross_target(e): continue
                a, b = [index.alerts[i] for i in e.support.support_pair]
                at = {t.key for t in targets(a, index, scorer.settings)}
                bt = {t.key for t in targets(b, index, scorer.settings)}
                bridge |= bool(at and bt and at != bt)
            rejects = []
            if hard(left, right): rejects.append('component_hard_conflict')
            if span > cfg.max_incident_span_seconds: rejects.append('max_incident_span_seconds')
            if sum(sizes) > cfg.max_representatives: rejects.append('max_representatives')
            if lt and rt and lt != rt and not bridge: rejects.append('target_set_without_propagation')
            if count < needed and not (cfg.permit_explicit_relation_single_bridge and explicit):
                rejects.append('independent_support_count')
            diagnostics.append(dict(stage='clustering', support_key=edge.support.support_key, component_sizes=sizes,
                                    independent_support_count=count, required=needed, propagation_bridge=bridge,
                                    decision='reject' if rejects else 'accept', rejection_codes=rejects))
            if rejects: continue
            root = min(l, r); components[root] = left | right
            del components[max(l, r)]
            for rep in components[root]: owners[rep] = root
            changed = True
        if not changed: break
    incidents = []; nodes = []; node_by_alert = {}
    for reps in sorted(components.values(), key=lambda x: sorted(x)):
        members = raw_members(reps)
        es = [e for e in edges if e.source_alert_id in reps and e.target_alert_id in reps]
        data = dict(alert_ids=members, start_time=min(index.alerts[a].timestamp for a in members),
                    end_time=max(index.alerts[a].timestamp for a in members),
                    severity=maximum_severity(index.alerts[a] for a in members),
                    entity_ids=sorted({eid for a in members for eid in index.alerts[a].entity_ids}),
                    correlation_edge_ids=sorted(e.edge_id for e in es))
        data['incident_id'] = id_for('Incident', data)
        inc = Incident.model_validate(data); incidents.append(inc)
        ns = build_nodes(inc, index, scorer); nodes.extend(ns)
        for node in ns:
            for aid in node.alert_ids: node_by_alert[aid] = node
    adjacency = {n.node_id: set() for n in nodes}
    def reachable(a, b):
        stack = [a]; seen = set()
        while stack:
            n = stack.pop()
            if n == b: return True
            if n not in seen: seen.add(n); stack.extend(adjacency[n])
        return False
    chains = []
    for edge in sorted(edges, key=lambda e: (-e.support.direction.direction_confidence, e.edge_id)):
        d = edge.support.direction; decision = admitted[edge.edge_id]
        why = None
        if not decision['accepted']: why = decision['reason']
        else:
            src, dst = node_by_alert[d.source_alert_id], node_by_alert[d.target_alert_id]
            if src.incident_id != dst.incident_id: why = 'component_guard'
            elif src.node_id == dst.node_id: why = 'same_node'
            elif (event_microseconds(src.end_time)-event_microseconds(dst.start_time))/1e6 > policy['observation_policy']['clock_skew_seconds']:
                why = 'node_interval_chronology'
            elif reachable(dst.node_id, src.node_id): why = 'cycle'
        diagnostics.append(dict(stage='chain_admission', edge_id=edge.edge_id, support_key=edge.support.support_key,
                                semantic_admission=decision, decision='reject' if why else 'accept', rejection_code=why))
        if why: continue
        channels = {c['channel'] for c in d.forward_evidence+d.reverse_evidence}
        relation = 'ACCOUNT_PIVOT' if 'host_to_login_source' in channels else 'BOUND_OPERATION'
        data = dict(incident_id=src.incident_id, source_node_id=src.node_id, target_node_id=dst.node_id, relation_type=relation)
        chain = dict(schema_version=SCHEMA_VERSION, edge_id=id_for('ChainEdge', data), **data,
                     alert_ids=sorted(edge.support.support_pair), correlation_edge_ids=[edge.edge_id],
                     entity_ids=sorted({e for c in d.forward_evidence+d.reverse_evidence for e in c['entity_ids']}),
                     correlation_confidence=edge.score, direction_confidence=d.direction_confidence,
                     direction_evidence=d.model_dump(mode='json'), score_breakdown=edge.score_breakdown,
                     chain_admission_policy=decision, transition_evidence=edge.support.hierarchy,
                     reasons=[dict(rule_id='semantic_repair.bound_operation', alert_ids=sorted(edge.support.support_pair),
                                   direction_reason=d.direction_reason)])
        chains.append(chain); adjacency[src.node_id].add(dst.node_id)
    assert len(node_by_alert) == len(index.alerts)
    return incidents, nodes, chains, diagnostics

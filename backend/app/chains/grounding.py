"""Closed-snapshot validation; dangling or unsupported results cannot publish."""

from collections import Counter
from dataclasses import dataclass

from app.models import AttackChain, Incident
from app.models.base import resolve_pointer
from app.utils.stable_id import content_digest, id_for
from .conflicts import select_dag
from .direction import decide_direction
from .nodes import build_nodes
from .reconstruction import reconstruct_candidates, validate_support


@dataclass
class GroundingReport:
    errors: list[dict]
    node_count: int
    edge_count: int

    @property
    def valid(self):
        return not self.errors

    def json_data(self):
        return {"valid": self.valid, "errors": self.errors, "node_count": self.node_count,
                "edge_count": self.edge_count,
                "node_traceability": 1.0 if self.valid and self.node_count else None,
                "edge_traceability": 1.0 if self.valid and self.edge_count else None}

    def require_valid(self):
        if self.errors:
            raise ValueError("evidence_grounding_failed: " + str(self.errors))


def validate_grounding(index, incidents, chains, edges, scorer, record=None, support_cache=None):
    errors = []
    def fail(code, identity=None):
        errors.append({"code": code, "object_id": identity})
    edge_map = {e.edge_id: e for e in edges}
    cache = support_cache if support_cache is not None else {}
    context = {"alerts": index.alerts, "groups": index.groups, "correlation_edges": edge_map,
               "config_hash": scorer.config_hash, "score_weights": scorer.algorithm.score.weights.model_dump(),
               "independence_rule_ids": sorted({r.id for m in scorer.independence_mappings for r in m.rules})}
    node_count = sum(len(c.nodes) for c in chains)
    edge_count = sum(len(c.edges) for c in chains)
    if len(edge_map) != len(edges):
        fail("duplicate_correlation_id")
    if record is not None:
        expected_snapshot = {"algorithm": scorer.config.snapshot,
                             "sources": {k: v.snapshot() for k, v in sorted(scorer.settings.items())}}
        if (record.config_snapshot != expected_snapshot or record.config_hash != content_digest(expected_snapshot)
                or record.config_hash != scorer.config_hash or record.config_digest != record.config_hash):
            fail("analysis_config_mismatch", record.analysis_id)
        if record.analysis_id != id_for("AnalysisRecord", record):
            fail("analysis_identity_mismatch", record.analysis_id)
        if set(record.input_alert_ids) != set(index.alerts):
            fail("analysis_input_mismatch", record.analysis_id)
        if record.dataset_digest != content_digest([[aid, a.raw_fingerprint] for aid, a in index.alerts.items()]):
            fail("analysis_dataset_mismatch", record.analysis_id)
        if record.mapping_digest != scorer.config.mapping_digest:
            fail("analysis_mapping_mismatch", record.analysis_id)
    for aid, alert in index.alerts.items():
        try:
            type(alert).model_validate(alert.model_dump())
            if id_for("CanonicalAlert", alert) != aid:
                fail("alert_identity_mismatch", aid)
            for item in alert.entity_occurrences:
                resolve_pointer(alert.raw_alert, item.raw_pointer)
                if item.entity_id not in index.entities or aid not in index.entities[item.entity_id].alert_ids:
                    fail("entity_occurrence_mismatch", aid)
        except (ValueError, KeyError, TypeError) as exc:
            fail("alert_evidence_invalid:" + str(exc), aid)
    for edge in sorted(edges, key=lambda e: e.edge_id):
        try:
            # A caller-provided cached score is only an optimization during
            # assembly. Grounding always validates the submitted evidence again.
            cache[edge.edge_id] = validate_support(edge, index, scorer)
        except (ValueError, KeyError, TypeError) as exc:
            fail("correlation_evidence_invalid:" + str(exc), edge.edge_id)
    if errors:
        return GroundingReport(errors, node_count, edge_count)
    # A closed partition can still violate bridge/target/hard guards. Verify
    # membership against the frozen controlled algorithm, without new scoring.
    from app.incidents.clustering import cluster_incidents
    expected_membership = cluster_incidents(index, edges, scorer)
    if [(i.incident_id, i.alert_ids) for i in expected_membership.incidents] != [
            (i.incident_id, i.alert_ids) for i in sorted(incidents, key=lambda i: i.incident_id)]:
        fail("incident_controlled_membership_mismatch")
    incident_map = {i.incident_id: i for i in incidents}
    if len(incident_map) != len(incidents):
        fail("duplicate_incident_id")
    membership = Counter(aid for i in incidents for aid in i.alert_ids)
    if set(membership) != set(index.alerts) or any(n != 1 for n in membership.values()):
        fail("incident_membership_not_exact_partition")
    chain_map = {c.incident_id: c for c in chains}
    if len(chain_map) != len(chains) or set(chain_map) != set(incident_map):
        fail("chain_incident_coverage")
    global_nodes, global_edges = set(), set()
    alert_incident = {aid: i.incident_id for i in incidents for aid in i.alert_ids}
    internal_edges = {identity: [] for identity in incident_map}
    for edge in edges:
        left = alert_incident.get(edge.source_alert_id)
        right = alert_incident.get(edge.target_alert_id)
        if left is not None and left == right:
            internal_edges[left].append(edge.edge_id)
    for identity, incident in sorted(incident_map.items()):
        try:
            Incident.model_validate(incident.model_dump())
            if identity != id_for("Incident", incident):
                raise ValueError("incident_identity_mismatch")
            alerts = [index.alerts[aid] for aid in incident.alert_ids]
            from .nodes import maximum_severity
            if (incident.start_time != min(a.timestamp for a in alerts)
                    or incident.end_time != max(a.timestamp for a in alerts)
                    or incident.severity != maximum_severity(alerts)
                    or incident.entity_ids != sorted({eid for a in alerts for eid in a.entity_ids})):
                raise ValueError("incident_fact_summary_mismatch")
            ids = set(incident.alert_ids)
            internal = sorted(internal_edges[identity])
            if internal != incident.correlation_edge_ids:
                raise ValueError("incident_correlation_closure")
            chain = chain_map[identity]
            AttackChain.model_validate(chain.model_dump(), context=context)
            if chain.chain_id != id_for("AttackChain", chain):
                raise ValueError("chain_identity_mismatch")
            expected_nodes = build_nodes(incident, index, scorer)
            if [n.canonical_json() for n in chain.nodes] != [n.canonical_json() for n in expected_nodes]:
                raise ValueError("node_fact_or_confidence_mismatch")
            for node in chain.nodes:
                if node.node_id in global_nodes:
                    raise ValueError("duplicate_node_identity")
                global_nodes.add(node.node_id)
                if node.node_id != id_for("ChainNode", node):
                    raise ValueError("node_identity_mismatch")
            candidates = reconstruct_candidates(incident, expected_nodes, [edge_map[i] for i in internal],
                                                index, scorer, support_cache=cache)
            decisions = [decide_direction(c, scorer) for c in candidates]
            expected_edges, rejected = select_dag(decisions, expected_nodes)
            covered = {i for e in expected_edges for i in e.correlation_edge_ids}
            unresolved = sorted(set(internal) - covered | set(rejected))
            if [e.canonical_json() for e in chain.edges] != [e.canonical_json() for e in expected_edges]:
                raise ValueError("chain_edge_direction_or_support_mismatch")
            if chain.unresolved_correlation_edge_ids != unresolved:
                raise ValueError("unresolved_correlation_mismatch")
            if chain.status != ("partial" if unresolved else "complete"):
                raise ValueError("chain_status_mismatch")
            for edge in chain.edges:
                if edge.edge_id in global_edges:
                    raise ValueError("duplicate_chain_edge_identity")
                global_edges.add(edge.edge_id)
        except (ValueError, KeyError, TypeError, StopIteration) as exc:
            fail("incident_chain_evidence_invalid:" + str(exc), identity)
    return GroundingReport(errors, node_count, edge_count)

"""Explicitly synthetic facts; background only supplies population rarity.

The three foreground alerts form two actual parent-child process-instance
relations. No stages or causal relationships are assigned to background facts.
"""

from app.correlation.edges import run_correlation
from app.correlation.scoring import CorrelationScorer
from app.models import CorrelationEdge
from app.utils.stable_id import content_digest, id_for
from test_correlation_score import alert, inputs, process


def linear_fixture(config, background_count=32, extra_context=False):
    common = {"host": "synthetic-chain-host", "account": "synthetic-account", "session": "synthetic-session"}
    if extra_context:
        common.update(file="/synthetic/context", command="synthetic command --context")
    foreground = [alert("synthetic-A", category="process_execution", process=process(101), **common),
                  alert("synthetic-B", 1, category="command_execution", process=process(102, 1),
                        parent_process=process(101), **common),
                  alert("synthetic-C", 2, category="privilege_escalation", process=process(103, 2),
                        parent_process=process(102, 1), **common)]
    background = [alert("synthetic-background-" + str(i), 20000 + i * 9000, host="synthetic-background-host-" + str(i))
                  for i in range(background_count)]
    index, settings = inputs(foreground + background)
    correlation = run_correlation(list(index.alerts.values()), [], list(index.entities.values()), config, settings)
    return index, settings, foreground, correlation


def scorer_for(index, settings, config):
    digest = content_digest({"algorithm": config.snapshot, "sources": {k: v.snapshot() for k, v in sorted(settings.items())}})
    return CorrelationScorer(index, config, settings, digest)


def edge_for(index, settings, config, a, b):
    scorer = scorer_for(index, settings, config)
    left, right = sorted((a.alert_id, b.alert_id))
    scored = scorer.score_pair(left, right)
    data = {"source_alert_id": left, "target_alert_id": right, "score": round(scored.score, 6),
            "reasons": scored.reasons, "entity_ids": scored.entity_ids, "score_breakdown": scorer.breakdown(scored),
            "support_pair": {"alert_id_src": left, "alert_id_dst": right}}
    data["edge_id"] = id_for("CorrelationEdge", data)
    return CorrelationEdge.model_validate(data), scored


def attested_fixture(config, kind, source_category, target_category, seconds=1, dual_parent=False):
    """Reuse the existing synthetic upstream AlertRelation attestation contract.

    /operation explicitly records the observed operation, endpoint sides,
    request and launched process/order. Production extraction is unchanged.
    """
    from app.adapters.base import AdapterSettings
    from app.models import AlertRelation, CanonicalAlert
    from app.utils.stable_id import raw_fingerprint
    common = {"account": "u", "session": "s"}
    a = alert("synthetic-relation-a", category=source_category, host="h", dst_ip="192.0.2.2", dst_port=80,
              **({"process": process(1)} if dual_parent else {}), **common)
    b = alert("synthetic-relation-b", seconds, category=target_category,
              host="other" if kind == "account_host_pivot" else "h", src_ip="192.0.2.2", process=process(2),
              **({"parent_process": process(1)} if dual_parent else {}), **common)
    updated = []
    for item, side, order in ((a, "source", 1), (b, "target", 2)):
        raw = {**item.raw_alert, "operation": {"observed_relation": kind, "side": side, "request_id": "request",
                "started_process": process(2) if kind == "target_to_process" else None, "order": order}}
        data = item.model_dump()
        data.update(raw_alert=raw, raw_fingerprint=raw_fingerprint(raw))
        data["alert_id"] = id_for("CanonicalAlert", data)
        updated.append(CanonicalAlert.model_validate(data))
    a, b = updated
    background = [alert("attested-background-" + str(i), 20000 + i * 9000, host="attested-other-host-" + str(i))
                  for i in range(64)]
    settings = {"synthetic": AdapterSettings("synthetic", "synthetic", "synthetic", session_scope="application")}
    index, settings = inputs([a, b, *background], settings)
    roles = {"target_to_process": ("host", "process"), "account_host_pivot": ("account", "host"),
             "network_pivot": ("dst_ip", "src_ip"), "session_continuity": ("session", "session")}
    def entity_id(aid, role):
        return next(eid for eid, roles in index.roles[aid].items() if role in roles)
    src_role, dst_role = roles[kind]
    relation = AlertRelation.model_validate({"relation_type": kind, "source_entity_id": entity_id(a.alert_id, src_role),
        "target_entity_id": entity_id(b.alert_id, dst_role), "raw_pointers": [
            {"alert_id": a.alert_id, "pointer": "/operation", "side": "src"},
            {"alert_id": b.alert_id, "pointer": "/operation", "side": "dst"}]})
    data = index.alerts[b.alert_id].model_dump()
    data["relations"] = [*data["relations"], relation.model_dump()]
    index.alerts[b.alert_id] = CanonicalAlert.model_validate(data, context={"alerts": index.alerts})
    correlation = run_correlation(list(index.alerts.values()), [], list(index.entities.values()), config, settings)
    return index, settings, [a, b], correlation

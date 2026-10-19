"""Pair hard guards and target summaries; no component union or clustering."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    key: tuple
    alert_id: str
    pointers: tuple[str, ...]


def targets(alert, index, source_settings):
    """Only canonical execution/target host and complete destination endpoint.

    Adapters exclude collector hosts. No DNS, URL-host, source IP, port stripping
    or speculative asset equivalence is introduced here.
    """
    result = []
    for eid, roles in index.roles[alert.alert_id].items():
        e = index.entities[eid]
        if e.type.value == "HOST" and "host" in roles:
            result.append(Target(("HOST", e.scope, e.value), alert.alert_id,
                                 (alert.field_provenance["host"].raw_pointer,)))
        if e.type.value == "IP" and "dst_ip" in roles and alert.dst_port is not None:
            result.append(Target(("ENDPOINT", e.scope, e.value, alert.dst_port), alert.alert_id,
                                 (alert.field_provenance["dst_ip"].raw_pointer, alert.field_provenance["dst_port"].raw_pointer)))
    return sorted(result, key=lambda t: t.key)


def group_targets(rep, index, source_settings):
    result = []
    for aid in index.groups[rep]:
        result.extend(targets(index.alerts[aid], index, source_settings))
    return sorted(result, key=lambda t: (t.key, t.alert_id, t.pointers))


def target_diagnostic(values):
    return [{"key": list(t.key), "alert_id": t.alert_id,
             "raw_pointers": [{"alert_id": t.alert_id, "pointer": pointer, "side": "shared"} for pointer in t.pointers]}
            for t in values]


def verified_incompatible_session(a, b):
    """Frozen guard interface; present contract has no exclusivity proof input.

    User confirmation: neither distinct session IDs, arbitrary raw fields nor
    time/category assumptions constitute evidence. Future proof support needs a
    contract-defined source and bound pointers before this may return verified.
    """
    return {"rule_id": "verified_incompatible_session", "verified": False,
            "status": "unproven", "evidence": [], "basis": "no_contract_defined_exclusivity_proof"}


def pair_conflicts(a, b, index, config, source_settings, relations, shared, behavior_windows):
    soft, hard = [], []
    cfg = config.conflict
    left_targets, right_targets = targets(a, index, source_settings), targets(b, index, source_settings)
    left_keys, right_keys = {t.key for t in left_targets}, {t.key for t in right_targets}
    types = {index.entities[eid].type.value for eid in shared}
    contextual = bool(types.intersection({"ACCOUNT", "SESSION"})) or any(
        index.entities[eid].type.value == "PROCESS" and index.entities[eid].value.startswith("{") for eid in shared)
    propagation = bool(relations)
    gap = abs(index.times[a.alert_id] - index.times[b.alert_id]) / 1000000
    def penalty(rule):
        soft.append((rule, getattr(cfg.strengths, rule)))
    if left_keys and right_keys and left_keys != right_keys and not (contextual or propagation):
        penalty("different_target_without_bridge")
    if not shared and not propagation:
        penalty("no_context_bridge")
    if behavior_windows and gap > max(behavior_windows):
        penalty("beyond_behavior_window")
    reversed_relations = [r for r in relations if index.times[r.source_alert_id] > index.times[r.target_alert_id] + config.time.clock_skew_seconds * 1000000]
    if reversed_relations:
        penalty("reversed_explicit_relation")
    # A different product/source namespace does not establish isolation. Scoped
    # facts can establish explicitly different networks/assets/realms. An actual
    # cross-scope shared context or attested propagation is required to bridge.
    if a.source_namespace != b.source_namespace:
        explicit_isolation = False
        for attr in ("network_namespace", "asset_namespace", "account_realm", "session_scope"):
            l = getattr(source_settings[a.source_namespace], attr)
            r = getattr(source_settings[b.source_namespace], attr)
            if l is not None and r is not None and l != r:
                explicit_isolation = True
        bridge_types = types.intersection({"HOST", "ACCOUNT", "SESSION", "PROCESS"})
        if explicit_isolation and not (bridge_types or propagation):
            hard.append("cross_namespace_without_bridge")
    session_check = verified_incompatible_session(a, b)
    if session_check["verified"]:
        hard.append("verified_incompatible_session")
        penalty("incompatible_session")
    return {"penalty": max((p for _, p in soft), default=0.0), "soft": soft, "hard": sorted(hard),
            "left_targets": target_diagnostic(left_targets), "right_targets": target_diagnostic(right_targets),
            "propagation_bridge": propagation, "reversed_relation": bool(reversed_relations),
            "session_compatibility": session_check}

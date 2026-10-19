"""Role-aware nomination policy. Matching never attests causal propagation."""

MONITORED = "monitored_host_ip"
ACCOUNT_ROLES = {"account", "target_account", "authenticated_account", "source_account", "audit_account"}


def compatible(index, left, right, eid):
    a, b = index.alerts[left], index.alerts[right]
    la, rb = index.roles[left][eid], index.roles[right][eid]
    if index.entities[eid].type.value != "IP" or MONITORED not in la | rb:
        return True
    # Existing network endpoint witnesses retain their original eligibility.
    if la & {"src_ip", "dst_ip"} and rb & {"src_ip", "dst_ip"}:
        return True
    if MONITORED in la and a.source_type.value != "wazuh" or MONITORED in rb and b.source_type.value != "wazuh":
        return False
    if MONITORED in la and MONITORED in rb:
        return True
    endpoint_sources = {"suricata", "wazuh"}
    return ((MONITORED in la and b.source_type.value in endpoint_sources and bool(rb & {"src_ip", "dst_ip"}))
            or (MONITORED in rb and a.source_type.value in endpoint_sources and bool(la & {"src_ip", "dst_ip"})))


def bridge_witnesses(index, a, b):
    """Audit labels for already generated pairs; no runtime input from audit."""
    result = []
    for eid in sorted(set(a.entity_ids) & set(b.entity_ids)):
        la, rb = index.roles[a.alert_id][eid], index.roles[b.alert_id][eid]
        kind = index.entities[eid].type.value
        label = None
        if kind == "IP" and MONITORED in la | rb:
            label = "monitored_host_ip" if MONITORED in la & rb else "network_monitored_ip"
        elif kind == "HOST" and (a.semantic_observations or b.semantic_observations):
            label = "local_host"
        elif kind == "ACCOUNT" and (la | rb) - {"account"}:
            label = "account_roles"
        if label:
            result.append(dict(bridge_type=label, entity_id=eid, source_roles=sorted(la), target_roles=sorted(rb),
                               source_types=[a.source_type.value, b.source_type.value]))
    return result

"""Explicit local-endpoint capability; never infer it for remote collectors."""
from app.entities.normalization import hostname, ip, text
from app.models import ProcessRef, SourceType
from app.models.base import resolve_pointer


def project_local(raw, facts, pointers):
    if facts["source_type"] != SourceType.WAZUH:
        return
    agent = raw.get("agent", {})
    name = text(agent.get("name"))
    # Explicit contradictory execution-host evidence wins over agent identity.
    local = bool(name) and (not facts.get("host") or hostname(facts["host"]) == hostname(name))
    observations = []
    def add(path, kind, role):
        try:
            value = resolve_pointer(raw, path)
        except ValueError:
            return
        value = text(value)
        if value is None:
            return
        if kind == "IP":
            value = ip(value)
        if role == "audit_account" and value.lower() in {"-1", "4294967295", "unset", "(unset)"}:
            return
        observations.append(dict(entity_type=kind, role=role, value=value, raw_pointer=path))
    if local:
        if not facts.get("host"):
            facts["host"], pointers["host"] = name, "/agent/name"
        add("/agent/ip", "IP", "monitored_host_ip")
    # Detector/manager is separate from the monitored asset.
    manager = raw.get("manager", {}).get("name")
    facts.pop("sensor", None)
    pointers.pop("sensor", None)
    if text(manager):
        facts["sensor"], pointers["sensor"] = text(manager), "/manager/name"
    for path, role in (("/data/target_user", "target_account"),
                       ("/data/dstuser", "authenticated_account"),
                       ("/data/srcuser", "source_account"),
                       ("/data/audit/auid", "audit_account")):
        add(path, "ACCOUNT", role)
    if observations:
        facts["semantic_observations"] = observations
    audit = raw.get("data", {}).get("audit", {})
    if isinstance(audit, dict) and not facts.get("parent_process") and (audit.get("parent_exe") or audit.get("parent_name")):
        facts["parent_process"] = ProcessRef(name=text(audit.get("parent_name")), executable=text(audit.get("parent_exe")))
        pointers["parent_process"] = "/data/audit"
        for child, key in (('name', 'parent_name'), ('executable', 'parent_exe')):
            if audit.get(key):
                pointers['parent_process.'+child] = '/data/audit/'+key

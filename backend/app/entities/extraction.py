"""Nine scoped entity types and evidence-bound, local process lineage."""

from dataclasses import dataclass

from app.adapters.base import AdapterSettings
from app.models import AlertRelation, AlertRelationType, Entity, EntityOccurrence, EntityRole, EntityType, EvidencePointer
from app.models.base import resolve_pointer
from app.utils.stable_id import canonical_json, id_for
from .normalization import file_path, hostname, ip, url


@dataclass
class EntityResult:
    alerts: list
    entities: list[Entity]
    identity_projection: object = None


def process_value(process, alert):
    if alert.host is not None and process.pid is not None and process.start_time is not None:
        return canonical_json({"host": alert.host, "pid": process.pid, "start_time": process.start_time})
    return process.executable or process.name or canonical_json({"alert_id": alert.alert_id, "pid": process.pid})


def extract_entities(alerts, source_settings: dict[str, AdapterSettings], *, contract=None) -> EntityResult:
    """New runs use reliable core entities; legacy is explicit historical replay."""
    if contract is None:
        contracts = {s.extraction_contract for s in source_settings.values()}
        if len(contracts) != 1:
            raise ValueError('mixed_extraction_contracts')
        contract = contracts.pop()
    if contract == 'front-data-v1':
        from .front_data import extract_front_data
        return extract_front_data(alerts, source_settings)
    if contract != 'legacy-v1':
        raise ValueError('unknown_extraction_contract')
    return _extract_legacy_entities(alerts, source_settings)


def _extract_legacy_entities(alerts, source_settings: dict[str, AdapterSettings]) -> EntityResult:
    """Sorted input/output and minimum-alert display selection make this idempotent."""
    from app.services.capacity import AlertSequence, execution_state
    state = execution_state()
    entities, updated = {}, state.alerts() if state else []
    fields = {
        "src_ip": EntityType.IP, "dst_ip": EntityType.IP, "host": EntityType.HOST,
        "account": EntityType.ACCOUNT, "session": EntityType.SESSION,
        "process": EntityType.PROCESS, "parent_process": EntityType.PROCESS,
        "url": EntityType.URL, "domain": EntityType.DOMAIN, "file": EntityType.FILE, "command": EntityType.COMMAND,
    }
    ordered = alerts if isinstance(alerts, AlertSequence) else sorted(alerts, key=lambda a: a.alert_id)
    for alert in ordered:
        settings = source_settings[alert.source_namespace]
        host_scope = canonical_json({"asset_namespace": settings.asset_namespace or alert.source_namespace, "host": alert.host}) if alert.host else alert.source_namespace
        occurrences, ids_by_role = [], {}
        projected = [(role, kind, getattr(alert, role), alert.field_provenance[role].raw_pointer)
                     for role, kind in fields.items() if getattr(alert, role) is not None]
        # Additional source observations preserve multiple accounts and host IP
        # roles without overloading network endpoint fields or scalar account.
        for observation in alert.semantic_observations:
            projected.append((observation.role.value, observation.entity_type, observation.value, observation.raw_pointer))
        for role, kind, original, raw_pointer in projected:
            raw_value = resolve_pointer(alert.raw_alert, raw_pointer)
            display = canonical_json(raw_value) if isinstance(raw_value, (dict, list)) else str(raw_value)
            if kind == EntityType.IP:
                value, scope = ip(original), settings.network_namespace or alert.source_namespace
            elif kind == EntityType.HOST:
                value, scope = hostname(original), settings.asset_namespace or alert.source_namespace
            elif kind == EntityType.DOMAIN:
                value, scope = hostname(original), "global"
            elif kind == EntityType.ACCOUNT:
                value, scope = original, settings.account_realm or alert.source_namespace
                if role == "audit_account" and original.isdecimal():
                    # Linux login UID numbers are host-local, never usernames.
                    scope = canonical_json({"audit_uid_host_scope": host_scope}) if alert.host else canonical_json({"audit_uid_alert": alert.alert_id})
            elif kind == EntityType.SESSION:
                value, scope = original, settings.session_scope or host_scope
                if settings.format_profile == 'multisource_native_v1':
                    from app.adapters.multisource import session_scope
                    scope = session_scope(alert, settings)
            elif kind == EntityType.PROCESS:
                value, scope = process_value(original, alert), host_scope
            elif kind == EntityType.URL:
                value = url(original)
                scope = "global" if "://" in value else host_scope if alert.host else canonical_json({"domain": alert.domain}) if alert.domain else alert.source_namespace
                if settings.format_profile == 'multisource_native_v1' and '://' not in value and alert.domain:
                    # Explicit HTTP authority, shared by network and WAF alerts,
                    # is the target scope for the observed relative resource.
                    scope = canonical_json({'domain': alert.domain})
            elif kind == EntityType.FILE:
                value, scope = file_path(original, settings.os_type), host_scope
            else:
                value, scope = original, host_scope
            data = {"type": kind.value, "scope": scope, "value": value}
            entity_id = id_for("Entity", data)
            if entity_id not in entities:
                entities[entity_id] = {**data, "entity_id": entity_id, "display_value": display, "alert_ids": set() if state else []}
            if state:
                entities[entity_id]['alert_ids'].add(alert.alert_id)
            elif alert.alert_id not in entities[entity_id]["alert_ids"]:
                entities[entity_id]["alert_ids"].append(alert.alert_id)
            occurrences.append(EntityOccurrence(entity_id=entity_id, role=EntityRole(role), raw_pointer=raw_pointer))
            ids_by_role[role] = entity_id
        if settings.format_profile == 'multisource_native_v1':
            from app.adapters.multisource import additional_entities
            for role, kind, value, pointer, scope in additional_entities(alert, settings):
                entity_id = id_for('Entity', {'type': kind.value, 'scope': scope, 'value': value})
                if entity_id not in entities:
                    entities[entity_id] = dict(type=kind.value,scope=scope,value=value,entity_id=entity_id,
                        display_value=str(resolve_pointer(alert.raw_alert,pointer)),alert_ids=set() if state else [])
                if state: entities[entity_id]['alert_ids'].add(alert.alert_id)
                elif alert.alert_id not in entities[entity_id]['alert_ids']: entities[entity_id]['alert_ids'].append(alert.alert_id)
                occurrence = EntityOccurrence(entity_id=entity_id,role=EntityRole(role),raw_pointer=pointer)
                if occurrence not in occurrences: occurrences.append(occurrence)
        relations = []
        # A structured parent_process and child process with complete identities
        # are direct lineage evidence. Descriptors and pid-only references are not.
        if alert.host and alert.process and alert.parent_process and all(
            p.pid is not None and p.start_time is not None for p in (alert.process, alert.parent_process)
        ) and alert.parent_process.start_time <= alert.process.start_time and alert.parent_process.pid != alert.process.pid:
            relations.append(AlertRelation.model_validate({
                "relation_type": AlertRelationType.PARENT_CHILD_PROCESS,
                "source_entity_id": ids_by_role["parent_process"], "target_entity_id": ids_by_role["process"],
                "raw_pointers": [EvidencePointer(alert_id=alert.alert_id, pointer=alert.field_provenance[role].raw_pointer, side=side)
                                 for role, side in (("parent_process", "src"), ("process", "dst"))],
            }))
        # No request/session/host co-occurrence is promoted into a causal relation.
        data = alert.model_dump()
        data.update(entity_ids=sorted({o.entity_id for o in occurrences}), entity_occurrences=occurrences, relations=relations)
        parsed = type(alert).model_validate(data)
        if state:
            updated.add(parsed)
        else:
            updated.append(parsed)
    return EntityResult(updated.sequence() if state else updated, [Entity(**{**entities[key],
        'alert_ids':sorted(entities[key]['alert_ids']), "type": EntityType(entities[key]["type"])}) for key in sorted(entities)])

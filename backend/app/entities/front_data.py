"""Observed HOST/ACCOUNT/PROCESS identities; all other fields stay context."""
from app.models import AlertRelation, AlertRelationType, EvidencePointer, Entity, EntityOccurrence, EntityType
from app.models.base import resolve_pointer
from app.utils.stable_id import canonical_json, id_for
from .context import clean, observed, context_refs
from .normalization import hostname, ip


def extract_front_data(alerts, source_settings):
    from .extraction import EntityResult
    from .identity_projection import host_alias_plan, host_authority_scope, project_auth_sessions, project_context_identities
    from app.services.capacity import AlertSequence, execution_state
    state = execution_state()
    updated = state.alerts() if state else []
    entities = {}
    ordered = alerts if isinstance(alerts, AlertSequence) else sorted(alerts, key=lambda a: a.alert_id)
    alias_plan, alias_bindings, diagnostics = host_alias_plan(ordered, source_settings)
    for alert in ordered:
        settings = source_settings[alert.source_namespace]
        asset = settings.asset_namespace
        raw = alert.raw_alert
        native = settings.format_profile == 'multisource_native_v1'
        host_id, host_pointer = observed(raw, '/asset_id', '/host_id', '/server_host_id') if native else (None, None)
        if not clean(host_id):
            host_pointer = None
        host = clean(host_id) or hostname(clean(alert.host))
        host_kind = 'asset_id' if clean(host_id) else 'hostname'
        if not host:
            host_ip, host_pointer = observed(raw, '/host_ip') if native else (None, None)
            if host_ip is None:
                monitored = next((o for o in alert.semantic_observations if o.role.value == 'monitored_host_ip'), None)
                if monitored:
                    host_ip, host_pointer = monitored.value, monitored.raw_pointer
            host = ip(clean(host_ip)) if host_ip is not None else None
            host_kind = 'host_ip'
        asset_scope = canonical_json(dict(identity_kind=host_kind, **({'asset_scope': asset} if asset else {})))
        authority = host_authority_scope(alert, settings)
        if authority is not None:
            asset_scope = canonical_json(dict(identity_kind=host_kind, identity_authority=authority))
        if alert.alert_id in alias_plan:
            host, asset_scope, alias_id = alias_plan[alert.alert_id]
        host_scope = canonical_json(dict(scope=asset_scope, host=host)) if host else None
        occurrences, ids_by_role = [], {}

        def add(kind, role, value, scope, pointer):
            if value is None:
                return
            data = dict(type=kind, scope=scope, value=value)
            eid = id_for('Entity', data)
            witness = resolve_pointer(raw, pointer)
            display = canonical_json(witness) if isinstance(witness, (dict, list)) else str(witness)
            if eid not in entities:
                entities[eid] = dict(**data, entity_id=eid, display_value=display, alert_ids=set())
            entities[eid]['alert_ids'].add(alert.alert_id)
            occurrence = EntityOccurrence(entity_id=eid, role=role, raw_pointer=pointer)
            if occurrence not in occurrences:
                occurrences.append(occurrence)
            ids_by_role[role] = eid

        if host:
            add('HOST', 'host', host, asset_scope, host_pointer or alert.field_provenance['host'].raw_pointer)
        realm, _ = observed(raw, '/realm', '/account_domain', '/user_domain', '/tenant') if native else observed(raw, '/data/realm', '/data/account_realm')
        realm = clean(realm) or settings.account_realm
        accounts = [('account', alert.account, alert.field_provenance['account'].raw_pointer)] if alert.account else []
        accounts += [(o.role.value, o.value, o.raw_pointer) for o in alert.semantic_observations if o.entity_type == EntityType.ACCOUNT]
        for role, value, pointer in accounts:
            value = clean(value)
            if value is None:
                continue
            account_scope = realm or host_scope or canonical_json(dict(unscoped_account_alert=alert.alert_id))
            if '\\' in value:
                domain, value = value.split('\\', 1)
                domain, value = clean(domain), clean(value)
                if not domain or not value:
                    continue
                account_scope = domain
            if role == 'audit_account' and value.isdecimal():
                account_scope = canonical_json(dict(uid_host=host_scope)) if host_scope else canonical_json(dict(uid_alert=alert.alert_id))
            add('ACCOUNT', role, value, account_scope, pointer)
        for role in ('process', 'parent_process'):
            process = getattr(alert, role)
            if process is None:
                continue
            prefix = '' if role == 'process' else 'parent_'
            guid, pointer = observed(raw, '/'+prefix+'process_guid', '/'+prefix+'process_instance_id') if native else (None, None)
            guid = clean(guid) or clean(process.guid) or clean(process.instance_id)
            if guid:
                value = canonical_json(dict(instance_id=guid))
                pointer = pointer or alert.field_provenance[role].raw_pointer
            elif host is not None and process.pid is not None:
                value = canonical_json(dict(host=host, pid=process.pid, start_time=process.start_time,
                    **({'observation':alert.alert_id} if process.start_time is None else {})))
                pointer = alert.field_provenance[role].raw_pointer
            elif host is not None and (process.executable or process.name):
                value = canonical_json(dict(host=host, descriptor=process.executable or process.name))
                pointer = alert.field_provenance[role].raw_pointer
            else:
                continue
            add('PROCESS', role, value, host_scope or canonical_json(dict(process_source=alert.source_namespace)), pointer)
        # Existing structured parent-child extraction, with unchanged admission.
        relations = []
        if host and alert.process and alert.parent_process and all(
            p.pid is not None and p.start_time is not None for p in (alert.process, alert.parent_process)
        ) and alert.parent_process.start_time <= alert.process.start_time and alert.parent_process.pid != alert.process.pid:
            relations.append(AlertRelation.model_validate({
                'relation_type': AlertRelationType.PARENT_CHILD_PROCESS,
                'source_entity_id': ids_by_role['parent_process'], 'target_entity_id': ids_by_role['process'],
                'raw_pointers': [EvidencePointer(alert_id=alert.alert_id,
                    pointer=alert.field_provenance[role].raw_pointer, side=side)
                    for role, side in (('parent_process', 'src'), ('process', 'dst'))],
            }))
        data = alert.model_dump()
        data.update(entity_ids=sorted({o.entity_id for o in occurrences}),
                    entity_occurrences=sorted(occurrences, key=lambda o: (o.entity_id, o.role.value, o.raw_pointer)),
                    contexts=context_refs(alert, settings, host_scope), extraction_version='front-data-v1', relations=relations)
        data['identity_binding_ids'] = [alias_plan[alert.alert_id][2]] if alert.alert_id in alias_plan else []
        parsed = type(alert).model_validate(data)
        if state:
            updated.add(parsed)
        else:
            updated.append(parsed)
    entity_list = [Entity(**{**entities[eid], 'alert_ids': sorted(entities[eid]['alert_ids'])}) for eid in sorted(entities)]
    aa, ee, projection = project_auth_sessions(updated.sequence() if state else updated,
        entity_list, source_settings, alias_bindings, diagnostics)
    aa, ee, projection = project_context_identities(aa, ee, source_settings, projection)
    return EntityResult(aa, ee, projection)

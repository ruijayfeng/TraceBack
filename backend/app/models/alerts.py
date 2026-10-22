"""Alert facts, entities and explicitly bound references; no extraction logic."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, ValidationInfo, field_validator, model_validator, model_serializer

from app.utils.stable_id import pointer_set, raw_fingerprint
from .base import (AlertID, Digest, DomainModel, EntityID, Json, NonNegativeInt,
                   Pointer, StrictModel, Text, UTCDateTime, check_evidence, ids, resolve_pointer)
from .enums import AlertRelationType, Category, EntityRole, EntityType, Severity, SourceType


class ProcessRef(StrictModel):
    name: Text | None = None
    executable: Text | None = None
    pid: NonNegativeInt | None = None
    start_time: UTCDateTime | None = None
    guid: Text | None = None
    instance_id: Text | None = None

    @model_serializer(mode='wrap')
    def legacy_shape(self, handler):
        data = handler(self)
        for name in ('guid', 'instance_id'):
            if getattr(self, name) is None:
                data.pop(name, None)
        return data

    @model_validator(mode="after")
    def identifiable(self):
        if all(value is None for value in (self.name, self.executable, self.pid, self.guid, self.instance_id)):
            raise ValueError("process requires name, executable or pid")
        return self


class FieldProvenance(StrictModel):
    raw_pointer: Pointer
    transform: Text


class EntityOccurrence(StrictModel):
    entity_id: EntityID
    role: EntityRole
    raw_pointer: Pointer


class EvidencePointer(StrictModel):
    alert_id: AlertID
    pointer: Pointer
    side: Literal["src", "dst", "shared"]

    def resolve(self, alerts: dict):
        if self.alert_id not in alerts:
            raise ValueError("bound alert is absent")
        alert = alerts[self.alert_id]
        raw = alert.raw_alert if hasattr(alert, "raw_alert") else alert["raw_alert"]
        return resolve_pointer(raw, self.pointer)


def canonical_pointers(values):
    return [EvidencePointer.model_validate(v) for v in pointer_set([v.model_dump(mode="json") for v in values])]


EvidencePointers = Annotated[list[EvidencePointer], AfterValidator(canonical_pointers)]


class SupportPair(StrictModel):
    alert_id_src: AlertID
    alert_id_dst: AlertID

    @model_validator(mode="after")
    def different(self):
        if self.alert_id_src == self.alert_id_dst:
            raise ValueError("support pair requires distinct original alerts")
        return self

    def alert_ids(self) -> set[str]:
        return {self.alert_id_src, self.alert_id_dst}


class AlertRelation(StrictModel):
    relation_type: AlertRelationType
    source_entity_id: EntityID
    target_entity_id: EntityID
    raw_pointers: Annotated[EvidencePointers, Field(min_length=1)]

    @model_validator(mode="after")
    def structured_evidence(self, info: ValidationInfo):
        require_relation_fields(self.raw_pointers, info)
        return self


def require_relation_fields(pointers, info: ValidationInfo):
    """Reject structurally insufficient evidence, without inventing vendor lineage.

    Field semantics/scope/instance verification belongs to extraction/scoring and
    Grounding. This shape check never certifies arbitrary pointer contents as a
    causal relation. A raw root or only known context fields is insufficient.
    """
    weak = {"", "/host", "/timestamp", "/category", "/session", "/request_id", "/process/name"}
    substantive = False
    for p in pointers:
        known_context = set(weak)
        if info.context and "alerts" in info.context and p.alert_id in info.context["alerts"]:
            alert = info.context["alerts"][p.alert_id]
            provenance = alert.field_provenance if hasattr(alert, "field_provenance") else alert.get("field_provenance", {})
            for field in ("host", "timestamp", "category", "session"):
                if field in provenance:
                    item = provenance[field]
                    known_context.add(item.raw_pointer if hasattr(item, "raw_pointer") else item["raw_pointer"])
        if p.pointer not in known_context:
            substantive = True
    if not substantive:
        raise ValueError("explicit relation requires structured relationship fields beyond host/time/category/session")


def normalized_ip(value):
    if type(value) is not str:
        raise ValueError("IP address must be a string")
    if "%" in value:
        raise ValueError("IP scope belongs in Entity.scope, not the address")
    return str(ip_address(value))


IPAddress = Annotated[str, AfterValidator(normalized_ip)]
Port = Annotated[int, Field(ge=0, le=65535)]


class SemanticObservation(StrictModel):
    """Versioned source projection, before scoped entity identity is assigned."""
    contract_version: Literal["role-aware-v1"] = "role-aware-v1"
    entity_type: EntityType
    value: Text
    role: EntityRole
    raw_pointer: Pointer

    @model_validator(mode="after")
    def role_type(self):
        allowed = {"monitored_host_ip": "IP", "target_account": "ACCOUNT",
                   "authenticated_account": "ACCOUNT", "source_account": "ACCOUNT", "audit_account": "ACCOUNT"}
        if allowed.get(self.role.value) != self.entity_type.value:
            raise ValueError("semantic_observation_role_type_mismatch")
        if self.entity_type == EntityType.IP:
            object.__setattr__(self, "value", normalized_ip(self.value))
        return self


class ContextCandidate(StrictModel):
    kind: Literal['request', 'flow', 'session', 'task']
    value: Text
    raw_pointer: Pointer


class ContextRef(ContextCandidate):
    scope: Text


class CanonicalAlert(DomainModel):
    alert_id: AlertID
    timestamp: UTCDateTime
    source_type: SourceType
    source_namespace: Text
    source_product: Text | None = None
    title: Text | None = None
    context_candidates: list[ContextCandidate] = Field(default_factory=list)
    contexts: list[ContextRef] = Field(default_factory=list)
    identity_binding_ids: list[Text] = Field(default_factory=list)
    extraction_version: Literal['front-data-v1'] | None = None
    sensor: Text | None = None
    source_record_id: Text | None = None
    origin_namespace: Text | None = None
    origin_record_id: Text | None = None
    rule_id: Text | None = None
    alert_type: Text | None = None
    category: Category = Category.UNKNOWN
    signature: Text | None = None
    severity: Severity = Severity.UNKNOWN
    src_ip: IPAddress | None = None
    dst_ip: IPAddress | None = None
    src_port: Port | None = None
    dst_port: Port | None = None
    host: Text | None = None
    account: Text | None = None
    session: Text | None = None
    process: ProcessRef | None = None
    parent_process: ProcessRef | None = None
    url: Text | None = None
    domain: Text | None = None
    file: Text | None = None
    command: Text | None = None
    entity_ids: ids(EntityID) = Field(default_factory=list)
    entity_occurrences: list[EntityOccurrence] = Field(default_factory=list)
    semantic_observations: list[SemanticObservation] = Field(default_factory=list)
    relations: list[AlertRelation] = Field(default_factory=list)
    raw_alert: Annotated[dict[str, Json] | str, Field(min_length=1)]
    raw_fingerprint: Digest
    field_provenance: Annotated[dict[Text, FieldProvenance], Field(min_length=1)]
    metadata_provenance: dict[Literal['source_product'], Literal['adapter_settings.generator']] = Field(default_factory=dict)

    @field_validator("semantic_observations")
    @classmethod
    def ordered_observations(cls, values):
        return sorted({(v.entity_type.value, v.role.value, v.value, v.raw_pointer): v for v in values}.values(),
                      key=lambda v: (v.entity_type.value, v.role.value, v.value, v.raw_pointer))

    @model_serializer(mode="wrap")
    def compatible_serialization(self, handler):
        data = handler(self)
        if not self.semantic_observations:
            data.pop("semantic_observations", None)
        for key in ('source_product', 'title', 'context_candidates', 'contexts', 'extraction_version', 'metadata_provenance', 'identity_binding_ids'):
            if getattr(self, key) in (None, [], {}):
                data.pop(key, None)
        return data

    @property
    def raw_evidence(self):
        """Existing persisted raw_alert is the sole copy of raw evidence."""
        return self.raw_alert

    @field_validator("raw_alert", mode="before")
    @classmethod
    def raw_json_only(cls, value):
        from .base import json_value
        return json_value(value)

    @model_validator(mode="after")
    def fact_references(self, info: ValidationInfo):
        from app.entities.normalization import text
        for context in [*self.context_candidates, *self.contexts]:
            value = text(resolve_pointer(self.raw_alert, context.raw_pointer))
            if value is None or value.strip() != context.value:
                raise ValueError('context_value_requires_raw_witness')
        if self.contexts and self.extraction_version is None:
            raise ValueError('contexts_require_extraction_version')
        for observation in self.semantic_observations:
            raw = resolve_pointer(self.raw_alert, observation.raw_pointer)
            if isinstance(raw, (dict, list, bool)) or raw is None:
                raise ValueError("semantic_observation_requires_scalar_witness")
            from app.utils.stable_id import nfc
            expected = normalized_ip(str(raw)) if observation.entity_type == EntityType.IP else nfc(str(raw))
            if expected != observation.value:
                raise ValueError("semantic_observation_value_mismatch")
        if self.semantic_observations and self.source_type != SourceType.WAZUH:
            raise ValueError("unsupported_semantic_observation_source")
        if (self.origin_namespace is None) != (self.origin_record_id is None):
            raise ValueError("origin namespace and record ID must both be present or both null")
        if self.raw_fingerprint != raw_fingerprint(self.raw_alert):
            raise ValueError("raw_fingerprint differs from raw_alert")
        # Namespace is deployment metadata, not an invented raw field. Unknown
        # category/severity defaults and derived references need no raw provenance.
        facts = ("source_product", "title", "sensor", "source_record_id", "origin_namespace", "origin_record_id", "rule_id", "alert_type",
                 "signature", "src_ip", "dst_ip", "src_port", "dst_port", "host", "account", "session",
                 "process", "parent_process", "url", "domain", "file", "command")
        required = {"timestamp", "source_type"} | {name for name in facts if getattr(self, name) is not None}
        if self.category != Category.UNKNOWN:
            required.add("category")
        if self.severity != Severity.UNKNOWN:
            required.add("severity")
        for name in self.metadata_provenance:
            if getattr(self, name) is None or name in self.field_provenance:
                raise ValueError('metadata_provenance_requires_exclusive_nonnull_field')
            required.discard(name)
        if not required <= self.field_provenance.keys():
            raise ValueError("field_provenance is missing extracted fact fields")
        for provenance in self.field_provenance.values():
            resolve_pointer(self.raw_alert, provenance.raw_pointer)
        # New adapters attest each observed ProcessRef child independently.
        # Historical snapshots with aggregate-only provenance remain readable.
        for role in ('process', 'parent_process'):
            process = getattr(self, role)
            for child in ProcessRef.model_fields:
                provenance = self.field_provenance.get(role + '.' + child)
                if provenance is None:
                    continue
                value = getattr(process, child) if process else None
                observed = resolve_pointer(self.raw_alert, provenance.raw_pointer)
                from app.entities.normalization import integer, timestamp, text
                if child == 'pid':
                    observed = integer(observed)
                elif child == 'start_time':
                    # Adapter parsing attests the source timezone in transform.
                    if observed != value:
                        zone = provenance.transform.partition(':timezone=')[2]
                        observed = timestamp(observed, source_timezone=zone if zone and zone != 'None' else None)
                else:
                    observed = text(observed)
                if value is None or observed != value:
                    raise ValueError('process_child_provenance_mismatch')
        if set(self.entity_ids) != {v.entity_id for v in self.entity_occurrences}:
            raise ValueError("entity_ids must match entity_occurrences")
        for occurrence in self.entity_occurrences:
            resolve_pointer(self.raw_alert, occurrence.raw_pointer)
        for relation in self.relations:
            if {relation.source_entity_id, relation.target_entity_id} - set(self.entity_ids):
                raise ValueError("relation references absent alert entities")
            # Cross-alert lineage is permitted, but only the owning record can be
            # resolved locally; a supplied alerts context resolves the other side.
            for p in relation.raw_pointers:
                if p.alert_id == self.alert_id:
                    resolve_pointer(self.raw_alert, p.pointer)
                elif info.context and "alerts" in info.context:
                    check_evidence([p], info.context["alerts"].keys(), info)
        return self


class Entity(DomainModel):
    entity_id: EntityID
    type: EntityType
    value: Text
    scope: Text
    display_value: Text
    alert_ids: Annotated[ids(AlertID), Field(min_length=1)]

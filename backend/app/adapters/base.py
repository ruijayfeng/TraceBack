"""Source settings, record isolation and generic JSON batch ingress."""

from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Iterable

from pydantic import ValidationError

from app.config import EffectiveConfig, MappingConflict, resolve_mapping
from app.models import CanonicalAlert, Category, FieldProvenance, Severity, SourceType
from app.models.base import resolve_pointer
from app.entities.normalization import file_path, hostname, integer, ip, text, timestamp, url
from app.utils.stable_id import id_for, nfc, raw_fingerprint
from .truth import reject_truth


@dataclass(frozen=True)
class AdapterSettings:
    """Internal deployment input, preserved in the effective run snapshot.

    Does not extend AlgorithmConfig, Mapping v1 or a frozen domain Schema.
    """
    source_namespace: str
    format_profile: str
    generator: str
    generator_version: str = "unknown"
    dataset_version: int | None = None
    epoch_unit: str | None = None
    network_namespace: str | None = None
    asset_namespace: str | None = None
    account_realm: str | None = None
    session_scope: str | None = None
    os_type: str | None = None
    semantic_profile: str | None = None
    extraction_contract: str = 'front-data-v1'
    identity_authorities: dict | None = None

    def __post_init__(self):
        from app.entities.identity_contracts import IdentityAuthorities
        object.__setattr__(self, 'identity_authorities', IdentityAuthorities.model_validate(
            self.identity_authorities or {}).model_dump(mode='json', exclude_none=True))
        if self.extraction_contract not in ('front-data-v1', 'legacy-v1'):
            raise ValueError('invalid_extraction_contract')
        for name in ("source_namespace", "format_profile", "generator", "generator_version"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ValueError("missing_source_setting:" + name)
            object.__setattr__(self, name, nfc(getattr(self, name)))
        for name in ("network_namespace", "asset_namespace", "account_realm", "session_scope"):
            value = getattr(self, name)
            if value is not None:
                if type(value) is not str or not value:
                    raise ValueError("invalid_source_setting:" + name)
                object.__setattr__(self, name, nfc(value))
        if self.dataset_version is not None and (type(self.dataset_version) is not int or self.dataset_version < 1):
            raise ValueError("invalid_dataset_version")
        if self.epoch_unit not in (None, "seconds", "milliseconds", "microseconds"):
            raise ValueError("invalid_epoch_unit")
        if self.os_type not in (None, "windows", "linux"):
            raise ValueError("invalid_os_type")
        if self.semantic_profile not in (None, "wazuh_local_v1"):
            raise ValueError("invalid_semantic_profile")
        if self.semantic_profile and self.format_profile != "wazuh_json_v1":
            raise ValueError("semantic_profile_requires_wazuh")

    @property
    def identity_contract(self):
        from app.entities.identity_contracts import IdentityAuthorities
        return IdentityAuthorities.model_validate(self.identity_authorities)

    def snapshot(self):
        data = asdict(self)
        if not self.identity_authorities:
            data.pop('identity_authorities', None)
        if self.semantic_profile is None:
            data.pop("semantic_profile")
        return data


@dataclass(frozen=True)
class RejectedRecord:
    source_namespace: str
    reason: str
    record_fingerprint: str | None


@dataclass
class BatchResult:
    input_count: int = 0
    accepted_count: int = 0
    alerts: list[CanonicalAlert] = field(default_factory=list)
    rejected: list[RejectedRecord] = field(default_factory=list)
    duplicate_import_count: int = 0

    @property
    def rejection_reasons(self):
        return dict(sorted(Counter(r.reason for r in self.rejected).items()))


class AlertAdapter(ABC):
    def __init__(self, config: EffectiveConfig, settings: AdapterSettings):
        self.config = config
        self.settings = settings
        self.normalization = config.algorithm.normalization
        self.mappings = config.mapping_files

    @abstractmethod
    def extract(self, raw: dict) -> tuple[dict, dict, dict]:
        """Return facts, their raw pointers and controlled vendor context."""

    def convert(self, raw: dict) -> CanonicalAlert:
        if type(raw) is not dict or not raw:
            raise ValueError("invalid_record_structure")
        reject_truth(raw)
        facts, pointers, context = self.extract(raw)
        from app.entities.context import project_candidates
        facts['context_candidates'] = project_candidates(raw, self.settings)
        facts['source_product'] = text(raw.get('source_product')) or text(raw.get('product')) or self.settings.generator
        facts['title'] = text(raw.get('title')) or text(facts.get('signature'))
        if raw.get('source_product') or raw.get('product'):
            pointers['source_product'] = '/source_product' if raw.get('source_product') else '/product'
        else:
            facts['metadata_provenance'] = {'source_product': 'adapter_settings.generator'}
        if facts['title'] is not None:
            pointers['title'] = '/title' if raw.get('title') else pointers['signature']
        facts["source_namespace"] = self.settings.source_namespace
        for name in ("source_record_id", "origin_namespace", "origin_record_id"):
            if name in facts:
                facts[name] = text(facts[name])
        facts["raw_alert"] = raw
        facts["raw_fingerprint"] = raw_fingerprint(raw)
        # Identity is fixed after source/time parsing, before derived mappings.
        facts["alert_id"] = id_for("CanonicalAlert", facts)
        transforms = {name: "adapter-v1:" + self.settings.format_profile for name in pointers}
        metadata = json.dumps(self.settings.snapshot(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        transforms["source_type"] += ":" + metadata
        transforms["timestamp"] += ":timezone=" + str(self.normalization.source_timezones.get(self.settings.source_namespace)) + ":epoch_unit=" + str(self.settings.epoch_unit)
        for name in pointers:
            if name.endswith('.start_time'):
                transforms[name] += ':timezone=' + str(self.normalization.source_timezones.get(self.settings.source_namespace))
        for name in ("src_ip", "dst_ip"):
            if name in facts:
                facts[name] = ip(facts[name])
                transforms[name] += ":ip-canonical-v1"
        for name in ("src_port", "dst_port"):
            if name in facts and facts[name] is not None and facts[name] != "":
                try:
                    facts[name] = integer(facts[name], maximum=65535)
                except ValueError as exc:
                    raise ValueError("invalid_port") from exc
            elif name in facts:
                facts[name] = None
        for name in ("host", "domain"):
            if name in facts:
                facts[name] = hostname(facts[name], self.normalization.host_aliases if name == "host" else None)
                transforms[name] += ":dns-case-alias-v1"
        if "url" in facts:
            facts["url"] = url(facts["url"])
            transforms["url"] += ":url-conservative-v1"
        for name in ("sensor", "source_record_id", "rule_id", "alert_type", "signature", "account", "session", "file", "command", "origin_namespace", "origin_record_id"):
            if name in facts:
                facts[name] = text(facts[name])
        if "file" in facts:
            facts["file"] = file_path(facts["file"], self.settings.os_type)
        context.update({name: value.value if hasattr(value, "value") else value for name, value in facts.items()
                        if name not in ("raw_alert", "field_provenance")})
        for kind, enum in (("category", Category), ("severity", Severity)):
            selected = [m for m in self.mappings["normalization." + kind + "_mapping_files"]
                        if m.source_type == facts["source_type"].value]
            if not selected:
                raise ValueError("missing_" + kind + "_mapping")
            resolutions = [resolve_mapping(m, context, category_priority=self.normalization.category_priority) for m in selected]
            outputs = {r.output for r in resolutions if r.matched_rule_ids}
            if not outputs:
                outputs = {r.output for r in resolutions}
            if kind == "category":
                output = min(outputs, key=self.normalization.category_priority.index)
            elif len(outputs) != 1:
                raise MappingConflict("severity: conflicting mapping files")
            else:
                output = outputs.pop()
            facts[kind] = enum(output)
            pointers[kind] = ""  # Whole alert binds the controlled context and all rule hits.
            transforms[kind] = "mapping-v1:" + json.dumps([
                {"digest": r.mapping_digest, "rule_ids": list(r.matched_rule_ids)} for r in resolutions
            ], sort_keys=True, separators=(",", ":"))
        facts["field_provenance"] = {name: FieldProvenance(raw_pointer=pointer, transform=transforms[name])
                                     for name, pointer in pointers.items() if name not in facts or facts[name] is not None}
        return CanonicalAlert(**facts)

    def parse_time(self, value):
        return timestamp(value, source_timezone=self.normalization.source_timezones.get(self.settings.source_namespace),
                         epoch_unit=self.settings.epoch_unit)

    def batch(self, records: Iterable, *, alert_store=None) -> BatchResult:
        result = BatchResult()
        seen = {} if alert_store is None else alert_store
        for raw in records:
            result.input_count += 1
            try:
                alert = self.convert(raw)
            except MappingConflict:
                raise  # An invalid configuration cannot be disguised as a bad input record.
            except (ValueError, TypeError, KeyError, OverflowError) as exc:
                reason = "schema_violation" if isinstance(exc, ValidationError) else str(exc)
                if not reason or len(reason) > 100:
                    reason = "invalid_record_structure"
                # Only a digest is retained; quarantined annotations are never propagated.
                try:
                    fingerprint = raw_fingerprint(raw) if isinstance(raw, (dict, str)) else None
                except ValueError:
                    fingerprint = None
                result.rejected.append(RejectedRecord(self.settings.source_namespace, reason, fingerprint))
                continue
            result.accepted_count += 1
            if alert.alert_id in seen:
                result.duplicate_import_count += 1
                if seen[alert.alert_id].canonical_json() != alert.canonical_json():
                    raise ValueError("same_alert_id_conflicting_content")
            else:
                if alert_store is None:
                    seen[alert.alert_id] = alert
                else:
                    alert_store.add(alert)
        result.alerts = [seen[k] for k in sorted(seen)] if alert_store is None else alert_store.sequence()
        result.rejected.sort(key=lambda r: (r.source_namespace, r.reason, r.record_fingerprint or ""))
        return result

    def read_file(self, path: str | Path, *, alert_store=None) -> BatchResult:
        path = Path(path).resolve()
        if path.suffix.lower() not in (".json", ".jsonl", ".ndjson") or any(
            part.lower() == "evaluation" for part in path.parts
        ):
            raise ValueError("input_path_not_security_alert")
        def records():
            with path.open(encoding="utf-8-sig") as handle:
                first = handle.read(1)
                handle.seek(0)
                if first == "[":
                    if alert_store is not None:
                        from app.services.capacity import json_array_records
                        yield from json_array_records(handle)
                        return
                    try:
                        value = json.load(handle)
                    except ValueError:
                        yield "invalid JSON array"
                        return
                    yield from value
                else:
                    for line in handle:
                        if line.strip():
                            try:
                                yield json.loads(line)
                            except ValueError:
                                yield line
        return self.batch(records(), alert_store=alert_store) if alert_store is not None else self.batch(records())


def pick(raw, facts, pointers, name, *paths):
    for path in paths:
        try:
            value = resolve_pointer(raw, path)
        except ValueError:
            continue
        if value is not None and value != "":
            facts[name], pointers[name] = value, path
            return value
    return None

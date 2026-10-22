"""Independent audit contracts; CanonicalAlert and raw evidence stay unchanged."""
from dataclasses import dataclass
from enum import Enum
import gzip
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.utils.stable_id import raw_fingerprint


class NoiseReason(str, Enum):
    KEEP = 'KEEP'
    DUPLICATE_NOISE = 'DUPLICATE_NOISE'
    KNOWN_BACKGROUND_NOISE = 'KNOWN_BACKGROUND_NOISE'
    INVALID_FOR_RECONSTRUCTION = 'INVALID_FOR_RECONSTRUCTION'


class NoiseAuditRecord(BaseModel):
    model_config = ConfigDict(extra='forbid')
    input_index: int = Field(ge=0)
    alert_id: str
    keep: bool
    reason_code: NoiseReason
    rule_id: str | None = None
    evidence: dict[str, Any]
    representative_alert_id: str | None = None
    duplicate_group_id: str | None = None
    duplicate_count: int | None = Field(default=None, ge=2)
    raw_fingerprint: str
    raw_evidence_ref: str

    @model_validator(mode='after')
    def coherent(self):
        if self.keep != (self.reason_code == NoiseReason.KEEP):
            raise ValueError('noise_decision_reason_mismatch')
        if not self.keep and not self.rule_id:
            raise ValueError('removed_alert_requires_rule')
        if self.reason_code == NoiseReason.DUPLICATE_NOISE and not (
                self.representative_alert_id and self.duplicate_group_id and self.duplicate_count):
            raise ValueError('duplicate_requires_representative_and_group')
        return self


@dataclass
class NoiseFilterResult:
    original_alerts: list
    kept_alerts: list
    audit_records: list[NoiseAuditRecord]
    statistics: dict
    config_snapshot: dict
    config_hash: str

    def raw_evidence(self, record):
        """Resolve against the complete input archive, including removed alerts."""
        original = self.original_alerts[record.input_index]
        if (original.alert_id != record.alert_id or original.raw_fingerprint != record.raw_fingerprint
                or raw_fingerprint(original.raw_alert) != record.raw_fingerprint):
            raise ValueError('noise_audit_archive_mismatch')
        return original.raw_alert


def resolve_raw_evidence(archive_path, record):
    """Resolve the zero-based record in a persisted noise_source_alerts archive.

    Read plain JSON so even a structurally invalid CanonicalAlert retains a
    usable raw payload. The archive hash is additionally sealed by its manifest.
    """
    record = NoiseAuditRecord.model_validate(record)
    with gzip.open(archive_path, 'rt', encoding='utf8') as stream:
        for i, line in enumerate(stream):
            if i == record.input_index:
                original = json.loads(line)
                if (original['alert_id'] != record.alert_id or original['raw_fingerprint'] != record.raw_fingerprint
                        or raw_fingerprint(original['raw_alert']) != record.raw_fingerprint):
                    raise ValueError('noise_audit_archive_mismatch')
                return original['raw_alert']
    raise ValueError('noise_audit_archive_record_missing')

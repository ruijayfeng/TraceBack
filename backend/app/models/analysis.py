"""Analysis snapshot metadata and the isolated evaluation summary whitelist."""

from typing import Annotated, Literal
from pydantic import Field, model_validator

from app.utils.stable_id import content_digest
from .base import (AlertID, AnalysisID, Digest, DomainModel, Json, NonNegative, NonNegativeInt,
                   Number, StrictModel, Text, ids)
from .enums import AnalysisStatus


class AnalysisMetrics(StrictModel):
    alert_count: NonNegativeInt
    representative_count: NonNegativeInt
    candidate_pair_count: NonNegativeInt
    candidate_dropped_count: NonNegativeInt
    correlation_runtime_seconds: NonNegative
    clustering_runtime_seconds: NonNegative
    chain_runtime_seconds: NonNegative
    total_runtime_seconds: NonNegative
    peak_memory_mb: NonNegative


class AnalysisRecord(DomainModel):
    analysis_id: AnalysisID
    input_alert_ids: Annotated[ids(AlertID), Field(min_length=1)]
    config_hash: Digest
    config_snapshot: dict[Text, Json]
    algorithm_version: Text
    dataset_digest: Digest
    config_digest: Digest
    mapping_digest: Digest
    diagnostics_ref: Text
    frequency_snapshot_ref: Text
    is_complete: bool
    incomplete_reason: Text | None
    status: AnalysisStatus = AnalysisStatus.QUEUED
    candidate_truncated: bool = False
    errors: list[Text] = Field(default_factory=list)
    metrics: AnalysisMetrics

    @model_validator(mode="after")
    def snapshot_contract(self):
        if self.config_hash != self.config_digest or self.config_hash != content_digest(self.config_snapshot):
            raise ValueError("config_hash/config_digest must match the effective config snapshot")
        for field, filename in (("diagnostics_ref", "diagnostics.jsonl"), ("frequency_snapshot_ref", "frequency_snapshot.json")):
            if getattr(self, field) != f"outputs/analyses/{self.analysis_id}/{filename}":
                raise ValueError("analysis file reference must be in the fixed analysis directory")
        ended_badly = self.status in (AnalysisStatus.FAILED, AnalysisStatus.INCOMPLETE)
        if ended_badly and (self.incomplete_reason is None or not self.errors):
            raise ValueError("failed/incomplete analysis requires reason and errors")
        if not ended_badly and self.incomplete_reason is not None:
            raise ValueError("unfinished/completed analysis requires null incomplete_reason")
        if self.is_complete != (self.status == AnalysisStatus.COMPLETED):
            raise ValueError("is_complete must agree with completed status")
        if self.candidate_truncated and (self.status != AnalysisStatus.INCOMPLETE or self.is_complete):
            raise ValueError("candidate truncation requires incomplete status")
        return self


class EvaluationSummaryExport(StrictModel):
    run_id: Text
    config_hash: Digest
    algorithm_version: Text
    split: Text
    metrics: dict[Text, Number | None]
    metric_status: dict[Text, Literal["available", "not_applicable", "unavailable"]]
    evaluation_coverage: Annotated[Number, Field(ge=0, le=1)]
    counts: dict[Text, int]
    runtime: dict[Text, Number]
    limitations: list[Text]

    @model_validator(mode="after")
    def export_contract(self):
        import re
        # Portable filename component only. The evaluation Task supplies its
        # manifest-derived hash convention; no new run-ID prefix is invented here.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", self.run_id):
            raise ValueError("run_id must be a safe filename component")
        if self.metrics.keys() != self.metric_status.keys():
            raise ValueError("each metric requires exactly one metric_status")
        for key, value in self.metrics.items():
            available = self.metric_status[key] == "available"
            if available != (value is not None):
                raise ValueError("available metrics require a number; other statuses require null")
        if any(v is None for v in self.metrics.values()) and not self.limitations:
            raise ValueError("null metrics require a limitation explaining unavailability/empty denominator")
        return self

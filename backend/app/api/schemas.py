"""API envelopes; domain fields remain the existing frozen v1 models."""

from typing import Annotated, Generic, Literal, TypeVar
from pydantic import BaseModel, ConfigDict, Field
from app.models import (AnalysisMetrics, AttackChain, CanonicalAlert, ChainEdge, CorrelationEdge,
                        Entity, Incident)
from app.models.base import AnalysisID, Json, UTCDateTime
from app.models.enums import AnalysisStatus, SourceType
from app.services.storage import RunAnalysisRecord


class Transport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class InputReference(Transport):
    source: Literal["wazuh", "aminer"]
    source_ref: Annotated[str, Field(min_length=1)]
    path: Annotated[str, Field(min_length=1)]


class CreateAnalysis(Transport):
    inputs: Annotated[list[InputReference], Field(min_length=1)]
    config_version: Annotated[str, Field(min_length=1)]


class AnalysisAccepted(Transport):
    analysis_id: AnalysisID
    status: AnalysisStatus


class APIError(Transport):
    detail: str


class AnalysisDetail(Transport):
    analysis_id: AnalysisID
    status: AnalysisStatus
    is_complete: bool
    created_at: UTCDateTime
    started_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    config_hash: str
    config_digest: str
    mapping_digest: str
    config_snapshot: dict[str, Json]
    algorithm_version: str
    dataset_digest: str | None
    config_version: str
    inputs: list[InputReference]
    input_files: list[dict[str, Json]]
    counts: dict[str, int]
    runtime: dict[str, float]
    metrics: AnalysisMetrics
    errors: list[str]
    warnings: list[str]
    incomplete_reason: str | None
    candidate_contract_version: Literal["v1.1"] | None = None
    potential_pair_stats: dict[str, Json] | None = None
    candidate_admission_stats: dict[str, Json] | None = None
    policy_pruned_count: Annotated[int, Field(ge=0)] | None = None
    resource_truncated_count: Annotated[int, Field(ge=0)] | None = None
    admitted_candidate_count: Annotated[int, Field(ge=0)] | None = None
    scored_candidate_count: Annotated[int, Field(ge=0)] | None = None
    resource_truncation_events: list[str] | None = None
    candidate_truncated: bool
    state_history: list[AnalysisStatus]
    diagnostics_ref: str
    frequency_snapshot_ref: str
    manifest_ref: str
    grounding: dict[str, Json] | None = None
    dataset_metadata: dict[str, Json] | None = None
    correlation_v2: dict[str, Json] | None = None
    record: RunAnalysisRecord | None = None


T = TypeVar("T")


class Page(Transport, Generic[T]):
    items: list[T]
    page: Annotated[int, Field(ge=1)]
    page_size: Annotated[int, Field(ge=1, le=100)]
    total: Annotated[int, Field(ge=0)]


class AlertDetail(Transport):
    analysis_id: AnalysisID
    alert: CanonicalAlert
    entities: list[Entity]


class IncidentDetail(Transport):
    analysis_id: AnalysisID
    incident: Incident
    entities: list[Entity]
    chain_status: Literal["complete", "partial"]


class ChainDetail(Transport):
    analysis_id: AnalysisID
    chain: AttackChain
    diagnostics_ref: str


class TimelineItem(Transport):
    id: str
    kind: Literal["alert", "node"]
    alert_ids: list[str]
    node_id: str | None
    event_time: UTCDateTime
    end_time: UTCDateTime
    source_type: SourceType
    sensor: str | None


class EdgeDetail(Transport):
    analysis_id: AnalysisID
    edge: ChainEdge
    correlation_edges: list[CorrelationEdge]


class ExplainRequest(Transport):
    pass

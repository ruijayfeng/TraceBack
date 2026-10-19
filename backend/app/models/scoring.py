"""Stored seven-component scores and formula validation, not a scoring engine."""

from decimal import Decimal
from typing import Annotated
from pydantic import Field, ValidationInfo, model_validator, model_serializer
from app.utils.stable_id import content_digest

from .base import CorrelationID, Digest, NonNegative, OutputNumber, Score, StrictModel
from .enums import ReasonCode, SourceIndependence
from .correlation_v2 import EvidenceV2
from .correlation_v3 import EvidenceV3, EvidenceV4


COMPONENTS = ("time", "entity", "relation", "behavior", "source", "conflict", "duplicate")
POSITIVE_COMPONENTS = COMPONENTS[:5]
TOLERANCE = Decimal("0.00001")  # Frozen serialization/recalculation tolerance, not an algorithm parameter.


def close(left, right):
    return abs(Decimal(str(left)) - Decimal(str(right))) <= TOLERANCE


class ScoreWeights(StrictModel):
    time: NonNegative
    entity: NonNegative
    relation: NonNegative
    behavior: NonNegative
    source: NonNegative
    conflict: Annotated[NonNegative, Field(le=1)]
    duplicate: Annotated[NonNegative, Field(le=1)]

    @model_validator(mode="after")
    def sum_one(self):
        if abs(sum(Decimal(str(getattr(self, k))) for k in POSITIVE_COMPONENTS) - 1) > Decimal("1e-12"):
            raise ValueError("five positive weights must sum to one")
        return self


class ScoreContributions(StrictModel):
    time: Annotated[OutputNumber, Field(ge=0)]
    entity: Annotated[OutputNumber, Field(ge=0)]
    relation: Annotated[OutputNumber, Field(ge=0)]
    behavior: Annotated[OutputNumber, Field(ge=0)]
    source: Annotated[OutputNumber, Field(ge=0)]
    conflict: Annotated[OutputNumber, Field(le=0)]
    duplicate: Annotated[OutputNumber, Field(le=0)]


class ScoreBreakdown(StrictModel):
    time_score: Score
    entity_score: Score
    relation_score: Score
    behavior_score: Score
    source_score: Score
    source_independence: SourceIndependence
    conflict_penalty: Score
    duplicate_penalty: Score
    weights: ScoreWeights
    contributions: ScoreContributions
    raw_total: OutputNumber
    final_score: Score
    config_hash: Digest
    selected_correlation_edge_id: CorrelationID | None = None
    evidence_v2: EvidenceV2 | EvidenceV3 | EvidenceV4 | None = None

    @model_serializer(mode="wrap")
    def legacy_serialization(self, handler):
        data = handler(self)
        if self.evidence_v2 is None:
            data.pop("evidence_v2", None)
        return data

    @model_validator(mode="after")
    def recalculate(self, info: ValidationInfo):
        if self.source_independence != SourceIndependence.CONFIRMED_INDEPENDENT and self.source_score != 0:
            raise ValueError("unknown/same-origin source independence requires source_score=0")
        expected = {}
        for component in COMPONENTS:
            field = component + ("_penalty" if component in COMPONENTS[5:] else "_score")
            sign = -1 if component in COMPONENTS[5:] else 1
            expected[component] = sign * Decimal(str(getattr(self.weights, component))) * Decimal(str(getattr(self, field)))
            if not close(getattr(self.contributions, component), expected[component]):
                raise ValueError(f"{component} contribution differs from signed weight × raw value")
        raw = sum(expected.values())
        if self.evidence_v2 is not None:
            v = self.evidence_v2
            if any(not close(v.family_weights[k], getattr(self.weights, k)) for k in POSITIVE_COMPONENTS):
                raise ValueError("v2 family weights differ from configuration weights")
            raw = Decimal(str(v.quality_factor))*Decimal(str(v.normalized_quality)) + Decimal(str(v.mass_factor))*Decimal(str(v.evidence_mass)) + expected["conflict"] + expected["duplicate"]
            if v.threshold_passed != (self.final_score >= v.threshold) and abs(self.final_score-v.threshold) > float(TOLERANCE):
                raise ValueError("v2 threshold decision differs from final score")
        if not close(self.raw_total, raw):
            raise ValueError("raw_total differs from the versioned scoring formula")
        if self.evidence_v2 is None and not close(self.raw_total, sum(self.contributions.model_dump().values())):
            raise ValueError("raw_total differs from the seven signed contributions")
        if not close(self.final_score, max(Decimal(0), min(Decimal(1), raw))):
            raise ValueError("final_score differs from clamped raw_total")
        if info.context and "config_hash" in info.context and self.config_hash != info.context["config_hash"]:
            raise ValueError("score config_hash differs from supplied configuration")
        if info.context and "score_weights" in info.context:
            weights = ScoreWeights.model_validate(info.context["score_weights"])
            if self.weights != weights:
                raise ValueError("score weights differ from supplied configuration")
        if info.context and "config_snapshot" in info.context:
            snapshot = info.context["config_snapshot"]
            if self.config_hash != content_digest(snapshot):
                raise ValueError("score config_hash differs from supplied configuration snapshot")
            if self.weights != ScoreWeights.model_validate(snapshot["score"]["weights"]):
                raise ValueError("score weights differ from supplied configuration snapshot")
        return self


def check_source_reasons(breakdown, reasons):
    source_reasons = [r for r in reasons if r.code == ReasonCode.SOURCE_COMPLEMENT]
    if (breakdown.source_independence != SourceIndependence.UNKNOWN or breakdown.source_score > 0) and not source_reasons:
        raise ValueError("confirmed source state requires a source_complement reason")
    for reason in source_reasons:
        if reason.params["source_independence"] != breakdown.source_independence.value:
            raise ValueError("source_complement and breakdown independence states differ")
        if breakdown.source_score > 0:
            if len(reason.params["sensor_names"]) == 1:
                raise ValueError("same sensor cannot receive source complement reward")
            if not any(r.code in (ReasonCode.SHARED_ENTITY, ReasonCode.EXPLICIT_RELATION) for r in reasons):
                raise ValueError("source complement reward requires a context bridge")


def check_source_snapshot(breakdown, reasons, pair, info):
    """Validate recorded source facts against explicitly supplied pair records.

    No product-name heuristic confirms independence. Absence of origin data
    leaves confirmation to the recorded field/config basis, never a guess.
    """
    if not info.context or "alerts" not in info.context:
        return
    alerts = info.context["alerts"]
    data = []
    for aid in (pair.alert_id_src, pair.alert_id_dst):
        if aid not in alerts:
            raise ValueError("support_pair alert is absent from supplied snapshot")
        alert = alerts[aid]
        data.append(alert.model_dump(mode="json") if hasattr(alert, "model_dump") else alert)
    left, right = data
    source_types = {left["source_type"], right["source_type"]}
    sensors = {v["sensor"] for v in data if v.get("sensor") is not None}
    for reason in reasons:
        if reason.code == ReasonCode.SOURCE_COMPLEMENT:
            if set(reason.params["source_types"]) != source_types or set(reason.params["sensor_names"]) != sensors:
                raise ValueError("source_complement facts differ from actual support_pair sources/sensors")
    if left.get("sensor") is not None and left.get("sensor") == right.get("sensor") and breakdown.source_score > 0:
        raise ValueError("same sensor in the support_pair cannot receive a source reward")
    def origin_key(alert):
        if alert.get("origin_namespace") is not None and alert.get("origin_record_id") is not None:
            return (alert["origin_namespace"], alert["origin_record_id"])
        if alert.get("source_namespace") is not None and alert.get("source_record_id") is not None:
            return (alert["source_namespace"], alert["source_record_id"])
        return None
    origin = origin_key(left)
    if origin is not None and origin == origin_key(right) and breakdown.source_independence != SourceIndependence.CONFIRMED_SAME_ORIGIN:
        raise ValueError("confirmed same origin takes precedence over other source states")

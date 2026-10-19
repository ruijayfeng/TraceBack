"""Optional versioned evidence audit; legacy seven-component scores stay readable."""

import math
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .base import EntityID, NonNegative, NonNegativeInt, Number, Text, StrictModel, ids


Availability = Literal["AVAILABLE_MATCH", "AVAILABLE_MISMATCH", "UNAVAILABLE", "NOT_APPLICABLE"]
Family = Literal["time", "entity", "relation", "behavior", "source"]
Unit = Annotated[Number, Field(ge=0, le=1)]


class EvidenceDimension(StrictModel):
    dimension: Text
    family: Family
    state: Availability
    weight: NonNegative
    strength: Unit
    entity_ids: ids(EntityID) = Field(default_factory=list)

    @model_validator(mode="after")
    def observable(self):
        if self.state != "AVAILABLE_MATCH" and self.strength != 0:
            raise ValueError("non-matching dimensions cannot have positive strength")
        return self


class EvidenceV2(StrictModel):
    version: Literal["v2"] = "v2"
    quality_factor: Unit
    mass_factor: Unit
    family_weights: dict[Family, NonNegative]
    family_strengths: dict[Family, Unit]
    dimensions: list[EvidenceDimension]
    available_weight: NonNegative
    matched_weight: NonNegative
    total_configured_weight: NonNegative
    normalized_quality: Unit
    evidence_mass: Unit
    available_evidence: list[Text]
    matched_evidence: list[Text]
    mismatched_evidence: list[Text]
    unavailable_evidence: list[Text]
    not_applicable_evidence: list[Text]
    strong_evidence_count: NonNegativeInt
    supporting_evidence_count: NonNegativeInt
    evidence_gate_passed: bool
    gate_reason: Text
    threshold: Unit
    threshold_passed: bool
    decision: Literal["ACCEPT", "REJECT_LOW_SCORE", "REJECT_INSUFFICIENT_EVIDENCE", "REJECT_GUARD", "REJECT_NO_RELATION"]

    @model_validator(mode="after")
    def recalculate(self):
        keys = {"time", "entity", "relation", "behavior", "source"}
        if set(self.family_weights) != keys or set(self.family_strengths) != keys:
            raise ValueError("v2 requires all five evidence families")
        def close(a, b):
            return abs(a-b) <= .00001  # Existing six-decimal round-trip tolerance.
        if not close(self.quality_factor + self.mass_factor, 1):
            raise ValueError("v2 factors must sum to one")
        names = [d.dimension for d in self.dimensions]
        if len(set(names)) != len(names) or names != sorted(names):
            raise ValueError("v2 dimensions must be unique and sorted")
        available = []
        for family in sorted(keys):
            dims = [d for d in self.dimensions if d.family == family and d.state.startswith("AVAILABLE")]
            denominator = math.fsum(d.weight for d in dims)
            strength = (max((d.strength for d in dims), default=0) if family == "relation" else
                        math.fsum(d.weight*d.strength for d in dims)/denominator if denominator else 0)
            if not close(self.family_strengths[family], strength):
                raise ValueError("v2 family strength differs from its observable dimensions")
            if denominator:
                available.append(family)
        aw = math.fsum(self.family_weights[k] for k in available)
        mw = math.fsum(self.family_weights[k]*self.family_strengths[k] for k in available)
        tw = math.fsum(self.family_weights.values())
        if not close(tw, 1) or not close(self.total_configured_weight, tw) or not close(self.available_weight, aw) or not close(self.matched_weight, mw):
            raise ValueError("v2 evidence weight totals differ")
        if not close(self.normalized_quality, mw/aw if aw else 0) or not close(self.evidence_mass, mw/tw if tw else 0):
            raise ValueError("v2 quality/mass differ from weights")
        for field, predicate in (
            ("available_evidence", lambda d: d.state.startswith("AVAILABLE")),
            ("matched_evidence", lambda d: d.state == "AVAILABLE_MATCH"),
            ("mismatched_evidence", lambda d: d.state == "AVAILABLE_MISMATCH"),
            ("unavailable_evidence", lambda d: d.state == "UNAVAILABLE"),
            ("not_applicable_evidence", lambda d: d.state == "NOT_APPLICABLE")):
            if getattr(self, field) != [d.dimension for d in self.dimensions if predicate(d)]:
                raise ValueError("v2 availability partition differs from dimensions")
        if not self.evidence_gate_passed and self.decision == "ACCEPT":
            raise ValueError("insufficient evidence cannot be accepted")
        return self

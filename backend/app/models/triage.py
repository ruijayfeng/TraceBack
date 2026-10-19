"""Deterministic SOC triage, independent of pair correlation and fact severity."""

from typing import Annotated, Literal
from pydantic import Field, model_validator

from .alerts import EvidencePointer
from .base import AlertID, Json, NonNegative, NonNegativeInt, Score, StrictModel, Text


class RiskReason(StrictModel):
    field: Literal["severity", "category", "rarity"]
    value: Json
    strength: Score
    weight: NonNegative
    contribution: NonNegative
    message: Text
    evidence_refs: Annotated[list[EvidencePointer], Field(min_length=1)]


class SingleAlertTriage(StrictModel):
    version: Literal["v2"] = "v2"
    alert_id: AlertID
    description: Text
    single_alert_risk_score: Score
    risk_level: Literal["unknown", "low", "medium", "high", "critical"]
    recommended_priority: Literal["UNRATED", "P4", "P3", "P2", "P1"]
    available_weight: NonNegative
    matched_weight: NonNegative
    rarity_only_cap: Score
    risk_reasons: list[RiskReason]
    evidence_refs: list[EvidencePointer]
    unavailable_evidence: list[Literal["severity", "category", "rarity"]]
    candidate_count: NonNegativeInt
    gate_passed_count: NonNegativeInt
    formal_edge_count: NonNegativeInt
    rejection_counts: dict[Text, NonNegativeInt]
    correlation_diagnostic: Text
    search_complete: bool

    @model_validator(mode="after")
    def closed(self):
        priority = {"unknown":"UNRATED", "low":"P4", "medium":"P3", "high":"P2", "critical":"P1"}
        if self.recommended_priority != priority[self.risk_level]:
            raise ValueError("triage priority differs from risk level")
        refs = [p for r in self.risk_reasons for p in r.evidence_refs]
        if any(p.alert_id != self.alert_id for p in refs + self.evidence_refs):
            raise ValueError("triage pointer belongs to another alert")
        keys = lambda values: sorted({(p.alert_id, p.pointer, p.side) for p in values})
        if keys(refs) != keys(self.evidence_refs):
            raise ValueError("triage evidence closure differs")
        aw = sum(r.weight for r in self.risk_reasons)
        mw = sum(r.contribution for r in self.risk_reasons)
        if abs(aw-self.available_weight) > .00001 or abs(mw-self.matched_weight) > .00001:
            raise ValueError("triage weight totals differ")
        if any(abs(r.contribution-r.weight*r.strength) > .00001 for r in self.risk_reasons):
            raise ValueError("triage contribution differs")
        score = mw/aw if aw else 0.0
        if self.risk_reasons and all(r.field == "rarity" for r in self.risk_reasons):
            score = min(score, self.rarity_only_cap)
        if abs(score-self.single_alert_risk_score) > .00001:
            raise ValueError("triage risk score differs")
        return self

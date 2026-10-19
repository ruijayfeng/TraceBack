"""Versioned independence audit in the existing scoring extension slot."""

from typing import Literal
import math
from pydantic import model_validator, model_serializer
from .base import Text, AlertID, EntityID, NonNegativeInt, StrictModel, ids
from .correlation_v2 import EvidenceV2, Unit
from .alerts import EvidencePointer


EvidenceFamily = Literal['ENTITY_IDENTITY', 'NETWORK_FLOW', 'TEMPORAL', 'HOST_CONTEXT',
    'ACCOUNT_CONTEXT', 'PROCESS_CONTEXT', 'RESOURCE_CONTEXT', 'BEHAVIOR_SEMANTIC', 'RULE_METADATA', 'SOURCE_CONTEXT']


class EvidenceFact(StrictModel):
    family: EvidenceFamily
    fact_key: Text
    dimension: Text
    role: Literal['primary', 'supporting']
    strength: Unit
    entity_ids: list[EntityID]
    evidence_refs: list[EvidencePointer]
    source_alert_ids: ids(AlertID) | None = None
    observation_ids: list[Text] | None = None

    @model_validator(mode='after')
    def provenance(self):
        if (self.source_alert_ids is None) != (self.observation_ids is None):
            raise ValueError('fact provenance must include both alerts and observations')
        if self.observation_ids is not None:
            if not self.source_alert_ids or not self.observation_ids or self.observation_ids != sorted(set(self.observation_ids)):
                raise ValueError('fact provenance must be nonempty and deterministic')
            if any(p.alert_id not in self.source_alert_ids for p in self.evidence_refs):
                raise ValueError('fact pointers outside source alerts')
        return self

    @model_serializer(mode='wrap')
    def legacy(self, handler):
        data = handler(self)
        for name in ('source_alert_ids','observation_ids'):
            if data[name] is None:
                data.pop(name)
        return data


class EntityReliability(StrictModel):
    entity_id: EntityID
    frequency: NonNegativeInt
    population: NonNegativeInt
    rarity: Unit
    reliability: Unit
    role_factor: Unit
    descriptor_factor: Unit
    hot: bool


class EvidenceV3(EvidenceV2):
    version: Literal['v3'] = 'v3'
    evidence: list[EvidenceFact]
    evidence_families: list[EvidenceFamily]
    primary_evidence: list[Text]
    supporting_evidence: list[Text]
    applicable_evidence_families: list[EvidenceFamily]
    entity_reliability: list[EntityReliability]
    duplicate_observation_risk: bool
    metadata_dominated: bool
    network_continuity_valid: bool
    network_diagnostic: Text
    relation_support: list[Text]
    suppressed_dimensions: list[Text]
    reliability_floor: Unit
    frequency_population_floor: NonNegativeInt
    rarity_floor: Unit

    @model_validator(mode='after')
    def independent(self):
        keys = [f.fact_key for f in self.evidence]
        if len(keys) != len(set(keys)):
            raise ValueError('v3 cannot count a fact more than once')
        if self.evidence_families != sorted({f.family for f in self.evidence}):
            raise ValueError('v3 family list differs from evidence')
        for role, field in (('primary', 'primary_evidence'), ('supporting', 'supporting_evidence')):
            if getattr(self, field) != sorted(f.fact_key for f in self.evidence if f.role == role):
                raise ValueError('v3 evidence role partition differs')
        if any(f.dimension not in self.matched_evidence for f in self.evidence):
            raise ValueError('v3 evidence must reference a matching dimension')
        dimensions = {d.dimension: d for d in self.dimensions}
        if any(abs(f.strength-dimensions[f.dimension].strength) > .00001 for f in self.evidence):
            raise ValueError('v3 fact strength differs from dimension')
        for row in self.entity_reliability:
            if row.population < 1 or row.frequency > row.population:
                raise ValueError('v3 invalid representative frequency')
            population = max(row.population, self.frequency_population_floor)
            rarity = max(self.rarity_floor, math.log((population+1)/(row.frequency+1))/math.log(population+1))
            strength = (self.reliability_floor+(1-self.reliability_floor)*rarity)*row.role_factor*row.descriptor_factor
            if abs(rarity-row.rarity) > .00001 or abs(strength-row.reliability) > .00001:
                raise ValueError('v3 entity reliability differs from frozen frequency formula')
        if self.strong_evidence_count != len(self.primary_evidence) or self.supporting_evidence_count != len(self.supporting_evidence):
            raise ValueError('v3 evidence counts differ from facts')
        if self.network_continuity_valid != ('topology.network_continuity' in self.matched_evidence):
            raise ValueError('v3 network validity differs from matching dimension')
        if self.decision == 'ACCEPT' and (not self.primary_evidence or self.duplicate_observation_risk or self.metadata_dominated):
            raise ValueError('v3 accepted edge requires independent primary evidence')
        return self


class EvidenceV4(EvidenceV3):
    """Additive audit version; identical shape, explicit v4 execution recipe."""
    version: Literal['v4'] = 'v4'

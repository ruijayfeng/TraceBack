"""Independent V5 score contract; never reinterprets historical breakdowns."""
from typing import Literal
from pydantic import Field, ValidationInfo, model_validator
from .base import StrictModel, Digest, Score, OutputNumber, CorrelationID, Text, EntityID
from .alerts import EvidencePointer
from .correlation_v2 import Unit
from .enums import SourceIndependence
from .scoring import ScoreWeights, ScoreContributions, close


class V5Feature(StrictModel):
    name: Text
    family: Literal['time','entity','relation','behavior','source','conflict']
    state: Literal['SUPPORTED','UNOBSERVABLE','OBSERVED_ZERO','CONTRADICTED',
                   'MISSING','OBSERVED_NEUTRAL','OBSERVED_SUPPORT','OBSERVED_CONTRADICTION']
    strength: Unit
    reliability: Unit
    role: Literal['generic','host','account','endpoint','direct','flow']
    hot: bool
    entity_ids: list[EntityID]
    provenance: list[EvidencePointer]

    @model_validator(mode='after')
    def valid_state(self):
        if (self.state in {'SUPPORTED','OBSERVED_SUPPORT'}) != (self.strength>0):
            raise ValueError('V5 feature state/strength mismatch')
        return self


class V5Gate(StrictModel):
    passed: bool
    hard_contradiction: bool
    duplicate_observation: bool
    non_temporal_support: bool


class ScoreBreakdownV5(StrictModel):
    schema_version: Literal['5.0','5.1'] = '5.0'
    algorithm_version: Literal['alert-correlation-v5-f3-independent-support-v1','alert-correlation-v5-evidence-semantics-v1']
    implementation_version: Literal['v5-formula-f3-v1','v5-evidence-semantics-v1']
    config_hash: Digest
    mapping_digest: Digest
    features: list[V5Feature]
    policy: dict
    group_support: dict[str,Unit]
    direct_support: Unit
    evidence_mass: Unit
    quality: Unit
    temporal_factor: Unit
    positive_support: Unit
    conflict_penalty: Unit
    duplicate_penalty: Unit
    raw_total: OutputNumber
    final_score: Score
    duplicate: Unit
    weak_only: bool
    gate: V5Gate
    threshold: Unit
    threshold_passed: bool
    source_independence: SourceIndependence
    # Legacy raw components are explicitly an audit, not the V5 formula.
    legacy_audit: dict
    selected_correlation_edge_id: CorrelationID | None = None

    @property
    def evidence_v2(self):
        return None

    @property
    def source_score(self):
        return self.legacy_audit['values']['source']

    @property
    def weights(self):
        return ScoreWeights.model_validate(self.legacy_audit['weights'])

    @model_validator(mode='after')
    def recalculate(self,info:ValidationInfo):
        from app.correlation.formula_v5 import aggregate, identity
        from app.config import EvidenceV5Config
        policy=EvidenceV5Config.model_validate(self.policy).model_dump()
        expected_identity=identity(policy)
        if (self.algorithm_version,self.implementation_version)!=expected_identity:
            raise ValueError('V5 formula identity mismatch')
        semantic=policy['formula']=='evidence-semantics-v1'
        if self.schema_version!=('5.1' if semantic else '5.0'):
            raise ValueError('V5 schema/formula mismatch')
        states=({'MISSING','UNOBSERVABLE','OBSERVED_NEUTRAL','OBSERVED_SUPPORT','OBSERVED_CONTRADICTION'} if semantic
                else {'SUPPORTED','UNOBSERVABLE','OBSERVED_ZERO','CONTRADICTED'})
        if any(f.state not in states for f in self.features): raise ValueError('V5 state vocabulary mismatch')
        expected=aggregate([f.model_dump(mode='json') for f in self.features],policy,
            hard=self.gate.hard_contradiction,duplicate_risk=self.gate.duplicate_observation,duplicate=self.duplicate)
        for key,value in expected.items():
            actual=getattr(self,key)
            if key=='gate':
                actual=actual.model_dump()
            if isinstance(value,(dict,bool)):
                if actual!=value:raise ValueError('V5 recomputation mismatch:'+key)
            elif not close(actual,value):raise ValueError('V5 recomputation mismatch:'+key)
        if len({f.name for f in self.features})!=len(self.features):
            raise ValueError('duplicate V5 feature')
        if self.threshold_passed != (expected['final_score']>=self.threshold):
            raise ValueError('V5 threshold mismatch')
        if self.source_independence!=SourceIndependence.CONFIRMED_INDEPENDENT and self.source_score:
            raise ValueError('unconfirmed V5 source reward')
        if info.context and info.context.get('config_hash',self.config_hash)!=self.config_hash:
            raise ValueError('V5 config mismatch')
        if info.context and 'score_weights' in info.context and self.weights!=ScoreWeights.model_validate(info.context['score_weights']):
            raise ValueError('V5 audit weights mismatch')
        values=self.legacy_audit['values']
        weights=self.weights
        contributions=ScoreContributions.model_validate(self.legacy_audit['contributions'])
        for k,v in values.items():
            if not close(getattr(contributions,k),getattr(weights,k)*v*(-1 if k in {'conflict','duplicate'} else 1)):
                raise ValueError('V5 legacy audit mismatch')
        return self

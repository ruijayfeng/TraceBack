"""Explicit candidate schemas: never deserialize them as historical v1 edges."""
from typing import Literal
from pydantic import Field, model_validator
from app.models.base import StrictModel, AlertID, CorrelationID, EntityID, Digest
from app.models.correlation_v2 import Unit
from app.models import EvidencePointer
from . import ALGORITHM_VERSION


class TransitionRule(StrictModel):
    id: str
    from_: str = Field(alias='from')
    to: str
    strength: Unit
    contexts: list[Literal['IP','HOST','ACCOUNT','SESSION','PROCESS']]


class Policy(StrictModel):
    version: Literal['alert-correlation-v5-separation-direction-v1']
    schema_version: Literal['5.2-candidate']
    transition_ceiling: Unit
    weak_ceiling: Unit
    hot_min_count: int = Field(gt=0)
    hot_ratio: Unit
    direction_support: Unit
    direction_threshold: Unit
    direction_margin: Unit
    clock_skew_seconds: int = Field(ge=0)
    network_sources: list[str]
    category_classes: dict[str,str]
    wazuh_fields: dict[str,str]
    execution_types: list[str]
    resource_operations: list[str]
    auth_success: list[str]
    detector_tokens: dict[str,list[str]]
    flow_fields: dict[str,str]
    receive_actions: list[str]
    transitions: list[TransitionRule]
    diagnostic_operating_points: list[Unit]

    @model_validator(mode='after')
    def validate_policy(self):
        if set(self.wazuh_fields)!={'execution_type','operation','file','auth_status'}:
            raise ValueError('wazuh field contract')
        if set(self.flow_fields)!={'source_id','received_id','receive_action'}:
            raise ValueError('flow field contract')
        if len({t.id for t in self.transitions})!=len(self.transitions):raise ValueError('duplicate transition rule')
        for pointer in [*self.wazuh_fields.values(),*self.flow_fields.values()]:
            if not pointer.startswith('/') or any(x in pointer.casefold() for x in ('label','truth','stage','gold')):
                raise ValueError('non-observation policy pointer')
        return self


class DirectionEvidence(StrictModel):
    status: Literal['AMBIGUOUS_DIRECTION','DERIVED_VERIFIED_DIRECTION']
    source_alert_id: AlertID | None
    target_alert_id: AlertID | None
    forward_support: Unit
    reverse_support: Unit
    contradiction: bool
    direction_confidence: Unit
    forward_evidence: list[dict]
    reverse_evidence: list[dict]
    rejection_reason: str | None
    direction_reason: str
    semantic_scope: str

    @model_validator(mode='after')
    def evidence_invariants(self):
        accepted=self.status=='DERIVED_VERIFIED_DIRECTION'
        if accepted!=(self.source_alert_id is not None and self.target_alert_id is not None):
            raise ValueError('direction endpoints/status mismatch')
        if accepted and (self.contradiction or self.rejection_reason or not self.direction_confidence):
            raise ValueError('unproved direction accepted')
        if not accepted and self.direction_confidence:raise ValueError('ambiguous confidence must be zero')
        for c in self.forward_evidence+self.reverse_evidence:
            if set(c)!={'channel','entity_ids','provenance'} or not c['provenance']:
                raise ValueError('direction clue contract')
            for p in c['provenance']:EvidencePointer.model_validate(p)
        return self


class PairResult(StrictModel):
    schema_version: Literal['5.2-candidate'] = '5.2-candidate'
    algorithm_version: Literal['alert-correlation-v5-separation-direction-v1'] = ALGORITHM_VERSION
    support_pair: list[AlertID]
    support_key: list[AlertID]
    baseline_score: Unit
    valid: bool
    baseline: dict
    policy_hash: Digest
    groups: dict[str,Unit]
    transition: dict | None
    score_breakdown: dict
    score: Unit
    direction: DirectionEvidence

    @model_validator(mode='after')
    def validate_computation(self):
        if len(self.support_pair)!=2 or len(set(self.support_pair))!=2 or len(self.support_key)!=2:
            raise ValueError('pair identity contract')
        from app.utils.stable_id import content_digest
        from .formula import aggregate
        policy=self.score_breakdown['policy']
        Policy.model_validate(policy)
        if content_digest(policy)!=self.policy_hash:raise ValueError('policy hash mismatch')
        expected=aggregate(self.baseline,self.groups,self.transition,policy)
        if self.score_breakdown!={**expected,'policy':policy} or abs(self.score-expected['final_score'])>1e-12:
            raise ValueError('candidate score recomputation mismatch')
        ids=set(self.support_pair)
        if self.direction.status=='DERIVED_VERIFIED_DIRECTION' and {
            self.direction.source_alert_id,self.direction.target_alert_id}!=ids:
            raise ValueError('direction endpoints outside support pair')
        proofs=[]
        if self.transition:proofs.extend(self.transition['provenance'])
        for c in self.direction.forward_evidence+self.direction.reverse_evidence:proofs.extend(c['provenance'])
        for p in proofs:
            p=EvidencePointer.model_validate(p)
            if p.alert_id not in ids:raise ValueError('cross-member evidence splicing')
        return self


class CandidateCorrelationEdge(StrictModel):
    schema_version: Literal['5.2-candidate'] = '5.2-candidate'
    edge_id: CorrelationID
    source_alert_id: AlertID
    target_alert_id: AlertID
    score: Unit
    support: PairResult

    @model_validator(mode='after')
    def identity_and_admission(self):
        from app.utils.stable_id import id_for
        if self.source_alert_id>=self.target_alert_id or id_for('CorrelationEdge',self)!=self.edge_id:
            raise ValueError('candidate correlation identity')
        if not self.support.valid or not self.support.baseline['gate']['passed'] or self.score!=self.support.score:
            raise ValueError('candidate correlation support rejected')
        if self.support.support_key!=[self.source_alert_id,self.target_alert_id]:
            raise ValueError('candidate representative endpoints mismatch')
        return self

"""Strict opt-in schema; historical and production domain schemas remain unchanged."""
from typing import Literal
from pydantic import Field, model_validator
from app.models.base import StrictModel, AlertID, CorrelationID, Digest
from app.models.correlation_v2 import Unit
from app.models import EvidencePointer
from app.correlation.separation_direction.models import Policy as ObservationPolicy, DirectionEvidence
from . import ALGORITHM_VERSION, SCHEMA_VERSION


class AdmissionPolicy(StrictModel):
    strong_correlation: Unit
    moderate_correlation: Unit
    minimum_direction: Unit
    high_direction: Unit

    @model_validator(mode='after')
    def order(self):
        if self.strong_correlation != .70 or self.moderate_correlation >= self.strong_correlation:
            raise ValueError('strong_threshold_frozen_or_invalid_order')
        if self.minimum_direction > self.high_direction:
            raise ValueError('direction_order')
        return self


class Policy(StrictModel):
    version: Literal['alert-correlation-v5-semantic-repair-v1']
    schema_version: Literal['5.3-candidate']
    observation_policy: ObservationPolicy
    weak_ceiling: Unit
    partial_ceiling: Unit
    transition_ceiling: Unit
    chain_admission_policy: AdmissionPolicy
    designs: list[Literal['A', 'B', 'C']]
    chain_policies: list[Literal['A', 'B', 'C', 'D']]
    diagnostic_operating_points: list[Unit]

    @model_validator(mode='after')
    def frozen_points(self):
        if self.designs != ['A', 'B', 'C'] or self.chain_policies != ['A', 'B', 'C', 'D']:
            raise ValueError('comparison_incomplete')
        if self.diagnostic_operating_points != [.45, .50, .55, .60, .65, .70]:
            raise ValueError('diagnostic_points_frozen')
        if self.weak_ceiling != .45 or not self.weak_ceiling < self.partial_ceiling < .65:
            raise ValueError('weak_ceiling_or_partial_order')
        return self


class PairResult(StrictModel):
    schema_version: Literal['5.3-candidate'] = SCHEMA_VERSION
    algorithm_version: Literal['alert-correlation-v5-semantic-repair-v1'] = ALGORITHM_VERSION
    support_pair: list[AlertID]
    support_key: list[AlertID]
    valid: bool
    old_score: Unit
    baseline: dict
    groups: dict[str, Unit]
    hierarchy: dict
    direction: DirectionEvidence
    variants: dict[str, dict]
    policy_hash: Digest

    @model_validator(mode='after')
    def invariants(self):
        import math
        if len(set(self.support_pair)) != 2 or len(self.support_pair) != 2 or len(self.support_key) != 2:
            raise ValueError('pair_identity')
        if self.support_key != sorted(set(self.support_key)):
            raise ValueError('representative_identity')
        ids = set(self.support_pair)
        if self.direction.source_alert_id and {self.direction.source_alert_id, self.direction.target_alert_id} != ids:
            raise ValueError('direction_outside_member_pair')
        verified = self.direction.status == 'DERIVED_VERIFIED_DIRECTION'
        if (self.hierarchy['level'] == 3) != verified or self.hierarchy['progression_proven'] != verified:
            raise ValueError('bound_tier_requires_direction_proof')
        for key in ('identity_evidence', 'role_evidence', 'behavior_evidence', 'binding_evidence'):
            for clue in self.hierarchy[key]:
                for raw in clue['provenance']:
                    if EvidencePointer.model_validate(raw).alert_id not in ids:
                        raise ValueError('cross_member_evidence')
        if verified and not self.hierarchy['binding_evidence']:
            raise ValueError('binding_evidence_required')
        for design, breakdown in self.variants.items():
            if design not in {'A', 'B', 'C'} or breakdown['design'] != design:
                raise ValueError('unknown_variant')
            if breakdown['group_support'] != self.groups or set(breakdown['upgraded_group_support']) != set(self.groups):
                raise ValueError('duplicate_dependency_group')
            mass = 1-math.prod(1-v for _, v in sorted(breakdown['upgraded_group_support'].items()))
            raw = max(self.baseline['direct_support'], mass*self.baseline['temporal_factor'])-self.baseline['conflict_penalty']-self.baseline['duplicate_penalty']
            final = min(breakdown['ceiling'], max(0., min(1., raw))) if self.baseline['gate']['passed'] else 0.
            if abs(mass-breakdown['evidence_mass']) > 1e-12 or abs(raw-breakdown['raw_total']) > 1e-12 or abs(final-breakdown['final_score']) > 1e-12:
                raise ValueError('score_recomputation_mismatch')
            if self.baseline['weak_only'] and not verified and design != 'B' and breakdown['ceiling'] > .45:
                raise ValueError('unbound_transition_unlocked_ceiling')
        return self


class CorrelationEdge(StrictModel):
    schema_version: Literal['5.3-candidate'] = SCHEMA_VERSION
    edge_id: CorrelationID
    source_alert_id: AlertID
    target_alert_id: AlertID
    score: Unit
    design: Literal['A', 'B', 'C']
    score_breakdown: dict
    support: PairResult

    @model_validator(mode='after')
    def recompute(self):
        from app.utils.stable_id import id_for
        if self.source_alert_id >= self.target_alert_id or id_for('CorrelationEdge', self) != self.edge_id:
            raise ValueError('correlation_identity')
        if self.support.support_key != [self.source_alert_id, self.target_alert_id]:
            raise ValueError('representative_support_mismatch')
        if not self.support.valid or not self.support.baseline['gate']['passed']:
            raise ValueError('invalid_support')
        if self.score_breakdown != self.support.variants[self.design] or self.score != self.score_breakdown['final_score']:
            raise ValueError('correlation_score_mismatch')
        return self

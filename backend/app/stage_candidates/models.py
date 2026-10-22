"""Undirected retrieval contracts. Hints never represent validated relations."""
from typing import Literal

from pydantic import Field, model_validator

from app.community.models import CommunityID
from app.models.alerts import EvidencePointer, canonical_pointers
from app.models.base import AlertID, Digest, StrictModel, Text, id_type, ids
from app.stages.models import StageID
from app.utils.stable_id import content_digest


def candidate_id(a, b):
    return 'scp_' + content_digest(dict(id_version='v1', kind='StagePairCandidate', stage_ids=sorted([a, b])))


class FeatureWitness(StrictModel):
    alert_id: AlertID
    source_namespace: Text
    context_scope: Text | None = None
    role: Text
    pointers: list[EvidencePointer]

    @model_validator(mode='after')
    def bound(self):
        if not self.pointers or {p.alert_id for p in self.pointers} != {self.alert_id}:
            raise ValueError('candidate_feature_requires_bound_raw_witness')
        object.__setattr__(self, 'pointers', canonical_pointers(self.pointers))
        return self


class StageCandidateFeature(StrictModel):
    stage_id: StageID
    key: Text
    kind: Text
    identity: dict
    retrieval_hint: Literal['STRONG_RETRIEVAL_HINT', 'NORMAL_RETRIEVAL_HINT', 'WEAK_RETRIEVAL_HINT']
    mode: Literal['DIRECT', 'SELECTIVE_WEAK', 'COMPOUND', 'CONTEXT_ONLY']
    witnesses: list[FeatureWitness]

    @model_validator(mode='after')
    def identity_matches(self):
        if self.key != self.kind + ':' + content_digest(self.identity) or not self.witnesses:
            raise ValueError('candidate_feature_identity_or_witness_mismatch')
        return self


class StagePairCandidate(StrictModel):
    contract_version: Literal['stage-candidates-v1'] = 'stage-candidates-v1'
    candidate_id: id_type('scp')
    stage_a_id: StageID
    stage_b_id: StageID
    same_community: bool
    community_a_id: CommunityID
    community_b_id: CommunityID
    candidate_reasons: list[Text]
    retrieval_keys: list[Text]
    candidate_sources: list[Text]
    retrieval_features: list[StageCandidateFeature]
    metadata: dict

    @model_validator(mode='after')
    def canonical(self):
        if self.stage_a_id >= self.stage_b_id or self.candidate_id != candidate_id(self.stage_a_id, self.stage_b_id):
            raise ValueError('candidate_requires_canonical_distinct_pair')
        if self.same_community != (self.community_a_id == self.community_b_id):
            raise ValueError('candidate_community_mismatch')
        for values in (self.candidate_reasons, self.retrieval_keys, self.candidate_sources):
            if not values or values != sorted(set(values)):
                raise ValueError('candidate_requires_canonical_retrieval_justifications')
        if set(self.retrieval_keys) != {f.key for f in self.retrieval_features}:
            raise ValueError('candidate_key_feature_mismatch')
        for key in self.retrieval_keys:
            if {f.stage_id for f in self.retrieval_features if f.key == key} != {self.stage_a_id, self.stage_b_id}:
                raise ValueError('candidate_key_requires_both_stage_witnesses')
        if len({(f.stage_id, f.key) for f in self.retrieval_features}) != len(self.retrieval_features):
            raise ValueError('duplicate_candidate_feature')
        return self


class StagePairCandidateResult(StrictModel):
    contract_version: Literal['stage-candidates-v1'] = 'stage-candidates-v1'
    config_hash: Digest
    input_digest: Digest
    candidates: list[StagePairCandidate]
    features: list[StageCandidateFeature]
    diagnostics: list[dict]
    statistics: dict

    @model_validator(mode='after')
    def unique_pairs(self):
        pairs = [(p.stage_a_id, p.stage_b_id) for p in self.candidates]
        if pairs != sorted(set(pairs)):
            raise ValueError('candidate_pairs_must_be_unique_sorted')
        return self

"""Stage graph assembly v1; historical AttackChain/ChainEdge stay unchanged."""
from typing import Annotated, Literal

from pydantic import Field, model_validator

from app.community.models import CommunityID
from app.models.base import AnalysisID, Digest, NonNegativeInt, PositiveInt, StrictModel, id_type, ids
from app.stages.models import StageID
from app.utils.stable_id import content_digest

VERSION = 'stage-attack-chain-v1'
StageChainID = id_type('sch')
RelationID = id_type('str')
SubjectType = Literal['STAGE', 'STRONG_DIRECTED_EDGE', 'STRONG_UNDIRECTED_EDGE', 'WEAK_DIRECTED_RELATION']


def chain_id(community_id, stage_ids, relation_ids):
    return 'sch_' + content_digest(dict(id_version='v1', kind='StageAttackChain',
        identity=dict(community_id=community_id, stage_ids=sorted(set(stage_ids)),
                      relation_ids=sorted(set(relation_ids)))))


class TraceReference(StrictModel):
    """Addresses an existing EvidenceTrace by snapshot and subject, not a copy."""
    analysis_id: AnalysisID
    subject_type: SubjectType
    subject_id: StageID | RelationID

    @model_validator(mode='after')
    def subject_kind(self):
        if self.subject_id.startswith('stg_') != (self.subject_type == 'STAGE'):
            raise ValueError('trace_reference_subject_kind_mismatch')
        return self


class StageAttackChain(StrictModel):
    contract_version: Literal['stage-attack-chain-v1'] = VERSION
    chain_id: StageChainID
    source_analysis_id: AnalysisID
    community_id: CommunityID
    stage_ids: Annotated[ids(StageID), Field(min_length=1)]
    relation_ids: ids(RelationID)
    stage_count: PositiveInt
    relation_count: NonNegativeInt
    strong_directed_count: NonNegativeInt
    strong_undirected_count: NonNegativeInt
    weak_directed_count: NonNegativeInt
    entry_stage_ids: ids(StageID)
    exit_stage_ids: ids(StageID)
    entry_exit_basis: Literal['existing_directed_relations_only'] = 'existing_directed_relations_only'
    entry_exit_are_candidates: Literal[True] = True
    single_stage: bool
    has_directed_cycle: bool
    evidence_refs: list[TraceReference]

    @model_validator(mode='after')
    def closure(self):
        if self.chain_id != chain_id(self.community_id, self.stage_ids, self.relation_ids):
            raise ValueError('stage_chain_identity_mismatch')
        if (self.stage_count != len(self.stage_ids) or self.relation_count != len(self.relation_ids) or
                self.relation_count != self.strong_directed_count + self.strong_undirected_count + self.weak_directed_count):
            raise ValueError('stage_chain_counts_mismatch')
        if self.single_stage != (self.stage_count == 1) or self.single_stage and self.relation_count:
            raise ValueError('single_stage_chain_mismatch')
        if set(self.entry_stage_ids + self.exit_stage_ids) - set(self.stage_ids):
            raise ValueError('entry_exit_outside_chain')
        keys = [(ref.subject_type, ref.subject_id) for ref in self.evidence_refs]
        if keys != sorted(set(keys)):
            raise ValueError('chain_trace_refs_must_be_sorted_unique')
        if any(ref.analysis_id != self.source_analysis_id for ref in self.evidence_refs):
            raise ValueError('chain_trace_ref_crosses_snapshot')
        if ([ref.subject_id for ref in self.evidence_refs if ref.subject_type == 'STAGE'] != self.stage_ids or
                sorted(ref.subject_id for ref in self.evidence_refs if ref.subject_type != 'STAGE') != self.relation_ids):
            raise ValueError('chain_trace_ref_coverage_mismatch')
        return self


class StageChainResult(StrictModel):
    contract_version: Literal['stage-attack-chain-v1'] = VERSION
    source_analysis_id: AnalysisID
    input_digest: Digest
    membership_policy: Literal['connected_components_all_existing_relations'] = 'connected_components_all_existing_relations'
    cycle_policy: Literal['preserve_and_report'] = 'preserve_and_report'
    chains: list[StageAttackChain]

    @model_validator(mode='after')
    def ordered(self):
        keys = [c.chain_id for c in self.chains]
        if keys != sorted(set(keys)) or any(c.source_analysis_id != self.source_analysis_id for c in self.chains):
            raise ValueError('result_chain_order_identity_or_snapshot_mismatch')
        return self

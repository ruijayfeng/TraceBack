"""Official v2 claims, context membership and normalized raw-observation trace.

models.py remains a sealed v1 compatibility reader. Production uses this
contract; no Alert-pair witness is a logical evidence object in its output.
"""
from collections import Counter
from typing import Literal

from pydantic import Field, ValidationInfo, model_validator

from app.models.alerts import EvidencePointer
from app.models.base import AlertID, Digest, StrictModel, Text, UTCDateTime, id_type
from app.stage_candidates.models import candidate_id
from app.stages.models import StageID
from app.utils.stable_id import content_digest
from .config import DIRECTIONAL, ASSOCIATIVE, DIRECT_ASSOCIATIVE, SUPPORTING
from .models import Direction, RelationType

ClaimID=id_type('ecl')
ContextID=id_type('ctx')
ObservationID=id_type('obs')
PointerID=id_type('erp')
ValidationID=id_type('evc')
SemanticClass=Literal['DIRECTIONAL_RELATION','DIRECT_ASSOCIATIVE_RELATION','CONTEXT','SUPPORTING']


def stable(prefix,data):
    return prefix+'_'+content_digest(data)


def context_id(kind,identity):
    return stable('ctx',dict(context_type=kind,scoped_identity=identity))


def claim_key(stage_a_id,stage_b_id,evidence_type,identity,direction_claim,role_a,role_b):
    return dict(stage_a_id=stage_a_id,stage_b_id=stage_b_id,evidence_type=evidence_type,
        identity=identity,direction_claim=direction_claim,role_a=role_a,role_b=role_b)


class RawEvidenceReference(StrictModel):
    pointer_id: PointerID
    raw_pointer: EvidencePointer

    @model_validator(mode='after')
    def identity(self,info:ValidationInfo):
        if not self.raw_pointer.pointer or self.pointer_id!=stable('erp',self.raw_pointer.model_dump(mode='json')):
            raise ValueError('raw_pointer_reference_identity_mismatch')
        if info.context and 'alerts' in info.context:
            self.raw_pointer.resolve(info.context['alerts'])
        return self


class ObservationValidation(StrictModel):
    validation_id: ValidationID
    temporal_check: dict
    conflict_status: list[Text]
    valid: bool

    @model_validator(mode='after')
    def identity(self):
        if self.valid!= (not self.conflict_status):
            raise ValueError('observation_conflict_status_mismatch')
        data=self.model_dump(mode='json',exclude={'validation_id'})
        if self.validation_id!=stable('evc',data):
            raise ValueError('validation_identity_mismatch')
        return self


class SupportingObservation(StrictModel):
    observation_id: ObservationID
    alert_a_id: AlertID
    alert_b_id: AlertID
    raw_pointer_ids: list[PointerID]=Field(min_length=2)
    validation_id: ValidationID

    @model_validator(mode='after')
    def identity(self):
        if self.alert_a_id==self.alert_b_id or self.raw_pointer_ids!=sorted(set(self.raw_pointer_ids)):
            raise ValueError('observation_requires_distinct_alerts_and_canonical_pointers')
        if self.observation_id!=stable('obs',self.model_dump(mode='json',exclude={'observation_id'})):
            raise ValueError('observation_identity_mismatch')
        return self


class EvidenceTraceIndex(StrictModel):
    raw_pointers: list[RawEvidenceReference]
    validations: list[ObservationValidation]
    observations: list[SupportingObservation]

    @model_validator(mode='after')
    def closure(self):
        pointers={p.pointer_id:p for p in self.raw_pointers}
        validations={v.validation_id:v for v in self.validations}
        if len(pointers)!=len(self.raw_pointers) or len(validations)!=len(self.validations) or len({o.observation_id for o in self.observations})!=len(self.observations):
            raise ValueError('duplicate_trace_index_entry')
        for observation in self.observations:
            if set(observation.raw_pointer_ids)-pointers.keys() or observation.validation_id not in validations:
                raise ValueError('dangling_observation_raw_pointer_or_validation_reference')
            if {pointers[p].raw_pointer.alert_id for p in observation.raw_pointer_ids}!={observation.alert_a_id,observation.alert_b_id}:
                raise ValueError('observation_raw_pointer_endpoint_mismatch')
        return self

    def pointers_for(self,observation_id):
        observations={o.observation_id:o for o in self.observations}
        pointers={p.pointer_id:p.raw_pointer for p in self.raw_pointers}
        return [pointers[p] for p in observations[observation_id].raw_pointer_ids]

    def resolve_observation(self,observation_id,alerts):
        return [dict(alert_id=p.alert_id,pointer=p.pointer,side=p.side,value=p.resolve(alerts)) for p in self.pointers_for(observation_id)]


class ContextMembership(StrictModel):
    stage_id: StageID
    alert_id: AlertID
    role: str
    raw_pointer_ids: list[PointerID]=Field(min_length=1)


class ContextIdentityPosting(StrictModel):
    context_identity_id: ContextID
    context_type: Literal['FLOW','SESSION','PROCESS','REQUEST','OBJECT','CONNECTION','TASK']
    scoped_identity: dict
    stage_ids: list[StageID]=Field(min_length=1)
    alert_ids: list[AlertID]=Field(min_length=1)
    source_namespaces: list[Text]=Field(min_length=1)
    first_seen: UTCDateTime
    last_seen: UTCDateTime
    evidence_claim_ids: list[ClaimID]
    memberships: list[ContextMembership]=Field(min_length=1)
    metadata: dict

    @model_validator(mode='after')
    def closure(self):
        if self.context_identity_id!=context_id(self.context_type,self.scoped_identity):
            raise ValueError('context_identity_mismatch')
        if self.stage_ids!=sorted({m.stage_id for m in self.memberships}) or self.alert_ids!=sorted({m.alert_id for m in self.memberships}):
            raise ValueError('context_membership_summary_mismatch')
        for values in (self.source_namespaces,self.evidence_claim_ids):
            if values!=sorted(set(values)):
                raise ValueError('canonical_context_references_required')
        if self.first_seen>self.last_seen:
            raise ValueError('context_time_range_invalid')
        direct_stages = {m.stage_id for m in self.memberships if m.role=='process'} if self.context_type=='PROCESS' else set(self.stage_ids)
        if self.metadata.get('exclusive_direct_eligible') and (len(direct_stages)!=2 or not self.metadata.get('identity_complete') or self.metadata.get('identity_polluted')):
            raise ValueError('exclusive_identity_requires_complete_unpolluted_two_stage_membership')
        return self


class EvidenceClaim(StrictModel):
    claim_id: ClaimID
    stage_a_id: StageID
    stage_b_id: StageID
    evidence_type: Text
    semantic_class: SemanticClass
    identity: dict
    direction_claim: Direction
    role_a: Text
    role_b: Text
    valid: bool
    temporal_check: dict
    conflict_status: list[Text]
    reason: Text
    observation_ids: list[ObservationID]=Field(min_length=1)
    observation_count: int=Field(ge=1)
    context_identity_id: ContextID|None
    metadata: dict

    @model_validator(mode='after')
    def identity_matches(self):
        if self.stage_a_id>=self.stage_b_id:
            raise ValueError('canonical_claim_stage_pair_required')
        key=claim_key(self.stage_a_id,self.stage_b_id,self.evidence_type,self.identity,self.direction_claim,self.role_a,self.role_b)
        if self.claim_id!=stable('ecl',key):
            raise ValueError('claim_identity_mismatch')
        if self.observation_ids!=sorted(set(self.observation_ids)) or self.observation_count!=len(self.observation_ids):
            raise ValueError('claim_observation_count_mismatch')
        if self.evidence_type in DIRECTIONAL:
            if self.semantic_class!='DIRECTIONAL_RELATION' or self.direction_claim not in {'A_TO_B','B_TO_A'}:
                raise ValueError('directional_claim_semantics_mismatch')
        elif self.evidence_type in ASSOCIATIVE:
            if self.semantic_class not in {'DIRECT_ASSOCIATIVE_RELATION','CONTEXT'} or self.direction_claim!='UNDIRECTED':
                raise ValueError('associative_claim_semantics_mismatch')
        elif self.evidence_type not in SUPPORTING or self.semantic_class!='SUPPORTING' or self.direction_claim!='NONE':
            raise ValueError('supporting_claim_semantics_mismatch')
        if self.valid!=(not self.conflict_status):
            raise ValueError('claim_effective_conflict_status_mismatch')
        return self


class StageRelationDecision(StrictModel):
    candidate_id: id_type('scp')
    stage_a_id: StageID
    stage_b_id: StageID
    relation_type: RelationType
    direction_claim: Direction
    from_stage_id: StageID|None
    to_stage_id: StageID|None
    primary_claim_id: ClaimID|None
    relation_claim_ids: list[ClaimID]
    context_claim_ids: list[ClaimID]
    context_identity_ids: list[ContextID]
    supporting_claim_ids: list[ClaimID]
    invalid_claim_ids: list[ClaimID]
    relation_claim_count: int
    context_claim_count: int
    supporting_claim_count: int
    invalid_claim_count: int
    raw_supporting_observation_count: int
    unique_claim_count: int
    evidence_type_counts: dict[str,int]
    diagnostics: list[Text]
    reason: Text

    @model_validator(mode='after')
    def closure(self):
        if self.stage_a_id>=self.stage_b_id or self.candidate_id!=candidate_id(self.stage_a_id,self.stage_b_id):
            raise ValueError('candidate_decision_identity_mismatch')
        if self.relation_type=='DIRECTED_EDGE':
            endpoints={'A_TO_B':(self.stage_a_id,self.stage_b_id),'B_TO_A':(self.stage_b_id,self.stage_a_id)}
            if (self.from_stage_id,self.to_stage_id)!=endpoints.get(self.direction_claim):
                raise ValueError('directed_semantic_endpoints_required')
        elif self.from_stage_id is not None or self.to_stage_id is not None or self.direction_claim!=('UNDIRECTED' if self.relation_type=='UNDIRECTED_EDGE' else 'NONE'):
            raise ValueError('unresolved_decision_cannot_assert_direction')
        if bool(self.primary_claim_id)!=(self.relation_type!='NO_RELATION'):
            raise ValueError('only_edges_have_primary_relation_claim')
        if self.relation_type=='NO_RELATION' and not self.diagnostics:
            raise ValueError('no_relation_requires_diagnostics')
        return self


class CrossStageEvidenceResult(StrictModel):
    contract_version: Literal['stage-evidence-v2']='stage-evidence-v2'
    config_hash: Digest
    input_digest: Digest
    decisions: list[StageRelationDecision]
    claims: list[EvidenceClaim]
    context_postings: list[ContextIdentityPosting]
    trace: EvidenceTraceIndex
    statistics: dict

    @model_validator(mode='after')
    def closure(self,info:ValidationInfo):
        claims={c.claim_id:c for c in self.claims}
        contexts={c.context_identity_id:c for c in self.context_postings}
        observations={o.observation_id:o for o in self.trace.observations}
        validations={v.validation_id:v for v in self.trace.validations}
        pointers={p.pointer_id:p.raw_pointer for p in self.trace.raw_pointers}
        if len(claims)!=len(self.claims) or len(contexts)!=len(self.context_postings) or len({d.candidate_id for d in self.decisions})!=len(self.decisions):
            raise ValueError('duplicate_claim_context_or_decision')
        used_claims,used_observations,used_pointers,used_validations=set(),set(),set(),set()
        ctx=info.context or {}
        for posting in self.context_postings:
            for member in posting.memberships:
                if set(member.raw_pointer_ids)-pointers.keys():
                    raise ValueError('dangling_context_raw_pointer_reference')
                if any(pointers[p].alert_id!=member.alert_id for p in member.raw_pointer_ids):
                    raise ValueError('context_raw_pointer_endpoint_mismatch')
                if 'stages' in ctx and member.alert_id not in ctx['stages'][member.stage_id].alert_ids:
                    raise ValueError('context_member_outside_stage')
                used_pointers.update(member.raw_pointer_ids)
            if set(posting.evidence_claim_ids)-claims.keys():
                raise ValueError('dangling_context_claim_reference')
            if set(posting.evidence_claim_ids)!={c.claim_id for c in self.claims if c.context_identity_id==posting.context_identity_id}:
                raise ValueError('context_claim_index_mismatch')
        for claim in self.claims:
            if set(claim.observation_ids)-observations.keys():
                raise ValueError('dangling_claim_observation_reference')
            checks=[]
            for oid in claim.observation_ids:
                observation=observations[oid]
                if 'stages' in ctx and any(aid not in ctx['stages'][sid].alert_ids for sid,aid in ((claim.stage_a_id,observation.alert_a_id),(claim.stage_b_id,observation.alert_b_id))):
                    raise ValueError('claim_observation_outside_stage')
                checks.append(validations[observation.validation_id])
                used_observations.add(oid)
                used_validations.add(observation.validation_id)
                used_pointers.update(observation.raw_pointer_ids)
            if claim.valid!=any(v.valid for v in checks):
                raise ValueError('claim_must_use_valid_supporting_observations_only')
            if claim.context_identity_id:
                posting=contexts.get(claim.context_identity_id)
                if not posting or not {claim.stage_a_id,claim.stage_b_id}<=set(posting.stage_ids):
                    raise ValueError('dangling_or_mismatched_claim_context')
                direct_stages = {m.stage_id for m in posting.memberships if m.role=='process'} if posting.context_type=='PROCESS' else set(posting.stage_ids)
                exclusive=(direct_stages=={claim.stage_a_id,claim.stage_b_id} and posting.metadata.get('exclusive_direct_eligible') is True)
                if claim.semantic_class!=('DIRECT_ASSOCIATIVE_RELATION' if exclusive else 'CONTEXT'):
                    raise ValueError('context_membership_cannot_certify_pairwise_relation')
            elif claim.valid and claim.evidence_type in ASSOCIATIVE-DIRECT_ASSOCIATIVE:
                raise ValueError('shared_identity_claim_requires_global_context_posting')
        for d in self.decisions:
            groups=[d.relation_claim_ids,d.context_claim_ids,d.supporting_claim_ids,d.invalid_claim_ids]
            ids=[i for group in groups for i in group]
            if len(set(ids))!=len(ids) or set(ids)-claims.keys() or (d.primary_claim_id and d.primary_claim_id not in d.relation_claim_ids):
                raise ValueError('duplicate_or_dangling_decision_claim_reference')
            selected=[claims[i] for i in ids]
            if any((c.stage_a_id,c.stage_b_id)!=(d.stage_a_id,d.stage_b_id) for c in selected):
                raise ValueError('decision_claim_endpoint_mismatch')
            expected_groups=[[c.claim_id for c in selected if c.valid and c.semantic_class in {'DIRECTIONAL_RELATION','DIRECT_ASSOCIATIVE_RELATION'}],
                [c.claim_id for c in selected if c.valid and c.semantic_class=='CONTEXT'],
                [c.claim_id for c in selected if c.valid and c.semantic_class=='SUPPORTING'],[c.claim_id for c in selected if not c.valid]]
            if any(group!=sorted(set(expected)) for group,expected in zip(groups,expected_groups)):
                raise ValueError('decision_claim_semantic_partition_mismatch')
            directions={c.direction_claim for c in selected if c.valid and c.semantic_class=='DIRECTIONAL_RELATION'}
            expected='DIRECTED_EDGE' if len(directions)==1 else 'UNDIRECTED_EDGE' if d.relation_claim_ids else 'NO_RELATION'
            if d.relation_type!=expected or (expected=='DIRECTED_EDGE' and d.direction_claim not in directions):
                raise ValueError('decision_must_aggregate_relation_claims_only')
            if d.primary_claim_id and expected=='DIRECTED_EDGE' and claims[d.primary_claim_id].direction_claim!=d.direction_claim:
                raise ValueError('primary_claim_must_assert_final_direction')
            if len(directions)>1 and 'DIRECTION_CONFLICT' not in d.diagnostics:
                raise ValueError('direction_conflict_diagnostic_required')
            expected_contexts=sorted(p.context_identity_id for p in self.context_postings if {d.stage_a_id,d.stage_b_id}<=set(p.stage_ids))
            if d.context_identity_ids!=expected_contexts:
                raise ValueError('decision_context_membership_index_mismatch')
            if (d.context_claim_ids or d.context_identity_ids) and not d.relation_claim_ids and 'SHARED_CONTEXT_ONLY' not in d.diagnostics:
                raise ValueError('shared_context_requires_specific_diagnostic')
            if (d.relation_claim_count,d.context_claim_count,d.supporting_claim_count,d.invalid_claim_count)!=tuple(len(g) for g in groups):
                raise ValueError('decision_claim_counts_mismatch')
            if d.unique_claim_count!=len(selected) or d.raw_supporting_observation_count!=sum(c.observation_count for c in selected) or d.evidence_type_counts!=dict(Counter(c.evidence_type for c in selected)):
                raise ValueError('decision_observation_summary_mismatch')
            used_claims.update(ids)
        if used_claims!=claims.keys() or used_observations!=observations.keys() or used_pointers!=pointers.keys() or used_validations!=validations.keys():
            raise ValueError('orphan_claim_or_trace_index_entry')
        return self

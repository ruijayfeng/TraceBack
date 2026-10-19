"""Candidate-only models. Membership reasons never assert attack or causality."""
from typing import Annotated, Literal

from pydantic import Field, ValidationInfo, model_validator

from app.models.alerts import EvidencePointer, canonical_pointers
from app.models.base import (AlertID, Digest, EntityID, PositiveInt, StrictModel,
                             Text, UTCDateTime, check_evidence, id_type, ids)
from app.utils.stable_id import content_digest, id_for

CommunityID = id_type('com')


def community_id(alert_ids):
    return 'com_' + content_digest(dict(id_version='v1', kind='Community',
                                        identity=dict(alert_ids=sorted(set(alert_ids)))))


class MatchingEvidence(StrictModel):
    match_reason: Text
    match_level: Annotated[int, Field(ge=1, le=5)]
    alert_ids: Annotated[ids(AlertID), Field(min_length=2, max_length=2)]
    entity_ids: ids(EntityID) = Field(default_factory=list)
    identity_kind: Text
    identity_key: Text
    time_delta_seconds: Annotated[float, Field(ge=0)]
    supporting_evidence: Annotated[list[EvidencePointer], Field(min_length=2)]

    @model_validator(mode='after')
    def bound(self, info: ValidationInfo):
        pointers = canonical_pointers(self.supporting_evidence)
        object.__setattr__(self, 'supporting_evidence', pointers)
        if {p.alert_id for p in pointers} != set(self.alert_ids):
            raise ValueError('match_requires_witnesses_from_both_alerts')
        check_evidence(pointers, self.alert_ids, info)
        return self


class MembershipDecision(StrictModel):
    alert_id: AlertID
    action: Literal['CREATE', 'JOIN', 'MERGE']
    prior_community_ids: ids(CommunityID)
    matching_evidence: list[MatchingEvidence]
    reason: Text

    @model_validator(mode='after')
    def basis(self):
        if self.action == 'CREATE':
            if self.prior_community_ids or self.matching_evidence:
                raise ValueError('creation_has_no_prior_match')
        elif not self.prior_community_ids or not self.matching_evidence:
            raise ValueError('join_or_merge_requires_prior_match')
        if self.action == 'MERGE' and len(self.prior_community_ids) < 2:
            raise ValueError('merge_requires_multiple_prior_communities')
        if any(self.alert_id not in e.alert_ids for e in self.matching_evidence):
            raise ValueError('decision_witness_must_include_incoming_alert')
        return self


class IncidentCandidate(StrictModel):
    contract_version: Literal['community-v1'] = 'community-v1'
    community_id: CommunityID
    incident_candidate_id: Text
    alert_ids: Annotated[ids(AlertID), Field(min_length=1)]
    start_time: UTCDateTime
    end_time: UTCDateTime
    sources: list[Text]
    entity_ids: ids(EntityID)
    contexts: dict[str, list[Text]]
    member_count: PositiveInt
    matching_evidence: list[MatchingEvidence]
    membership_decisions: list[MembershipDecision]

    @model_validator(mode='after')
    def closure(self, info: ValidationInfo):
        if self.community_id != community_id(self.alert_ids):
            raise ValueError('community_identity_mismatch')
        expected = 'icd_' + content_digest(dict(id_version='v1', kind='IncidentCandidate',
                                               identity=dict(alert_ids=self.alert_ids)))
        if self.incident_candidate_id != expected:
            raise ValueError('incident_candidate_identity_mismatch')
        if self.member_count != len(self.alert_ids) or self.start_time > self.end_time:
            raise ValueError('candidate_size_or_time_mismatch')
        if set(d.alert_id for d in self.membership_decisions) != set(self.alert_ids) or len(self.membership_decisions) != self.member_count:
            raise ValueError('every_member_requires_exactly_one_decision')
        if self.sources != sorted(set(self.sources)):
            raise ValueError('sources_must_be_sorted_unique')
        for evidence in self.matching_evidence:
            if set(evidence.alert_ids) - set(self.alert_ids) or set(evidence.entity_ids) - set(self.entity_ids):
                raise ValueError('candidate_evidence_reference_outside_members')
            check_evidence(evidence.supporting_evidence, self.alert_ids, info)
        declared = {e.model_dump_json() for e in self.matching_evidence}
        used = {e.model_dump_json() for d in self.membership_decisions for e in d.matching_evidence}
        if declared != used:
            raise ValueError('candidate_and_decision_evidence_must_agree')
        # The explanation witnesses form a connected undirected membership proof.
        reached = {self.alert_ids[0]}
        pending = [set(e.alert_ids) for e in self.matching_evidence]
        while True:
            size = len(reached)
            for pair in pending:
                if pair & reached:
                    reached.update(pair)
            if len(reached) == size:
                break
        if reached != set(self.alert_ids):
            raise ValueError('membership_evidence_is_disconnected')
        if info.context and 'alerts' in info.context:
            alerts = info.context['alerts']
            members = [alerts[aid] for aid in self.alert_ids]
            if self.start_time != min(a.timestamp for a in members) or self.end_time != max(a.timestamp for a in members):
                raise ValueError('candidate_time_does_not_match_members')
            if set(self.entity_ids) != {eid for a in members for eid in a.entity_ids}:
                raise ValueError('candidate_entities_do_not_match_members')
            if set(self.sources) != {a.source_namespace for a in members}:
                raise ValueError('candidate_sources_do_not_match_members')
        return self

    def to_incident(self, alerts):
        """Explicit downstream compatibility conversion; no chain or score objects."""
        from app.models import Incident, Severity
        severity_order = list(Severity)
        severity = max((alerts[aid].severity for aid in self.alert_ids), key=severity_order.index)
        return Incident(incident_id=id_for('Incident', dict(alert_ids=self.alert_ids)),
                        alert_ids=self.alert_ids, entity_ids=self.entity_ids,
                        start_time=self.start_time, end_time=self.end_time, severity=severity,
                        summary='候选安全活动；成员依据见 community-v1 matching_evidence。')


class CommunityResult(StrictModel):
    contract_version: Literal['community-v1'] = 'community-v1'
    config_hash: Digest
    input_fingerprint: Digest
    incident_candidates: list[IncidentCandidate]
    diagnostics: list[dict]
    statistics: dict

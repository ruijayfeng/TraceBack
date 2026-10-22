"""Versioned semantic annotations and undirected activity aggregates.

These are independent of historical ChainNode/AIExplanation contracts. A label
describes the observed alert, never confirms compromise or an unobserved step.
"""
from typing import Annotated, Literal

from pydantic import Field, ValidationInfo, model_validator, model_serializer

from app.community.models import CommunityID
from app.models.alerts import EvidencePointer, canonical_pointers
from app.models.base import (AlertID, Digest, EntityID, PositiveInt, Score,
                             StrictModel, Text, UTCDateTime, check_evidence,
                             id_type, ids)
from app.utils.stable_id import content_digest

Behavior = Literal['RECONNAISSANCE', 'INITIAL_ACCESS', 'WEB_EXPLOIT',
    'EXECUTION', 'PERSISTENCE', 'PRIVILEGE_ESCALATION', 'DEFENSE_EVASION',
    'CREDENTIAL_ACTIVITY', 'DISCOVERY', 'LATERAL_MOVEMENT',
    'COMMAND_AND_CONTROL', 'COLLECTION', 'EXFILTRATION', 'IMPACT',
    'AUTHENTICATION', 'FILE_ACTIVITY', 'NETWORK_ACTIVITY', 'UNKNOWN']
VOCABULARY = list(Behavior.__args__)
StageID = id_type('stg')


def stage_id(community_id, behavior, alert_ids):
    return 'stg_' + content_digest(dict(id_version='v1', kind='Stage',
        identity=dict(community_id=community_id, behavior=behavior,
                      alert_ids=sorted(set(alert_ids)))))


class SemanticAnswer(StrictModel):
    behavior: Behavior
    confidence: Score
    reasoning: Annotated[Text, Field(max_length=1000)]


class BehaviorAnnotation(StrictModel):
    contract_version: Literal['behavior-stage-v1'] = 'behavior-stage-v1'
    alert_id: AlertID
    # Set only when a downstream consumer binds an already computed annotation.
    # Older sealed snapshots carrying this context remain valid.
    community_id: CommunityID | None = None
    behavior: Behavior
    resolver: Literal['mapping', 'ai', 'unknown']
    matched_rule: list[Text]
    confidence: Score
    reason: Text
    evidence: Annotated[list[EvidencePointer], Field(min_length=1)]
    input_digest: Digest

    @model_serializer(mode='wrap')
    def optional_context(self, handler):
        data = handler(self)
        if self.community_id is None:
            data.pop('community_id', None)
        return data

    @model_validator(mode='after')
    def closure(self, info: ValidationInfo):
        if self.matched_rule != sorted(set(self.matched_rule)):
            raise ValueError('mapping_rules_must_be_sorted_unique')
        if (self.resolver == 'mapping') != bool(self.matched_rule):
            raise ValueError('only_mapping_has_matched_rules')
        if self.resolver == 'unknown' and self.behavior != 'UNKNOWN':
            raise ValueError('unknown_resolver_cannot_assert_behavior')
        object.__setattr__(self, 'evidence', canonical_pointers(self.evidence))
        check_evidence(self.evidence, [self.alert_id], info)
        return self


class AggregationBasis(StrictModel):
    """Undirected same-stage proof; never a causal Stage-to-Stage relation.

    Optional graph metadata keeps sealed legacy complete-link artifacts readable.
    """
    alert_ids: Annotated[ids(AlertID), Field(min_length=2, max_length=2)]
    rule: Literal['shared_strong_binding', 'consistent_core_context']
    shared_keys: Annotated[list[Text], Field(min_length=1)]
    evidence: Annotated[list[EvidencePointer], Field(min_length=2)]
    edge_strength: Literal['STRONG', 'NORMAL', 'WEAK'] | None = None
    evidence_types: list[Text] = Field(default_factory=list)
    behavior_compatible: bool = True
    binding_evidence: list[Text] = Field(default_factory=list)
    entity_evidence: ids(EntityID) = Field(default_factory=list)
    temporal_check: dict = Field(default_factory=dict)

    @model_validator(mode='after')
    def closure(self, info: ValidationInfo):
        object.__setattr__(self, 'evidence', canonical_pointers(self.evidence))
        if {p.alert_id for p in self.evidence} != set(self.alert_ids):
            raise ValueError('aggregation_requires_both_witnesses')
        if self.edge_strength is not None:
            if not self.behavior_compatible or not self.evidence_types or not self.temporal_check.get('passed'):
                raise ValueError('stage_edge_requires_semantics_context_and_time')
            if self.edge_strength == 'STRONG' and not self.binding_evidence:
                raise ValueError('strong_stage_edge_requires_binding')
        check_evidence(self.evidence, self.alert_ids, info)
        return self


class Stage(StrictModel):
    contract_version: Literal['behavior-stage-v1'] = 'behavior-stage-v1'
    stage_id: StageID
    community_id: CommunityID
    behavior: Behavior
    start_time: UTCDateTime
    end_time: UTCDateTime
    alert_ids: Annotated[ids(AlertID), Field(min_length=1)]
    alert_count: PositiveInt
    source_types: list[Text]
    host_entities: ids(EntityID)
    account_entities: ids(EntityID)
    process_entities: ids(EntityID)
    request_bindings: list[Text]
    flow_bindings: list[Text]
    session_bindings: list[Text]
    task_bindings: list[Text]
    evidence_summary: Text
    aggregation_basis: list[AggregationBasis]

    @model_validator(mode='after')
    def closure(self, info: ValidationInfo):
        if self.stage_id != stage_id(self.community_id, self.behavior, self.alert_ids):
            raise ValueError('stage_identity_mismatch')
        if self.alert_count != len(self.alert_ids) or self.start_time > self.end_time:
            raise ValueError('stage_size_or_time_mismatch')
        for field in ('source_types', 'request_bindings', 'flow_bindings',
                      'session_bindings', 'task_bindings'):
            values = getattr(self, field)
            if values != sorted(set(values)):
                raise ValueError('stage_sets_must_be_sorted_unique')
        pairs = set()
        for proof in self.aggregation_basis:
            if set(proof.alert_ids) - set(self.alert_ids):
                raise ValueError('stage_basis_outside_members')
            pairs.add(tuple(proof.alert_ids))
            check_evidence(proof.evidence, self.alert_ids, info)
        if len(pairs) != len(self.aggregation_basis):
            raise ValueError('duplicate_stage_connectivity_edge')
        from .graph import connected_components
        if len(connected_components(self.alert_ids, self.aggregation_basis)) != 1:
            raise ValueError('stage_requires_connected_proof')
        if info.context and 'alerts' in info.context:
            members = [info.context['alerts'][aid] for aid in self.alert_ids]
            if (self.start_time != min(a.timestamp for a in members) or
                    self.end_time != max(a.timestamp for a in members)):
                raise ValueError('stage_time_mismatch')
            if self.source_types != sorted({a.source_type.value for a in members}):
                raise ValueError('stage_source_types_mismatch')
            for field, roles, kind in (('host_entities', {'host'}, 'HOST'),
                    ('account_entities', {'account', 'target_account', 'authenticated_account', 'source_account', 'audit_account'}, 'ACCOUNT'),
                    ('process_entities', {'process', 'parent_process'}, 'PROCESS')):
                entity_map = info.context.get('entities')
                expected = {o.entity_id for a in members for o in a.entity_occurrences
                            if (entity_map[o.entity_id].type.value == kind if entity_map else o.role.value in roles)}
                if set(getattr(self, field)) != expected:
                    raise ValueError('stage_entities_mismatch:' + field)
            if 'communities' in info.context:
                community = info.context['communities'][self.community_id]
                if set(self.alert_ids) - set(community.alert_ids):
                    raise ValueError('stage_members_outside_community')
        return self


class StageResult(StrictModel):
    contract_version: Literal['behavior-stage-v1'] = 'behavior-stage-v1'
    config_hash: Digest
    behaviors: list[BehaviorAnnotation]
    stages: list[Stage]
    diagnostics: list[dict]
    statistics: dict

    @model_validator(mode='after')
    def partition(self):
        annotations = {b.alert_id: b for b in self.behaviors}
        if len(annotations) != len(self.behaviors):
            raise ValueError('duplicate_behavior_annotation')
        covered = []
        for stage in self.stages:
            from .evidence import OBSERVATION_BEHAVIORS
            labels = {annotations[aid].behavior for aid in stage.alert_ids if aid in annotations}
            cross_label = [e for e in stage.aggregation_basis if all(i in annotations for i in e.alert_ids)
                           and len({annotations[i].behavior for i in e.alert_ids}) > 1]
            http_observations = (labels == {'WEB_EXPLOIT', 'UNKNOWN'} and bool(cross_label)
                and all('http_transaction' in e.evidence_types and e.edge_strength == 'STRONG' for e in cross_label))
            for aid in stage.alert_ids:
                if (aid not in annotations or annotations[aid].community_id != stage.community_id
                        or (annotations[aid].behavior != stage.behavior and
                            not (stage.behavior in labels and (labels <= OBSERVATION_BEHAVIORS or http_observations)))):
                    raise ValueError('stage_annotation_mismatch')
            covered.extend(stage.alert_ids)
        if sorted(covered) != sorted(annotations):
            raise ValueError('stages_must_partition_all_alerts_exactly_once')
        if len({s.stage_id for s in self.stages}) != len(self.stages):
            raise ValueError('duplicate_stage_id')
        return self

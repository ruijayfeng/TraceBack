"""Explicit uncalibrated ranking/confidence and clock tolerance policy."""
from pathlib import Path
from typing import Literal
from pydantic import model_validator
import yaml

from app.models.base import NonNegative, PositiveInt, Score, StrictModel, Text
from app.utils.stable_id import content_digest


class EvidencePolicy(StrictModel):
    rank: PositiveInt
    strength: Score


class RelationConfig(StrictModel):
    version: Literal['stage-relations-v1']
    time_reversal_tolerance_seconds: NonNegative
    evidence: dict[Text, EvidencePolicy]
    request_operations: list[Text]
    response_operations: list[Text]
    session_start_operations: list[Text]
    object_create_operations: list[Text]
    object_execute_operations: list[Text]

    @model_validator(mode='after')
    def complete(self):
        expected = {'parent_child_process', 'request_response', 'session_followup',
                    'object_create_execute', 'object_handoff', 'attested_relation',
                    'shared_process_instance', 'shared_binding', 'shared_entity', 'network_context'}
        # Optional additive policy keeps sealed legacy v1 snapshots readable.
        if 'same_instance' in self.evidence:
            expected.add('same_instance')
        if set(self.evidence) != expected:
            raise ValueError('all_and_only_supported_evidence_policies_required')
        if set(self.request_operations) & set(self.response_operations):
            raise ValueError('request_response_operations_must_be_disjoint')
        if set(self.object_create_operations) & set(self.object_execute_operations):
            raise ValueError('create_execute_operations_must_be_disjoint')
        strong = expected - {'shared_process_instance', 'shared_binding', 'shared_entity', 'network_context'}
        weak = expected - strong
        if max(self.evidence[k].rank for k in strong) >= min(self.evidence[k].rank for k in weak):
            raise ValueError('semantic_binding_must_outrank_context')
        if min(self.evidence[k].strength for k in strong) <= max(self.evidence[k].strength for k in weak):
            raise ValueError('strong_evidence_strength_must_exceed_context')
        return self

    @property
    def digest(self):
        return content_digest(self.model_dump(mode='json'))


def load_relation_config(path: str | Path):
    return RelationConfig.model_validate(yaml.safe_load(Path(path).read_text(encoding='utf8')))

"""Stage ⑧ policy: semantic roles and evidence-specific clock tolerances."""
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, model_validator

from app.models.base import NonNegative, StrictModel, Text
from app.utils.stable_id import content_digest

DIRECTIONAL = frozenset({'PARENT_CHILD_PROCESS', 'REQUEST_RESPONSE', 'OBJECT_CREATE_EXECUTE',
    'OBJECT_HANDOFF', 'AUTH_ESTABLISH_USE', 'EXPLICIT_ATTESTED_RELATION', 'CONNECTION_ESTABLISH_ACCEPT'})
ASSOCIATIVE = frozenset({'SAME_PROCESS_INSTANCE', 'SAME_SCOPED_FLOW', 'SAME_STRONG_SESSION',
    'SAME_SCOPED_OBJECT', 'SAME_SCOPED_REQUEST', 'SAME_TRUSTED_CONNECTION', 'SAME_SCOPED_TASK',
    'EXPLICIT_RELATED_EVENT'})
DIRECT_ASSOCIATIVE = frozenset({'EXPLICIT_RELATED_EVENT'})
CONTEXT_TYPES = {'process_instance':('PROCESS','SAME_PROCESS_INSTANCE'),
    'flow':('FLOW','SAME_SCOPED_FLOW'), 'session':('SESSION','SAME_STRONG_SESSION'),
    'application_session':('SESSION','SAME_STRONG_SESSION'), 'request':('REQUEST','SAME_SCOPED_REQUEST'),
    'object':('OBJECT','SAME_SCOPED_OBJECT'), 'connection':('CONNECTION','SAME_TRUSTED_CONNECTION'),
    'task':('TASK','SAME_SCOPED_TASK')}
SUPPORTING = frozenset({'SAME_HOST', 'SAME_ACCOUNT', 'SAME_URL', 'SAME_COMMAND',
    'NETWORK_ENDPOINT_OVERLAP', 'INCOMPLETE_FLOW', 'SHARED_PROCESS_DESCRIPTOR', 'SHARED_FILE_PATH'})


class EvidenceConfig(StrictModel):
    version: Literal['stage-evidence-v1']
    enabled_evidence_types: list[Text]
    reversal_tolerance_seconds: dict[Text, NonNegative]
    request_operations: list[Text]
    response_operations: list[Text]
    session_start_operations: list[Text]
    session_use_operations: list[Text]
    connection_initiate_operations: list[Text] = Field(default_factory=list)
    connection_accept_operations: list[Text] = Field(default_factory=list)
    object_create_operations: list[Text]
    object_execute_operations: list[Text]
    directional_reference_fields: dict[Text, list[Text]]
    associative_reference_fields: dict[Text, list[Text]]
    direction_conflict_policy: Literal['UNDIRECTED_IF_STRONG_ASSOCIATION']
    exclusive_context_policy: Literal['TWO_STAGE_COMPLETE_UNPOLLUTED_IDENTITY']
    exclusive_context_evidence_types: list[Text]

    @model_validator(mode='after')
    def coherent(self):
        if set(self.enabled_evidence_types) - (DIRECTIONAL | ASSOCIATIVE | SUPPORTING):
            raise ValueError('unsupported_evidence_type')
        if set(self.reversal_tolerance_seconds) != DIRECTIONAL:
            raise ValueError('directional_types_require_individual_temporal_policy')
        if set(self.exclusive_context_evidence_types) - (ASSOCIATIVE-DIRECT_ASSOCIATIVE):
            raise ValueError('exclusive_context_policy_requires_membership_evidence_type')
        for left, right in ((self.request_operations, self.response_operations),
                (self.session_start_operations, self.session_use_operations),
                (self.connection_initiate_operations, self.connection_accept_operations),
                (self.object_create_operations, self.object_execute_operations)):
            if set(left) & set(right):
                raise ValueError('semantic_roles_must_be_disjoint')
        for profile, fields in self.directional_reference_fields.items():
            if set(fields) & set(self.associative_reference_fields.get(profile,[])):
                raise ValueError('reference_roles_must_be_disjoint')
        if any(not p.startswith('/') for mapping in (self.directional_reference_fields,self.associative_reference_fields)
               for fields in mapping.values() for p in fields):
            raise ValueError('reference_projection_requires_explicit_raw_path')
        return self

    @property
    def digest(self):
        return content_digest(self.model_dump(mode='json'))


def load_evidence_config(path: str | Path):
    return EvidenceConfig.model_validate(yaml.safe_load(Path(path).read_text(encoding='utf8')))

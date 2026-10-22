"""Candidate policy references existing locality/frequency settings by meaning."""
from pathlib import Path
from typing import Literal

import yaml
from pydantic import model_validator

from app.models.base import StrictModel
from app.utils.stable_id import content_digest

FEATURE_KINDS = {'request', 'session', 'connection', 'application_session', 'task',
    'object', 'process_instance', 'native_flow', 'network_tuple', 'direct_reference',
    'host_account', 'file', 'session_entity', 'host', 'url', 'command', 'endpoint',
    'endpoint_pair', 'host_url', 'host_command', 'url_endpoint_pair',
    'object_at_observed_host', 'host_auth_session', 'connection_endpoints_hint', 'file_at_host'}


class CandidateConfig(StrictModel):
    version: Literal['stage-candidates-v1']
    enabled_feature_kinds: list[str]
    selective_host_window_tier: Literal['3', '4', '5']
    compound_context_window_tier: Literal['3', '4', '5']
    connection_context_window_tier: Literal['1', '2']
    frequency_policy: Literal['community_common_entities_on_stage_postings']
    cross_source_connection_recall: Literal['token_and_both_endpoints_preserve_declared_network_scope']

    @model_validator(mode='after')
    def known_features(self):
        if len(set(self.enabled_feature_kinds)) != len(self.enabled_feature_kinds) or set(self.enabled_feature_kinds) - FEATURE_KINDS:
            raise ValueError('candidate_features_must_be_unique_supported_kinds')
        return self

    @property
    def digest(self):
        return content_digest(self.model_dump(mode='json'))


def load_candidate_config(path: str | Path):
    return CandidateConfig.model_validate(yaml.safe_load(Path(path).read_text(encoding='utf8')))

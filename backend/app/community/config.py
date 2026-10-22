"""Independent evidence-tier policy; historical correlation configurations stay intact."""
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
import yaml

from app.models.base import Pointer, PositiveInt, StrictModel
from app.utils.stable_id import content_digest

ProjectionKind = Literal['trace', 'correlation', 'transaction', 'direct_reference',
                         'object', 'file_hash', 'protocol', 'direction', 'source_role',
                         'destination_role', 'service', 'operation', 'behavior']


class TemporalPolicy(StrictModel):
    min_seconds: PositiveInt = 5
    fallback_seconds: PositiveInt = 30
    max_seconds: PositiveInt = 300
    min_intervals: Annotated[int, Field(ge=2)] = 3

    @model_validator(mode='after')
    def bounds(self):
        if not self.min_seconds <= self.fallback_seconds <= self.max_seconds:
            raise ValueError('temporal_min_fallback_max_must_be_ordered')
        return self


class CommonEntityPolicy(StrictModel):
    min_count: Annotated[int, Field(ge=2)] = 10
    ratio: Annotated[float, Field(gt=0, le=1)] = 0.1


class CommunityConfig(StrictModel):
    version: Literal['community-v1']
    windows_seconds: dict[str, PositiveInt]
    max_community_span_seconds: PositiveInt
    max_community_members: Annotated[int, Field(ge=2)]
    max_weak_members: Annotated[int, Field(ge=2)]
    max_witnesses_per_key: PositiveInt
    max_candidates_per_alert: PositiveInt
    hot_host_min_count: PositiveInt
    hot_host_ratio: Annotated[float, Field(gt=0, le=1)]
    temporal: TemporalPolicy = Field(default_factory=TemporalPolicy)
    common_entities: CommonEntityPolicy = Field(default_factory=CommonEntityPolicy)
    projections: dict[str, dict[ProjectionKind, list[Pointer]]]

    @model_validator(mode='after')
    def policy(self):
        if set(self.windows_seconds) != {'1', '2', '3', '4', '5'}:
            raise ValueError('all_five_tier_windows_required')
        values = [self.windows_seconds[str(i)] for i in range(1, 6)]
        if values != sorted(values, reverse=True) or max(values) > self.max_community_span_seconds:
            raise ValueError('tier_windows_must_descend_within_lifetime')
        if self.max_weak_members > self.max_community_members:
            raise ValueError('weak_member_cap_exceeds_total_cap')
        if self.temporal.max_seconds > self.max_community_span_seconds:
            raise ValueError('temporal_max_exceeds_community_lifetime')
        for profile, fields in self.projections.items():
            if profile not in {'multisource_native_v1', 'suricata_eve_v1', 'wazuh_json_v1'}:
                raise ValueError('undeclared_projection_profile')
            for paths in fields.values():
                if not paths or len(paths) != len(set(paths)) or any(not p for p in paths):
                    raise ValueError('projection_requires_unique_nonroot_pointers')
        return self

    @property
    def digest(self):
        return content_digest(self.model_dump(mode='json'))


def load_community_config(path: str | Path) -> CommunityConfig:
    return CommunityConfig.model_validate(yaml.safe_load(Path(path).read_text(encoding='utf8')))

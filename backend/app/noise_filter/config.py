"""Strict YAML policy: exact background matches, no implicit allowlist."""
from datetime import time
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.config import read_yaml
from app.utils.stable_id import content_digest

DEFAULT_POLICY = Path(__file__).resolve().parents[3] / 'configs/noise-filter.yaml'
MatchField = Literal['source_type', 'source_namespace', 'alert_type', 'signature', 'rule_id',
                     'src_ip', 'dst_ip', 'host', 'process', 'path']
Text = Annotated[str, Field(min_length=1)]


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class TimePattern(PolicyModel):
    timezone: Literal['UTC'] = 'UTC'
    weekdays: list[Annotated[int, Field(ge=0, le=6)]] = Field(default_factory=lambda: list(range(7)))
    start: str = '00:00:00'
    end: str = '23:59:59.999999'

    @model_validator(mode='after')
    def valid(self):
        if not self.weekdays or len(set(self.weekdays)) != len(self.weekdays):
            raise ValueError('time_pattern_requires_unique_weekdays')
        for value in (self.start, self.end):
            parsed = time.fromisoformat(value)
            if parsed.tzinfo is not None:
                raise ValueError('time_pattern_uses_explicit_UTC_only')
        return self


class BackgroundRule(PolicyModel):
    rule_id: Text
    match: dict[MatchField, Text]
    time_pattern: TimePattern | None = None

    @model_validator(mode='after')
    def scoped(self):
        sources = {'source_type', 'source_namespace'}
        if not (sources & self.match.keys()) or not (self.match.keys() - sources):
            raise ValueError('background_rule_requires_source_and_explicit_fact')
        return self


class NoiseFilterConfig(PolicyModel):
    version: Literal['noise-filter-v1'] = 'noise-filter-v1'
    duplicate_window_seconds: Annotated[int, Field(ge=0, le=300)] = 2
    background_rules: list[BackgroundRule] = Field(default_factory=list)

    @model_validator(mode='after')
    def unique_rules(self):
        ids = [r.rule_id for r in self.background_rules]
        if len(ids) != len(set(ids)) or any(r.startswith('builtin:') for r in ids):
            raise ValueError('duplicate_or_reserved_noise_rule_id')
        return self

    @property
    def digest(self):
        return content_digest(self.model_dump(mode='json'))


def load_noise_config(path=DEFAULT_POLICY):
    return NoiseFilterConfig.model_validate(read_yaml(path))

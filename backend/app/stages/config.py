"""Separate versioned policy; no changes to Adapter Mapping v1 semantics."""
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
import yaml

from app.models.base import PositiveInt, Score, StrictModel, Text
from app.utils.stable_id import content_digest
from .models import Behavior

SemanticField = Literal['source_type', 'alert_type', 'signature', 'category',
    'action', 'process_name', 'executable', 'protocol', 'src_ip', 'dst_ip',
    'src_port', 'dst_port', 'command', 'file', 'url', 'severity', 'host', 'account', 'session',
    'pid', 'parent_pid', 'parent_process_name', 'parent_executable', 'method', 'status', 'domain']


class Condition(StrictModel):
    field: SemanticField
    op: Literal['in', 'exists']
    values: list[Text]

    @model_validator(mode='after')
    def shape(self):
        if (self.op == 'in' and not self.values) or (self.op == 'exists' and self.values):
            raise ValueError('invalid_behavior_condition')
        object.__setattr__(self, 'values', sorted(set(self.values)))
        return self


class BehaviorRule(StrictModel):
    id: Text
    all: Annotated[list[Condition], Field(min_length=1)]
    behavior: Behavior
    confidence: Score

    @model_validator(mode='after')
    def known(self):
        if self.behavior == 'UNKNOWN':
            raise ValueError('unknown_is_a_fallback_not_a_positive_rule')
        return self


class StageConfig(StrictModel):
    version: Literal['behavior-stage-v1']
    ai_confidence_threshold: Score
    max_stage_span_seconds: PositiveInt
    unknown_max_stage_span_seconds: PositiveInt
    semantic_max_field_chars: PositiveInt
    rules: list[BehaviorRule]

    @model_validator(mode='after')
    def policy(self):
        if len({r.id for r in self.rules}) != len(self.rules):
            raise ValueError('duplicate_behavior_rule_id')
        if self.unknown_max_stage_span_seconds > self.max_stage_span_seconds:
            raise ValueError('unknown_window_must_be_more_conservative')
        object.__setattr__(self, 'rules', sorted(self.rules, key=lambda r: r.id))
        return self

    @property
    def digest(self):
        return content_digest(self.model_dump(mode='json'))


def load_stage_config(path: str | Path):
    return StageConfig.model_validate(yaml.safe_load(Path(path).read_text(encoding='utf8')))

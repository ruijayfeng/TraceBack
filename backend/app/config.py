"""Task 001 configuration and Mapping File Contract v1; no alert pipeline."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field as dataclass_field
from decimal import Decimal
from hashlib import sha256
import json
import math
from pathlib import Path
from typing import Annotated, Any, Literal, get_args
import unicodedata
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator
import yaml


CategoryValue = Literal[
    "unknown", "reconnaissance", "initial_access", "web_attack", "authentication",
    "process_execution", "command_execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "command_and_control", "collection", "exfiltration", "impact",
]
EntityKey = Literal["IP", "HOST", "ACCOUNT", "SESSION", "PROCESS", "URL", "DOMAIN", "FILE", "COMMAND"]
SourceValue = Literal[
    "wazuh", "aminer", "suricata", "waf", "edr", "ids", "siem",
    "windows_security", "cloud_security", "other",
]
AlertRelationKey = Literal[
    "target_to_process", "parent_child_process", "account_host_pivot", "network_pivot", "session_continuity",
]
ChainRelationValue = Literal[
    "PROCESS_CAUSAL", "REQUEST_TO_PROCESS", "ACCOUNT_PIVOT", "NETWORK_PIVOT", "SESSION_FLOW",
]
ChannelKey = Literal["IP", "HOST", "ACCOUNT", "SESSION", "PROCESS", "URL", "DOMAIN", "FILE", "COMMAND", "explicit_relation"]
Fraction = Annotated[float, Field(strict=True, ge=0, le=1, allow_inf_nan=False)]
PositiveNumber = Annotated[float, Field(strict=True, gt=0, allow_inf_nan=False)]
NonnegativeNumber = Annotated[float, Field(strict=True, ge=0, allow_inf_nan=False)]
PositiveInt = Annotated[int, Field(strict=True, gt=0)]
NonnegativeInt = Annotated[int, Field(strict=True, ge=0)]
Text = Annotated[str, Field(strict=True, min_length=1)]


class ConfigurationError(ValueError):
    """Configuration is invalid; do not run an analysis."""


class MappingConflict(ConfigurationError):
    """Matching rules have different outputs; no ordered winner is permitted."""


class ConfigSection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_assignment=True)

    @model_validator(mode="before")
    @classmethod
    def strict_numeric_literals(cls, value):
        if isinstance(value, dict):
            for name, field in cls.model_fields.items():
                choices = get_args(field.annotation)
                if choices and all(type(c) in (int, float) for c in choices):
                    if name in value and type(value[name]) not in (int, float):
                        raise ValueError(f"{name} requires a number, not boolean/text")
        return value


def _unique(items: list, label: str) -> None:
    if len(items) != len(set(items)):
        raise ValueError(f"{label}: duplicate entries")


def _complete_keys(values: dict, expected: tuple, label: str) -> None:
    if set(values) != set(expected):
        raise ValueError(f"{label}: expected exactly {sorted(expected)}")


def _sum_one(values: list[float], label: str) -> None:
    if not math.isclose(math.fsum(values), 1.0, rel_tol=0, abs_tol=1e-12):
        raise ValueError(f"{label}: weights must sum to 1")


class NormalizationConfig(ConfigSection):
    timestamp_precision: Literal["microseconds"]
    missing_timestamp: Literal["quarantine"]
    missing_timezone: Literal["require_source_timezone"]
    unknown_category: Literal["unknown"]
    unknown_severity: Literal["unknown"]
    source_timezones: dict[Text, Text]
    host_aliases: dict[Text, Text]
    category_mapping_files: list[Text]
    category_priority: list[CategoryValue]
    severity_mapping_files: list[Text]

    @model_validator(mode="after")
    def check(self):
        _unique(self.category_priority, "category_priority")
        if set(self.category_priority) != set(get_args(CategoryValue)):
            raise ValueError("category_priority must cover every frozen category")
        for timezone in self.source_timezones.values():
            if timezone == "UTC":
                continue  # UTC needs no OS timezone database.
            try:
                ZoneInfo(timezone)
            except (ZoneInfoNotFoundError, ValueError) as exc:
                raise ValueError(f"invalid or unavailable source timezone: {timezone}") from exc
        return self


class CategoryPair(ConfigSection):
    from_category: CategoryValue
    to_category: CategoryValue


class WindowOverride(CategoryPair):
    window_seconds: PositiveInt


class HalfLifeRule(WindowOverride):
    half_life_seconds: PositiveInt


class BehaviorRule(CategoryPair):
    score: Fraction


def _check_pairs(rows: list[CategoryPair], label: str) -> None:
    _unique([(r.from_category, r.to_category) for r in rows], label)


class CandidateConfig(ConfigSection):
    time_only_window_seconds: PositiveInt
    default_window_seconds: PositiveInt
    max_window_seconds: PositiveInt
    source_complement_window_seconds: PositiveInt
    explicit_relation_window_seconds: PositiveInt
    behavior_override_channels: list[ChannelKey]
    behavior_window_overrides: list[WindowOverride]
    per_channel_neighbors: PositiveInt
    time_only_neighbors: PositiveInt
    max_neighbors_per_alert: PositiveInt
    max_candidate_pairs: PositiveInt
    overflow_policy: Literal["mark_incomplete"]
    hot_entity_ratio: Annotated[float, Field(strict=True, gt=0, le=1, allow_inf_nan=False)]
    hot_entity_min_count: PositiveInt
    hot_entity_neighbors: PositiveInt
    entity_windows_seconds: dict[EntityKey, PositiveInt]

    @model_validator(mode="after")
    def check(self):
        _complete_keys(self.entity_windows_seconds, get_args(EntityKey), "entity_windows_seconds")
        _unique(self.behavior_override_channels, "behavior_override_channels")
        _check_pairs(self.behavior_window_overrides, "behavior_window_overrides")
        windows = [self.time_only_window_seconds, self.default_window_seconds,
                   self.source_complement_window_seconds, self.explicit_relation_window_seconds,
                   *self.entity_windows_seconds.values(),
                   *(r.window_seconds for r in self.behavior_window_overrides)]
        if any(w > self.max_window_seconds for w in windows):
            raise ValueError("candidate window exceeds max_window_seconds")
        return self


class TimeConfig(ConfigSection):
    method: Literal["exponential_half_life"]
    default_half_life_seconds: PositiveInt
    clock_skew_seconds: NonnegativeNumber
    transition_half_lives: list[HalfLifeRule]

    @model_validator(mode="after")
    def check(self):
        _check_pairs(self.transition_half_lives, "transition_half_lives")
        return self


class RoleFactors(ConfigSection):
    same_role: Fraction
    src_dst_bridge: Fraction
    other_role: Fraction


class EntityConfig(ConfigSection):
    weights: dict[EntityKey, Fraction]
    role_factors: RoleFactors
    process_descriptor_factor: Fraction
    rarity_enabled: StrictBool
    rarity_floor: Fraction
    rarity_smoothing: PositiveNumber
    rarity_scope: Literal["analysis_representatives"]
    frequency_unit: Literal["dedupe_group"]
    max_contributors_per_type: PositiveInt

    @model_validator(mode="after")
    def check(self):
        _complete_keys(self.weights, get_args(EntityKey), "entity.weights")
        return self


class RelationConfig(ConfigSection):
    scores: dict[AlertRelationKey, Fraction]

    @model_validator(mode="after")
    def check(self):
        _complete_keys(self.scores, get_args(AlertRelationKey), "relation.scores")
        return self


class BehaviorConfig(ConfigSection):
    same_category: Fraction
    unknown_category: Literal[0.0]
    unlisted_transition: Fraction
    transitions: list[BehaviorRule]

    @model_validator(mode="after")
    def check(self):
        _check_pairs(self.transitions, "behavior.transitions")
        if any(r.from_category == "unknown" or r.to_category == "unknown" or
               r.from_category == r.to_category for r in self.transitions):
            raise ValueError("transitions cannot override unknown/same-category semantics")
        return self


class ComplementRule(ConfigSection):
    source_types: Annotated[list[SourceValue], Field(min_length=2, max_length=2)]
    condition: Text
    score: Fraction

    @model_validator(mode="after")
    def check(self):
        _unique(self.source_types, "complement source_types")
        return self


class SourceConfig(ConfigSection):
    same_sensor_score: Literal[0.0]
    same_type_independent_score: Fraction
    different_type_confirmed_independent_unlisted_score: Fraction
    unknown_independence_score: Literal[0.0]
    independence_mapping_files: list[Text]
    require_context_bridge: StrictBool
    forwarded_same_origin_score: Literal[0.0]
    complement_rules: list[ComplementRule]

    @model_validator(mode="after")
    def check(self):
        if not self.require_context_bridge:
            raise ValueError("source context bridge is a frozen prerequisite")
        _unique([tuple(sorted(r.source_types)) for r in self.complement_rules], "complement source pair")
        return self


class CorrelationWeights(ConfigSection):
    time: Fraction
    entity: Fraction
    relation: Fraction
    behavior: Fraction
    source: Fraction
    conflict: Fraction
    duplicate: Fraction

    @model_validator(mode="after")
    def check(self):
        _sum_one([self.time, self.entity, self.relation, self.behavior, self.source], "score")
        return self


class EvidenceGateConfig(ConfigSection):
    minimum_mass: Fraction
    temporal_support_minimum: Fraction
    semantic_support_minimum: Fraction
    topology_support_minimum: Fraction
    strong_entity_types: list[EntityKey]
    specific_entity_types: list[EntityKey]
    specific_minimum_rarity: Fraction
    strong_identifier_minimum_rarity: Fraction
    strong_minimum_strength: Fraction
    reject_hot_identifiers: StrictBool

    @model_validator(mode="after")
    def check(self):
        _unique(self.strong_entity_types, "strong_entity_types")
        _unique(self.specific_entity_types, "specific_entity_types")
        if not self.reject_hot_identifiers or "IP" in self.strong_entity_types or "DOMAIN" in self.strong_entity_types:
            raise ValueError("ordinary IP/domain and hot identities cannot independently satisfy the gate")
        return self


class EvidenceV2Config(ConfigSection):
    quality_factor: Fraction
    mass_factor: Fraction
    entity_quality_rarity_floor: Fraction
    semantic_weights: dict[Literal["category", "rule_id", "signature", "alert_type"], Fraction]
    semantic_candidate_fields: list[Literal["category", "rule_id", "signature", "alert_type"]]
    semantic_candidate_window_seconds: PositiveInt
    gate: EvidenceGateConfig

    @model_validator(mode="after")
    def check(self):
        _sum_one([self.quality_factor, self.mass_factor], "v2 quality/mass")
        _complete_keys(self.semantic_weights, ("category", "rule_id", "signature", "alert_type"), "semantic weights")
        _sum_one(list(self.semantic_weights.values()), "semantic weights")
        _unique(self.semantic_candidate_fields, "semantic candidate fields")
        return self


class TriageConfig(ConfigSection):
    weights: dict[Literal["severity", "category", "rarity"], Fraction]
    severity_scores: dict[Literal["informational", "low", "medium", "high", "critical"], Fraction]
    category_scores: dict[CategoryValue, Fraction]
    risk_thresholds: dict[Literal["medium", "high", "critical"], Fraction]
    rarity_smoothing: PositiveNumber
    rarity_only_cap: Fraction

    @model_validator(mode="after")
    def check(self):
        _complete_keys(self.weights, ("severity", "category", "rarity"), "triage weights")
        _sum_one(list(self.weights.values()), "triage weights")
        _complete_keys(self.severity_scores, ("informational", "low", "medium", "high", "critical"), "severity scores")
        _complete_keys(self.category_scores, get_args(CategoryValue), "category scores")
        _complete_keys(self.risk_thresholds, ("medium", "high", "critical"), "risk thresholds")
        if not 0 < self.risk_thresholds["medium"] < self.risk_thresholds["high"] < self.risk_thresholds["critical"] <= 1:
            raise ValueError("triage risk thresholds must increase")
        return self


class EvidenceV3Config(ConfigSection):
    reliability_floor: Fraction
    frequency_population_floor: PositiveInt
    primary_minimum_reliability: Fraction
    metadata_cap: Fraction
    network_strength: Fraction
    network_behavior_minimum: Fraction
    weak_resource_descriptor_factor: Fraction = 1.0


class EvidenceV4Config(ConfigSection):
    destination_only_ip_factor: Fraction
    metadata_support_fields: list[Literal['category', 'rule_id', 'signature']]
    primary_detector_fields: list[Literal['rule_id', 'signature']]
    network_require_behavior_transition: Literal[True]

    @model_validator(mode='after')
    def check(self):
        _unique(self.metadata_support_fields, 'v4 metadata support fields')
        _unique(self.primary_detector_fields, 'v4 primary detector fields')
        if not self.metadata_support_fields or not self.primary_detector_fields:
            raise ValueError('v4 evidence whitelists must be nonempty')
        return self


class ObservationConfig(ConfigSection):
    message_pointers: dict[SourceValue, list[Text]]
    event_pointers: dict[SourceValue, dict[Literal['flow_id', 'transaction_id', 'protocol', 'event_time'], list[Text]]] = Field(default_factory=dict)
    window_seconds: PositiveNumber
    minimum_context_matches: PositiveInt
    equivalence_score: Fraction

    @model_validator(mode="after")
    def check(self):
        from app.models.base import pointer_text
        pointer_lists = list(self.message_pointers.values()) + [p for fields in self.event_pointers.values() for p in fields.values()]
        for pointers in pointer_lists:
            _unique(pointers, "observation message pointers")
            for pointer in pointers:
                pointer_text(pointer)
                if not pointer or any(token in pointer.lower() for token in ("label", "ground_truth", "attack_timeline", "gold_chain")):
                    raise ValueError("observation pointers must reference embedded alert messages")
        return self


class EvidenceV5Config(ConfigSection):
    formula: Literal['F3-independent-support-v1','evidence-semantics-v1']
    time_floor: Fraction
    weak_ceiling: Fraction
    strong_identifier_minimum: Fraction
    conflict_weight: Fraction
    duplicate_weight: Fraction
    reliability: dict[Text,Fraction]

    @model_validator(mode='after')
    def check_reliability(self):
        _complete_keys(self.reliability, ('IP','HOST','ACCOUNT','SESSION','PROCESS','URL','DOMAIN','FILE','COMMAND',
            'role_host','role_account','monitored_endpoint','attested_relation','flow','time','behavior','source'), 'v5 reliability')
        return self


class ScoreConfig(ConfigSection):
    weights: CorrelationWeights
    correlation_threshold: Fraction
    require_non_time_support: StrictBool
    evidence_v2: EvidenceV2Config | None = None
    evidence_v3: EvidenceV3Config | None = None
    evidence_v4: EvidenceV4Config | None = None
    evidence_v5: EvidenceV5Config | None = None

    @model_validator(mode="after")
    def check(self):
        if not self.require_non_time_support:
            raise ValueError("non-time support is a frozen prerequisite")
        return self


class DuplicateWeights(ConfigSection):
    rule: Fraction
    payload: Fraction
    target: Fraction
    time: Fraction

    @model_validator(mode="after")
    def check(self):
        _sum_one(list(self.model_dump().values()), "duplicate")
        return self


class DuplicateConfig(ConfigSection):
    candidate_indexes: list[Literal["source_record", "origin_record", "payload_target_rule_time"]]
    window_seconds: PositiveInt
    half_life_seconds: PositiveInt
    threshold: Fraction
    suspected_floor: Annotated[float, Field(strict=True, ge=0, lt=1, allow_inf_nan=False)]
    feature_weights: DuplicateWeights
    require_payload_and_target: StrictBool
    grouping: Literal["complete_link"]
    representative: Literal["minimum_alert_id"]
    payload_mapping_files: list[Text]
    rule_equivalence_mapping_files: list[Text]
    observation: ObservationConfig | None = None

    @model_validator(mode="after")
    def check(self):
        expected = {"source_record", "origin_record", "payload_target_rule_time"}
        _unique(self.candidate_indexes, "duplicate.candidate_indexes")
        if set(self.candidate_indexes) != expected:
            raise ValueError("all three frozen duplicate indexes are required")
        if not self.require_payload_and_target:
            raise ValueError("payload and target are frozen duplicate prerequisites")
        if self.suspected_floor >= self.threshold:
            raise ValueError("suspected_floor must be below duplicate.threshold")
        weights = self.feature_weights.model_dump()
        for missing in ("rule", "payload", "target"):
            upper_bound = math.fsum(v for k, v in weights.items() if k != missing)
            if upper_bound >= self.threshold:
                raise ValueError(f"duplicate indexes need revision: missing {missing} can reach threshold")
        return self


class ConflictStrengths(ConfigSection):
    different_target_without_bridge: Fraction
    no_context_bridge: Fraction
    beyond_behavior_window: Fraction
    reversed_explicit_relation: Fraction
    incompatible_session: Fraction


class ConflictConfig(ConfigSection):
    combine: Literal["maximum"]
    hard_rules: list[Literal["cross_namespace_without_bridge", "verified_incompatible_session"]]
    strengths: ConflictStrengths

    @model_validator(mode="after")
    def check(self):
        _unique(self.hard_rules, "hard_rules")
        if set(self.hard_rules) != {"cross_namespace_without_bridge", "verified_incompatible_session"}:
            raise ValueError("frozen hard guards cannot be removed")
        return self


class ClusteringConfig(ConfigSection):
    method: Literal["controlled_components"]
    edge_threshold: Fraction
    max_incident_span_seconds: PositiveInt
    max_representatives: PositiveInt
    bridge_min_edges_between_non_singletons: PositiveInt
    bridge_min_edges_with_singleton: PositiveInt
    bridge_min_edges_between_singletons: PositiveInt
    permit_explicit_relation_single_bridge: StrictBool
    reject_component_hard_conflict: StrictBool
    keep_singletons: StrictBool

    @model_validator(mode="after")
    def check(self):
        if self.bridge_min_edges_between_non_singletons < 2 or self.bridge_min_edges_with_singleton < 2:
            raise ValueError("ordinary component attachment requires at least two support pairs")
        if self.bridge_min_edges_between_singletons != 1:
            raise ValueError("singleton bootstrap requires one support pair")
        if not self.reject_component_hard_conflict or not self.keep_singletons:
            raise ValueError("hard conflicts and singleton preservation cannot be disabled")
        return self


class DirectionWeights(ConfigSection):
    chronology: Fraction
    relation: Fraction
    behavior: Fraction
    source: Fraction

    @model_validator(mode="after")
    def check(self):
        _sum_one(list(self.model_dump().values()), "direction")
        return self


class ChainConfig(ConfigSection):
    edge_threshold: Fraction
    direction_threshold: Fraction
    direction_margin: Fraction
    require_explicit_propagation: StrictBool
    direction_weights: DirectionWeights
    explicit_relation_minimum: Fraction
    relation_type_mapping: dict[AlertRelationKey, ChainRelationValue]
    relation_priority: list[AlertRelationKey]
    merge_synonymous_actions: StrictBool
    node_confidence_base: Fraction
    node_confidence_category_bonus: Fraction
    node_confidence_context_bonus: Fraction
    node_confidence_independent_source_bonus: Fraction
    node_confidence_cap: Fraction
    graph_policy: Literal["dag"]
    cycle_policy: Literal["descending_confidence_then_edge_id"]

    @model_validator(mode="after")
    def check(self):
        # This literal is a frozen enum mapping, not a second set of algorithm defaults.
        expected = dict(zip(
            ("parent_child_process", "target_to_process", "account_host_pivot", "network_pivot", "session_continuity"),
            ("PROCESS_CAUSAL", "REQUEST_TO_PROCESS", "ACCOUNT_PIVOT", "NETWORK_PIVOT", "SESSION_FLOW"),
        ))
        if self.relation_type_mapping != expected or self.relation_priority != list(expected):
            raise ValueError("v0 chain relation mapping/priority is frozen")
        if not self.require_explicit_propagation:
            raise ValueError("explicit propagation is a frozen prerequisite")
        if self.node_confidence_base > self.node_confidence_cap:
            raise ValueError("node confidence base exceeds cap")
        return self


class EvaluationConfig(ConfigSection):
    baseline_window_seconds: PositiveInt
    thresholds: Annotated[list[Fraction], Field(min_length=1)]
    window_multipliers: Annotated[list[PositiveNumber], Field(min_length=1)]
    weight_multipliers: Annotated[list[PositiveNumber], Field(min_length=1)]
    noise_ratios: Annotated[list[NonnegativeNumber], Field(min_length=1)]
    seed: NonnegativeInt

    @model_validator(mode="after")
    def check(self):
        for key in ("thresholds", "window_multipliers", "weight_multipliers", "noise_ratios"):
            _unique(getattr(self, key), f"evaluation.{key}")
        return self


class AlgorithmConfig(ConfigSection):
    version: Literal["v0", "v2", "v3", "v4"]
    # Execution identity is independent of the retained v4 scoring dispatch.
    implementation_version: Literal['v5-preformula-candidate-v1','v5-formula-f3-v1','v5-evidence-semantics-v1'] | None = None
    normalization: NormalizationConfig
    candidate: CandidateConfig
    time: TimeConfig
    entity: EntityConfig
    relation: RelationConfig
    behavior: BehaviorConfig
    source: SourceConfig
    score: ScoreConfig
    duplicate: DuplicateConfig
    conflict: ConflictConfig
    clustering: ClusteringConfig
    chain: ChainConfig
    evaluation: EvaluationConfig
    single_alert_triage: TriageConfig | None = None

    @model_validator(mode="after")
    def check(self):
        v5=self.implementation_version in {'v5-formula-f3-v1','v5-evidence-semantics-v1'}
        if v5 != (self.score.evidence_v5 is not None):
            raise ValueError('V5 formula requires explicit implementation and V5 policy')
        if v5 and ((self.implementation_version=='v5-evidence-semantics-v1') !=
                   (self.score.evidence_v5.formula=='evidence-semantics-v1')):
            raise ValueError('V5 policy/implementation mismatch')
        if self.implementation_version is not None and self.version != 'v4':
            raise ValueError('preformula implementation requires frozen v4 scoring')
        if self.version in {"v2", "v3", "v4"}:
            if self.score.evidence_v2 is None or self.single_alert_triage is None:
                raise ValueError("v2 requires evidence and independent triage configuration")
            if self.score.evidence_v2.semantic_candidate_window_seconds > self.candidate.max_window_seconds:
                raise ValueError("semantic candidate window exceeds maximum")
        elif self.score.evidence_v2 is not None or self.single_alert_triage is not None:
            raise ValueError("v2 features require explicit v2 configuration")
        if self.version in {"v3", "v4"}:
            if self.score.evidence_v3 is None or self.duplicate.observation is None:
                raise ValueError("v3 requires evidence independence and observation configuration")
            if not v5 and self.score.correlation_threshold != 0.65:
                raise ValueError("v3 repair keeps the 0.65 threshold")
            if self.duplicate.observation.equivalence_score < self.duplicate.threshold:
                raise ValueError("observation score cannot be below dedupe threshold")
        elif self.score.evidence_v3 is not None or self.duplicate.observation is not None:
            raise ValueError("v3 features require explicit v3 version")
        if self.version == 'v4':
            if self.score.evidence_v4 is None or not self.duplicate.observation.event_pointers:
                raise ValueError('v4 requires explicit context policy and flow provenance')
        elif self.score.evidence_v4 is not None:
            raise ValueError('v4 context policy requires explicit v4 version')
        if self.clustering.edge_threshold < self.score.correlation_threshold:
            raise ValueError("clustering threshold is below correlation threshold")
        if self.chain.edge_threshold < self.score.correlation_threshold:
            raise ValueError("chain threshold is below correlation threshold")
        if any(r.window_seconds > self.candidate.max_window_seconds for r in self.time.transition_half_lives):
            raise ValueError("behavior reasonable window exceeds max_window_seconds")
        return self


MappingType = Literal["category", "severity", "payload", "source_independence", "rule_equivalence"]
SeverityValue = Literal["unknown", "informational", "low", "medium", "high", "critical"]
PayloadField = Literal[
    "source_type", "rule_id", "alert_type", "signature", "src_ip", "dst_ip",
    "src_port", "dst_port", "host", "account", "session", "process",
    "parent_process", "url", "domain", "file", "command",
]
_CATEGORY_FIELDS = frozenset((
    "source_type", "source_namespace", "sensor", "rule_id", "alert_type",
    "signature", "vendor_category", "raw_severity", "rule_groups",
))
MAPPING_FIELDS = {
    "category": _CATEGORY_FIELDS,
    "severity": _CATEGORY_FIELDS,
    "payload": frozenset(get_args(PayloadField)),
    "source_independence": frozenset(
        f"{side}.{name}" for side in ("left", "right")
        for name in ("source_type", "source_namespace", "sensor", "origin_namespace")
    ),
    "rule_equivalence": frozenset((
        "source_type", "source_namespace", "rule_id", "alert_type", "signature",
    )),
}
MAPPING_REFERENCES = (
    ("normalization", "category_mapping_files", "category"),
    ("normalization", "severity_mapping_files", "severity"),
    ("duplicate", "payload_mapping_files", "payload"),
    ("source", "independence_mapping_files", "source_independence"),
    ("duplicate", "rule_equivalence_mapping_files", "rule_equivalence"),
)


def _json_parameter(value: Any, ancestors: frozenset[int] = frozenset()) -> Any:
    """Validate JSON without Pydantic/YAML scalar coercions or runtime objects."""
    if type(value) is str:
        return unicodedata.normalize("NFC", value)
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if type(value) in (dict, list):
        if id(value) in ancestors:
            raise ValueError("recursive mapping JSON")
        ancestors = ancestors | {id(value)}
        if isinstance(value, dict):
            if any(type(key) is not str for key in value):
                raise ValueError("mapping JSON keys must be strings")
            result = {}
            for key, child in value.items():
                key = unicodedata.normalize("NFC", key)
                if key in result:
                    raise ValueError("mapping JSON keys collide after Unicode NFC")
                result[key] = _json_parameter(child, ancestors)
            return result
        else:
            return [_json_parameter(child, ancestors) for child in value]
    raise ValueError("mapping parameters must be finite JSON values")


class EqCondition(ConfigSection):
    field: Text
    op: Literal["eq"]
    value: Any

    @field_validator("value")
    @classmethod
    def check_json(cls, value):
        return _json_parameter(value)


class InCondition(ConfigSection):
    field: Text
    op: Literal["in"]
    values: Annotated[list[Any], Field(min_length=1)]

    @field_validator("values")
    @classmethod
    def check_json(cls, value):
        return _json_parameter(value)


class ContainsCondition(EqCondition):
    op: Literal["contains"]


class ExistsCondition(ConfigSection):
    field: Text
    op: Literal["exists"]
    value: StrictBool


class RangeCondition(ConfigSection):
    field: Text
    op: Literal["range"]
    min: Annotated[int | float, Field(allow_inf_nan=False)]
    max: Annotated[int | float, Field(allow_inf_nan=False)]

    @model_validator(mode="after")
    def check_bounds(self):
        if self.min > self.max:
            raise ValueError("range min must not exceed max")
        return self


MappingCondition = Annotated[
    EqCondition | InCondition | ContainsCondition | ExistsCondition | RangeCondition,
    Field(discriminator="op"),
]


class MappingMatch(ConfigSection):
    all: list[MappingCondition]


class MappingRule(ConfigSection):
    id: Text
    match: MappingMatch
    output: Any

    @field_validator("id")
    @classmethod
    def normalize_id(cls, value):
        return unicodedata.normalize("NFC", value)


class PayloadOutput(ConfigSection):
    fields: Annotated[list[PayloadField], Field(min_length=1)]

    @model_validator(mode="after")
    def check_fields(self):
        _unique(self.fields, "payload fields")
        self.fields.sort()
        return self


class EquivalenceOutput(ConfigSection):
    equivalence_key: Text


class MappingFile(ConfigSection):
    """Configuration schema only; does not extract or normalize alert fields."""

    schema_version: Literal["1.0"]
    mapping_type: MappingType
    source_type: SourceValue
    default: Any
    rules: list[MappingRule]

    @model_validator(mode="after")
    def check_contract(self):
        expected_default = "unknown" if self.mapping_type in (
            "category", "severity", "source_independence"
        ) else None
        if type(self.default) is not type(expected_default) or self.default != expected_default:
            raise ValueError(f"illegal {self.mapping_type} default")
        _unique([rule.id for rule in self.rules], "mapping rule id")
        for rule in self.rules:
            if any(c.field not in MAPPING_FIELDS[self.mapping_type] for c in rule.match.all):
                raise ValueError(f"illegal {self.mapping_type} match field")
            if self.mapping_type in ("category", "severity", "source_independence"):
                allowed = (get_args(CategoryValue) if self.mapping_type == "category" else
                           get_args(SeverityValue) if self.mapping_type == "severity" else
                           ("confirmed_independent",))
                if type(rule.output) is not str or rule.output not in allowed:
                    raise ValueError(f"illegal {self.mapping_type} output")
            elif self.mapping_type == "payload":
                rule.output = PayloadOutput.model_validate(rule.output).model_dump()
            else:
                rule.output = _json_parameter(EquivalenceOutput.model_validate(rule.output).model_dump())
        self.rules.sort(key=lambda rule: rule.id)
        return self


_MISSING = object()


def _strict_equal(left: Any, right: Any) -> bool:
    # JSON numbers share numeric semantics; bool is a separate JSON type.
    if type(left) in (int, float) and type(right) in (int, float):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_strict_equal(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_strict_equal(a, b) for a, b in zip(left, right))
    return left == right


def _condition_matches(condition: MappingCondition, value: Any) -> bool:
    if condition.op == "exists":
        return (value is not _MISSING and value is not None) == condition.value
    if value is _MISSING:
        return False
    if condition.op == "eq":
        return _strict_equal(value, condition.value)
    if condition.op == "in":
        return type(value) in (str, bool, int, float, type(None)) and any(
            _strict_equal(value, item) for item in condition.values
        )
    if condition.op == "contains":
        return type(value) is list and any(_strict_equal(item, condition.value) for item in value)
    finite_number = type(value) is int or (type(value) is float and math.isfinite(value))
    return finite_number and condition.min <= value <= condition.max


def _provable_overlap(left: MappingRule, right: MappingRule) -> bool:
    """Fail at load time when a concrete witness proves both rules can match.

    Fields are independent AND predicates. Lack of a witness is not a proof of
    disjointness: resolution still checks every actual input for conflicts.
    """
    by_field: dict[str, list] = {}
    for condition in (*left.match.all, *right.match.all):
        by_field.setdefault(condition.field, []).append(condition)
    for conditions in by_field.values():
        candidates = [_MISSING, None, True, 0, ""]
        required_members = []
        for condition in conditions:
            if condition.op in ("eq", "contains"):
                candidates.append(condition.value)
                if condition.op == "contains":
                    required_members.append(condition.value)
            elif condition.op == "in":
                candidates.extend(condition.values)
            elif condition.op == "range":
                candidates.extend((condition.min, condition.max))
        candidates.append(required_members)
        if not any(all(_condition_matches(c, value) for c in conditions) for value in candidates):
            return False
    return True


def load_mapping_file(path: str | Path, *, expected_type: MappingType | None = None) -> MappingFile:
    mapping = MappingFile.model_validate(read_yaml(path))
    if expected_type is not None and mapping.mapping_type != expected_type:
        raise ConfigurationError(f"mapping_type {mapping.mapping_type} is incompatible with {expected_type} reference")
    if mapping.mapping_type != "category":
        for index, left in enumerate(mapping.rules):
            for right in mapping.rules[index + 1:]:
                if _digest(left.output) != _digest(right.output) and _provable_overlap(left, right):
                    raise MappingConflict(f"{mapping.mapping_type}: conflicting rules {left.id}, {right.id}")
    return mapping


@dataclass(frozen=True)
class MappingResolution:
    """Resolved config output/provenance, not a CanonicalAlert or domain model."""

    mapping_type: str
    output: Any
    matched_rule_ids: tuple[str, ...]
    mapping_digest: str
    payload_fingerprint: str | None = None
    blocked_by_same_origin: bool = False


def resolve_mapping(mapping: MappingFile, context: dict[str, Any], *,
                    category_priority: list[str] | None = None,
                    confirmed_same_origin: bool = False) -> MappingResolution:
    """Evaluate only frozen predicates against caller-provided controlled context.

    The caller selects the source mapping and supplies extracted facts; this
    function never traverses raw_alert, reads data or infers detector lineage.
    confirmed_same_origin carries an already verified same-origin/lineage guard.
    """
    mapping = MappingFile.model_validate(mapping.model_dump())
    if type(context) is not dict or type(confirmed_same_origin) is not bool:
        raise ConfigurationError("controlled mapping context/guard has invalid type")
    # Validate only the frozen context fields; never traverse arbitrary raw paths.
    try:
        context = {name: _json_parameter(context[name]) for name in MAPPING_FIELDS[mapping.mapping_type]
                   if name in context}
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc
    hits = [rule for rule in mapping.rules if all(
        _condition_matches(c, context.get(c.field, _MISSING)) for c in rule.match.all
    )]
    outputs = {_digest(rule.output): rule.output for rule in hits}
    if len(outputs) > 1:
        if mapping.mapping_type != "category":
            raise MappingConflict(f"{mapping.mapping_type}: conflicting rules {', '.join(r.id for r in hits)}")
        if category_priority is None or set(category_priority) != set(get_args(CategoryValue)) or len(
            category_priority
        ) != len(get_args(CategoryValue)):
            raise ConfigurationError("category resolution requires complete normalization.category_priority")
        output = min(outputs.values(), key=category_priority.index)
    else:
        output = next(iter(outputs.values()), mapping.default)
    fingerprint = None
    blocked = False
    if mapping.mapping_type == "source_independence":
        left = context.get("left.origin_namespace")
        right = context.get("right.origin_namespace")
        blocked = confirmed_same_origin or (type(left) is str and bool(left) and _strict_equal(left, right))
        if blocked:
            output = mapping.default  # A config declaration cannot override verified lineage.
    if mapping.mapping_type == "payload" and output is not None:
        fields = output["fields"]
        if all(name in context and context[name] is not None for name in fields):
            fingerprint = _digest({name: context[name] for name in fields})
    return MappingResolution(mapping.mapping_type, deepcopy(output), tuple(sorted(r.id for r in hits)),
                             _digest(mapping.model_dump()), fingerprint, blocked)


def rule_equivalent(left: MappingResolution, right: MappingResolution) -> bool:
    """Compare declared equivalence keys only; no rule/signature similarity."""
    if left.mapping_type != "rule_equivalence" or right.mapping_type != "rule_equivalence":
        raise ConfigurationError("rule equivalence requires rule_equivalence resolutions")
    left_key = left.output["equivalence_key"] if left.output is not None else None
    right_key = right.output["equivalence_key"] if right.output is not None else None
    return bool(left_key) and _strict_equal(left_key, right_key)


class _UniqueKeyLoader(yaml.SafeLoader):
    """Reject duplicate keys, including implicit YAML merges, at every depth."""

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise ConfigurationError("YAML merge keys are not explicit overrides")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ConfigurationError("YAML keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def read_yaml(path: str | Path) -> dict[str, Any]:
    """Read configuration YAML only; no alert or evaluation inputs are read."""
    resolved = Path(path).resolve()
    if resolved.suffix.lower() not in (".yaml", ".yml") or any(
        part.lower() in ("data", "evaluation") for part in resolved.parts
    ):
        raise ConfigurationError("configuration path must be YAML outside data/evaluation")
    try:
        content = resolved.read_text(encoding="utf-8")
        result = yaml.load(content, Loader=_UniqueKeyLoader)
    except (OSError, yaml.YAMLError, RecursionError) as exc:
        raise ConfigurationError(f"cannot read configuration YAML: {path}") from exc
    if not isinstance(result, dict):
        raise ConfigurationError("configuration YAML must contain an object")
    return result


def _merge(base: dict, override: dict, location: str = "") -> dict:
    """Recursive mapping overrides; arrays/scalars replace, never append.

    Dynamic keys are limited to the two declared deployment dictionaries.
    Validation after merging checks their types and all required fields.
    """
    result = deepcopy(base)
    for key, value in override.items():
        if key not in base and location not in ("normalization.source_timezones", "normalization.host_aliases"):
            raise ConfigurationError(f"unknown override key: {location}.{key}")
        child = f"{location}.{key}".lstrip(".")
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            result[key] = _merge(base[key], value, child)
        else:
            result[key] = deepcopy(value)
    return result


def _canonical_value(value: Any) -> Any:
    # Config digest uses DATA_CONTRACT §2 NFC/key/decimal normalization only.
    # This is not the domain Stable ID implementation scheduled for Task 002.
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            normalized = unicodedata.normalize("NFC", key)
            if normalized in result:
                raise ConfigurationError("configuration keys collide after Unicode NFC")
            result[normalized] = _canonical_value(child)
        return result
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ConfigurationError("non-finite configuration number")
        return value
    return value


def _canonical_json(value: Any) -> str:
    """Canonical config/payload JSON with decimal *numbers*, not identity tags.

    Config and payload digests are not domain Stable IDs. Keeping numbers as
    JSON numbers avoids aliasing a number with a legal {"$decimal": ...} object.
    """
    if isinstance(value, dict):
        return "{" + ",".join(
            f"{_canonical_json(key)}:{_canonical_json(value[key])}" for key in sorted(value)
        ) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if isinstance(value, float):
        decimal = Decimal(str(value))
        return "0" if decimal.is_zero() else format(decimal.normalize(), "f")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    encoded = _canonical_json(_canonical_value(value)).encode("utf-8")
    return sha256(encoded).hexdigest()


def _snapshot(config: AlgorithmConfig) -> dict:
    snapshot = config.model_dump()
    if config.score.evidence_v5 is None:
        snapshot['score'].pop('evidence_v5',None)
    if config.implementation_version is None:
        snapshot.pop('implementation_version')
    if config.version in {'v3', 'v4'}:
        if 'event_pointers' not in config.duplicate.observation.model_fields_set:
            snapshot['duplicate']['observation'].pop('event_pointers')
        if 'weak_resource_descriptor_factor' not in config.score.evidence_v3.model_fields_set:
            snapshot['score']['evidence_v3'].pop('weak_resource_descriptor_factor')
    if config.version not in {"v3", "v4"}:
        snapshot["score"].pop("evidence_v3", None)
        snapshot["duplicate"].pop("observation", None)
    if config.version != 'v4':
        snapshot['score'].pop('evidence_v4', None)
    else:
        for field in ('metadata_support_fields', 'primary_detector_fields'):
            snapshot['score']['evidence_v4'][field].sort()
    if config.version == "v0":
        snapshot.pop("single_alert_triage", None)
        snapshot["score"].pop("evidence_v2", None)
    else:
        for field in ("semantic_candidate_fields",):
            snapshot["score"]["evidence_v2"][field].sort()
        for field in ("strong_entity_types", "specific_entity_types"):
            snapshot["score"]["evidence_v2"]["gate"][field].sort()
    for section, key in (("candidate", "behavior_override_channels"),
                         ("duplicate", "candidate_indexes"), ("conflict", "hard_rules")):
        snapshot[section][key].sort()
    for section, key in (("candidate", "behavior_window_overrides"),
                         ("time", "transition_half_lives"), ("behavior", "transitions")):
        snapshot[section][key].sort(key=lambda row: (row["from_category"], row["to_category"]))
    for row in snapshot["source"]["complement_rules"]:
        row["source_types"].sort()
    snapshot["source"]["complement_rules"].sort(key=lambda row: tuple(row["source_types"]))
    return snapshot


@dataclass(frozen=True)
class EffectiveConfig:
    """Defensive serialized snapshot; callers cannot mutate its digest basis."""

    _snapshot_json: str
    config_hash: str
    config_digest: str
    mapping_digest: str
    _algorithm_json: str = dataclass_field(repr=False, compare=False)

    @property
    def snapshot(self) -> dict:
        return json.loads(self._snapshot_json)

    @property
    def algorithm(self) -> AlgorithmConfig:
        return AlgorithmConfig.model_validate(json.loads(self._algorithm_json))

    @property
    def mapping_files(self) -> dict[str, tuple[MappingFile, ...]]:
        snapshot = self.snapshot
        return {f"{section}.{key}": tuple(MappingFile.model_validate(content) for content in snapshot[section][key])
                for section, key, _ in MAPPING_REFERENCES}


def _expand_mapping_files(config: AlgorithmConfig, origins: dict[tuple[str, str], Path]) -> dict:
    snapshot = _snapshot(config)
    for section, key, mapping_type in MAPPING_REFERENCES:
        expanded = []
        for reference in getattr(getattr(config, section), key):
            path = Path(reference)
            if not path.is_absolute():
                path = origins[(section, key)] / path
            mapping = load_mapping_file(path, expected_type=mapping_type)
            # Category/severity defaults follow the currently effective normalization.
            if mapping_type in ("category", "severity") and mapping.default != getattr(
                config.normalization, f"unknown_{mapping_type}"
            ):
                raise ConfigurationError(f"{mapping_type} default differs from normalization")
            expanded.append(mapping.model_dump())
        # Reference names, locations and filesystem traversal never enter the snapshot.
        snapshot[section][key] = sorted(expanded, key=_digest)
    return snapshot


def load_config(baseline: str | Path, *, deployment_override: str | Path | None = None,
                experiment_override: str | Path | None = None) -> EffectiveConfig:
    """Load baseline → explicit deployment → explicit experiment, fail fast.

    Mapping references are relative to the YAML file declaring that list.
    Effective snapshots replace references with all validated mapping contents.
    """
    value = read_yaml(baseline)
    # A partial override cannot hide missing/invalid baseline parameters.
    origins = {(section, key): Path(baseline).resolve().parent for section, key, _ in MAPPING_REFERENCES}
    config = AlgorithmConfig.model_validate(value)
    snapshot = _expand_mapping_files(config, origins)
    for override in (deployment_override, experiment_override):
        if override is not None:
            layer = read_yaml(override)
            value = _merge(value, layer)
            for section, key, _ in MAPPING_REFERENCES:
                if isinstance(layer.get(section), dict) and key in layer[section]:
                    origins[(section, key)] = Path(override).resolve().parent
            config = AlgorithmConfig.model_validate(value)
            snapshot = _expand_mapping_files(config, origins)
    mappings = [mapping for section, key, _ in MAPPING_REFERENCES for mapping in snapshot[section][key]]
    digest = _digest(snapshot)
    return EffectiveConfig(json.dumps(snapshot, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":"), allow_nan=False), digest, digest,
                           _digest(sorted(mappings, key=_digest)),
                           json.dumps(config.model_dump(), ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":"), allow_nan=False))

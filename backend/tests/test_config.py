"""Task 001 configuration tests. Fixtures are configuration, never alerts/labels."""

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from pydantic import ValidationError
import pytest
import yaml

from app.config import (
    AlgorithmConfig, ConfigurationError, MappingConflict, MappingFile, MAPPING_FIELDS,
    MAPPING_REFERENCES, load_config, load_mapping_file, read_yaml, resolve_mapping, rule_equivalent,
)


ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "configs/algorithm-v0.yaml"


@pytest.fixture
def baseline():
    return read_yaml(BASELINE)


def write_yaml(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(value, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path


def set_value(value, path, replacement):
    keys = path.split(".")
    for key in keys[:-1]:
        value = value[key]
    value[keys[-1]] = replacement


def test_baseline_defaults_match_frozen_document(baseline):
    text = (ROOT / "docs/ALGORITHM_CONFIG.md").read_text(encoding="utf-8")
    documented = yaml.safe_load(re.search(r"```yaml\n(.*?)\n```", text, re.S).group(1))
    expanded = deepcopy(baseline)
    # These three lists are explicitly expanded from the document's subsequent tables.
    for section, key in (("time", "transition_half_lives"),
                         ("behavior", "transitions"), ("source", "complement_rules")):
        expanded[section][key] = []
    assert expanded == documented


def test_all_table_entries_match_document(baseline):
    text = (ROOT / "docs/ALGORITHM_CONFIG.md").read_text(encoding="utf-8")
    time_section = text.split("### 4.1 TimeScore")[1].split("### 4.2")[0]
    expected_time = set(re.findall(r"\| (\w+) → (\w+) \| (\d+) \| (\d+) \|", time_section))
    actual_time = {(r["from_category"], r["to_category"], str(r["half_life_seconds"]),
                    str(r["window_seconds"])) for r in baseline["time"]["transition_half_lives"]}
    assert actual_time == expected_time
    assert len(actual_time) == 7
    behavior_section = text.split("### 4.4 BehaviorCompatibilityScore")[1].split("### 4.5")[0]
    expected_behavior = {(a, b, float(s)) for a, b, s in
                         re.findall(r"\| (\w+) \| (\w+) \| ([0-9.]+) \|", behavior_section)}
    actual_behavior = {(r["from_category"], r["to_category"], r["score"])
                       for r in baseline["behavior"]["transitions"]}
    assert actual_behavior == expected_behavior
    assert len(actual_behavior) == 23
    source_section = text.split("### 4.5 SourceComplementScore")[1].split("### 4.6")[0]
    expected_source = {(tuple(sorted((a, b))), condition, float(score)) for a, b, condition, score in
                       re.findall(r"\| (\w+) \+ (\w+) \| (.*?) \| ([0-9.]+) \|", source_section)}
    actual_source = {(tuple(sorted(r["source_types"])), r["condition"], r["score"])
                     for r in baseline["source"]["complement_rules"]}
    assert actual_source == expected_source
    assert len(actual_source) == 5


def test_load_and_round_trip(tmp_path):
    effective = load_config(BASELINE, deployment_override=ROOT / "configs/sources.yaml")
    restored_input = effective.snapshot
    for section, key, _ in MAPPING_REFERENCES:
        references = []
        for index, mapping in enumerate(restored_input[section][key]):
            path = write_yaml(tmp_path, f"{section}-{key}-{index}.yaml", mapping)
            references.append(path.name)
        restored_input[section][key] = references
    saved = write_yaml(tmp_path, "snapshot.yaml", restored_input)
    restored = load_config(saved)
    assert restored == effective
    assert restored.snapshot == effective.snapshot
    assert restored.config_hash == effective.config_hash
    assert restored.config_digest == effective.config_digest
    assert restored.mapping_digest == effective.mapping_digest
    assert effective.config_hash == effective.config_digest
    assert re.fullmatch("[0-9a-f]{64}", effective.mapping_digest)
    declared = read_yaml(ROOT / "configs/sources.yaml")["normalization"]
    assert effective.algorithm.normalization.source_timezones == declared["source_timezones"]
    assert effective.algorithm.normalization.host_aliases == {}


def test_override_priority_and_arrays_replace(tmp_path):
    deployment = write_yaml(tmp_path, "deployment.yaml", {
        "score": {"correlation_threshold": 0.60},
        "candidate": {"per_channel_neighbors": 40},
        "normalization": {"source_timezones": {"synthetic-test-source": "UTC"}},
        "evaluation": {"thresholds": [0.60, 0.70]},
    })
    experiment = write_yaml(tmp_path, "experiment.yaml", {
        "score": {"correlation_threshold": 0.62},
        "evaluation": {"thresholds": [0.62]},
    })
    result = load_config(BASELINE, deployment_override=deployment, experiment_override=experiment)
    assert result.algorithm.score.correlation_threshold == 0.62
    assert result.algorithm.candidate.per_channel_neighbors == 40
    assert result.algorithm.evaluation.thresholds == [0.62]
    assert result.algorithm.normalization.source_timezones == {"synthetic-test-source": "UTC"}
    assert load_config(BASELINE).algorithm.score.correlation_threshold == 0.65


def test_invalid_lower_layer_cannot_be_hidden(tmp_path):
    invalid = write_yaml(tmp_path, "invalid.yaml", {"score": {"correlation_threshold": 2}})
    valid = write_yaml(tmp_path, "valid.yaml", {"score": {"correlation_threshold": 0.60}})
    with pytest.raises(ValidationError):
        load_config(BASELINE, deployment_override=invalid, experiment_override=valid)


INVALID_PARAMETERS = [
    ("version", "v1"),
    ("normalization.timestamp_precision", "seconds"),
    ("normalization.missing_timezone", "guess_utc"),
    ("normalization.source_timezones", {"test": "Not/A_Timezone"}),
    ("normalization.category_priority", ["unknown"]),
    ("candidate.time_only_window_seconds", 0),
    ("candidate.default_window_seconds", -1),
    ("candidate.max_window_seconds", 600),
    ("candidate.source_complement_window_seconds", 7201),
    ("candidate.explicit_relation_window_seconds", 7201),
    ("candidate.behavior_override_channels", ["time_only"]),
    ("candidate.behavior_override_channels", ["source_complement"]),
    ("candidate.behavior_override_channels", ["HOST", "HOST"]),
    ("candidate.per_channel_neighbors", 0),
    ("candidate.max_neighbors_per_alert", -1),
    ("candidate.max_candidate_pairs", 1.5),
    ("candidate.overflow_policy", "silently_drop"),
    ("candidate.hot_entity_ratio", 1.1),
    ("candidate.hot_entity_min_count", True),
    ("candidate.entity_windows_seconds.IP", 7201),
    ("time.default_half_life_seconds", 0),
    ("time.clock_skew_seconds", -1),
    ("time.method", "linear"),
    ("entity.weights.IP", -0.1),
    ("entity.weights.HOST", 1.1),
    ("entity.role_factors.same_role", 1.1),
    ("entity.rarity_floor", -0.01),
    ("entity.rarity_smoothing", 0),
    ("entity.rarity_scope", "labels"),
    ("entity.frequency_unit", "raw_record"),
    ("entity.rarity_enabled", "true"),
    ("relation.scores.network_pivot", 1.1),
    ("behavior.same_category", float("nan")),
    ("behavior.unknown_category", 0.1),
    ("behavior.unknown_category", False),
    ("source.same_sensor_score", 0.1),
    ("source.unknown_independence_score", 0.1),
    ("source.forwarded_same_origin_score", 0.1),
    ("source.require_context_bridge", False),
    ("score.weights.time", 0.3),
    ("score.weights.conflict", -0.1),
    ("score.weights.duplicate", 1.01),
    ("score.correlation_threshold", "0.65"),
    ("score.require_non_time_support", False),
    ("duplicate.window_seconds", -1),
    ("duplicate.half_life_seconds", 0),
    ("duplicate.feature_weights.rule", 0.5),
    ("duplicate.threshold", 0.75),
    ("duplicate.suspected_floor", 0.95),
    ("duplicate.suspected_floor", 1),
    ("duplicate.require_payload_and_target", False),
    ("duplicate.candidate_indexes", ["source_record"]),
    ("duplicate.grouping", "single_link"),
    ("duplicate.representative", "random"),
    ("conflict.combine", "sum"),
    ("conflict.hard_rules", []),
    ("clustering.edge_threshold", 0.64),
    ("clustering.bridge_min_edges_with_singleton", 1),
    ("clustering.bridge_min_edges_between_non_singletons", 1),
    ("clustering.bridge_min_edges_between_singletons", 2),
    ("clustering.max_representatives", 0),
    ("clustering.reject_component_hard_conflict", False),
    ("clustering.keep_singletons", False),
    ("chain.require_explicit_propagation", False),
    ("chain.relation_type_mapping.target_to_process", "PROCESS_CAUSAL"),
    ("chain.relation_type_mapping.network_pivot", "mixed_evidence"),
    ("chain.relation_priority", ["network_pivot"]),
    ("chain.direction_weights.chronology", 0.5),
    ("chain.direction_margin", -0.1),
    ("chain.node_confidence_base", 0.90),
    ("chain.graph_policy", "cyclic"),
    ("chain.edge_threshold", 0.64),
    ("evaluation.baseline_window_seconds", 0),
    ("evaluation.thresholds", [1.1]),
    ("evaluation.window_multipliers", [0]),
    ("evaluation.weight_multipliers", [-1]),
    ("evaluation.noise_ratios", [-0.1]),
    ("evaluation.seed", True),
]


@pytest.mark.parametrize("path,replacement", INVALID_PARAMETERS)
def test_invalid_parameters_fail_fast(baseline, path, replacement):
    set_value(baseline, path, replacement)
    with pytest.raises(ValidationError):
        AlgorithmConfig.model_validate(baseline)


@pytest.mark.parametrize("section", [None, "normalization", "candidate", "time", "entity", "relation",
                                    "behavior", "source", "score", "duplicate", "conflict", "clustering",
                                    "chain", "evaluation"])
def test_unknown_key_rejected(baseline, section):
    target = baseline if section is None else baseline[section]
    target["not_frozen"] = 1
    with pytest.raises(ValidationError):
        AlgorithmConfig.model_validate(baseline)


@pytest.mark.parametrize("path", ["entity.weights", "candidate.entity_windows_seconds", "relation.scores"])
def test_unknown_enum_dictionary_key_rejected(baseline, path):
    section, key = path.split(".")
    baseline[section][key]["not_frozen"] = 1
    with pytest.raises(ValidationError):
        AlgorithmConfig.model_validate(baseline)


@pytest.mark.parametrize("section", ["normalization", "candidate", "time", "entity", "relation", "behavior",
                                    "source", "score", "duplicate", "conflict", "clustering", "chain", "evaluation"])
def test_all_section_fields_required(baseline, section):
    for key in baseline[section]:
        missing = deepcopy(baseline)
        del missing[section][key]
        with pytest.raises(ValidationError):
            AlgorithmConfig.model_validate(missing)


@pytest.mark.parametrize("path,missing", [("entity.weights", "IP"),
                                          ("candidate.entity_windows_seconds", "HOST"),
                                          ("relation.scores", "network_pivot")])
def test_complete_enum_dictionaries_required(baseline, path, missing):
    section, field = path.split(".")
    del baseline[section][field][missing]
    with pytest.raises(ValidationError):
        AlgorithmConfig.model_validate(baseline)


@pytest.mark.parametrize("section,key", [("time", "transition_half_lives"),
                                         ("candidate", "behavior_window_overrides"),
                                         ("behavior", "transitions"), ("source", "complement_rules")])
def test_duplicate_table_keys_rejected(baseline, section, key):
    baseline[section][key].append(deepcopy(baseline[section][key][0]))
    with pytest.raises(ValidationError):
        AlgorithmConfig.model_validate(baseline)


def test_override_window_bound_and_unknown_rows(baseline):
    baseline["candidate"]["behavior_window_overrides"][0]["window_seconds"] = 7201
    with pytest.raises(ValidationError):
        AlgorithmConfig.model_validate(baseline)
    baseline["candidate"]["behavior_window_overrides"][0]["window_seconds"] = 300
    baseline["time"]["transition_half_lives"][0]["from_category"] = "not_frozen"
    with pytest.raises(ValidationError):
        AlgorithmConfig.model_validate(baseline)


@pytest.mark.parametrize("missing,threshold", [("rule", 0.75), ("payload", 0.65), ("target", 0.70)])
def test_duplicate_index_missing_feature_upper_bound(baseline, missing, threshold):
    baseline["duplicate"]["threshold"] = threshold
    with pytest.raises(ValidationError, match="indexes need revision"):
        AlgorithmConfig.model_validate(baseline)


def test_unknown_override_not_hidden(tmp_path):
    override = write_yaml(tmp_path, "unknown.yaml", {"candidate": {"future_feature": True}})
    with pytest.raises(ConfigurationError, match="unknown override key"):
        load_config(BASELINE, deployment_override=override)


@pytest.mark.parametrize("text", ["version: v0\nversion: v0\n", "[1, 2]", "null", "",
                                 "version: v0\n---\nversion: v0\n", "x: {x: 1, x: 2}",
                                 "x: &x {a: 1}\ny: {<<: *x}", "? [a, b]\n: c"])
def test_invalid_yaml_rejected(tmp_path, text):
    path = tmp_path / "bad.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigurationError):
        read_yaml(path)


def test_missing_file_rejected(tmp_path):
    with pytest.raises(ConfigurationError):
        load_config(tmp_path / "missing.yaml")


def reverse_keys(value):
    if isinstance(value, dict):
        return {key: reverse_keys(child) for key, child in reversed(list(value.items()))}
    if isinstance(value, list):
        return [reverse_keys(child) for child in value]
    return value


def test_yaml_key_order_does_not_change_hash(baseline, tmp_path):
    reordered = write_yaml(tmp_path, "reordered.yaml", reverse_keys(baseline))
    assert load_config(reordered) == load_config(BASELINE)


def test_declared_tables_and_sets_reorder_stably(baseline, tmp_path):
    for section, key in (("time", "transition_half_lives"), ("behavior", "transitions"),
                         ("candidate", "behavior_window_overrides"),
                         ("candidate", "behavior_override_channels"),
                         ("source", "complement_rules"), ("conflict", "hard_rules"),
                         ("duplicate", "candidate_indexes")):
        baseline[section][key].reverse()
    for row in baseline["source"]["complement_rules"]:
        row["source_types"].reverse()
    assert load_config(write_yaml(tmp_path, "tables.yaml", baseline)) == load_config(BASELINE)


def test_parameter_change_updates_digest_and_snapshot_is_defensive(tmp_path):
    original = load_config(BASELINE)
    override = write_yaml(tmp_path, "changed.yaml", {"candidate": {"max_neighbors_per_alert": 201}})
    changed = load_config(BASELINE, experiment_override=override)
    assert original.config_hash != changed.config_hash
    assert original.mapping_digest == changed.mapping_digest
    snapshot = original.snapshot
    snapshot["candidate"]["max_neighbors_per_alert"] = 1
    algorithm = original.algorithm
    algorithm.candidate.max_neighbors_per_alert = 1
    assert original.snapshot["candidate"]["max_neighbors_per_alert"] == 200
    assert original.config_hash == load_config(BASELINE).config_hash


def test_config_hash_is_cross_process_and_no_environment_override(monkeypatch):
    monkeypatch.setenv("TRACEBACK_CORRELATION_THRESHOLD", "0.1")
    script = "from app.config import load_config; print(load_config('configs/algorithm-v0.yaml').config_hash)"
    outputs = [subprocess.run([sys.executable, "-c", script], cwd=ROOT, check=True,
                              capture_output=True, text=True, env=dict(os.environ, PYTHONHASHSEED=seed)).stdout.strip()
               for seed in ("1", "99")]
    assert outputs == [load_config(BASELINE).config_hash] * 2


def test_nfc_normalization_and_no_path_in_hash(baseline, tmp_path):
    baseline["normalization"]["host_aliases"] = {"synthetic-café": "synthetic-host"}
    composed = load_config(write_yaml(tmp_path, "composed.yaml", baseline))
    baseline["normalization"]["host_aliases"] = {"synthetic-cafe\u0301": "synthetic-host"}
    decomposed = load_config(write_yaml(tmp_path, "decomposed.yaml", baseline))
    assert composed.config_hash == decomposed.config_hash
    baseline["normalization"]["host_aliases"]["synthetic-café"] = "other-host"
    with pytest.raises(ConfigurationError, match="NFC"):
        load_config(write_yaml(tmp_path, "collision.yaml", baseline))


@pytest.mark.parametrize("section,key,kind", MAPPING_REFERENCES)
def test_missing_mapping_reference_fails_closed(baseline, tmp_path, section, key, kind):
    baseline[section][key] = ["mappings/missing.yaml"]
    with pytest.raises(ConfigurationError, match="cannot read configuration"):
        load_config(write_yaml(tmp_path, "missing-mapping.yaml", baseline))


def test_production_config_does_not_consume_data_or_ground_truth(monkeypatch):
    original_read = Path.read_text
    attempted = []

    def tripwire(path, *args, **kwargs):
        if any(p.lower() in ("data", "evaluation") for p in path.parts):
            attempted.append(str(path))
            raise AssertionError("production tried to consume data/Ground Truth")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", tripwire)
    load_config(BASELINE, deployment_override=ROOT / "configs/sources.yaml")
    for forbidden in (ROOT / "data/ait_ads/russellmitchell/evaluation/labels.csv",
                      ROOT / "evaluation/pending.yaml",
                      ROOT / "data/ait_ads/russellmitchell/raw/russellmitchell_wazuh.json"):
        with pytest.raises(ConfigurationError, match="configuration path"):
            load_config(forbidden)
    assert attempted == []


# These are synthetic configuration/context fixtures, never real source mappings.
def mapping_document(kind="category", *, rules=None):
    outputs = {"category": "web_attack", "severity": "high",
               "payload": {"fields": ["url", "host"]},
               "source_independence": "confirmed_independent",
               "rule_equivalence": {"equivalence_key": "synthetic-equivalence"}}
    field = "left.sensor" if kind == "source_independence" else "rule_id"
    default = None if kind in ("payload", "rule_equivalence") else "unknown"
    return {"schema_version": "1.0", "mapping_type": kind, "source_type": "other", "default": default,
            "rules": rules if rules is not None else [
                {"id": "synthetic-rule", "match": {"all": [{"field": field, "op": "eq", "value": "synthetic"}]},
                 "output": outputs[kind]}]}


def configured_mapping(baseline, tmp_path, kind="category", document=None):
    document = document if document is not None else mapping_document(kind)
    mapping_path = write_yaml(tmp_path, f"{kind}.yaml", document)
    section, key, _ = next(r for r in MAPPING_REFERENCES if r[2] == kind)
    baseline[section][key] = [mapping_path.name]
    effective = load_config(write_yaml(tmp_path, "algorithm.yaml", baseline))
    return effective, effective.mapping_files[f"{section}.{key}"][0]


def test_mapping_whitelists_match_frozen_document():
    text = (ROOT / "docs/ALGORITHM_CONFIG.md").read_text(encoding="utf-8")
    section = text.split("#### 2.0.3")[1].split("#### 2.0.4")[0]
    fields = [set(block.splitlines()) for block in re.findall(r"```text\n(.*?)\n```", section, re.S)]
    assert MAPPING_FIELDS == dict(zip(
        ("category", "severity", "payload", "source_independence", "rule_equivalence"),
        (fields[0], fields[0], fields[1], fields[2], fields[3]),
    ))


@pytest.mark.parametrize("kind", ["category", "severity", "payload", "source_independence", "rule_equivalence"])
def test_legal_mapping_load_expand_and_default(baseline, tmp_path, kind):
    effective, mapping = configured_mapping(baseline, tmp_path, kind)
    unmatched = resolve_mapping(mapping, {})
    assert unmatched.output == mapping.default
    assert unmatched.matched_rule_ids == ()
    assert unmatched.payload_fingerprint is None
    slot = next(f"{s}.{k}" for s, k, t in MAPPING_REFERENCES if t == kind)
    section, key = slot.split(".")
    assert effective.snapshot[section][key] == [mapping.model_dump()]
    assert effective.algorithm.model_dump()[section][key] == [f"{kind}.yaml"]
    snapshot = effective.snapshot
    snapshot[section][key][0]["rules"][0]["id"] = "modified-copy"
    mapping.rules[0].id = "another-copy"
    assert effective.mapping_files[slot][0].rules[0].id == "synthetic-rule"
    assert effective.config_hash == effective.config_digest


@pytest.mark.parametrize("path,replacement", [
    ("schema_version", 1.0), ("schema_version", "2.0"),
    ("mapping_type", "normalization"), ("mapping_type", None),
    ("source_type", "synthetic-product"), ("source_type", 1),
    ("default", None), ("default", "high"), ("rules", {}),
    ("version", "v0"), ("extra", True),
])
def test_mapping_public_schema_invalid(path, replacement):
    document = mapping_document()
    document[path] = replacement
    with pytest.raises(ValidationError):
        MappingFile.model_validate(document)


@pytest.mark.parametrize("location", ["file", "rule", "match", "condition"])
def test_mapping_unknown_keys_and_required_keys(location):
    document = mapping_document()
    targets = {"file": document, "rule": document["rules"][0],
               "match": document["rules"][0]["match"],
               "condition": document["rules"][0]["match"]["all"][0]}
    target = targets[location]
    for name in list(target):
        original = target.pop(name)
        with pytest.raises(ValidationError):
            MappingFile.model_validate(document)
        target[name] = original
    target["priority" if location == "rule" else "unknown_key"] = 1
    with pytest.raises(ValidationError):
        MappingFile.model_validate(document)


@pytest.mark.parametrize("value", ["", 1, None, True])
def test_mapping_rule_id_is_nonempty_strict_string(value):
    document = mapping_document()
    document["rules"][0]["id"] = value
    with pytest.raises(ValidationError):
        MappingFile.model_validate(document)


def test_mapping_duplicate_ids_fail_including_nfc_collision():
    document = mapping_document()
    document["rules"].append(deepcopy(document["rules"][0]))
    for ids in (("same", "same"), ("café", "cafe\u0301")):
        for rule, identifier in zip(document["rules"], ids):
            rule["id"] = identifier
        with pytest.raises(ValidationError, match="duplicate"):
            MappingFile.model_validate(document)


@pytest.mark.parametrize("kind", ["category", "severity", "payload", "source_independence", "rule_equivalence"])
@pytest.mark.parametrize("field", ["raw_alert.rule.id", "raw_fingerprint", "rule_description", "label", "not_frozen"])
def test_mapping_rejects_non_whitelisted_fields(kind, field):
    document = mapping_document(kind)
    document["rules"][0]["match"]["all"][0]["field"] = field
    with pytest.raises(ValidationError, match="match field"):
        MappingFile.model_validate(document)


@pytest.mark.parametrize("condition", [
    {"op": "regex", "value": ".*"}, {"op": "script", "value": "True"},
    {"op": "python", "value": "1 == 1"}, {"op": "template", "value": "{{ field }}"},
    {"op": "llm", "value": "similar"}, {"op": "eq"}, {"op": "contains"},
    {"op": "eq", "values": [1]}, {"op": "eq", "value": 1, "min": 0},
    {"op": "in", "values": []}, {"op": "in", "values": "synthetic"},
    {"op": "in", "value": "synthetic"}, {"op": "in", "values": [1], "value": 1},
    {"op": "exists", "value": 1}, {"op": "exists", "value": "true"},
    {"op": "range", "min": 0}, {"op": "range", "min": 0, "max": "1"},
    {"op": "range", "min": True, "max": 1}, {"op": "range", "min": 2, "max": 1},
    {"op": "range", "min": 0, "max": float("inf")},
    {"op": "range", "min": float("nan"), "max": 1},
    {"op": "range", "min": 0, "max": 1, "value": 0.5},
    {"op": "eq", "value": float("nan")}, {"op": "contains", "value": {"nested": float("inf")}},
    {"op": "in", "values": [object()]},
])
def test_mapping_operator_shapes_fail_fast(condition):
    document = mapping_document()
    document["rules"][0]["match"]["all"] = [{"field": "raw_severity", **condition}]
    with pytest.raises(ValidationError):
        MappingFile.model_validate(document)


@pytest.mark.parametrize("kind,invalid", [
    ("category", "not_frozen"), ("category", 1), ("severity", "web_attack"),
    ("severity", 5), ("source_independence", "unknown"),
    ("source_independence", "confirmed_same_origin"),
    ("payload", None), ("payload", {"fields": []}), ("payload", {"fields": ["url", "url"]}),
    ("payload", {"fields": ["raw_alert.url"]}), ("payload", {"fields": "url"}),
    ("payload", {"fields": ["url"], "extra": True}),
    ("rule_equivalence", None), ("rule_equivalence", {"equivalence_key": ""}),
    ("rule_equivalence", {"equivalence_key": 123}),
    ("rule_equivalence", {"equivalence_key": "synthetic", "extra": True}),
])
def test_mapping_illegal_output(kind, invalid):
    document = mapping_document(kind)
    document["rules"][0]["output"] = invalid
    with pytest.raises(ValidationError):
        MappingFile.model_validate(document)


@pytest.mark.parametrize("kind,invalid", [
    ("category", "web_attack"), ("severity", "high"), ("payload", {"fields": ["url"]}),
    ("source_independence", "confirmed_independent"),
    ("rule_equivalence", {"equivalence_key": "synthetic"}),
])
def test_mapping_default_must_be_frozen_value(kind, invalid):
    document = mapping_document(kind)
    document["default"] = invalid
    with pytest.raises(ValidationError, match="default"):
        MappingFile.model_validate(document)


@pytest.mark.parametrize("condition,context,matched", [
    ({"op": "eq", "value": 1}, {"raw_severity": 1}, True),
    ({"op": "eq", "value": 1}, {"raw_severity": "1"}, False),
    ({"op": "eq", "value": 1}, {"raw_severity": True}, False),
    ({"op": "eq", "value": None}, {}, False),
    ({"op": "eq", "value": None}, {"raw_severity": None}, True),
    ({"op": "in", "values": [1, 2]}, {"raw_severity": 2}, True),
    ({"op": "in", "values": [1]}, {"raw_severity": [1]}, False),
    ({"op": "in", "values": [1]}, {"raw_severity": True}, False),
    ({"op": "contains", "value": 1}, {"raw_severity": [2, 1]}, True),
    ({"op": "contains", "value": 1}, {"raw_severity": [True]}, False),
    ({"op": "contains", "value": 1}, {"raw_severity": 1}, False),
    ({"op": "exists", "value": True}, {"raw_severity": False}, True),
    ({"op": "exists", "value": True}, {"raw_severity": None}, False),
    ({"op": "exists", "value": False}, {}, True),
    ({"op": "exists", "value": False}, {"raw_severity": None}, True),
    ({"op": "exists", "value": False}, {"raw_severity": 0}, False),
    ({"op": "range", "min": 1, "max": 2}, {"raw_severity": 1}, True),
    ({"op": "range", "min": 1, "max": 2}, {"raw_severity": 2}, True),
    ({"op": "range", "min": 1, "max": 2}, {"raw_severity": 0.999}, False),
    ({"op": "range", "min": 1, "max": 2}, {"raw_severity": "1"}, False),
    ({"op": "range", "min": 0, "max": 2}, {"raw_severity": True}, False),
    ({"op": "range", "min": 0, "max": 2}, {"raw_severity": 10 ** 400}, False),
])
def test_mapping_operator_evaluation_is_strict(condition, context, matched):
    document = mapping_document("severity")
    document["rules"][0]["match"]["all"] = [{"field": "raw_severity", **condition}]
    result = resolve_mapping(MappingFile.model_validate(document), context)
    assert result.output == ("high" if matched else "unknown")
    assert result.matched_rule_ids == (("synthetic-rule",) if matched else ())


def test_mapping_all_requires_every_condition_and_never_traverses_raw():
    document = mapping_document()
    document["rules"][0]["match"]["all"].append({"field": "sensor", "op": "eq", "value": "synthetic"})
    mapping = MappingFile.model_validate(document)
    assert resolve_mapping(mapping, {"rule_id": "synthetic"}).output == "unknown"
    assert resolve_mapping(mapping, {"rule_id": "synthetic", "sensor": "synthetic"}).output == "web_attack"
    assert resolve_mapping(mapping, {"raw_alert": {"rule_id": "synthetic", "sensor": "synthetic"}}).output == "unknown"


def test_equal_outputs_preserve_all_rule_provenance(baseline, tmp_path):
    document = mapping_document("severity")
    document["rules"].append(deepcopy(document["rules"][0]))
    document["rules"][0]["id"] = "z"
    document["rules"][1]["id"] = "a"
    _, mapping = configured_mapping(baseline, tmp_path, "severity", document)
    result = resolve_mapping(mapping, {"rule_id": "synthetic"})
    assert result.output == "high"
    assert result.matched_rule_ids == ("a", "z")
    assert re.fullmatch("[0-9a-f]{64}", result.mapping_digest)


def test_static_conflicts_fail_loading_and_runtime_conflicts_fail_resolution(tmp_path):
    document = mapping_document("severity")
    document["rules"].append(deepcopy(document["rules"][0]))
    document["rules"][1].update(id="second", output="low")
    with pytest.raises(MappingConflict):
        load_mapping_file(write_yaml(tmp_path, "conflict.yaml", document))
    # Directly validated config objects still have the input-time conflict guard.
    mapping = MappingFile.model_validate(document)
    with pytest.raises(MappingConflict):
        resolve_mapping(mapping, {"rule_id": "synthetic"})
    assert resolve_mapping(mapping, {"rule_id": "unmatched"}).output == "unknown"


def test_overlapping_closed_ranges_fail_fast_but_disjoint_rules_load(tmp_path):
    document = mapping_document("severity")
    document["rules"] = [
        {"id": "one", "match": {"all": [{"field": "raw_severity", "op": "range", "min": 1, "max": 3}]}, "output": "low"},
        {"id": "two", "match": {"all": [{"field": "raw_severity", "op": "range", "min": 3, "max": 5}]}, "output": "high"},
    ]
    with pytest.raises(MappingConflict):
        load_mapping_file(write_yaml(tmp_path, "ranges.yaml", document))
    document["rules"][1]["match"]["all"][0]["min"] = 4
    mapping = load_mapping_file(write_yaml(tmp_path, "disjoint.yaml", document))
    assert resolve_mapping(mapping, {"raw_severity": 3}).output == "low"
    assert resolve_mapping(mapping, {"raw_severity": 4}).output == "high"


def test_category_uses_configured_priority_and_keeps_all_hits(baseline, tmp_path):
    document = mapping_document()
    document["rules"].append(deepcopy(document["rules"][0]))
    document["rules"][1].update(id="second", output="command_execution")
    effective, mapping = configured_mapping(baseline, tmp_path, document=document)
    context = {"rule_id": "synthetic"}
    result = resolve_mapping(mapping, context, category_priority=effective.algorithm.normalization.category_priority)
    assert result.output == "web_attack"
    assert result.matched_rule_ids == ("second", "synthetic-rule")
    document["rules"].reverse()
    reordered = MappingFile.model_validate(document)
    assert resolve_mapping(reordered, context, category_priority=baseline["normalization"]["category_priority"]) == result
    priority = list(reversed(baseline["normalization"]["category_priority"]))
    assert resolve_mapping(mapping, context, category_priority=priority).output == "command_execution"
    with pytest.raises(ConfigurationError, match="category_priority"):
        resolve_mapping(mapping, context)


def test_payload_fingerprint_uses_only_declared_names_and_values(baseline, tmp_path):
    effective, mapping = configured_mapping(baseline, tmp_path, "payload")
    context = {"rule_id": "synthetic", "host": "synthetic-host", "url": "/synthetic", "command": "ignored"}
    result = resolve_mapping(mapping, context)
    expected = sha256(b'{"host":"synthetic-host","url":"/synthetic"}').hexdigest()
    assert result.output == {"fields": ["host", "url"]}
    assert result.payload_fingerprint == expected
    assert len(expected) == 64
    for fields in (["url", "host"], ["host", "url"]):
        document = mapping_document("payload")
        document["rules"][0]["output"]["fields"] = fields
        assert resolve_mapping(MappingFile.model_validate(document), context) == result
    context["command"] = "still ignored"
    assert resolve_mapping(mapping, context).payload_fingerprint == expected
    context["url"] = "/changed"
    assert resolve_mapping(mapping, context).payload_fingerprint != expected
    assert effective.snapshot["duplicate"]["payload_mapping_files"][0]["rules"][0]["output"]["fields"] == ["host", "url"]


@pytest.mark.parametrize("context", [
    {"rule_id": "synthetic", "host": "synthetic-host"},
    {"rule_id": "synthetic", "host": "synthetic-host", "url": None},
    {"rule_id": "synthetic", "url": "/synthetic", "raw_fingerprint": "f" * 64},
    {"rule_id": "synthetic", "raw_alert": {"host": "synthetic-host", "url": "/synthetic"}},
    {"rule_id": "unmatched", "host": "synthetic-host", "url": "/synthetic"},
])
def test_payload_missing_null_unmatched_never_falls_back(context):
    result = resolve_mapping(MappingFile.model_validate(mapping_document("payload")), context)
    assert result.payload_fingerprint is None


def test_payload_equal_field_sets_accept_all_hits_but_different_sets_conflict():
    document = mapping_document("payload")
    document["rules"].append(deepcopy(document["rules"][0]))
    document["rules"][1]["id"] = "second"
    document["rules"][1]["output"]["fields"].reverse()
    context = {"rule_id": "synthetic", "host": "synthetic-host", "url": None}
    result = resolve_mapping(MappingFile.model_validate(document), context)
    assert result.matched_rule_ids == ("second", "synthetic-rule")
    assert result.payload_fingerprint is None
    document["rules"][1]["output"]["fields"] = ["host"]
    with pytest.raises(MappingConflict):
        resolve_mapping(MappingFile.model_validate(document), context)


def test_rule_equivalence_requires_equal_nonempty_declared_keys():
    document = mapping_document("rule_equivalence")
    mapping = MappingFile.model_validate(document)
    declared = resolve_mapping(mapping, {"rule_id": "synthetic"})
    unknown = resolve_mapping(mapping, {"rule_id": "unmatched", "signature": "synthetic-equivalence"})
    assert rule_equivalent(declared, declared)
    assert not rule_equivalent(declared, unknown)
    assert not rule_equivalent(unknown, unknown)
    document["rules"][0]["output"]["equivalence_key"] = "different"
    other = resolve_mapping(MappingFile.model_validate(document), {"rule_id": "synthetic"})
    assert not rule_equivalent(declared, other)
    document["rules"] = []
    assert resolve_mapping(MappingFile.model_validate(document), {"rule_id": "synthetic"}).output is None


def test_source_independence_unknown_and_same_origin_guard():
    mapping = MappingFile.model_validate(mapping_document("source_independence"))
    context = {"left.sensor": "synthetic", "left.source_type": "waf", "right.source_type": "edr"}
    assert resolve_mapping(mapping, {"left.source_type": "waf", "right.source_type": "edr"}).output == "unknown"
    assert resolve_mapping(mapping, context).output == "confirmed_independent"
    context.update({"left.origin_namespace": "synthetic-origin", "right.origin_namespace": "synthetic-origin"})
    blocked = resolve_mapping(mapping, context)
    assert blocked.output == "unknown" and blocked.blocked_by_same_origin
    assert blocked.matched_rule_ids == ("synthetic-rule",)
    context["right.origin_namespace"] = "different-origin"
    assert resolve_mapping(mapping, context).output == "confirmed_independent"
    assert resolve_mapping(mapping, context, confirmed_same_origin=True).output == "unknown"
    assert resolve_mapping(mapping, context, confirmed_same_origin=True).blocked_by_same_origin


@pytest.mark.parametrize("kind", ["category", "severity", "payload", "source_independence", "rule_equivalence"])
def test_reference_type_must_match_position(baseline, tmp_path, kind):
    section, key, _ = next(r for r in MAPPING_REFERENCES if r[2] == kind)
    other = "severity" if kind != "severity" else "category"
    path = write_yaml(tmp_path, "incompatible.yaml", mapping_document(other))
    baseline[section][key] = [path.name]
    with pytest.raises(ConfigurationError, match="incompatible"):
        load_config(write_yaml(tmp_path, "algorithm.yaml", baseline))


@pytest.mark.parametrize("change", ["object_keys", "rules", "payload_fields"])
def test_mapping_reordering_preserves_expansion_digest_and_hash(baseline, tmp_path, change):
    document = mapping_document("payload")
    document["rules"].append(deepcopy(document["rules"][0]))
    document["rules"][1]["id"] = "second"
    effective, _ = configured_mapping(baseline, tmp_path, "payload", document)
    if change == "object_keys":
        document = reverse_keys(document)
    elif change == "rules":
        document["rules"].reverse()
    else:
        for rule in document["rules"]:
            rule["output"]["fields"].reverse()
    write_yaml(tmp_path, "payload.yaml", document)
    changed = load_config(tmp_path / "algorithm.yaml")
    assert changed.mapping_digest == effective.mapping_digest
    assert changed.config_hash == effective.config_hash
    assert changed.snapshot == effective.snapshot


@pytest.mark.parametrize("change", ["id", "field", "operator", "parameter", "output", "source_type", "new_rule"])
def test_actual_mapping_changes_update_both_hashes(baseline, tmp_path, change):
    document = mapping_document("severity")
    effective, _ = configured_mapping(baseline, tmp_path, "severity", document)
    rule = document["rules"][0]
    if change == "id":
        rule["id"] = "changed-id"
    elif change == "field":
        rule["match"]["all"][0]["field"] = "signature"
    elif change == "operator":
        rule["match"]["all"][0] = {"field": "rule_id", "op": "in", "values": ["synthetic"]}
    elif change == "parameter":
        rule["match"]["all"][0]["value"] = "changed-match"
    elif change == "output":
        rule["output"] = "low"
    elif change == "source_type":
        document["source_type"] = "siem"
    else:
        document["rules"].append(deepcopy(rule))
        document["rules"][1]["id"] = "added-rule"
    write_yaml(tmp_path, "severity.yaml", document)
    changed = load_config(tmp_path / "algorithm.yaml")
    assert changed.mapping_digest != effective.mapping_digest
    assert changed.config_hash != effective.config_hash


def test_reference_paths_and_file_order_do_not_enter_hash(baseline, tmp_path):
    first = write_yaml(tmp_path, "one.yaml", mapping_document())
    document = mapping_document()
    document["rules"][0]["match"]["all"][0]["value"] = "other"
    second = write_yaml(tmp_path, "two.yaml", document)
    baseline["normalization"]["category_mapping_files"] = [first.name, second.name]
    original = load_config(write_yaml(tmp_path, "algorithm.yaml", baseline))
    baseline["normalization"]["category_mapping_files"] = [str(second.resolve()), str(first.resolve())]
    changed = load_config(write_yaml(tmp_path, "absolute-reversed.yaml", baseline))
    assert changed == original
    assert original.algorithm.normalization.category_mapping_files == ["one.yaml", "two.yaml"]
    assert str(tmp_path) not in json.dumps(changed.snapshot)
    # The repeated ID is legal in separate files, and file-content digests disambiguate provenance.
    mappings = original.mapping_files["normalization.category_mapping_files"]
    assert len(mappings) == 2
    results = [resolve_mapping(m, {"rule_id": "synthetic"}) for m in mappings]
    assert results[0].mapping_digest != results[1].mapping_digest


def test_mapping_refs_resolve_from_declaring_override_and_invalid_lower_layer_fails(baseline, tmp_path):
    deployment_dir = tmp_path / "deployment"
    deployment_dir.mkdir()
    write_yaml(deployment_dir, "category.yaml", mapping_document())
    deployment = write_yaml(deployment_dir, "override.yaml", {"normalization": {"category_mapping_files": ["category.yaml"]}})
    effective = load_config(BASELINE, deployment_override=deployment)
    assert len(effective.mapping_files["normalization.category_mapping_files"]) == 1
    invalid = mapping_document()
    invalid["default"] = "web_attack"
    write_yaml(deployment_dir, "category.yaml", invalid)
    experiment = write_yaml(tmp_path, "experiment.yaml", {"normalization": {"category_mapping_files": []}})
    with pytest.raises(ValidationError, match="default"):
        load_config(BASELINE, deployment_override=deployment, experiment_override=experiment)


def test_mapping_yaml_round_trip_and_cross_process_hash(baseline, tmp_path):
    effective, mapping = configured_mapping(baseline, tmp_path, "payload")
    saved = write_yaml(tmp_path, "payload.yaml", mapping.model_dump())
    assert load_mapping_file(saved).model_dump() == mapping.model_dump()
    assert load_config(tmp_path / "algorithm.yaml") == effective
    script = "import sys; from app.config import load_config; c=load_config(sys.argv[1]); print(c.config_hash, c.mapping_digest)"
    for seed in ("1", "99"):
        result = subprocess.run([sys.executable, "-c", script, str(tmp_path / "algorithm.yaml")], cwd=ROOT,
                                capture_output=True, check=True, text=True, env=dict(os.environ, PYTHONHASHSEED=seed))
        assert result.stdout.strip() == f"{effective.config_hash} {effective.mapping_digest}"


def test_mapping_nfc_and_nonfinite_context_handling(baseline, tmp_path):
    document = mapping_document("payload")
    document["rules"][0]["match"]["all"][0]["value"] = "café"
    effective, mapping = configured_mapping(baseline, tmp_path, "payload", document)
    context = {"rule_id": "cafe\u0301", "host": "synthetic-cafe\u0301", "url": "/synthetic"}
    result = resolve_mapping(mapping, context)
    context["host"] = "synthetic-café"
    assert resolve_mapping(mapping, context).payload_fingerprint == result.payload_fingerprint
    document["rules"][0]["match"]["all"][0]["value"] = "cafe\u0301"
    write_yaml(tmp_path, "payload.yaml", document)
    assert load_config(tmp_path / "algorithm.yaml") == effective
    context["process"] = {"ratio": float("nan")}
    with pytest.raises(ConfigurationError, match="finite JSON"):
        resolve_mapping(mapping, context)


def test_numeric_mapping_parameter_cannot_alias_a_json_object(baseline, tmp_path):
    document = mapping_document("payload")
    condition = document["rules"][0]["match"]["all"][0]
    condition.update(field="process", value=0.5)
    original, mapping = configured_mapping(baseline, tmp_path, "payload", document)
    context = {"process": 0.5, "host": "synthetic-host", "url": "/synthetic"}
    assert resolve_mapping(mapping, context).output is not None
    condition["value"] = {"$decimal": "0.5"}
    write_yaml(tmp_path, "payload.yaml", document)
    changed = load_config(tmp_path / "algorithm.yaml")
    assert changed.mapping_digest != original.mapping_digest
    assert changed.config_hash != original.config_hash
    assert resolve_mapping(changed.mapping_files["duplicate.payload_mapping_files"][0], context).output is None


def test_payload_fingerprint_preserves_numeric_and_object_types():
    document = mapping_document("payload")
    document["rules"][0]["output"]["fields"] = ["process"]
    mapping = MappingFile.model_validate(document)
    result = resolve_mapping(mapping, {"rule_id": "synthetic", "process": {"value": 0.5, "zero": -0.0}})
    assert result.payload_fingerprint == sha256(b'{"process":{"value":0.5,"zero":0}}').hexdigest()
    other = resolve_mapping(mapping, {"rule_id": "synthetic", "process": {"value": {"$decimal": "0.5"}, "zero": 0}})
    assert other.payload_fingerprint != result.payload_fingerprint

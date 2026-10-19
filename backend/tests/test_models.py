"""Frozen contract tests using only explicitly synthetic in-memory/JSON fixtures."""

from copy import deepcopy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import app.models as models
from app.models.base import DomainModel, StrictModel
from app.utils.stable_id import ID_FIELDS, content_digest, id_for, raw_fingerprint


FIXTURES = Path(__file__).parent / "fixtures/schema"
VALID = json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))["cases"]
INVALID = json.loads((FIXTURES / "invalid.json").read_text(encoding="utf-8"))["cases"]
SAMPLES = {case["name"]: case["data"] for case in VALID}


def sample(name):
    return deepcopy(SAMPLES[name])


def reidentify(kind, data):
    if kind in ID_FIELDS:
        data[ID_FIELDS[kind]] = id_for(kind, data)
    return data


@pytest.mark.parametrize("case", VALID, ids=lambda c: c["name"])
def test_legal_fixture_and_json_storage_roundtrip(case):
    model = getattr(models, case["model"])
    value = model.model_validate(case["data"])
    assert model.model_validate_json(value.model_dump_json()) == value
    assert model.model_validate_json(value.canonical_json()) == value
    assert model.model_validate(value.model_dump(mode="python")) == value
    assert model.model_json_schema()["additionalProperties"] is False


@pytest.mark.parametrize("case", INVALID, ids=lambda c: c["name"])
def test_illegal_fixtures_reject_extra_fields(case):
    with pytest.raises(ValidationError):
        getattr(models, case["model"]).model_validate(case["data"])


def test_every_public_schema_has_valid_and_invalid_synthetic_fixtures():
    classes = {name for name in models.__all__ if isinstance(getattr(models, name), type)
               and issubclass(getattr(models, name), StrictModel)}
    assert classes == {c["model"] for c in VALID} == {c["model"] for c in INVALID}
    for filename in ("valid.json", "invalid.json"):
        assert json.loads((FIXTURES / filename).read_text(encoding="utf-8"))["fixture_kind"] == "synthetic"


REQUIRED = [(case, name) for case in VALID if "." not in case["name"]
            for name, field in getattr(models, case["model"]).model_fields.items() if field.is_required()]


@pytest.mark.parametrize("case,field", REQUIRED, ids=[f"{c['model']}.{f}" for c, f in REQUIRED])
def test_every_required_field_is_actually_required(case, field):
    data = deepcopy(case["data"])
    del data[field]
    with pytest.raises(ValidationError):
        getattr(models, case["model"]).model_validate(data)


@pytest.mark.parametrize("case", VALID, ids=lambda c: c["name"])
def test_null_distinctions_for_every_field(case):
    model = getattr(models, case["model"])
    properties = model.model_json_schema()["properties"]
    for name in model.model_fields:
        if name == "params":
            continue
        schema = properties[name]
        allows_null = schema.get("type") == "null" or any(v.get("type") == "null" for v in schema.get("anyOf", []))
        # GroundedProposition.value is JSON and only snapshot context can decide null.
        if model is models.GroundedProposition and name == "value":
            allows_null = True
        data = deepcopy(case["data"])
        data[name] = None
        if not allows_null:
            with pytest.raises(ValidationError):
                model.model_validate(data)


@pytest.mark.parametrize("case", VALID, ids=lambda c: c["name"])
def test_domain_versions_and_nested_version_exclusion(case):
    model = getattr(models, case["model"])
    data = deepcopy(case["data"])
    if issubclass(model, DomainModel):
        data.pop("schema_version", None)
        assert model.model_validate(data).schema_version == "1.0"
        for invalid in (None, "1", "2.0", 1.0, 1):
            with pytest.raises(ValidationError):
                model.model_validate(data | {"schema_version": invalid})
    else:
        assert "schema_version" not in model.model_fields
        with pytest.raises(ValidationError):
            model.model_validate(data | {"schema_version": "1.0"})


def test_defaults_and_versioned_embedded_domain_objects():
    for name in ("CanonicalAlert", "Incident", "AIClaim", "AIExplanation", "AnalysisRecord"):
        model = getattr(models, name)
        data = sample(name)
        if name == "AIClaim":
            # Optional [] references are valid for a recommendation; facts keep
            # their conditional nonempty requirements despite field defaults.
            data.update(kind="recommendation", section="recommendations", text="建议核对告警。")
        for field, definition in model.model_fields.items():
            if not definition.is_required():
                data.pop(field, None)
        value = model.model_validate(reidentify(name, data))
        assert value.schema_version == "1.0"
    chain = models.AttackChain.model_validate(sample("AttackChain")).model_dump(mode="json")
    assert all(n["schema_version"] == "1.0" for n in chain["nodes"])
    assert all(e["schema_version"] == "1.0" for e in chain["edges"])
    assert "schema_version" not in chain["nodes"][0]["reasons"][0]
    claim = models.AIExplanation.model_validate(sample("AIExplanation")).claims[0]
    assert claim.schema_version == "1.0" and claim.grounding_status == "pending"


@pytest.mark.parametrize("name,field,value", [
    ("CanonicalAlert", "source_type", "invented"), ("CanonicalAlert", "source_namespace", 12),
    ("CanonicalAlert", "src_port", True), ("CanonicalAlert", "src_port", 1.0),
    ("CanonicalAlert", "src_port", -1), ("CanonicalAlert", "dst_port", 65536),
    ("CanonicalAlert", "src_ip", "invalid"), ("CanonicalAlert", "host", ""),
    ("CanonicalAlert", "raw_alert", {}), ("CanonicalAlert", "raw_alert", ""),
    ("ProcessRef", "pid", True), ("ProcessRef", "pid", -1),
    ("ScoreBreakdown", "time_score", 1.0000001), ("ScoreBreakdown", "time_score", 0.1234567),
    ("ScoreBreakdown", "time_score", -0.1), ("ScoreBreakdown", "time_score", "0.5"),
    ("ScoreBreakdown", "time_score", True), ("ScoreBreakdown", "time_score", float("nan")),
    ("ScoreWeights", "conflict", 1.1), ("ScoreWeights", "source", 0.2),
    ("ScoreContributions", "conflict", 0.2), ("ScoreContributions", "time", -0.2),
    ("EvidencePointer", "pointer", "raw_alert.foo"), ("EvidencePointer", "pointer", "/bad~2"),
    ("EvidencePointer", "side", "unknown"), ("Entity", "alert_ids", ()),
    ("AttackMapping", "technique_id", "T12"), ("AnalysisMetrics", "alert_count", 1.5),
    ("EvaluationSummaryExport", "evaluation_coverage", 1.1), ("EvaluationSummaryExport", "run_id", "../../run"),
])
def test_strict_types_enums_and_ranges(name, field, value):
    data = sample(name)
    data[field] = value
    with pytest.raises(ValidationError):
        getattr(models, name).model_validate(data)


def test_process_requires_identifying_field_and_origin_pair_is_atomic():
    for data in ({}, {"start_time": "2026-10-04T00:00:00Z"}):
        with pytest.raises(ValidationError):
            models.ProcessRef.model_validate(data)
    data = sample("CanonicalAlert") | {"origin_namespace": "synthetic/origin"}
    with pytest.raises(ValidationError, match="both"):
        models.CanonicalAlert.model_validate(reidentify("CanonicalAlert", data))


@pytest.mark.parametrize("name,field", [("Entity", "alert_ids"), ("DedupeGroup", "alert_ids"),
                                       ("CorrelationEdge", "reasons"), ("ChainNode", "reasons"),
                                       ("AttackChain", "nodes"), ("AIExplanation", "claims")])
def test_minimum_nonempty_fields(name, field):
    with pytest.raises(ValidationError):
        getattr(models, name).model_validate(sample(name) | {field: []})


def test_id_prefix_full_length_content_and_duplicate_id_arrays():
    for wrong in ("alt_short", "ent_" + "a" * 64, "alt_" + "A" * 64, "alt_" + "a" * 64):
        with pytest.raises(ValidationError):
            models.CanonicalAlert.model_validate(sample("CanonicalAlert") | {"alert_id": wrong})
    entity = sample("Entity")
    entity["alert_ids"].append(entity["alert_ids"][0])
    with pytest.raises(ValidationError, match="duplicates"):
        models.Entity.model_validate(entity)


def test_utc_offset_equivalence_truncation_and_naive_rejection():
    alert = sample("CanonicalAlert")
    equivalent = alert | {"timestamp": "2026-10-04T10:31:04.123456999+08:00"}
    assert models.CanonicalAlert.model_validate(equivalent).timestamp == alert["timestamp"]
    for value in ("2026-10-04T02:31:04", "2026-10-04", 1791052264, None,
                  "2026-10-04T02:31:04+08:99", "2026-02-30T02:31:04Z"):
        with pytest.raises(ValidationError):
            models.CanonicalAlert.model_validate(alert | {"timestamp": value})


def test_alert_fingerprint_provenance_occurrences_and_pointer_resolution():
    data = sample("CanonicalAlert")
    for changed in (data | {"raw_fingerprint": "0" * 64}, data | {"field_provenance": {}},
                    data | {"host": "synthetic-target"}, data | {"entity_ids": [sample("Entity")["entity_id"]]}):
        with pytest.raises(ValidationError):
            models.CanonicalAlert.model_validate(changed)
    data["entity_ids"] = [sample("Entity")["entity_id"]]
    data["entity_occurrences"] = [sample("EntityOccurrence")]
    value = models.CanonicalAlert.model_validate(data)
    alerts = {value.alert_id: value}
    ptr = models.EvidencePointer.model_validate({"alert_id": value.alert_id, "pointer": "/evidence~1key/~0name", "side": "shared"})
    assert ptr.resolve(alerts) == 0
    assert models.EvidencePointer.model_validate(ptr.model_dump() | {"pointer": "/values/0"}).resolve(alerts) == 2
    for path in ("/missing", "/values/01", "/values/-", "/values/9"):
        with pytest.raises(ValueError):
            models.EvidencePointer.model_validate(ptr.model_dump() | {"pointer": path}).resolve(alerts)
    with pytest.raises(ValueError, match="absent"):
        ptr.resolve({})
    text = "原始文本 e\u0301\n"
    text_data = sample("CanonicalAlert") | {"raw_alert": text, "raw_fingerprint": raw_fingerprint(text),
                                           "field_provenance": {"timestamp": {"raw_pointer": "", "transform": "synthetic/text-time"},
                                                                "source_type": {"raw_pointer": "", "transform": "synthetic/text-source"}}}
    text_alert = models.CanonicalAlert.model_validate(reidentify("CanonicalAlert", text_data))
    assert models.CanonicalAlert.model_validate_json(text_alert.model_dump_json()).raw_alert == text
    assert models.CanonicalAlert.model_validate_json(text_alert.canonical_json()).raw_alert == text
    with pytest.raises(ValueError, match="text"):
        models.EvidencePointer.model_validate(ptr.model_dump() | {"alert_id": text_alert.alert_id}).resolve({text_alert.alert_id: text_alert})


def test_evidence_pointer_never_resolves_another_alerts_same_named_field():
    data = sample("Reason.explicit_relation")
    wrong = "alt_" + "f" * 64
    data["params"]["raw_pointers"][0]["alert_id"] = wrong
    with pytest.raises(ValidationError, match="owning"):
        models.Reason.model_validate(reidentify("Reason", data))
    data = sample("Reason.explicit_relation")
    pointer = data["params"]["raw_pointers"][0]
    context = {"alerts": {aid: {"raw_alert": {"other": "synthetic"}} for aid in data["alert_ids"]}}
    other = data["alert_ids"][1] if pointer["alert_id"] == data["alert_ids"][0] else data["alert_ids"][0]
    context["alerts"][other]["raw_alert"] = {"request": {"trigger": "exists-only-on-wrong-alert"}}
    with pytest.raises(ValidationError, match="bound raw_alert"):
        models.Reason.model_validate(data, context=context)


def test_reason_params_bare_pointers_unknown_fields_and_component_multiset():
    data = sample("Reason.explicit_relation")
    with pytest.raises(ValidationError):
        models.Reason.model_validate(data | {"params": data["params"] | {"raw_pointers": ["/request/trigger"]}})
    data = sample("Reason.time_gap")
    with pytest.raises(ValidationError):
        models.Reason.model_validate(data | {"params": data["params"] | {"made_up": 1}})
    data = sample("Reason.clustering_guard")
    assert models.Reason.model_validate(data).params["component_sizes"] == [2, 2]
    for values in ([], [0], [-1], [True], [1.0]):
        with pytest.raises(ValidationError):
            models.Reason.model_validate(data | {"params": data["params"] | {"component_sizes": values}})


def test_source_independence_evidence_and_configuration_basis():
    data = sample("Reason.source_complement")
    for state in ("confirmed_independent", "confirmed_same_origin"):
        data["params"]["source_independence"] = state
        with pytest.raises(ValidationError, match="evidence"):
            models.Reason.model_validate(reidentify("Reason", data))
        data["params"]["independence_rule_ids"] = ["synthetic/topology"]
        data = reidentify("Reason", data)
        assert models.Reason.model_validate(data, context={"independence_rule_ids": ["synthetic/topology"]})
        with pytest.raises(ValidationError, match="configuration"):
            models.Reason.model_validate(data, context={"independence_rule_ids": []})
        data["params"]["independence_rule_ids"] = []


@pytest.mark.parametrize("state", ["unknown", "confirmed_same_origin"])
def test_nonindependent_state_cannot_receive_nonzero_source_score(state):
    data = sample("ScoreBreakdown") | {"source_independence": state, "source_score": 0.7}
    with pytest.raises(ValidationError, match="source_score=0"):
        models.ScoreBreakdown.model_validate(data)


def test_score_recalculation_penalties_clamp_tolerance_and_config_snapshot():
    data = sample("ScoreBreakdown")
    assert models.ScoreBreakdown.model_validate(data).final_score == 0.88
    for field, wrong in (("raw_total", 0.9), ("final_score", 0.5)):
        with pytest.raises(ValidationError):
            models.ScoreBreakdown.model_validate(data | {field: wrong})
    with pytest.raises(ValidationError, match="contribution"):
        models.ScoreBreakdown.model_validate(data | {"contributions": data["contributions"] | {"relation": 0.2}})
    assert models.ScoreBreakdown.model_validate(data | {"raw_total": 0.880009})
    with pytest.raises(ValidationError):
        models.ScoreBreakdown.model_validate(data | {"raw_total": 0.880011})
    negative = data | {k: 0 for k in ("time_score", "entity_score", "relation_score", "behavior_score")}
    negative.update(conflict_penalty=1, duplicate_penalty=1, raw_total=-0.85, final_score=0,
                    contributions={"time": 0, "entity": 0, "relation": 0, "behavior": 0, "source": 0,
                                   "conflict": -0.45, "duplicate": -0.4})
    assert models.ScoreBreakdown.model_validate(negative).raw_total == -0.85
    with pytest.raises(ValidationError, match="configuration"):
        models.ScoreBreakdown.model_validate(data, context={"config_hash": "0" * 64})


def test_independent_source_reason_mismatch_same_sensor_and_context_requirement():
    data = sample("CorrelationEdge")
    source = next(r for r in data["reasons"] if r["code"] == "source_complement")
    source["params"].update(source_independence="confirmed_independent", independence_rule_ids=["synthetic/topology"])
    source.update(reidentify("Reason", source))
    with pytest.raises(ValidationError, match="states differ"):
        models.CorrelationEdge.model_validate(data)
    data["score_breakdown"].update(source_independence="confirmed_independent", source_score=0.7,
                                    raw_total=0.95, final_score=0.95)
    data["score_breakdown"]["contributions"]["source"] = 0.07
    data["score"] = 0.95
    assert models.CorrelationEdge.model_validate(data)
    source["params"]["sensor_names"] = ["synthetic/same-sensor"]
    source.update(reidentify("Reason", source))
    with pytest.raises(ValidationError, match="same sensor"):
        models.CorrelationEdge.model_validate(data)


def test_independent_alert_and_chain_relations_and_five_mapping_results():
    assert models.AlertRelationType is not models.ChainRelationType
    assert set(models.CHAIN_RELATION_MAPPING.values()) == set(models.ChainRelationType)
    data = sample("ChainEdge")
    for invalid in (models.AlertRelationType.TARGET_TO_PROCESS, "target_to_process", "behavior_transition",
                    "entity_propagation", "source_complement", "mixed_evidence", "UNKNOWN"):
        with pytest.raises(ValidationError):
            models.ChainEdge.model_validate(data | {"relation_type": invalid})
    for alert_type, chain_type in models.CHAIN_RELATION_MAPPING.items():
        changed = deepcopy(data)
        reason = next(r for r in changed["reasons"] if r["code"] == "explicit_relation")
        reason["params"]["relation_type"] = alert_type.value
        reason.update(reidentify("Reason", reason))
        changed["relation_type"] = chain_type.value
        assert models.ChainEdge.model_validate(reidentify("ChainEdge", changed)).relation_type is chain_type


def test_v0_schema_admission_requires_matching_relation_direction_and_structured_fields():
    data = sample("ChainEdge")
    for code in ("explicit_relation", "direction"):
        with pytest.raises(ValidationError, match="requires direction"):
            models.ChainEdge.model_validate(data | {"reasons": [r for r in data["reasons"] if r["code"] != code]})
    relation = sample("Reason.explicit_relation")
    for pointer in ("", "/host", "/timestamp", "/category", "/session", "/request_id", "/process/name"):
        changed = deepcopy(relation)
        for p in changed["params"]["raw_pointers"]:
            p["pointer"] = pointer
        with pytest.raises(ValidationError, match="relationship fields"):
            models.Reason.model_validate(reidentify("Reason", changed))
    for invalid in (None, "cor_" + "a" * 64):
        with pytest.raises(ValidationError, match="selected"):
            models.ChainEdge.model_validate(data | {"score_breakdown": data["score_breakdown"] | {"selected_correlation_edge_id": invalid}})


def test_support_pair_required_distinct_group_members_and_reason_scope():
    data = sample("CorrelationEdge")
    del data["support_pair"]
    with pytest.raises(ValidationError):
        models.CorrelationEdge.model_validate(data)
    data = sample("CorrelationEdge")
    with pytest.raises(ValidationError, match="distinct"):
        models.CorrelationEdge.model_validate(data | {"support_pair": {"alert_id_src": data["source_alert_id"], "alert_id_dst": data["source_alert_id"]}})
    context = {"groups": {data["source_alert_id"]: [data["source_alert_id"]], data["target_alert_id"]: [data["target_alert_id"]]}}
    assert models.CorrelationEdge.model_validate(data, context=context)
    wrong = deepcopy(data)
    wrong["support_pair"]["alert_id_src"], wrong["support_pair"]["alert_id_dst"] = wrong["support_pair"]["alert_id_dst"], wrong["support_pair"]["alert_id_src"]
    with pytest.raises(ValidationError, match="source fact group"):
        models.CorrelationEdge.model_validate(wrong, context=context)
    wrong = deepcopy(data)
    wrong["support_pair"]["alert_id_src"] = "alt_" + "f" * 64
    with pytest.raises(ValidationError, match="owning"):
        models.CorrelationEdge.model_validate(wrong)


def test_selected_pair_cannot_borrow_relation_pointer_from_other_member():
    data = sample("ChainEdge")
    cor = models.CorrelationEdge.model_validate(sample("CorrelationEdge"))
    context = {"correlation_edges": {cor.edge_id: cor}}
    assert models.ChainEdge.model_validate(data, context=context)
    relation = next(r for r in data["reasons"] if r["code"] == "explicit_relation")
    extra = "alt_" + "f" * 64
    data["alert_ids"].append(extra)
    relation["alert_ids"].append(extra)
    relation["params"]["raw_pointers"][0]["alert_id"] = extra
    relation.update(reidentify("Reason", relation))
    with pytest.raises(ValidationError, match="owning"):
        models.ChainEdge.model_validate(data, context=context)


def test_chain_local_closure_duplicate_nodes_dag_and_isolated_node():
    data = sample("AttackChain")
    isolated = data | {"edges": []}
    assert models.AttackChain.model_validate(reidentify("AttackChain", isolated)).edges == []
    bad = deepcopy(data)
    bad["nodes"].append(bad["nodes"][0])
    with pytest.raises(ValidationError, match="unique"):
        models.AttackChain.model_validate(bad)
    bad = deepcopy(data)
    bad["nodes"] = bad["nodes"][:1]
    with pytest.raises(ValidationError, match="closed"):
        models.AttackChain.model_validate(reidentify("AttackChain", bad))
    reverse = deepcopy(data["edges"][0])
    reverse["source_node_id"], reverse["target_node_id"] = reverse["target_node_id"], reverse["source_node_id"]
    reason = next(r for r in reverse["reasons"] if r["code"] == "direction")
    reason["params"].update(source_node_id=reverse["source_node_id"], target_node_id=reverse["target_node_id"])
    reason.update(reidentify("Reason", reason))
    bad = data | {"edges": data["edges"] + [reidentify("ChainEdge", reverse)]}
    with pytest.raises(ValidationError, match="DAG"):
        models.AttackChain.model_validate(reidentify("AttackChain", bad))


def test_ai_reference_structure_whitelist_and_validation_status():
    data = sample("AIClaim")
    for changed in (data | {"alert_ids": []}, data | {"propositions": []},
                    data | {"grounding_status": "rejected"}, data | {"attack_mapping": sample("AttackMapping")}):
        with pytest.raises(ValidationError):
            models.AIClaim.model_validate(reidentify("AIClaim", changed))
    p = sample("GroundedProposition")
    for field in ("raw_alert", "raw_alert.foo", "payload", "diagnostics", "label"):
        with pytest.raises(ValidationError, match="whitelist"):
            models.GroundedProposition.model_validate(p | {"field": field})
    context = {"subjects": {("alert", p["subject_id"]): {"severity": "unknown"}}}
    assert models.GroundedProposition.model_validate(p, context=context)
    with pytest.raises(ValidationError, match="differs"):
        models.GroundedProposition.model_validate(p | {"value": "critical"}, context=context)
    explanation = sample("AIExplanation")
    with pytest.raises(ValidationError, match="every claim"):
        models.AIExplanation.model_validate(explanation | {"grounding_status": "validated"})
    # This is a data model, not an AI validator: pending drafts remain representable.
    assert models.AIExplanation.model_validate(explanation).grounding_status == "pending"


@pytest.mark.parametrize("status", ["queued", "running", "completed", "failed", "incomplete"])
def test_analysis_status_integrity(status):
    data = sample("AnalysisRecord")
    data.update(status=status, is_complete=status == "completed")
    if status in ("failed", "incomplete"):
        data.update(incomplete_reason="synthetic/resource-limit", errors=["synthetic/error"])
    assert models.AnalysisRecord.model_validate(data)
    with pytest.raises(ValidationError):
        models.AnalysisRecord.model_validate(data | {"is_complete": not data["is_complete"]})


def test_analysis_digests_fixed_refs_required_null_and_truncation():
    data = sample("AnalysisRecord")
    for wrong in (data | {"config_digest": "0" * 64}, data | {"config_snapshot": {"changed": True}},
                  data | {"diagnostics_ref": "outputs/analyses/other/diagnostics.jsonl"},
                  data | {"frequency_snapshot_ref": "../../external.json"}, data | {"candidate_truncated": True}):
        with pytest.raises(ValidationError):
            models.AnalysisRecord.model_validate(wrong)
    assert models.AnalysisRecord.model_validate(data | {"candidate_truncated": True, "status": "incomplete",
        "incomplete_reason": "synthetic/truncated", "errors": ["synthetic/truncated"]})
    del data["incomplete_reason"]
    with pytest.raises(ValidationError):
        models.AnalysisRecord.model_validate(data)


def test_evaluation_summary_status_coverage_and_no_truth_fields_or_old_pagination():
    data = sample("EvaluationSummaryExport")
    for status, value in (("available", 0.5), ("not_applicable", None), ("unavailable", None)):
        assert models.EvaluationSummaryExport.model_validate(data | {"metrics": {"precision": value}, "metric_status": {"precision": status}})
    for wrong in (data | {"metric_status": {}}, data | {"metric_status": {"precision": "available"}},
                  data | {"metrics": {"precision": 0.5}}, data | {"limitations": []}):
        with pytest.raises(ValidationError):
            models.EvaluationSummaryExport.model_validate(wrong)
    for field in ("labels", "gold_chain", "truth_path", "schema_version", "offset", "limit"):
        with pytest.raises(ValidationError):
            models.EvaluationSummaryExport.model_validate(data | {field: "synthetic"})


def test_config_model_analysis_schema_minimal_integration():
    from app.config import load_config
    root = Path(__file__).resolve().parents[2]
    effective = load_config(root / "configs/algorithm-v0.yaml")
    assert content_digest(effective.snapshot) == effective.config_hash
    analysis = sample("AnalysisRecord")
    analysis.update(config_hash=effective.config_hash, config_digest=effective.config_digest,
                    config_snapshot=effective.snapshot, mapping_digest=effective.mapping_digest)
    analysis = reidentify("AnalysisRecord", analysis)
    analysis.update(diagnostics_ref=f"outputs/analyses/{analysis['analysis_id']}/diagnostics.jsonl",
                    frequency_snapshot_ref=f"outputs/analyses/{analysis['analysis_id']}/frequency_snapshot.json")
    assert models.AnalysisRecord.model_validate_json(models.AnalysisRecord.model_validate(analysis).canonical_json())


def test_production_models_are_pure_and_never_read_ground_truth(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("schema/identity validation must not perform filesystem I/O")
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr("builtins.open", forbidden)
    for case in VALID:
        assert getattr(models, case["model"]).model_validate(case["data"])


def test_all_frozen_enum_values_are_strict_and_enum_types_do_not_alias():
    from pydantic import TypeAdapter
    from app.models.enums import ContractEnum
    for name in models.__all__:
        cls = getattr(models, name)
        if isinstance(cls, type) and issubclass(cls, ContractEnum):
            adapter = TypeAdapter(cls)
            for member in cls:
                assert adapter.validate_python(member.value, strict=True) is member
                assert adapter.validate_json(json.dumps(member.value), strict=True) is member
            for wrong in ("invented_value", "", None, 0, True):
                with pytest.raises(ValidationError):
                    adapter.validate_python(wrong, strict=True)
    with pytest.raises(ValidationError):
        TypeAdapter(models.SourceIndependence).validate_python(models.Severity.UNKNOWN, strict=True)


def test_nfc_dictionary_collisions_rejected_before_key_coercion():
    data = sample("EvaluationSummaryExport")
    data.update(metrics={"é": 0.1, "e\u0301": 0.2}, metric_status={"é": "available", "e\u0301": "available"})
    with pytest.raises(ValidationError, match="collide"):
        models.EvaluationSummaryExport.model_validate(data)


def test_nfc_bound_evidence_preserves_original_raw_keys():
    alert = sample("CanonicalAlert")
    alert["raw_alert"]["e\u0301"] = {"trigger": "synthetic-instance"}
    alert["raw_fingerprint"] = raw_fingerprint(alert["raw_alert"])
    alert = models.CanonicalAlert.model_validate(reidentify("CanonicalAlert", alert))
    ptr = models.EvidencePointer.model_validate({"alert_id": alert.alert_id, "pointer": "/é/trigger", "side": "shared"})
    assert ptr.resolve({alert.alert_id: alert}) == "synthetic-instance"
    assert "e\u0301" in alert.raw_alert and "é" not in alert.raw_alert
    restored = models.CanonicalAlert.model_validate_json(alert.canonical_json())
    assert ptr.resolve({restored.alert_id: restored}) == "synthetic-instance"


def test_source_pair_snapshot_mismatch_same_origin_priority_and_real_config_refs():
    data = sample("CorrelationEdge")
    source = next(r for r in data["reasons"] if r["code"] == "source_complement")
    sensors = source["params"]["sensor_names"]
    types = source["params"]["source_types"]
    # These in-memory synthetic records supply exactly the referenced fields;
    # no adapter, real data or origin inference is exercised.
    context = {"alerts": {aid: {"raw_alert": {"request": {"trigger": "synthetic-instance"}},
        "source_type": types[index], "source_namespace": f"synthetic/source-{index}", "sensor": sensors[index]}
        for index, aid in enumerate((data["support_pair"]["alert_id_src"], data["support_pair"]["alert_id_dst"]))}}
    assert models.CorrelationEdge.model_validate(data, context=context)
    source["params"]["source_types"] = ["other"]
    source.update(reidentify("Reason", source))
    with pytest.raises(ValidationError, match="actual support_pair"):
        models.CorrelationEdge.model_validate(data, context=context)
    source["params"]["source_types"] = types
    source.update(reidentify("Reason", source))
    for alert in context["alerts"].values():
        alert.update(origin_namespace="synthetic/origin", origin_record_id="synthetic/record")
    with pytest.raises(ValidationError, match="same origin takes precedence"):
        models.CorrelationEdge.model_validate(data, context=context)
    reason = sample("Reason.source_complement")
    reason["params"].update(source_independence="confirmed_independent", independence_rule_ids=["synthetic/topology"])
    reason = reidentify("Reason", reason)
    snapshot = {"source": {"independence_mapping_files": [{"rules": [{"id": "synthetic/topology"}]}]}}
    assert models.Reason.model_validate(reason, context={"config_snapshot": snapshot})
    with pytest.raises(ValidationError, match="configuration"):
        models.Reason.model_validate(reason, context={"config_snapshot": {"source": {"independence_mapping_files": []}}})


def test_proposition_snapshot_set_reorder_and_duplicates_are_normalized():
    p = sample("GroundedProposition")
    eid = sample("Entity")["entity_id"]
    p.update(field="entity_ids", value=[eid, eid])
    context = {"subjects": {("alert", p["subject_id"]): {"entity_ids": [eid]}}}
    assert models.GroundedProposition.model_validate(p, context=context).value == [eid]


def test_score_large_number_is_validation_error_and_config_weights_are_verified():
    with pytest.raises(ValidationError):
        models.AnalysisMetrics.model_validate(sample("AnalysisMetrics") | {"peak_memory_mb": 10 ** 500})
    data = sample("ScoreBreakdown")
    snapshot = {"score": {"weights": data["weights"]}}
    data["config_hash"] = content_digest(snapshot)
    assert models.ScoreBreakdown.model_validate(data, context={"config_snapshot": snapshot})
    changed = deepcopy(snapshot)
    changed["score"]["weights"].update(time=0.1, source=0.2)
    data["config_hash"] = content_digest(changed)
    with pytest.raises(ValidationError, match="weights"):
        models.ScoreBreakdown.model_validate(data, context={"config_snapshot": changed})


def test_explicit_relationship_without_shared_entities_remains_representable():
    # Frozen AGENTS/DATA_CONTRACT permit no shared entities with explicit fields.
    # Never invent an entity or a new required schema field to fill that gap.
    for kind in ("CorrelationEdge", "ChainEdge"):
        data = sample(kind)
        data["entity_ids"] = []
        for reason in data["reasons"]:
            reason["entity_ids"] = []
            reason.update(reidentify("Reason", reason))
        assert getattr(models, kind).model_validate(data).entity_ids == []

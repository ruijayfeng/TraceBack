"""Identity metamorphic tests and independently encoded canonical hash vectors."""

from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import subprocess
import sys

import pytest

import app.models as models
from app.utils.stable_id import (ID_FIELDS, PREFIXES, IdentityRegistry, canonical_json,
                                content_digest, id_for, identity_for, raw_fingerprint, stable_id, utc_text)


FIXTURES = Path(__file__).parent / "fixtures/schema"
CASES = json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))["cases"]
SAMPLES = {c["name"]: c["data"] for c in CASES}


@pytest.mark.parametrize("kind", PREFIXES)
def test_all_thirteen_identity_contracts_and_persistence(kind):
    data = deepcopy(SAMPLES[kind])
    result = id_for(kind, data)
    assert result == data[ID_FIELDS[kind]]
    assert len(result.split("_")[1]) == 64
    value = getattr(models, kind).model_validate(data)
    assert id_for(kind, value) == result
    for _ in range(10):
        pairs = list(data.items())
        random.Random(_).shuffle(pairs)
        assert id_for(kind, dict(pairs)) == result


def test_canonical_independently_encoded_vector_unicode_null_numbers_and_arrays():
    data = {"z": None, "e\u0301": "e\u0301", "array": [2, 1], "number": 0.5000, "negative_zero": -0.0}
    expected = '{"array":[2,1],"negative_zero":0,"number":0.5,"z":null,"é":"é"}'
    assert canonical_json(data) == expected
    assert content_digest(data) == sha256(expected.encode("utf-8")).hexdigest()
    identity = '{"array":[2,1],"negative_zero":0,"number":{"$decimal":"0.5"},"z":null,"é":"é"}'
    assert canonical_json(data, identity_numbers=True) == identity
    envelope = '{"id_version":"v1","identity":' + identity + ',"kind":"Reason"}'
    assert stable_id("Reason", data) == "rsn_" + sha256(envelope.encode("utf-8")).hexdigest()
    assert canonical_json({"v": 1.0}, identity_numbers=True) == '{"v":1}'
    assert canonical_json({"v": True}, identity_numbers=True) != canonical_json({"v": 1}, identity_numbers=True)


def test_decimal_context_does_not_round_canonical_numbers():
    with localcontext() as context:
        context.prec = 4
        assert canonical_json({"x": Decimal("123456789.0123000")}) == '{"x":123456789.0123}'
        assert canonical_json({"x": Decimal("0.000000000000000000000012300")}) == '{"x":0.0000000000000000000000123}'


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), {1: "bad"},
                                   {"e\u0301": 1, "é": 2}, {"tuple": (1, 2)}, {"runtime": object()}, "\ud800"])
def test_invalid_json_canonical_inputs_are_rejected(value):
    with pytest.raises((ValueError, UnicodeError)):
        canonical_json(value)


def test_raw_fingerprint_uses_decimal_numbers_and_preserves_text_and_array_order():
    assert raw_fingerprint({"x": 0.50, "y": [2, 1]}) == raw_fingerprint({"y": [2, 1], "x": Decimal("0.500")})
    assert raw_fingerprint({"x": 0.5}) == sha256(b'{"x":0.5}').hexdigest()
    assert raw_fingerprint({"x": 0.5}) != raw_fingerprint({"x": {"$decimal": "0.5"}})
    assert raw_fingerprint({"x": [1, 2]}) != raw_fingerprint({"x": [2, 1]})
    assert raw_fingerprint("e\u0301\n") == sha256("e\u0301\n".encode()).hexdigest()
    assert raw_fingerprint("é\n") != raw_fingerprint("e\u0301\n")


def test_time_helper_offset_equivalence_and_datetime_is_not_arbitrary_json():
    assert utc_text("2026-10-04T10:31:04.123456999+08:00") == "2026-10-04T02:31:04.123456Z"
    assert utc_text(datetime(2026, 10, 4, 2, 31, 4, tzinfo=timezone.utc)) == "2026-10-04T02:31:04.000000Z"
    with pytest.raises(ValueError):
        canonical_json(datetime(2026, 10, 4, tzinfo=timezone.utc))
    with pytest.raises(ValueError):
        utc_text(datetime(2026, 10, 4))


@pytest.mark.parametrize("name,set_field", [("shared_entity", "roles"), ("explicit_relation", "raw_pointers"),
    ("source_complement", "source_types"), ("source_complement", "sensor_names"),
    ("source_complement", "raw_pointers"), ("source_complement", "independence_rule_ids")])
def test_reason_declared_sets_reorder_duplicate_and_nfc_are_identity_neutral(name, set_field):
    data = deepcopy(SAMPLES["Reason." + name])
    if name == "source_complement" and set_field == "raw_pointers":
        data["params"][set_field] = deepcopy(SAMPLES["Reason.explicit_relation"]["params"]["raw_pointers"])
    if name == "source_complement" and set_field == "independence_rule_ids":
        data["params"][set_field] = ["synthetic/é", "synthetic/rule"]
    base = id_for("Reason", data)
    values = data["params"][set_field]
    data["params"][set_field] = list(reversed(values)) + deepcopy(values)
    assert id_for("Reason", data) == base
    data["reason_id"] = base
    parsed = models.Reason.model_validate(data)
    assert len(parsed.params[set_field]) == len(values)
    assert id_for("Reason", parsed) == base


def test_reason_alert_entity_identity_sets_vs_strict_persistence_and_multisets():
    data = deepcopy(SAMPLES["Reason.explicit_relation"])
    base = id_for("Reason", data)
    data["alert_ids"] = list(reversed(data["alert_ids"])) + data["alert_ids"]
    data["entity_ids"] *= 2
    assert id_for("Reason", data) == base
    guard = deepcopy(SAMPLES["Reason.clustering_guard"])
    guard["params"]["component_sizes"] = [3, 2, 2]
    original = id_for("Reason", guard)
    guard["params"]["component_sizes"] = [2, 3, 2]
    assert id_for("Reason", guard) == original
    guard["params"]["component_sizes"] = [2, 3]
    assert id_for("Reason", guard) != original


def test_reason_identity_changes_with_content_but_not_message():
    data = deepcopy(SAMPLES["Reason.time_gap"])
    original = id_for("Reason", data)
    assert id_for("Reason", data | {"message": "另一个展示模板"}) == original
    data["params"]["gap_seconds"] = 0.5
    assert id_for("Reason", data) != original
    assert '"$decimal":"0.5"' in canonical_json(identity_for("Reason", data), identity_numbers=True)


def test_propositions_set_numeric_nfc_and_ordinary_arrays():
    claim = deepcopy(SAMPLES["AIClaim"])
    aid = claim["alert_ids"][0]
    p = {"subject_type": "alert", "subject_id": aid, "field": "entity_occurrences", "value": ["e\u0301", 0.5, 2]}
    q = {"subject_type": "alert", "subject_id": aid, "field": "category", "value": None}
    claim["propositions"] = [p, q]
    original = id_for("AIClaim", claim)
    other = deepcopy(p)
    other["value"][0] = "é"
    claim["propositions"] = [q, other, p]
    assert id_for("AIClaim", claim) == original
    claim["claim_id"] = original
    parsed = models.AIClaim.model_validate(claim)
    assert len(parsed.propositions) == 2
    assert id_for("AIClaim", parsed) == original
    p["value"].reverse()
    claim["propositions"] = [p, q]
    assert id_for("AIClaim", claim) != original


def test_proposition_value_snapshot_sets_are_canonical_and_ordinary_values_are_not_sorted():
    claim = deepcopy(SAMPLES["AIClaim"])
    eid = SAMPLES["Entity"]["entity_id"]
    p = {"subject_type": "alert", "subject_id": claim["alert_ids"][0], "field": "entity_ids", "value": [eid]}
    claim["propositions"] = [p]
    original = id_for("AIClaim", claim)
    p["value"] *= 2
    assert id_for("AIClaim", claim) == original
    claim["claim_id"] = original
    assert models.AIClaim.model_validate(claim).propositions[0].value == [eid]


def test_cor_undirected_che_directed_identity_and_score_mutability():
    data = deepcopy(SAMPLES["CorrelationEdge"])
    original = id_for("CorrelationEdge", data)
    data["source_alert_id"], data["target_alert_id"] = data["target_alert_id"], data["source_alert_id"]
    assert id_for("CorrelationEdge", data) == original
    data.update(score=0.1, reasons=[], score_breakdown={"changed": True})
    assert id_for("CorrelationEdge", data) == original
    edge = deepcopy(SAMPLES["ChainEdge"])
    original = id_for("ChainEdge", edge)
    edge["source_node_id"], edge["target_node_id"] = edge["target_node_id"], edge["source_node_id"]
    assert id_for("ChainEdge", edge) != original


@pytest.mark.parametrize("kind,field", [("CanonicalAlert", "source_namespace"), ("CanonicalAlert", "source_record_id"),
    ("CanonicalAlert", "raw_fingerprint"), ("Entity", "scope"), ("Entity", "value"),
    ("ChainEdge", "relation_type"), ("AIClaim", "text"), ("AIExplanation", "provider"),
    ("AIExplanation", "input_digest"), ("AnalysisRecord", "config_hash"), ("AnalysisRecord", "algorithm_version")])
def test_identity_field_changes_change_id(kind, field):
    data = deepcopy(SAMPLES[kind])
    original = id_for(kind, data)
    data[field] = "synthetic/changed"
    assert id_for(kind, data) != original


def test_alert_derived_fields_and_origin_record_id_do_not_expand_frozen_identity():
    data = deepcopy(SAMPLES["CanonicalAlert"])
    original = id_for("CanonicalAlert", data)
    data.update(category="web_attack", severity="critical", entity_ids=[SAMPLES["Entity"]["entity_id"]],
                origin_record_id="synthetic/native-id", import_path="C:/temporary/file", row_number=20)
    assert id_for("CanonicalAlert", data) == original


def test_analysis_members_and_config_change_identity_runtime_does_not():
    data = deepcopy(SAMPLES["AnalysisRecord"])
    original = id_for("AnalysisRecord", data)
    data["input_alert_ids"].reverse()
    data["metrics"]["total_runtime_seconds"] = 99
    assert id_for("AnalysisRecord", data) == original
    data["input_alert_ids"].pop()
    assert id_for("AnalysisRecord", data) != original


def test_identity_registry_same_id_conflict_and_cross_analysis_keys():
    registry = IdentityRegistry()
    one = SAMPLES["AnalysisRecord"]["analysis_id"]
    two = "ana_" + "b" * 64
    entity = deepcopy(SAMPLES["Entity"])
    eid = entity["entity_id"]
    first = registry.register(one, eid, "Entity", entity)
    assert registry.register(one, eid, "Entity", entity | {"display_value": "changed display"}) == first
    with pytest.raises(ValueError, match="conflicting identity"):
        registry.register(one, eid, "Entity", entity | {"scope": "synthetic/other"})
    assert registry.register(two, eid, "Entity", entity | {"display_value": "another analysis display"}) != first
    with pytest.raises(ValueError, match="conflicting identity"):
        registry.register(two, eid, "Entity", entity | {"scope": "synthetic/other"})


def test_process_hash_seed_does_not_affect_identity():
    # Fresh interpreters guard against accidental Python hash()/set traversal IDs.
    code = ("import json; from pathlib import Path; from app.utils.stable_id import id_for; "
            "v=json.loads(Path('backend/tests/fixtures/schema/valid.json').read_text(encoding='utf-8')); "
            "print(id_for('AIClaim',next(c['data'] for c in v['cases'] if c['name']=='AIClaim')))")
    root = Path(__file__).resolve().parents[2]
    outputs = []
    for seed in ("1", "777"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        env["PYTHONPATH"] = str(root / "backend")
        outputs.append(subprocess.run([sys.executable, "-c", code], cwd=root, env=env,
                                      capture_output=True, text=True, check=True).stdout.strip())
    assert outputs == [SAMPLES["AIClaim"]["claim_id"]] * 2

"""Real t5 selection contract, reproducibility and leakage tripwires."""
import builtins
from collections import Counter
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("t5_selection", ROOT / "scripts/cptc_t5_dev_10k.py")
selection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selection)


@pytest.fixture(scope="module")
def real_run():
    """Run with import/file tripwires throughout both selection and validation."""
    old_import, old_open = builtins.__import__, Path.open
    forbidden = ("app.correlation", "app.incidents", "app.chains", "app.ai", "evaluation")
    opened = []
    def safe_import(name, *args, **kwargs):
        assert not any(name == p or name.startswith(p + ".") for p in forbidden), name
        return old_import(name, *args, **kwargs)
    def safe_open(path, mode="r", *args, **kwargs):
        text = str(path).lower().replace("\\", "/")
        assert not any(p in text.split("/") for p in ("evaluation", "labels", "ground_truth")), text
        assert not any(p in path.name.lower() for p in ("attacks.log", "gold_chain", "label")), text
        if "r" in mode and str(path).endswith(".json.gz"):
            assert path.resolve() in {selection.SOURCE.resolve(), selection.DEST.resolve(),
                                    (selection.OUT / "determinism_run2.json.gz").resolve()}, text
        opened.append(str(path))
        return old_open(path, mode, *args, **kwargs)
    before = {str(p): selection.sha(p) for base in (ROOT / "backend/app", ROOT / "configs")
              for p in base.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
    builtins.__import__, Path.open = safe_import, safe_open
    try:
        result = selection.run()
    finally:
        builtins.__import__, Path.open = old_import, old_open
    assert all(selection.sha(Path(p)) == digest for p, digest in before.items())
    return result, opened


def test_selected_count_exactly_10000(real_run):
    m, _ = real_run
    assert m["raw_count"] == 52833
    assert m["selected_count"] == 10000
    assert len(list(selection.read_cptc_file(selection.DEST))) == 10000


def test_two_complete_selection_runs_are_byte_deterministic(real_run):
    m, _ = real_run
    assert m["determinism"]["run1_sha256"] == m["determinism"]["run2_sha256"] == selection.sha(selection.DEST)


def test_source_unchanged(real_run):
    m, _ = real_run
    assert m["source_unchanged"] and selection.sha(selection.SOURCE) == m["source_sha256"]


def test_reader_adapter_and_wrappers_preserved(real_run):
    m, _ = real_run
    assert m["reader_adapter_validation"] == {"raw": 10000, "parsed": 10000, "rejected": 0,
        "canonical_records": 10000, "canonical_unique_ids": 10000, "errors": {}}
    source = Counter(selection.dumps(r.wrapper) for r in selection.read_cptc_file(selection.SOURCE))
    output = Counter(selection.dumps(r.wrapper) for r in selection.read_cptc_file(selection.DEST))
    assert not output - source


def test_no_production_correlation_import_or_call(real_run):
    # real_run executes with forbidden imports; production implementation/config
    # hashes are also unchanged. Static imports give an independent boundary check.
    import ast
    tree = ast.parse(Path(selection.__file__).read_text(encoding="utf8"))
    imports = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not any("correlation" in name or "evaluation" in name for name in imports)
    assert real_run[0]["selection_uses_correlation_result"] is False


def test_labels_payload_and_wrapper_not_selection_features(real_run):
    record = next(selection.read_cptc_file(selection.SOURCE))
    original = selection.features(record)
    poisoned = copy.deepcopy(record)
    poisoned.eve.update(label="unused", ground_truth="unused", payload="changed")
    poisoned.wrapper.update(label="unused", host="changed")
    poisoned.eve["alert"]["stage_label"] = "unused"
    assert selection.features(poisoned) == original
    assert real_run[0]["selection_uses_attack_labels"] is False
    # Actual contaminated ingestion is rejected, never silently included.
    with pytest.raises(ValueError, match="annotation_contamination"):
        from app.adapters.cptc import unwrap_splunk
        unwrap_splunk(poisoned.wrapper)


def test_full_time_span_and_all_active_minutes(real_run):
    m, _ = real_run
    assert m["source_time_range"] == m["selected_time_range"]
    audit = json.loads((selection.OUT / "audit_before_after.json").read_text(encoding="utf8"))
    for seconds in ("60", "300", "3600"):
        assert {r["start_utc"] for r in audit["before"]["buckets"][seconds]} == {
            r["start_utc"] for r in audit["after"]["buckets"][seconds]}


def test_rare_signatures_and_entity_values_retained(real_run):
    m, _ = real_run
    assert m["rare_signatures"] == {"unique_before": 13, "unique_after": 13,
                                    "records_before": 47, "records_after": 47}
    for key in selection.PROTECT:
        assert m["retention"][key]["ratio"] == 1


def test_burst_and_fingerprint_endpoints_and_exact_duplicates(real_run):
    m, _ = real_run
    p = m["protection"]
    assert p["burst_endpoint_candidates"] == p["burst_endpoints_retained"]
    assert p["fingerprint_endpoint_candidates"] == p["fingerprint_endpoints_retained"]
    audit = json.loads((selection.OUT / "audit_before_after.json").read_text(encoding="utf8"))
    assert audit["before"]["exact_duplicate_excess"] == 90
    assert audit["after"]["exact_duplicate_excess"] == 0


def test_source_evidence_limit_is_not_hidden(real_run):
    m, _ = real_run
    assert m["result"] == "CPTC_T5_DEV_10K_REQUIRES_REVIEW"
    audit = json.loads((selection.OUT / "audit_before_after.json").read_text(encoding="utf8"))
    assert audit["after"]["evidence"]["Medium"]["count"] == 4
    assert audit["after"]["evidence"]["Sparse"]["count"] == 0
    assert m["random_sampling"] is False

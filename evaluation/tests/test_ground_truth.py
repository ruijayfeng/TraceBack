from types import SimpleNamespace

import pytest

from evaluation.io.ground_truth import epoch_microseconds, load_windows, map_windows


def csv(tmp_path, rows, header="scenario,attack,start,end"):
    p = tmp_path / "labels.csv"
    p.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    return p


def test_real_shape_scope_halfopen_mapping_and_unmapped(tmp_path):
    p = csv(tmp_path, ["s,a,1.0,2.0", "s,b,3,4", "other,c,1,2"])
    before = p.read_bytes()
    gt = load_windows(p, "s")
    snapshot = SimpleNamespace(alerts={"a": {"time_us": 1000000}, "b": {"time_us": 1999999}, "c": {"time_us": 2000000}},
                               owner={"a": "a", "b": "a", "c": "c"})
    mapping = map_windows(gt, snapshot)
    assert (mapping["total_rows"], mapping["selected_rows"], mapping["out_of_scope_rows"]) == (3,2,1)
    assert (mapping["mapped"], mapping["unmapped"], mapping["ambiguous"]) == (1,1,0)
    assert mapping["temporal_overlap_alert_count"] == 2
    assert mapping["outside_window_alert_count"] == 1
    assert mapping["quality_evaluation_coverage"] == mapping["direct_alert_id_mapped"] == 0
    assert not any(gt["capabilities"][k] for k in ("alert_labels", "pair_labels", "incident_membership"))
    assert p.read_bytes() == before


def test_ambiguous_overlapping_intervals_deterministic_ids(tmp_path):
    p = csv(tmp_path, ["s,a,1,3", "s,b,2,4"])
    snap = SimpleNamespace(alerts={"a": {"time_us": 2500000}}, owner={"a": "rep"})
    first = map_windows(load_windows(p, "s"), snap)
    p.write_text("scenario,attack,start,end\ns,b,2,4\ns,a,1,3\n")
    second = map_windows(load_windows(p, "s"), snap)
    assert first == second
    assert first["ambiguous_alert_count"] == 1 and first["ambiguous"] == 2


def test_concurrent_gt_revision_is_rejected(tmp_path, monkeypatch):
    import evaluation.io.ground_truth as module
    path = csv(tmp_path, ["s,a,1,2"])
    original = module.file_digest
    calls = 0
    def revision(p):
        nonlocal calls
        calls += 1
        if calls == 2:
            path.write_text("scenario,attack,start,end\ns,a,1,3\n",encoding="utf-8")
        return original(p)
    monkeypatch.setattr(module,"file_digest",revision)
    with pytest.raises(ValueError,match="ground_truth_changed"):
        load_windows(path,"s")


@pytest.mark.parametrize("row", ["s,a,NaN,2", "s,a,Infinity,2", "s,a,2,1", "s,a,1,1", "s,a,x,2", "s,a,1", "s,a,1,2,extra"])
def test_invalid_gt_rows_are_not_silently_dropped(tmp_path, row):
    with pytest.raises(ValueError):
        load_windows(csv(tmp_path, [row]), "s")


def test_reject_unknown_schema_missing_scenario_duplicate(tmp_path):
    with pytest.raises(ValueError, match="schema"):
        load_windows(csv(tmp_path, ["1,2"], "alert_id,label"), "s")
    with pytest.raises(ValueError, match="scenario"):
        load_windows(csv(tmp_path, ["other,a,1,2"]), "s")
    with pytest.raises(ValueError, match="duplicate"):
        load_windows(csv(tmp_path, ["s,a,1,2", "s,a,1,2"]), "s")
    assert epoch_microseconds("1.123456789") == 1123456

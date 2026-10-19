"""Index oracle, fact-group frequency and scoped references."""

import pytest
from app.correlation.index import AlertIndex
from app.correlation.conflicts import group_targets
from test_correlation_score import alert, config, group, inputs, process


def test_empty_index_and_inclusive_time_oracle():
    assert AlertIndex([]).N == 0
    index, _ = inputs([alert("c", 2, host="h"), alert("a", 0, host="h"), alert("b", 1, host="h")])
    times = sorted(a.timestamp for a in index.alerts.values())
    got = index.query_time(times[0], times[1])
    assert len(got) == 2 and got == sorted(got, key=lambda a: (a.timestamp, a.alert_id))
    eid = next(eid for eid, e in index.entities.items() if e.type.value == "HOST")
    assert index.query_entity(eid, times[0], times[1], "host") == got
    assert index.query_entity(eid, times[0], times[1], "account") == []


def test_group_frequency_not_wrapper_count_and_missing_references(config):
    values = [alert("a", host="h"), alert("b", 1, host="h"), alert("c", 2, host="other")]
    g = group(values[:2])
    index, _ = inputs(values, groups=[g])
    assert index.N == 2
    assert all(df == 1 for df in index.df.values())
    assert len(index.groups[g.representative_alert_id]) == 2
    with pytest.raises(ValueError, match="missing_entity_reference"):
        AlertIndex(index.alerts.values(), [g], [])


def test_target_set_port_scope_empty_and_full_group():
    values = [alert("a", src_ip="192.0.2.1"), alert("b", dst_ip="192.0.2.2"),
              alert("c", dst_ip="192.0.2.2", dst_port=80, host="h"),
              alert("d", dst_ip="192.0.2.2", dst_port=443, host="h")]
    g = group(values[2:])
    index, settings = inputs(values, groups=[g])
    assert group_targets(values[0].alert_id, index, settings) == []
    assert group_targets(values[1].alert_id, index, settings) == []
    keys = {t.key for t in group_targets(g.representative_alert_id, index, settings)}
    assert keys == {("HOST", "synthetic", "h"), ("ENDPOINT", "synthetic", "192.0.2.2", 80),
                    ("ENDPOINT", "synthetic", "192.0.2.2", 443)}


def test_posting_mask_and_nearest_match_exhaustive_oracle():
    values = [alert(str(i), i // 3, host="h") for i in range(400)]
    index, _ = inputs(values)
    posting = index.by_entity[next(iter(index.entities))]["unknown"]
    member = values[210].alert_id
    center = index.times[member]
    start, end = center - 7_000_000, center + 9_000_000
    expected = sorted((a for a in index.alerts.values() if start <= index.times[a.alert_id] <= end and a.alert_id != member),
                      key=lambda a: (abs(index.times[a.alert_id] - center), a.alert_id))
    mask = posting.mask(start, end) & ~(1 << index.positions[member])
    assert mask.bit_count() == len(expected)
    assert [rep for rep, _, _ in posting.nearest(member, start, end, 10)] == [a.alert_id for a in expected[:10]]


@pytest.mark.parametrize("timestamp", [None,"not-a-time","2022-01-01T00:00:00"])
def test_corrupted_preprocessed_time_fails_without_backfill(timestamp):
    value=alert("a").model_dump();value["timestamp"]=timestamp
    with pytest.raises(ValueError):
        AlertIndex([value])

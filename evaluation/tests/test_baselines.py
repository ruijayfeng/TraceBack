from types import SimpleNamespace

import pytest

from evaluation.baselines.methods import baseline_counts


def snapshot(alerts, groups=None):
    groups = groups or {i:[i] for i in alerts}
    owner = {i:r for r, members in groups.items() for i in members}
    return SimpleNamespace(alerts=alerts, groups=groups, owner=owner,
                           entities={"ip-a":{"type":"IP"}, "ip-b":{"type":"IP"}, "host":{"type":"HOST"}})


def test_deterministic_scoped_baseline_counts_and_boundary():
    alerts = {"a":{"time_us":0,"entity_ids":["ip-a"]}, "b":{"time_us":300000000,"entity_ids":["ip-a","host"]},
              "c":{"time_us":300000001,"entity_ids":["ip-b","host"]}, "d":{"time_us":700000000,"entity_ids":[]}}
    first = {r["method"]:r["predicted_edge_count"] for r in baseline_counts(snapshot(alerts))}
    second = {r["method"]:r["predicted_edge_count"] for r in baseline_counts(snapshot(dict(reversed(list(alerts.items())))))}
    assert first == second == {"time_only":2, "time_ip":1, "time_all_entities":2}


def test_baseline_preserves_nonrepresentative_support_and_dedup():
    alerts = {"a":{"time_us":0,"entity_ids":[]},"b":{"time_us":1000000000,"entity_ids":["ip-a"]},
              "c":{"time_us":1000000001,"entity_ids":["ip-a"]}}
    rows = baseline_counts(snapshot(alerts,{"a":["a","b"],"c":["c"]}))
    assert all(r["predicted_edge_count"] == 1 for r in rows)


@pytest.mark.parametrize("kind", ["IP","HOST","ACCOUNT","SESSION","PROCESS","URL","DOMAIN","FILE","COMMAND"])
def test_all_entity_baseline_covers_every_frozen_entity_type(kind):
    s = snapshot({"a":{"time_us":0,"entity_ids":["scoped-entity"]},"b":{"time_us":1000000,"entity_ids":["scoped-entity"]}})
    s.entities = {"scoped-entity":{"type":kind,"scope":"synthetic-scope","value":"synthetic-value"}}
    rows = {r["method"]:r["predicted_edge_count"] for r in baseline_counts(s)}
    assert rows["time_all_entities"] == 1 and rows["time_ip"] == int(kind == "IP")

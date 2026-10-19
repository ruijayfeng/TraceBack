"""Analysis partitions, shared Stable IDs, evidence closure and tamper rejection."""

import json
from dataclasses import replace

from fastapi.testclient import TestClient

from app.main import create_app
from app.models.base import resolve_pointer
from app.services.queries import QueryService
from app.services.storage import SnapshotStore, file_digest
from test_analysis_service import deployment, edge_records, request_for, write_input
from test_api import api, create_run
from test_wazuh_adapter import synthetic_record


def test_two_disjoint_analyses_isolate_alert_incident_chain_edge_timeline_diagnostics(api):
    client, _, root = api
    first = create_run(api, edge_records("a"), "a.json")
    store = SnapshotStore(root, first)
    unchanged = {str(p.relative_to(root)): file_digest(p) for directory in (store.domain, store.details) for p in directory.iterdir()}
    second = create_run(api, edge_records("b"), "b.json")
    scope_a, scope_b = {"analysis_id": first}, {"analysis_id": second}
    inc_a = client.get("/api/v1/incidents", params=scope_a).json()["items"][0]
    inc_b = client.get("/api/v1/incidents", params=scope_b).json()["items"][0]
    for aid in inc_a["alert_ids"]:
        assert client.get("/api/v1/alerts/"+aid, params=scope_b).status_code == 404
    for aid in inc_b["alert_ids"]:
        assert client.get("/api/v1/alerts/"+aid, params=scope_a).status_code == 404
    for suffix in ("", "/chain", "/timeline"):
        assert client.get("/api/v1/incidents/"+inc_a["incident_id"]+suffix, params=scope_b).status_code == 404
        assert client.get("/api/v1/incidents/"+inc_b["incident_id"]+suffix, params=scope_a).status_code == 404
    chain_a = client.get("/api/v1/incidents/"+inc_a["incident_id"]+"/chain", params=scope_a).json()["chain"]
    edge_a = chain_a["edges"][0]["edge_id"]
    assert client.get("/api/v1/edges/"+edge_a, params=scope_b).status_code == 404
    timeline_a = client.get("/api/v1/incidents/"+inc_a["incident_id"]+"/timeline", params=scope_a).json()
    assert set(aid for row in timeline_a["items"] for aid in row["alert_ids"]) == set(inc_a["alert_ids"])
    assert SnapshotStore(root, second).details != store.details
    assert unchanged == {str(p.relative_to(root)): file_digest(p) for directory in (store.domain, store.details) for p in directory.iterdir()}
    assert QueryService(root).analysis(first)["diagnostics_ref"] != QueryService(root).analysis(second)["diagnostics_ref"]


def test_same_stable_ids_different_config_are_read_from_their_own_snapshot(tmp_path):
    config, sources = deployment(tmp_path, edge=True)
    path = write_input(tmp_path, edge_records())
    # Change a declared, already-supported entity scope; alert identity stays.
    alternate = {key: (kind, replace(setting, network_namespace="synthetic-alternate-network"))
                 for key, (kind, setting) in sources.items()}
    app_a = create_app(tmp_path, configs={"v0": config}, sources=sources)
    with TestClient(app_a) as client:
        first = client.post("/api/v1/analyses", json=request_for(path)).json()["analysis_id"]
        app_a.state.analyses.wait(first)
        before = client.get("/api/v1/analyses/"+first).json()
        inc = client.get("/api/v1/incidents", params={"analysis_id": first}).json()["items"][0]
        chain_a = client.get(f"/api/v1/incidents/{inc['incident_id']}/chain", params={"analysis_id": first}).json()["chain"]
    app_b = create_app(tmp_path, configs={"v0": config}, sources=alternate)
    with TestClient(app_b) as client:
        second = client.post("/api/v1/analyses", json=request_for(path)).json()["analysis_id"]
        app_b.state.analyses.wait(second)
        detail = client.get("/api/v1/analyses/"+second).json()
        assert detail["config_hash"] != before["config_hash"]
        assert client.get("/api/v1/analyses/"+first).json() == before
        inc_b = client.get("/api/v1/incidents", params={"analysis_id": second}).json()["items"][0]
        assert inc_b["incident_id"] == inc["incident_id"]
        chain_b = client.get(f"/api/v1/incidents/{inc['incident_id']}/chain", params={"analysis_id": second}).json()["chain"]
        assert chain_b["chain_id"] == chain_a["chain_id"]
        a = client.get("/api/v1/edges/"+chain_a["edges"][0]["edge_id"], params={"analysis_id": first}).json()
        b = client.get("/api/v1/edges/"+chain_a["edges"][0]["edge_id"], params={"analysis_id": second}).json()
        assert a["edge"]["score_breakdown"]["config_hash"] == before["config_hash"]
        assert b["edge"]["score_breakdown"]["config_hash"] == detail["config_hash"]
        assert a["edge"]["edge_id"] == b["edge"]["edge_id"]


def test_all_api_evidence_pointers_and_formal_edge_support_close(api):
    client, _, root = api
    identity = create_run(api)
    store = SnapshotStore(root, identity)
    assert store.validate_reconstruction().valid
    assert store.validate_reconstruction(parquet=True).valid
    scope = {"analysis_id": identity}
    incident = client.get("/api/v1/incidents", params=scope).json()["items"][0]
    chain = client.get(f"/api/v1/incidents/{incident['incident_id']}/chain", params=scope).json()["chain"]
    alerts = {aid: client.get("/api/v1/alerts/"+aid, params=scope).json()["alert"] for aid in incident["alert_ids"]}
    for node in chain["nodes"]:
        for aid in node["alert_ids"]:
            for occurrence in alerts[aid]["entity_occurrences"]:
                resolve_pointer(alerts[aid]["raw_alert"], occurrence["raw_pointer"])
    for edge in chain["edges"]:
        detail = client.get("/api/v1/edges/"+edge["edge_id"], params=scope).json()
        selected = next(c for c in detail["correlation_edges"] if c["edge_id"] == edge["score_breakdown"]["selected_correlation_edge_id"])
        breakdown = dict(edge["score_breakdown"])
        breakdown["selected_correlation_edge_id"] = None
        assert selected["score_breakdown"] == breakdown
        pair = set(selected["support_pair"].values())
        assert pair <= set(alerts) and pair <= set(edge["alert_ids"])
        for reason in edge["reasons"]:
            for pointer in reason["params"].get("raw_pointers", []):
                assert pointer["alert_id"] in reason["alert_ids"]
                assert pointer["alert_id"] in pair
                resolve_pointer(alerts[pointer["alert_id"]]["raw_alert"], pointer["pointer"])


def test_tampered_snapshot_is_not_served_and_other_analysis_survives(api):
    client, _, root = api
    first = create_run(api, [synthetic_record(id="first")], "first.json")
    second = create_run(api, [synthetic_record(id="second")], "second.json")
    # Warm integrity cache, then mutate a real immutable storage artifact.
    assert client.get("/api/v1/alerts", params={"analysis_id": first}).status_code == 200
    store = SnapshotStore(root, first)
    with (store.domain/"alerts.parquet").open("ab") as handle:
        handle.write(b"tampered")
    assert client.get("/api/v1/alerts", params={"analysis_id": first}).status_code == 409
    assert client.get("/api/v1/alerts", params={"analysis_id": second}).status_code == 200
    manifest = json.loads((store.details/"manifest.json").read_text(encoding="utf-8"))
    manifest["execution"]["token"] = "0"*64
    (store.details/"manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert client.get("/api/v1/analyses/"+first).status_code == 409
    assert client.get("/api/v1/analyses/"+second).status_code == 200


def test_identical_submission_new_run_keeps_algorithms_deterministic(api):
    client, _, root = api
    first = create_run(api)
    second = create_run(api)
    assert first != second
    a, b = SnapshotStore(root, first), SnapshotStore(root, second)
    from app.services.storage import MODELS
    for kind in MODELS:
        assert list(a.read_records(kind)) == list(b.read_records(kind))
    assert a.read_metadata()[1] == b.read_metadata()[1]


def test_missing_evidence_is_rejected_even_if_a_writer_updates_checksums(api):
    client, _, root = api
    identity = create_run(api)
    store = SnapshotStore(root, identity)
    record, frequency, manifest = store.read_metadata()
    incident = next(iter(store.read_records("incidents")))
    store.write_records("alerts", [])
    store.write_metadata(record, frequency, manifest["summary"], execution=manifest["execution"])
    response = client.get(f"/api/v1/incidents/{incident.incident_id}/chain", params={"analysis_id": identity})
    assert response.status_code == 409 and response.json()["detail"] == "snapshot_reference_missing"

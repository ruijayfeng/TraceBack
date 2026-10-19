"""End-to-end synthetic reconstruction, singleton and truthful unresolved."""

from pathlib import Path
import os

import pytest

from app.chains.assembly import run_reconstruction
from app.services.storage import SnapshotStore
from fixtures.chains.synthetic import linear_fixture
from test_correlation_score import alert, config, inputs


def run_fixture(index, settings, config, correlation, **kwargs):
    return run_reconstruction(list(index.alerts.values()), [], list(index.entities.values()), correlation.edges,
                              config, settings, upstream_record=correlation.record, **kwargs)


def test_a_b_c_actual_grounded_chain_and_no_added_steps(config):
    index, settings, values, correlation = linear_fixture(config)
    result = run_fixture(index, settings, config, correlation)
    chain = next(c for c in result.chains if len(c.nodes) == 3)
    owner = {aid: n.node_id for n in chain.nodes for aid in n.alert_ids}
    assert len(chain.edges) == 2
    assert {(e.source_node_id, e.target_node_id) for e in chain.edges} == {
        (owner[values[0].alert_id], owner[values[1].alert_id]), (owner[values[1].alert_id], owner[values[2].alert_id])}
    assert all(e.relation_type.value == "PROCESS_CAUSAL" for e in chain.edges)
    assert all(e.score_breakdown.selected_correlation_edge_id in {c.edge_id for c in correlation.edges} for e in chain.edges)
    assert chain.status == "complete" and not chain.unresolved_correlation_edge_ids
    assert result.grounding.valid
    assert result.summary["chain_node_count"] == len(index.alerts)
    # complete is the contract's reconstruction status; this observed path is
    # still only a partial account of any actual attack, never a full story.
    assert result.summary["partial_chain_count"] == 0


def test_singleton_chain_kept_without_any_direction(config):
    index, settings = inputs([alert("unconnected-A"), alert("unconnected-B"), alert("unconnected-C")])
    result = run_reconstruction(list(index.alerts.values()), [], list(index.entities.values()), [], config, settings)
    assert result.summary["singleton_incident_count"] == 3
    assert result.summary["attack_chain_count"] == 3
    assert all(len(c.nodes) == 1 and not c.edges for c in result.chains)
    assert result.grounding.edge_count == 0 and result.grounding.json_data()["edge_traceability"] is None


def test_determinism_reverse_all_inputs_and_three_replays(config):
    index, settings, _, correlation = linear_fixture(config)
    baseline = run_fixture(index, settings, config, correlation)
    for _ in range(3):
        repeated = run_reconstruction(list(reversed(list(index.alerts.values()))), [],
            list(reversed(list(index.entities.values()))), list(reversed(correlation.edges)), config,
            dict(reversed(list(settings.items()))), upstream_record=correlation.record)
        assert repeated.record.analysis_id == baseline.record.analysis_id
        assert repeated.incidents == baseline.incidents and repeated.chains == baseline.chains


def test_upstream_incomplete_preserved_and_gt_access_tripwire(config, monkeypatch, tmp_path):
    index, settings, _, correlation = linear_fixture(config)
    data = correlation.record.model_dump()
    data.update(status="incomplete", candidate_truncated=True, is_complete=False,
                incomplete_reason="candidate_budget_truncation", errors=["candidate_budget_truncation"])
    correlation.record = type(correlation.record).model_validate(data)
    original = Path.open
    def checked(path, *args, **kwargs):
        assert path.name.lower() not in {"labels.csv", "attacks.log", "gold_chain.json"}
        assert "evaluation" not in {part.lower() for part in path.parts}
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", checked)
    result = run_fixture(index, settings, config, correlation, output_root=tmp_path)
    assert result.record.status.value == "incomplete" and not result.record.is_complete
    assert result.record.candidate_truncated and result.grounding.valid
    assert SnapshotStore(tmp_path, result.record.analysis_id).validate_reconstruction().valid


def test_upstream_wrong_snapshot_rejected(config):
    index, settings, _, correlation = linear_fixture(config)
    correlation.record = correlation.record.model_copy(update={"config_hash": "f" * 64})
    with pytest.raises(ValueError, match="upstream_snapshot"):
        run_fixture(index, settings, config, correlation)


def test_no_empty_stage_analysis(config):
    with pytest.raises(ValueError, match="empty_reconstruction"):
        run_reconstruction([], [], [], [], config, {})


def test_branch_and_isolated_nodes_preserved(config):
    from app.correlation.edges import run_correlation
    from test_correlation_score import process
    common = {"host": "branch-host", "account": "branch-user", "session": "branch-session"}
    values = [alert("branch-parent", category="process_execution", process=process(1), **common),
              alert("branch-child-one", 1, category="command_execution", parent_process=process(1), process=process(2, 1), **common),
              alert("branch-child-two", 2, category="privilege_escalation", parent_process=process(1), process=process(3, 2), **common)]
    background = [alert("branch-bg-" + str(i), 20000 + 9000 * i, host="branch-bg-host-" + str(i)) for i in range(32)]
    index, settings = inputs(values + background)
    correlation = run_correlation(list(index.alerts.values()), [], list(index.entities.values()), config, settings)
    result = run_fixture(index, settings, config, correlation)
    chain = next(c for c in result.chains if len(c.nodes) == 3)
    parent = next(n for n in chain.nodes if values[0].alert_id in n.alert_ids)
    assert len(chain.edges) == 2 and all(e.source_node_id == parent.node_id for e in chain.edges)
    assert len([c for c in result.chains if len(c.nodes) == 1]) == 32


@pytest.mark.skipif(os.environ.get("TRACEBACK_TASK04_FULL_DATASET") != "1", reason="explicit Task 04 full dataset run")
def test_full_real_task04_reconstruction_and_dual_storage_reload(monkeypatch):
    """All frozen Task 03 inputs; no access to labels or evaluation results."""
    import builtins
    import json
    from app.adapters.base import AdapterSettings
    from app.services.storage import file_digest, restore_config
    root = Path(__file__).resolve().parents[2]
    source_id = os.environ["TRACEBACK_CORRELATION_ANALYSIS_ID"]
    upstream = SnapshotStore(root, source_id)
    original_open, original_path_open = builtins.open, Path.open
    def check(path):
        if isinstance(path, (str, Path)):
            value = Path(path)
            assert value.name.lower() not in {"labels.csv", "attacks.log", "gold_chain.json"}
            assert "evaluation" not in {part.lower() for part in value.parts}
    def opened(path, *args, **kwargs):
        check(path)
        return original_open(path, *args, **kwargs)
    def path_opened(path, *args, **kwargs):
        check(path)
        return original_path_open(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", opened)
    monkeypatch.setattr(Path, "open", path_opened)
    record, _, manifest = upstream.read_metadata()
    unchanged = file_digest(upstream.details / "manifest.json")
    cfg = restore_config(record.config_snapshot["algorithm"])
    settings = {k: AdapterSettings(**v) for k, v in record.config_snapshot["sources"].items()}
    values = {kind: list(upstream.read_records(kind)) for kind in ("alerts", "entities", "dedupe_groups", "correlation_edges")}
    assert len(values["alerts"]) == 45510 and len(values["dedupe_groups"]) == 9
    assert record.metrics.representative_count == 45501 and values["correlation_edges"] == []
    result = run_reconstruction(values["alerts"], values["dedupe_groups"], values["entities"], values["correlation_edges"],
        cfg, settings, upstream_record=record, output_root=root,
        progress=lambda row: print(json.dumps(row, sort_keys=True), flush=True))
    assert result.summary["incident_count"] == result.summary["singleton_incident_count"] == 45501
    assert result.summary["multi_alert_incident_count"] == result.summary["chain_edge_count"] == 0
    assert result.summary["chain_node_count"] == result.summary["attack_chain_count"] == 45501
    assert result.record.candidate_truncated and result.record.status.value == "incomplete"
    assert result.grounding.valid
    store = SnapshotStore(root, result.record.analysis_id)
    for parquet in (False, True):
        reloaded_incidents = list(store.read_records("incidents", parquet=parquet))
        reloaded_chains = list(store.read_records("attack_chains", parquet=parquet))
        assert reloaded_incidents == result.incidents and reloaded_chains == result.chains
        assert store.validate_reconstruction(parquet=parquet).valid
        print(json.dumps({"stage": "full_reload", "parquet": parquet, "valid": True}), flush=True)
    assert file_digest(upstream.details / "manifest.json") == unchanged
    print(json.dumps({"analysis_id": result.record.analysis_id, "input_raw_alert_count": 45544,
        "duplicate_import_count": 34, "summary": result.summary}, ensure_ascii=False, sort_keys=True), flush=True)

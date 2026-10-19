from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""Synthetic contract verification only; never a real cross-dataset experiment."""

import builtins
import copy
import json
from pathlib import Path
import shutil

import pytest
import yaml

from app.adapters import AdapterSettings, AMinerAdapter, WazuhAdapter
from app.config import load_config
from app.models import CanonicalAlert
from app.services.storage import file_digest
from evaluation.framework.cross_dataset_pipeline import adapter_coverage, run_pipeline
from evaluation.framework.task_06_6 import QUALITY, finalize_manifest, quality_metrics, run
from evaluation.io.cross_dataset import assert_frozen, compatibility, core_parameters, load_dataset, raw_inventory
from test_aminer_adapter import aminer_record, aminer_settings
from test_wazuh_adapter import ROOT, synthetic_record, settings


@pytest.fixture
def frozen_config():
    return load_config(ROOT / "configs/algorithm-v0.yaml", deployment_override=ROOT / "configs/sources.yaml")


def input_file(root, records, name="synthetic.json"):
    path = root / "data/input/alerts" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in records)+"\n", encoding="utf-8")
    return path


def inputs(root, config, records):
    return [(WazuhAdapter(config, settings("synthetic.independent")), input_file(root, records))]


def declarations(root):
    shutil.copytree(ROOT / "configs", root / "configs", dirs_exist_ok=True)
    cfg = root / "configs/synthetic-source.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(yaml.safe_dump({"normalization": {"source_timezones": {"synthetic.independent": "UTC"}}}), encoding="utf-8")
    raw = input_file(root, [synthetic_record(data={"host":"synthetic-independent-host"})])
    value = {"version":"cross-dataset-v1", "dataset":"synthetic-contract-scene", "origin":"synthetic test fixture, not real evaluation",
             "independence_evidence":"synthetic contract boundary", "source_config":cfg.relative_to(root).as_posix(),
             "sources":[{"adapter":"wazuh", "path":raw.relative_to(root).as_posix(), "format_reference":"synthetic wazuh_json_v1 fixture",
                         "settings":settings("synthetic.independent").snapshot()}]}
    path = root / "evaluation/configs/synthetic-dataset.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value), encoding="utf-8")
    return path, value, cfg


def test_adapter_new_namespace_contract_and_deterministic_rejection(frozen_config):
    adapter = WazuhAdapter(frozen_config, settings("synthetic.independent"))
    raw = synthetic_record(data={"src_ip":"192.0.2.1", "host":"synthetic-host"})
    result = adapter.batch([raw, synthetic_record(timestamp="bad")])
    again = adapter.batch([raw, synthetic_record(timestamp="bad")])
    assert result == again
    assert result.accepted_count == 1 and len(result.rejected) == 1
    assert CanonicalAlert.model_validate_json(result.alerts[0].canonical_json()) == result.alerts[0]
    assert result.alerts[0].source_namespace == "synthetic.independent"


def test_aminer_existing_profile_contract(frozen_config):
    adapter = AMinerAdapter(frozen_config, aminer_settings())
    batch = adapter.batch([aminer_record(), {}])
    assert batch.accepted_count == 1 and len(batch.rejected) == 1
    assert batch == adapter.batch([aminer_record(), {}])


def test_coverage_distinguishes_source_mapping_and_bad_input(frozen_config):
    adapter = WazuhAdapter(frozen_config, settings("synthetic.independent"))
    rows = [synthetic_record(data={"host":"synthetic-host", "srcip":"192.0.2.1"}),
            synthetic_record(id="bad", data={"srcip":"bad"})]
    result = adapter_coverage([(adapter, adapter.batch(rows))])
    assert result["total_records"] == 2 and result["acceptance_rate"] == .5
    assert result["canonical_fields"]["host"]["coverage_rate"] == 1
    assert result["canonical_fields"]["session"]["missing_by_source"] == 1
    assert result["canonical_fields"]["category"]["mapping_failure"] == 1
    assert result["rejected_record_outcomes"]["invalid_value"] == 1
    assert result["canonical_fields"]["raw_alert"]["covered"] == 1


def test_duplicate_import_coverage_denominator(frozen_config):
    adapter = WazuhAdapter(frozen_config, settings("synthetic.independent"))
    r = synthetic_record()
    coverage = adapter_coverage([(adapter, adapter.batch([r,r]))])
    assert coverage["accepted_records"] == 2 and coverage["unique_canonical_alerts"] == 1
    assert coverage["duplicate_imports"] == 1


def test_pipeline_all_stages_repeat_and_input_reordering(tmp_path, frozen_config):
    rows = [synthetic_record(id="synthetic-"+str(i), timestamp=f"2022-01-21T00:00:{i:02d}Z",
                            data={"host":"synthetic-host","user":"synthetic-user"}) for i in range(5)]
    first = run_pipeline(inputs(tmp_path, frozen_config, rows), tmp_path / "first")
    second = run_pipeline(inputs(tmp_path, frozen_config, list(reversed(rows))), tmp_path / "second")
    assert first["status"] == "completed"
    assert first["stage_digests"] == second["stage_digests"]
    assert first["prediction_digest"] == second["prediction_digest"]
    assert first["counts"] == second["counts"]
    assert first["scores"] == second["scores"]
    assert first["reachability"] == second["reachability"]
    assert first["counts"]["scored"] > 0
    assert first["grounding"]["valid"]
    assert first["stages"]["normalization"]["runtime_seconds"] is None
    assert first["stages"]["correlation_edge"]["status"] == "included_in_scoring"


def test_adapter_mapping_only_transfer_can_preserve_nonzero_chain(tmp_path, frozen_config):
    # Synthetic constructive witness: mapping changes only, every numerical
    # parameter equals production. This is not reported as real migration.
    mapping = {"schema_version":"1.0", "mapping_type":"category", "source_type":"wazuh", "default":"unknown",
               "rules":[{"id":rule,"match":{"all":[{"field":"rule_id","op":"eq","value":rule}]},"output":category}
                        for rule,category in (("synthetic-parent","process_execution"),("synthetic-child","privilege_escalation"))]}
    m = tmp_path / "synthetic-mapping.yaml"
    m.write_text(yaml.safe_dump(mapping), encoding="utf-8")
    overlay = tmp_path / "synthetic-source.yaml"
    overlay.write_text(yaml.safe_dump({"normalization":{"category_mapping_files":[str(m)]}}), encoding="utf-8")
    config = load_config(ROOT/"configs/algorithm-v0.yaml", deployment_override=ROOT/"configs/sources.yaml", experiment_override=overlay)
    assert core_parameters(config) == core_parameters(frozen_config)
    parent = {"pid":1,"name":"synthetic-parent-process","start_time":"2022-01-21T00:00:00Z"}
    common = {"host":"synthetic-host","user":"synthetic-account","session":"synthetic-session",
              "file":"/synthetic/file","command":"synthetic command"}
    rows = [synthetic_record(id="synthetic-parent", rule={"id":"synthetic-parent","level":6},data={**common,"process":parent}),
            synthetic_record(id="synthetic-child",timestamp="2022-01-21T00:00:01Z",rule={"id":"synthetic-child","level":6},
                             data={**common,"parent_process":parent,"process":{**parent,"pid":2}})]
    rows += [synthetic_record(id="synthetic-background-"+str(i),timestamp="2022-01-22T00:00:00Z",
                             data={"host":"synthetic-background-"+str(i)}) for i in range(64)]
    result = run_pipeline(inputs(tmp_path, config, rows), tmp_path/"prediction")
    assert result["status"] == "completed" and result["grounding"]["valid"]
    assert result["counts"]["correlation_edges"] == 1
    assert result["counts"]["chain_edges"] == 1
    assert result["reachability"]["status"] == "not_computable"
    assert result["reachability"]["reason"] == "dataset_zero_relation_proof_unavailable"


@pytest.mark.parametrize("rows", [[], [synthetic_record()], [synthetic_record(timestamp="bad")]])
def test_empty_sparse_zero_entities_edges_serializable(tmp_path, frozen_config, rows):
    result = run_pipeline(inputs(tmp_path, frozen_config, rows), tmp_path / "prediction")
    assert result["counts"]["correlation_edges"] == 0 and result["counts"]["chain_edges"] == 0
    assert result["entity_coverage"]["entity_type_distribution"]["SESSION"] == 0
    json.dumps(result, allow_nan=False)
    if not rows or rows[0]["timestamp"] == "bad":
        assert result["status"] == "not_applicable"
        assert result["stages"]["scoring"]["reason"] == "empty_canonical_input"
    else:
        assert result["status"] == "completed"
        assert result["scores"]["count"] == 0 and result["scores"]["max"] is None


def test_gt_add_change_delete_does_not_change_predictions(tmp_path, frozen_config, monkeypatch):
    gt = tmp_path / "evaluation/labels.csv"
    gt.parent.mkdir()
    rows = [synthetic_record(id=str(i), data={"host":"synthetic-host"}) for i in range(3)]
    original_path, original_open = Path.open, builtins.open
    def checked_path(path, *args, **kwargs):
        if Path(path) == gt:
            raise AssertionError("GT read during production prediction")
        return original_path(path, *args, **kwargs)
    def checked_open(path, *args, **kwargs):
        if isinstance(path,(str,Path)) and Path(path) == gt:
            raise AssertionError("GT read during production prediction")
        return original_open(path, *args, **kwargs)
    digests = []
    for index, label in enumerate(("synthetic-label-a", "synthetic-label-b", None)):
        if label is None:
            gt.unlink()
        else:
            gt.write_text(label, encoding="utf-8")
        with monkeypatch.context() as m:
            m.setattr(Path, "open", checked_path)
            m.setattr(builtins, "open", checked_open)
            result = run_pipeline(inputs(tmp_path, frozen_config, rows), tmp_path / ("prediction"+str(index)))
        digests.append(result["prediction_digest"])
    assert len(set(digests)) == 1


@pytest.mark.parametrize("path", ["backend/app/correlation/scoring.py", "backend/app/correlation/candidates.py",
    "backend/app/correlation/conflicts.py", "backend/app/incidents/clustering.py", "backend/app/chains/assembly.py", "configs/algorithm-v0.yaml"])
def test_freeze_detects_mutation(tmp_path, path):
    p = tmp_path / path
    p.parent.mkdir(parents=True)
    p.write_text("synthetic frozen core", encoding="utf-8")
    expected = {path:file_digest(p)}
    assert not assert_frozen(tmp_path, expected)["core_algorithm_changed"]
    p.write_text("synthetic changed core", encoding="utf-8")
    with pytest.raises(ValueError, match="freeze_failed"):
        assert_frozen(tmp_path, expected)


def test_freeze_detects_new_dataset_specific_production_file(tmp_path):
    p = tmp_path / "backend/app/correlation/synthetic_dataset_bonus.py"
    p.parent.mkdir(parents=True)
    p.write_text("if dataset == 'synthetic': score += 1", encoding="utf-8")
    with pytest.raises(ValueError, match="freeze_failed"):
        assert_frozen(tmp_path, {})


def test_production_no_new_hardcoding_or_core_modifications():
    expected = json.loads((ROOT / "evaluation/configs/task_06_6_core_freeze.json").read_text(encoding="utf-8"))
    # The historical core freeze is unchanged. Task 08 permits exactly two
    # presentation additions, independently frozen after their API acceptance.
    presentation = json.loads((ROOT / "outputs/task08/presentation_freeze.json").read_text(encoding="utf-8"))
    assert set(presentation) == {"backend/app/api/workbench.py", "backend/app/api/workbench_store.py"}
    assert not presentation.keys() & expected.keys()
    expected.update(presentation)
    # Keep historical receipts intact. Only these user-authorized additions /
    # presentation repairs may supersede them; all other hashes stay frozen.
    task091=json.loads((ROOT/'outputs/task09_1/presentation_freeze.json').read_text(encoding='utf-8'))
    assert set(task091['inherited_task09'])=={
        'backend/app/ai/provider.py','configs/llm.yaml','configs/llm.example.yaml','configs/llm.local.example.yaml',
        'docs/DEMO.md','docs/DEFENSE_OUTLINE.md','docs/EVALUATION_REPORT.md'}
    assert set(task091['presentation'])=={
        'backend/app/api/workbench.py','backend/app/api/incident_metrics.py','backend/app/api/score_diagnostics.py'}
    for path,digest in task091['inherited_task09'].items():
        assert digest==task091['pre_task091_hashes'][path]
    expected.update(task091['inherited_task09'])
    expected.update(task091['presentation'])
    # User-authorized dataset ingress refactor supersedes only these three
    # files. Historical receipts and every algorithm / mapping hash stay fixed.
    registry_freeze = json.loads((ROOT / 'outputs/ait_ads/registry_freeze.json').read_text(encoding='utf-8'))
    assert set(registry_freeze['production']) == {
        'backend/app/services/analysis.py', 'backend/app/services/datasets.py', 'configs/sources.yaml'}
    assert set(registry_freeze['previous']) == {'backend/app/services/analysis.py', 'configs/sources.yaml'}
    for path, digest in registry_freeze['previous'].items():
        assert expected[path] == digest
    assert 'backend/app/services/datasets.py' not in expected
    expected.update(registry_freeze['production'])
    # This explicit user-authorized algorithm upgrade supersedes only its
    # enumerated scope; historical v0 freezes/receipts remain byte-for-byte.
    v2 = json.loads((ROOT / 'outputs/correlation_v2/implementation_freeze.json').read_text(encoding='utf-8'))
    assert set(v2['production']) == {
        'backend/app/ai/explanation.py',
        'backend/app/api/schemas.py', 'backend/app/api/score_diagnostics.py',
        'backend/app/config.py', 'backend/app/correlation/candidates.py',
        'backend/app/correlation/edges.py', 'backend/app/correlation/evidence.py',
        'backend/app/correlation/index.py', 'backend/app/correlation/scoring.py',
        'backend/app/incidents/triage.py', 'backend/app/main.py',
        'backend/app/models/correlation_v2.py', 'backend/app/models/domain.py',
        'backend/app/models/scoring.py', 'backend/app/models/triage.py',
        'backend/app/services/analysis.py', 'backend/app/services/datasets.py',
        'configs/algorithm-v2.yaml', 'docs/ALGORITHM_CONFIG.md',
        'docs/CODEX_TASKS.md', 'docs/DATA_CONTRACT.md'}
    assert set(v2['previous']) == set(v2['production']) & set(expected)
    for path, digest in v2['previous'].items():
        assert expected[path] == digest
    expected.update(v2['production'])
    # Explicit Correlation v3 repair: extend the receipt chain, never replace
    # historical hashes or permit arbitrary production additions.
    v3 = json.loads((ROOT / 'outputs/correlation_v3/implementation_freeze.json').read_text(encoding='utf-8'))
    assert set(v3['production']) == {
        'backend/app/api/score_diagnostics.py', 'backend/app/config.py',
        'backend/app/correlation/candidates.py', 'backend/app/correlation/edges.py',
        'backend/app/correlation/evidence_v3.py', 'backend/app/correlation/scoring.py',
        'backend/app/dedup/grouping.py', 'backend/app/dedup/observation.py',
        'backend/app/main.py', 'backend/app/models/correlation_v3.py',
        'backend/app/models/domain.py', 'backend/app/models/scoring.py',
        'backend/app/services/analysis.py', 'backend/app/services/datasets.py',
        'configs/algorithm-v3.yaml'}
    assert set(v3['previous']) == set(v3['production']) & set(expected)
    for path, digest in v3['previous'].items():
        assert expected[path] == digest
    expected.update(v3['production'])
    repair = json.loads((ROOT / 'outputs/correlation_v3/repair_20261010/implementation_freeze.json').read_text(encoding='utf-8'))
    assert set(repair['production']) == {
        'backend/app/config.py', 'backend/app/correlation/edges.py',
        'backend/app/correlation/evidence_v3.py', 'backend/app/correlation/scoring.py',
        'backend/app/dedup/grouping.py', 'backend/app/dedup/observation.py',
        'backend/app/models/correlation_v3.py', 'backend/app/models/domain.py',
        'backend/app/services/analysis.py', 'backend/app/services/storage.py',
        'backend/app/services/bounded_diagnostics.py', 'configs/algorithm-v3.yaml'}
    assert set(repair['previous']) == set(repair['production']) & set(expected)
    for path, digest in repair['previous'].items():
        assert expected[path] == digest
    expected.update(repair['production'])
    # Task B.1 authorizes dependency/state maintenance only. Extend the exact
    # receipt chain; the existing scorer, guards, parameters and historical
    # receipts remain protected by their prior hashes.
    incremental = json.loads((ROOT / 'outputs/incremental_correlation/production/implementation_freeze.json').read_text(encoding='utf-8'))
    assert set(incremental['production']) == {
        'backend/app/correlation/candidates.py', 'backend/app/incidents/triage.py',
        'backend/app/services/incremental.py', 'backend/app/services/incremental_dependencies.py',
        'backend/app/services/incremental_store.py'}
    assert set(incremental['previous']) == set(incremental['production']) & set(expected)
    for path, digest in incremental['previous'].items():
        assert expected[path] == digest
    assert incremental['algorithm_semantics_changed'] is False
    expected.update(incremental['production'])
    # Explicit Correlation v4 authorization extends the chain for this exact
    # role/context upgrade. Historical receipts stay immutable; arbitrary
    # additions and all unrelated hashes are still rejected by assert_frozen.
    v4 = json.loads((ROOT/'outputs/correlation_v4/implementation_receipt.json').read_text(encoding='utf-8'))
    assert v4['algorithm_version'] == 'alert-correlation-v4-role-context-candidate-v1.1'
    assert set(v4['production']) == {
        'backend/app/config.py', 'backend/app/correlation/candidates.py',
        'backend/app/correlation/edges.py', 'backend/app/correlation/evidence_v3.py',
        'backend/app/correlation/evidence_v4.py', 'backend/app/correlation/scoring.py',
        'backend/app/dedup/grouping.py', 'backend/app/main.py',
        'backend/app/models/correlation_v3.py', 'backend/app/models/domain.py',
        'backend/app/models/scoring.py', 'backend/app/services/analysis.py',
        'backend/app/services/datasets.py', 'backend/app/services/incremental.py',
        'configs/algorithm-v4.yaml'}
    assert set(v4['previous']) == set(v4['production']) & set(expected)
    for path, digest in v4['previous'].items():
        assert expected[path] == digest
    expected.update(v4['production'])
    capacity = json.loads((ROOT/'outputs/correlation_v4_capacity/implementation_receipt.json').read_text(encoding='utf-8'))
    assert capacity['algorithm_semantics_changed'] is False
    assert capacity['algorithm_version'] == v4['algorithm_version']
    assert set(capacity['production']) == {
        'backend/app/adapters/base.py', 'backend/app/entities/extraction.py',
        'backend/app/correlation/index.py', 'backend/app/correlation/candidates.py',
        'backend/app/correlation/scoring.py', 'backend/app/chains/assembly.py',
        'backend/app/services/analysis.py', 'backend/app/services/storage.py',
        'backend/app/services/capacity.py'}
    assert set(capacity['previous']) == set(capacity['production']) & set(expected)
    for path,digest in capacity['previous'].items():
        assert expected[path] == digest
    expected.update(capacity['production'])
    assert 'configs/llm.local.yaml' in (ROOT/'.gitignore').read_text(encoding='utf-8')
    # Preserve the historical supersession chain above without applying it to active V5 code.
    assert verify_historical_inventory(expected)['status'] == 'PASS'
    # The explicit final-semantics task supersedes F3 source authority. Keep
    # every historical receipt immutable; active code uses the new own seal.
    from evaluation.framework.semantics_final.runtime import verify_freeze
    verify_freeze()
    for path in (ROOT / "backend/app").rglob("*.py"):
        assert "synthetic-contract-scene" not in path.read_text(encoding="utf-8")


def test_source_declaration_config_freeze_and_independent_namespace(tmp_path, frozen_config):
    path, value, cfg = declarations(tmp_path)
    metadata, parsed, binding = load_dataset(tmp_path, path, frozen_config)
    assert metadata == value and len(parsed) == 1
    assert core_parameters(parsed[0][0].config) == core_parameters(frozen_config)
    assert len(binding["input_fingerprint"]) == 64 and len(binding["mapping_digest"]) == 64
    # Full config varies because source timezone metadata has changed.
    assert parsed[0][0].config.config_hash != frozen_config.config_hash


@pytest.mark.parametrize("overlay", [{"score":{"correlation_threshold":.1}}, {"candidate":{"per_channel_neighbors":100}},
    {"conflict":{"hard_rules":[]}}, {"normalization":{"category_priority":["unknown"]}}, {"chain":{"direction_threshold":.1}}])
def test_dataset_source_config_cannot_change_algorithm(tmp_path, frozen_config, overlay):
    path, _, cfg = declarations(tmp_path)
    cfg.write_text(yaml.safe_dump(overlay), encoding="utf-8")
    with pytest.raises(ValueError, match="core_parameters"):
        load_dataset(tmp_path, path, frozen_config)


@pytest.mark.parametrize("field,value,reason", [("dataset","russellmitchell","not_cross_dataset"),
    ("origin","","missing_dataset_metadata"), ("independence_evidence","","missing_dataset_metadata")])
def test_readiness_metadata_rejects_invalid_claims(tmp_path, frozen_config, field, value, reason):
    path, meta, _ = declarations(tmp_path)
    meta[field] = value
    path.write_text(yaml.safe_dump(meta), encoding="utf-8")
    with pytest.raises(ValueError, match=reason):
        load_dataset(tmp_path, path, frozen_config)


def test_production_input_declaration_rejects_gt_paths_and_fields(tmp_path, frozen_config):
    path, meta, _ = declarations(tmp_path)
    meta["sources"][0]["path"] = "data/new/evaluation/labels.json"
    path.write_text(yaml.safe_dump(meta), encoding="utf-8")
    with pytest.raises(ValueError, match="input_path_not_independent"):
        load_dataset(tmp_path, path, frozen_config)
    meta["sources"][0]["gt_labels"] = "synthetic-labels"
    path.write_text(yaml.safe_dump(meta), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid_source_declaration"):
        load_dataset(tmp_path, path, frozen_config)


def test_inventory_excludes_truth_processed_and_fixtures(tmp_path):
    for name in ("data/scene/raw/alerts.json", "data/scene/evaluation/gold_chain.json", "data/processed/scene/alerts.json",
                 "backend/tests/fixtures/alerts/synthetic.json"):
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{}", encoding="utf-8")
    inventory = raw_inventory(tmp_path)
    assert [r["path"] for r in inventory] == ["data/scene/raw/alerts.json"]


def test_missing_gt_metrics_are_null_not_zero():
    result = quality_metrics(None)
    assert set(result["metrics"]) == set(QUALITY)
    assert all(r["value"] is None and r["status"] == "not_computable" for r in result["metrics"].values())


def test_pair_gt_reuses_existing_metrics_after_prediction(tmp_path, frozen_config):
    result = run_pipeline(inputs(tmp_path, frozen_config, [synthetic_record(id=str(i),data={"host":"synthetic-host"}) for i in range(2)]), tmp_path / "prediction")
    ids = [json.loads(line)["alert_id"] for line in (tmp_path/"prediction/canonical.jsonl").read_text(encoding="utf-8").splitlines()]
    gt = tmp_path / "evaluation/labels.csv"
    gt.parent.mkdir()
    gt.write_text("left_alert_id,right_alert_id,positive\n"+",".join([*ids,"true"])+"\n", encoding="utf-8")
    q = quality_metrics(tmp_path/"prediction", gt, "pair_labels")
    assert result["counts"]["correlation_edges"] == 0
    assert q["metrics"]["pairwise_precision"]["value"] is None
    assert q["metrics"]["pairwise_precision"]["status"] == "not_applicable"
    assert q["metrics"]["pairwise_recall"]["value"] == 0
    assert q["metrics"]["node_f1"]["status"] == "not_computable"


def test_compatibility_does_not_claim_new_adapter_support():
    value = compatibility(ROOT)
    assert value["status"] == "assessed_existing_adapters_only"
    assert set(value["adapters"]) == {"wazuh","aminer"}


def test_blocked_runner_outputs_no_synthetic_real_metrics(production_snapshot):
    root = production_snapshot.store.root
    shutil.copytree(ROOT / "backend/app/adapters", root / "backend/app/adapters", ignore=shutil.ignore_patterns("__pycache__"))
    aid = production_snapshot.record.analysis_id
    directory = root / "outputs/evaluation/task_06_5"
    directory.mkdir(parents=True)
    count = production_snapshot.manifest["summary"]["counts"]
    payloads = {
        "production_baseline.json":{"canonical_alert_count":len(production_snapshot.alerts), "representative_count":len(production_snapshot.groups),
            "scored":count["scored_candidate_count"], "unique_potential_pairs":0,"policy_pruned":0,"admitted":count["scored_candidate_count"],"resource_truncated":0},
        "score_distribution.json":{"max":.1,"edge_threshold":production_snapshot.config.algorithm.score.correlation_threshold,
                                  "near_threshold_counts":[{"actual_admissible_pair":0}]},
        "reachability.json":{"dataset_constrained_maximum_reachable_score":.58},
        "reproducibility.json":{"cache_binding":{"binding":{"analysis_id":aid}}}}
    for name,value in payloads.items():
        (directory/name).write_text(json.dumps(value), encoding="utf-8")
    summary = run(root, aid)
    assert summary["framework_status"] == "framework_completed"
    assert summary["run_status"] == "evaluation_blocked_by_missing_dataset"
    assert summary["generalization"]["classification"] is None
    out = root / "outputs/evaluation/task_06_6"
    for name in ("cross_dataset_summary.json","cross_dataset_metrics.json","adapter_coverage.json","entity_coverage.json",
                 "pipeline_stage_stats.json","score_distribution.json","runtime.json","baseline_comparison.csv","manifest.json","TASK_06_6_REPORT.md"):
        assert (out/name).is_file()
    manifest = json.loads((out/"manifest.json").read_text(encoding="utf-8"))
    for name,digest in manifest["output_file_sha256"].items():
        assert file_digest(out/name) == digest
    assert all(row["CrossDataset"] is None for row in summary["comparison"])


@pytest.mark.parametrize("output", ["outputs/evaluation/task_06_5", "data/processed", "outputs/evaluation"])
def test_runner_protects_prior_outputs(tmp_path, output):
    with pytest.raises(ValueError, match="output_must_be_independent"):
        run(tmp_path, "unused", destination=tmp_path/output)

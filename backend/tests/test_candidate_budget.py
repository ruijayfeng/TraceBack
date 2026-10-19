"""Hotspot counts, all budget levels and deterministic bounded enumeration."""

import os
import pytest

from app.correlation.candidates import CandidateAudit, candidate_diagnosis, generate_candidates
from test_correlation_score import alert, config, configured, inputs


def test_hot_entity_large_simultaneous_input_is_bounded(config):
    index,_ = inputs([alert(str(i),host="hot") for i in range(1000)])
    result = generate_candidates(index,config)
    assert not result.candidate_truncated and result.policy_pruned_count > 0
    assert result.examined_neighbors <= 1000 * 30
    assert len(result.pairs) <= 1000 * 30
    hot = [d for d in result.diagnostics if d.get("rule_id")=="hot_entity_neighbors"]
    assert len(hot)==1000 and all(d["proposed"]==999 and d["retained"]==10 for d in hot)
    assert result.resource_truncated_count == result.dropped_count == 0


def test_channel_endpoint_global_budgets_and_permutation(tmp_path):
    config = configured(tmp_path,candidate={"per_channel_neighbors":4,"time_only_neighbors":2,"max_neighbors_per_alert":2,"max_candidate_pairs":3})
    values = [alert(str(i),i,host="h",account="u",session="s") for i in range(15)]
    index,_=inputs(values)
    first=generate_candidates(index,config)
    index2,_=inputs(list(reversed(values)))
    second=generate_candidates(index2,config)
    assert first==second and len(first.pairs)==3
    assert first.candidate_truncated
    for rule in ("channel_neighbors","max_neighbors_per_alert","max_candidate_pairs"):
        assert any(d.get("rule_id")==rule and d["dropped"]>0 for d in first.diagnostics)


def diagnosed(index, config, scorer=None):
    reports = []
    with candidate_diagnosis(reports.append):
        result = generate_candidates(index, config, scorer)
    return result, reports[0]


def test_diagnosis_exact_multikey_counts_preserves_full_provenance(config):
    values = [alert(str(i), i, host="shared", account="shared", src_ip="192.0.2.1", dst_ip="192.0.2.2") for i in range(6)]
    index, _ = inputs(values)
    original = generate_candidates(index, config)
    observed, reports = diagnosed(index, config)
    assert observed == original  # Includes pair identity, all provenance, rank and budgets.
    report = reports["candidate_diagnostics"]
    # Five lookups per member: HOST, ACCOUNT, two IP keys, time. Both endpoints.
    assert report["raw_potential_discoveries"] == 6*5*5
    assert report["unique_potential_pairs"] == 15
    assert report["duplicate_potential_discoveries"] == 135
    assert report["duplicate_ratio"] == .9
    assert sum(row["unique_pairs_contributed"] for row in report["candidate_sources"]) == 15
    assert sum(row["exclusive_scoring_contribution"] for row in report["candidate_sources"]) == 15
    assert report["coverage"] == {"complete": 6}
    assert all(row["unique_pairs"] == 15 for row in report["candidate_sources"])
    assert all(row["not_admitted_via_channel"] == (15 if row["potential_source"] == "time_only" else 0) for row in report["candidate_sources"])


def test_diagnosis_dense_time_and_hot_bucket_are_local_not_global_overflow(config):
    index, _ = inputs([alert(str(i), host="legitimate-hotspot") for i in range(120)])
    original = generate_candidates(index, config)
    observed, reports = diagnosed(index, config)
    assert observed == original and not observed.candidate_truncated
    report = reports["candidate_diagnostics"]
    assert report["unique_potential_pairs"] == 120*119//2
    assert report["budget_stages"]["max_candidate_pairs"]["dropped"] == 0
    assert report["first_resource_truncation"] is None
    assert report["all_representatives_candidate_generation_processed"] == 120
    assert report["time_index"]["bucket_width"] is None
    assert report["time_index"]["per_alert_time_potential_count"]["max"] == 119
    assert report["coverage"] == {"complete":120}
    assert report["policy_pruned_count"] > 0 and report["resource_truncated_count"] == 0
    assert reports["candidate_hot_buckets"]["top_100"][0]["unique_pair_count"] == 7140
    # The old implementation already eliminates repeated discovery before the global budget.
    assert report["admitted_candidate_count"] < report["raw_potential_discoveries"]


def test_diagnosis_global_boundary_and_deterministic_shuffled_input(tmp_path):
    cfg = configured(tmp_path, candidate={"per_channel_neighbors":100, "time_only_neighbors":100,
        "max_neighbors_per_alert":100, "max_candidate_pairs":3})
    values = [alert(str(i), i, host="h") for i in range(5)]
    index, _ = inputs(values)
    first, report = diagnosed(index, cfg)
    shuffled, _ = inputs(list(reversed(values)))
    second, other_report = diagnosed(shuffled, cfg)
    assert first == second and report == other_report
    assert report["candidate_diagnostics"]["budget_stages"]["max_candidate_pairs"] == {"proposed":10, "retained":3, "dropped":7}
    assert report["candidate_diagnostics"]["resource_truncated_count"] == 7


def test_diagnosis_empty_missing_entities_does_not_invent_unknown_bucket(config):
    index, _ = inputs([alert("missing-a"), alert("missing-b", 61)])
    result, reports = diagnosed(index, config)
    assert not result.pairs
    report = reports["candidate_diagnostics"]
    assert report["raw_potential_discoveries"] == report["unique_potential_pairs"] == 0
    assert report["suspicious_value_buckets"] == []
    assert [row["potential_source"] for row in report["candidate_sources"]] == ["time_only"]


def test_diagnosis_windows_same_timestamp_multisource_and_duplicate_wrappers(config):
    from test_correlation_score import group
    values = [alert("a", host="h"), alert("a-wrapper", host="h"),
              alert("b", 60, host="h", source_type="aminer"), alert("c", 1800, host="h"),
              alert("d", 1800.000001, host="h")]
    index, _ = inputs(values, groups=[group(values[:2])])
    original = generate_candidates(index, config)
    observed, reports = diagnosed(index, config)
    assert observed == original and not observed.candidate_truncated
    report = reports["candidate_diagnostics"]
    assert report["unique_potential_pairs"] == len(original.pairs)
    assert report["coverage"] == {"complete": 4}
    assert report["raw_potential_discoveries"] > observed.proposed_count


def test_directional_relation_counts_not_halved(config):
    from app.correlation.scoring import CorrelationScorer
    from test_correlation_score import parent_child
    index, settings = inputs(parent_child())
    scorer = CorrelationScorer(index, config, settings)
    original = generate_candidates(index, config, scorer)
    observed, reports = diagnosed(index, config, scorer)
    assert original == observed
    report = reports["candidate_diagnostics"]
    assert report["unique_potential_pairs"] == 1
    assert next(row for row in report["candidate_sources"] if row["potential_source"]=="explicit_relation")["unique_pairs"] == 1


def test_directional_audit_oracle_handles_one_sided_discovery(config):
    index, _ = inputs([alert(str(i)) for i in range(4)])
    audit = CandidateAudit(index, config.algorithm)
    audit.rows["time_only"] = {0:2, 1:1}
    audit.rows["explicit_relation"] = {2:1, 0:8, 3:1}
    audit.raw.update(time_only=2, explicit_relation=3)
    from app.correlation.candidates import CandidateResult
    report = audit.finish(CandidateResult([], [], 0, 0, 0, False, 0))["candidate_diagnostics"]
    assert report["unique_potential_pairs"] == 3
    assert report["duplicate_potential_discoveries"] == 2
    assert report["coverage"] == {"complete":4}


@pytest.mark.parametrize("value", ["UNKNOWN", "N/A", "-", "default"])
def test_diagnosis_flags_suspect_values_without_deleting_valid_frozen_entities(config, value):
    index, _ = inputs([alert("a", host=value), alert("b", host=value)])
    original = generate_candidates(index, config)
    observed, reports = diagnosed(index, config)
    assert observed == original
    # Diagnostics cannot redefine a field's normalization or decide a real
    # shared host is missing. Such a change requires an existing contract rule.
    hosts = [e for e in index.entities.values() if e.type.value == "HOST"]
    if hosts:
        assert any(row["index_key"] == hosts[0].entity_id for row in reports["candidate_diagnostics"]["suspicious_value_buckets"])


@pytest.mark.skipif(os.environ.get("TRACEBACK_TASK051_DIAGNOSE") != "1", reason="explicit Task 05.1 Phase A real candidate audit")
def test_real_candidate_diagnosis_preserves_published_snapshot(monkeypatch):
    import hashlib
    import json
    import sys
    import time
    from pathlib import Path
    from app.adapters.base import AdapterSettings
    from app.correlation.edges import peak_memory_mb
    from app.correlation.index import AlertIndex
    from app.correlation.scoring import CorrelationScorer
    from app.services.storage import SnapshotStore, atomic_json, file_digest, restore_config
    from app.utils.stable_id import canonical_json
    from test_analysis_service import tripwire
    from test_correlation_score import ROOT
    sys.stdout.reconfigure(encoding="utf-8")
    tripwire(monkeypatch)
    identity = "ana_24956b3b6d45fcb0566703eda8874dfc84ebb35c9dfd3adc778448b557d7c663"
    store = SnapshotStore(ROOT, identity)
    frozen_manifest_digest = file_digest(store.details / "manifest.json")
    record, _, manifest = store.read_metadata(verify_files=False)
    loaded = {}
    for kind in ("alerts", "entities", "dedupe_groups"):
        path = store.domain / (kind + ".parquet")
        assert file_digest(path) == manifest["files"][path.name]
        loaded[kind] = list(store.read_records(kind, parquet=True))
    cfg = restore_config(record.config_snapshot["algorithm"])
    settings = {key: AdapterSettings(**value) for key, value in record.config_snapshot["sources"].items()}
    index = AlertIndex(loaded["alerts"], loaded["dedupe_groups"], loaded["entities"])
    scorer = CorrelationScorer(index, cfg, settings, record.config_hash)
    print(json.dumps({"stage":"phase_a_loaded", "representatives":index.N}), flush=True)
    started = time.perf_counter()
    from fixtures.candidates import legacy_v10
    reports = []
    with legacy_v10.candidate_diagnosis(reports.append):
        result = legacy_v10.generate_candidates(index, cfg, scorer)
    reports = reports[0]
    elapsed = time.perf_counter() - started
    print(json.dumps({"stage":"phase_a_candidates", "count":len(result.pairs), "seconds":elapsed}), flush=True)
    assert result.retained_count == record.metrics.candidate_pair_count == 1101244
    assert result.dropped_count == record.metrics.candidate_dropped_count == 193129993
    # Compare all real retained identities AND provenance against the original
    # publication, without rescoring or decoding its millions of member scores.
    expected, observed = hashlib.sha256(), hashlib.sha256()
    old_count = 0
    with (store.details / "diagnostics.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            if '"stage":"candidate"' not in line and '"stage": "candidate"' not in line:
                continue
            row = json.loads(line)
            if row.get("stage") == "candidate":
                expected.update((canonical_json(row)+"\n").encode("utf-8"))
                old_count += 1
    for pair in result.pairs:
        row = {"stage":"candidate", "support_key":list(pair.support_key), "channels":list(pair.channels),
               "evidence":[e.json_data() for e in pair.evidence]}
        observed.update((canonical_json(row)+"\n").encode("utf-8"))
    assert old_count == result.retained_count and expected.digest() == observed.digest()
    equivalence = {"before_unique_candidate_set":old_count, "after_unique_candidate_set":result.retained_count,
        "difference":0, "before_candidate_provenance_sha256":expected.hexdigest(),
        "after_candidate_provenance_sha256":observed.hexdigest()}
    for name, report in reports.items():
        atomic_json(store.details / (name+".json"), {"phase":"A_observation_only", "analysis_id":identity,
            "config_hash":record.config_hash, "dataset_digest":record.dataset_digest,
            "candidate_generation_seconds_including_diagnostics":elapsed, "peak_memory_mb":peak_memory_mb(),
            "equivalence":equivalence, **report})
    assert file_digest(store.details / "manifest.json") == frozen_manifest_digest
    print(json.dumps({"stage":"phase_a_finished", "analysis_id":identity,
        "candidate_generation_seconds_including_diagnostics":elapsed, "peak_memory_mb":peak_memory_mb(),
        "equivalence":equivalence, "diagnosis":reports["candidate_diagnostics"]}), flush=True)


@pytest.mark.parametrize("neighbors,k,hot", [(30,20,False),(50,10,True)])
def test_v11_admission_counts_and_stable_ranking(tmp_path, neighbors, k, hot):
    import random
    cfg = configured(tmp_path, candidate={"per_channel_neighbors":20,
        "hot_entity_neighbors":10,"hot_entity_min_count":2 if hot else 100,
        "hot_entity_ratio":0.1,"max_neighbors_per_alert":200})
    values = [alert("center",host="shared"), *[alert(f"neighbor-{i}",i+1,host="shared") for i in range(neighbors)]]
    results=[]
    shuffled=list(values); random.Random(52).shuffle(shuffled)
    for order in (values, list(reversed(values)), shuffled):
        index,_=inputs(order)
        result=generate_candidates(index,cfg)
        results.append(result)
        row=next(d for d in result.diagnostics if d.get("alert_id")==values[0].alert_id
            and d.get("rule_id")=="channel_neighbors")
        assert (row["proposed"],row["retained"],row["dropped"])==(neighbors,k,neighbors-k)
        assert row["decision"]=="policy_pruned"
        assert not result.candidate_truncated and result.resource_truncated_count==0
        assert result.admitted_count==result.retained_count
        assert all(e.admission_limit==k and e.hot==hot for pair in result.pairs for e in pair.evidence)
    assert results[0]==results[1]==results[2]


def test_provenance_keeps_discovered_channel_after_channel_pruning(tmp_path):
    cfg=configured(tmp_path,candidate={"per_channel_neighbors":1})
    values=[alert("a",host="h",account="u"), alert("near",1,host="h"),alert("far",2,host="h",account="u")]
    index,_=inputs(values)
    result=generate_candidates(index,cfg)
    pair=next(p for p in result.pairs if set(p.support_key)=={values[0].alert_id,values[2].alert_id})
    assert "ACCOUNT" in pair.channels
    assert all(e.json_data()["ranking_key"] and e.json_data()["admission_reason"] for e in pair.evidence)


@pytest.mark.parametrize("fixture", ["parent_child","entities","time_only","out_of_window"])
def test_v10_v11_common_candidate_scoring_and_edge_equivalence(tmp_path, monkeypatch, fixture):
    import app.correlation.edges as module
    from fixtures.candidates import legacy_v10
    from test_correlation_score import parent_child
    cfg=configured(tmp_path,entity={"rarity_enabled":False})
    values={"parent_child":parent_child(),
        "entities":[alert("a",host="h",session="s"),alert("b",30,host="h",session="s"),alert("c",50,host="h")],
        "time_only":[alert("a"),alert("b",1)],
        "out_of_window":[alert("a",host="h"),alert("b",1801,host="h")]}[fixture]
    index,settings=inputs(values)
    records={}
    for version,generator in (("v1.0",legacy_v10.generate_candidates),("v1.1",generate_candidates)):
        def compatible(*args):
            result=generator(*args)
            if version=="v1.0":
                result.potential_pair_stats={}
                result.candidate_admission_stats={}
                result.policy_pruned_count=0
                result.resource_truncated_count=result.dropped_count
                result.admitted_count=len(result.pairs)
                result.retrieval_seconds=result.admission_seconds=0
                result.resource_candidates=()
            return result
        monkeypatch.setattr(module,"generate_candidates",compatible)
        diagnostics=[]
        result=module.run_correlation(list(index.alerts.values()),[],list(index.entities.values()),cfg,settings,diagnostic_sink=diagnostics.append)
        records[version]=(result,diagnostics)
    old,old_rows=records["v1.0"]; new,new_rows=records["v1.1"]
    common={p.support_key for p in old.candidates.pairs}&{p.support_key for p in new.candidates.pairs}
    for stage in ("member_score","correlation_decision"):
        select=lambda rows:[r for r in rows if r["stage"]==stage and tuple(r["support_key"]) in common]
        assert select(old_rows)==select(new_rows)  # all seven raw values, total, reasons, evidence and admission
    assert [e.canonical_json() for e in old.edges]==[e.canonical_json() for e in new.edges]
    if fixture=="parent_child":
        assert common and new.edges
        assert any(e.relation_facts for e in new.candidates.pairs[0].evidence)
    if fixture=="entities":
        assert common
        assert all(r["values"]["time"]>0 for r in new_rows if r["stage"]=="member_score")
    if fixture in {"time_only","out_of_window"}:
        assert not new.candidates.pairs


def test_resource_candidates_keep_provenance_and_stable_priority(tmp_path):
    cfg=configured(tmp_path,candidate={"max_candidate_pairs":3})
    values=[alert(str(i),i,host="h",account="u") for i in range(6)]
    saved=[]
    for order in (values,list(reversed(values))):
        index,_=inputs(order)
        result=generate_candidates(index,cfg)
        rows=list(result.resource_candidates)
        assert len(rows)==result.resource_truncated_count==12
        assert all(row["evidence"] and row["ranking_key"] and row["channels"]==["ACCOUNT","HOST"] for row in rows)
        saved.append(rows)
    assert saved[0]==saved[1]

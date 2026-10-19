"""Meaningful isolation, exact component, admission and proof diagnostics."""

import builtins
import json
from pathlib import Path

import pytest

from app.chains.assembly import run_reconstruction
from app.config import load_config
from app.correlation.edges import run_correlation
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.services.storage import file_digest
from app.utils.stable_id import content_digest
from evaluation.io.diagnostics import extract_scores, VALUES
from evaluation.io.task_06_5 import (bind_scores,blocking_reasons,distribution,member_distribution,
                                    potential_masks,threshold_scan)
from evaluation.sensitivity.score_reachability import component_counterfactual,component_maxima,formula_witness,reachability
from evaluation.framework.task_06_5 import edge_schema_replay,top_candidates


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def diagnostic(production_snapshot,tmp_path):
    s=production_snapshot
    cache=tmp_path/"outputs/evaluation"/s.record.analysis_id
    cache.mkdir(parents=True,exist_ok=True)
    db,_=extract_scores(s,cache)
    db.close()
    db,binding=bind_scores(s,cache)
    index=AlertIndex(s.store.read_records("alerts",parquet=True),s.store.read_records("dedupe_groups",parquet=True),
                     s.store.read_records("entities",parquet=True))
    scorer=CorrelationScorer(index,s.config,s.settings,s.record.config_hash)
    yield s,db,binding,index,scorer,cache
    db.close()


def test_all_unrounded_decompositions_and_winners(diagnostic):
    s,db,binding,index,scorer,_=diagnostic
    assert binding["all_member_decompositions_verified"] and binding["all_winners_verified"]
    rows=db.execute("SELECT left_alert_id,right_alert_id,score,"+",".join(VALUES)+" FROM member_scores ORDER BY left_alert_id,right_alert_id").fetchall()
    assert rows
    for left,right,score,*values in rows:
        actual=scorer.score_pair(left,right)
        assert actual.score==score
        assert actual.values==dict(zip(VALUES,values))
        breakdown=scorer.breakdown(actual)
        assert breakdown.final_score==round(score,6)
        assert sum(actual.contributions.values())==actual.raw_total


def test_cache_tampering_is_rejected_before_diagnosis(diagnostic):
    s,_,_,_,_,cache=diagnostic
    with (cache/"selected_scores.parquet").open("ab") as handle:
        handle.write(b"synthetic-tamper")
    with pytest.raises(ValueError,match="hash_mismatch"):
        bind_scores(s,cache)


def test_cache_wrong_snapshot_is_rejected(diagnostic):
    s,_,_,_,_,cache=diagnostic
    path=cache/"score_snapshot.json"
    meta=json.loads(path.read_text())
    meta["binding"]["analysis_id"]="ana_"+"0"*64
    path.write_text(json.dumps(meta))
    with pytest.raises(ValueError,match="snapshot_mismatch"):
        bind_scores(s,cache)


def test_top_candidate_ranking_and_exact_replay_is_deterministic(diagnostic):
    s,db,_,_,scorer,_=diagnostic
    first=top_candidates(db,s,scorer)
    second=top_candidates(db,s,scorer)
    assert first==second and first
    assert all(r["production_replay_exact"] and r["schema_replay_passed"] for r in first)
    assert first==sorted(first,key=lambda r:(-r["final_score"],*r["support_key"],*r["support_pair"]))


def test_member_statistics_cover_seven_and_population_std(diagnostic):
    s,db,_,_,_,_=diagnostic
    cfg=s.config
    rows=member_distribution(db,component_maxima(cfg),cfg.algorithm.score.weights.model_dump())
    assert {r["member"] for r in rows}==set(VALUES)
    assert all(0<=r["nonzero_ratio"]<=1 for r in rows)
    stats=distribution(db)
    assert stats["median"]==stats["P50"] and stats["std"]>=0
    assert stats["P50"]<=stats["P75"]<=stats["P99.9"]<=stats["max"]


def test_threshold_scan_distinguishes_scoring_from_guard():
    import duckdb
    db=duckdb.connect()
    db.execute("CREATE TABLE member_scores(rep_left VARCHAR,rep_right VARCHAR,score DOUBLE)")
    db.execute("INSERT INTO member_scores VALUES ('a','b',.66),('c','d',.64),('e','f',.65)")
    db.execute("CREATE TABLE selected_scores(rep_left VARCHAR,rep_right VARCHAR,score DOUBLE)")
    db.execute("INSERT INTO selected_scores VALUES ('c','d',.64),('e','f',.65)")
    scan=threshold_scan(db,.65)
    assert scan[0]["score_passing_pair"]==2 and scan[0]["actual_admissible_pair"]==1
    assert scan[0]["remaining_guard_failed_pair"]==1
    assert scan[1]["actual_admissible_pair"]==2
    db.close()


def test_threshold_simulation_does_not_modify_frozen_config_or_production(diagnostic):
    s,db,_,_,_,cache=diagnostic
    config_before=s.config.snapshot
    cache_before={p.name:file_digest(p) for p in cache.iterdir() if p.is_file()}
    yaml_before=file_digest(ROOT/"configs/algorithm-v0.yaml")
    threshold_scan(db,s.config.algorithm.score.correlation_threshold)
    threshold_scan(db,.1) # hypothetical argument never installed in config
    assert s.config.snapshot==config_before
    assert yaml_before==file_digest(ROOT/"configs/algorithm-v0.yaml")
    assert cache_before=={p.name:file_digest(p) for p in cache.iterdir() if p.is_file()}
    s.assert_unchanged()


def test_offline_formal_edge_schema_replay(diagnostic):
    _,_,_,index,scorer,_=diagnostic
    a,b=sorted(index.alerts)[:2]
    scored=scorer.score_pair(a,b)
    edge=edge_schema_replay(scorer,scored,tuple(sorted((a,b))))
    assert edge.score==round(scored.score,6)
    assert edge.score_breakdown.final_score==edge.score


def test_blocking_uses_production_threshold_and_no_invented_direction_gate(diagnostic):
    s,db,_,_,_,_=diagnostic
    first=blocking_reasons(db,s.config.algorithm.score.correlation_threshold)
    second=blocking_reasons(db,s.config.algorithm.score.correlation_threshold)
    assert first==second
    assert first["hard_guard_failure_count"]==0
    assert sum(r["pair_count"] for r in first["first_blocking_reason"])==s.record.metrics.candidate_pair_count
    assert all("direction" not in r["reason"] for r in first["all_failed_conditions"])


def test_dataset_bound_not_observed_max_and_dominates_all_actual_pairs(diagnostic):
    s,db,_,index,scorer,_=diagnostic
    observed=distribution(db)["max"]
    bound=reachability(index,scorer,s.config,observed)
    assert bound["dataset_result_kind"]=="upper bound"
    assert bound["dataset_constrained_maximum_reachable_score"]>observed
    assert bound["dataset_bound_scope"].startswith("all original")
    for i,a in enumerate(index.alerts):
        for b in list(index.alerts)[i+1:]:
            assert scorer.score_pair(a,b).score<=bound["dataset_constrained_maximum_reachable_score"]+1e-12


def test_formula_has_real_production_satisfiability_witness():
    config=load_config(ROOT/"configs/algorithm-v0.yaml")
    witness=formula_witness(config)
    assert witness["valid"] and witness["passes_frozen_threshold"]
    assert witness["score"]>=config.algorithm.score.correlation_threshold
    assert witness["values"]["relation"]>0 and witness["values"]["source"]==0


def test_reachability_proof_rejects_unproven_relation_zero(diagnostic):
    s,db,_,index,scorer,_=diagnostic
    scorer.instances.add("synthetic-unsupported-proof")
    with pytest.raises(ValueError,match="zero_relation_proof"):
        reachability(index,scorer,s.config,distribution(db)["max"])


@pytest.mark.parametrize("member",VALUES)
def test_counterfactual_changes_only_one_actual_contribution(diagnostic,member):
    s,_,_,index,scorer,_=diagnostic
    a,b=sorted(index.alerts)[:2]
    actual=scorer.score_pair(a,b)
    before=content_digest({"values":actual.values,"contributions":actual.contributions})
    cfg=s.config
    cf=component_counterfactual(actual.values,actual.contributions,cfg)
    row=next(r for r in cf["single_member_to_allowed_maximum"] if r["member"]==member)
    sign=-1 if member in {"conflict","duplicate"} else 1
    expected=max(0,min(1,actual.raw_total+sign*getattr(cfg.algorithm.score.weights,member)*(component_maxima(cfg)[member]-actual.values[member])))
    assert row["final_score"]==expected
    assert not row["edge_guaranteed"]
    assert before==content_digest({"values":actual.values,"contributions":actual.contributions})


def test_potential_masks_use_complete_input_no_nomination_and_are_deterministic(diagnostic,tmp_path):
    s,_,_,index,scorer,_=diagnostic
    one,two=tmp_path/"one.gz",tmp_path/"two.gz"
    masks,result=potential_masks(index,s.config,scorer,one)
    again,other=potential_masks(index,s.config,scorer,two)
    assert masks==again and result==other and one.read_bytes()==two.read_bytes()
    assert result["unique_potential_pairs"]==s.manifest["summary"]["potential_pair_stats"]["unique_potential_pairs"]
    assert result["gt_loaded"] is False


def test_candidate_score_and_both_edge_types_unchanged_under_diagnostics_and_gt_tripwire(diagnostic,tmp_path,monkeypatch):
    s,db,_,index,scorer,_=diagnostic
    def production():
        rows=[]
        c=run_correlation(list(index.alerts.values()),[],list(index.entities.values()),s.config,s.settings,diagnostic_sink=rows.append)
        r=run_reconstruction(list(index.alerts.values()),[],list(index.entities.values()),c.edges,s.config,s.settings,upstream_record=c.record)
        return {"candidate":[p.support_key for p in c.candidates.pairs],
                "score":[x for x in rows if x.get("stage")=="member_score"],
                "correlation_edges":[e.model_dump(mode="json") for e in c.edges],
                "chain_edges":[e.model_dump(mode="json") for chain in r.chains for e in chain.edges]}
    original=builtins.open
    original_path=Path.open
    def trap(name,*args,**kwargs):
        assert "labels.csv" not in str(name)
        return original(name,*args,**kwargs)
    def trap_path(path,*args,**kwargs):
        assert path.name!="labels.csv"
        return original_path(path,*args,**kwargs)
    monkeypatch.setattr(builtins,"open",trap)
    monkeypatch.setattr(Path,"open",trap_path)
    before=production()
    top_candidates(db,s,scorer)
    threshold_scan(db,s.config.algorithm.score.correlation_threshold)
    potential_masks(index,s.config,scorer,tmp_path/"isolation.gz")
    assert before==production()
    s.assert_unchanged()


def test_gt_context_loaded_only_after_prediction_freeze_and_no_fake_pair_labels(diagnostic,tmp_path,monkeypatch):
    s,_,_,_,_,_=diagnostic
    # Existing synthetic fixture root lacks frozen source copies; runner hashes
    # whatever exists and its cache binder validates repository extractor code.
    from evaluation.framework import task_06_5 as runner
    gt=tmp_path/"labels.csv"
    gt.write_text("scenario,attack,start,end\ns,synthetic-window,1642723200,1642723204\n",encoding="utf-8")
    original=runner.load_windows
    destination=tmp_path/"outputs/evaluation/task_06_5"
    def loader(*args):
        assert (destination/"prediction_freeze.json").is_file()
        return original(*args)
    monkeypatch.setattr(runner,"load_windows",loader)
    predictions,context,verification=runner.diagnose(tmp_path,s.record.analysis_id,gt,"s")
    assert context["true_positive_same_incident_diagnostic"]["status"]=="unavailable"
    assert context["true_positive_same_incident_diagnostic"]["scored_pair"] is None
    assert not context["same_window_union"]["is_gt_positive"]
    assert verification["all_task06_output_files_unchanged"]
    assert gt.read_text().startswith("scenario,attack,start,end")
    digest=file_digest(destination/"top_candidates.json")
    repeated=runner.diagnose(tmp_path,s.record.analysis_id,gt,"s")
    assert predictions==repeated[0] and context==repeated[1]
    assert digest==file_digest(destination/"top_candidates.json")


def test_diagnostic_destination_cannot_overwrite_task06_cache(diagnostic,tmp_path):
    s,_,_,_,_,cache=diagnostic
    from evaluation.framework.task_06_5 import diagnose
    with pytest.raises(ValueError,match="overlaps_task06"):
        diagnose(tmp_path,s.record.analysis_id,tmp_path/"labels.csv","s",cache)

"""Task 06.5: isolated, deterministic score diagnostics; no production writes."""

import argparse
from collections import Counter
import csv
import gzip
import json
from pathlib import Path
import sys

from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.models import CorrelationEdge
from app.services.storage import file_digest
from app.utils.stable_id import content_digest, id_for
from evaluation.framework.runner import frozen_files
from evaluation.io.diagnostics import VALUES
from evaluation.io.ground_truth import load_windows, map_windows
from evaluation.io.snapshot import load_snapshot, protect_output
from evaluation.io.task_06_5 import (bind_scores, blocking_reasons, distribution, member_distribution,
                                    potential_masks, read_at, save, threshold_scan,csv_table)
from evaluation.sensitivity.score_reachability import component_counterfactual, component_maxima, formula_witness, reachability


def csv_save(path, rows):
    with Path(path).open("w",encoding="utf-8",newline="") as handle:
        writer = csv.DictWriter(handle,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def edge_schema_replay(scorer, scored, pair):
    """Use exactly production formal model and context, without storing it."""
    data = {"source_alert_id":pair[0],"target_alert_id":pair[1],"score":round(scored.score,6),
            "reasons":scored.reasons,"entity_ids":scored.entity_ids,"score_breakdown":scorer.breakdown(scored),
            "support_pair":{"alert_id_src":scored.source_member_id,"alert_id_dst":scored.target_member_id}}
    data["edge_id"] = id_for("CorrelationEdge",data)
    context = {"alerts":scorer.index.alerts,"groups":scorer.index.groups,"config_hash":scorer.config_hash,
               "score_weights":scorer.algorithm.score.weights.model_dump(),
               "independence_rule_ids":sorted({r.id for m in scorer.independence_mappings for r in m.rules})}
    return CorrelationEdge.model_validate(data,context=context)


def top_candidates(db,snapshot,scorer,count=20):
    cursor = db.execute("SELECT s.*,a.admission_metadata FROM selected_scores s JOIN admissions a USING(rep_left,rep_right) "
                        "ORDER BY score DESC,rep_left,rep_right,left_alert_id,right_alert_id LIMIT ?",[count])
    names = [c[0] for c in cursor.description]
    rows = [dict(zip(names,r)) for r in cursor.fetchall()]
    output = []
    for rank,row in enumerate(rows,1):
        pair = (row["rep_left"],row["rep_right"])
        members = (row["left_alert_id"],row["right_alert_id"])
        scored = scorer.score_pair(*members)
        original = read_at(snapshot.store.details / "diagnostics.jsonl",row["diagnostic_offset"])
        if (scored.values != original["values"] or scored.contributions != original["contributions"]
                or scored.score!=original["score"] or scored.rejection_codes!=original["rejection_codes"]
                or original["support_key"]!=list(pair) or original["support_pair"]!=list(members)):
            raise ValueError("top_candidate_production_replay_mismatch")
        # Validation does not decide threshold eligibility and creates no file.
        edge_schema_replay(scorer,scored,pair)
        admission = json.loads(row["admission_metadata"])
        entities = []
        for f in scored.diagnostics["entity_features"]:
            e = scorer.index.entities[f["entity_id"]]
            entities.append({**f,"scope":e.scope,"value_summary":e.value[:200],"value_sha256":content_digest(e.value)})
        alerts = []
        for aid in members:
            a = scorer.index.alerts[aid]
            alerts.append({"alert_id":aid,"source_type":a.source_type.value,"source_namespace":a.source_namespace,
                           "timestamp":a.timestamp,"category":a.category.value,"rule_id":a.rule_id,"sensor":a.sensor,
                           "raw_fingerprint":a.raw_fingerprint,
                           "field_references":{k:{"alert_id":aid,"pointer":v.raw_pointer,"side":"shared"}
                                               for k,v in sorted(a.field_provenance.items()) if k in {"host","account","file","command","process","session","src_ip","dst_ip"}}})
        output.append({"rank":rank,"pair_identifier":id_for("CorrelationEdge",{"source_alert_id":pair[0],"target_alert_id":pair[1]}),
                       "support_key":list(pair),"support_pair":list(members),"alerts":alerts,
                       "time_gap_seconds":scored.diagnostics["gap_seconds"],"associated_entities":entities,
                       "score_members":scored.values,"signed_contributions":scored.contributions,"raw_total":scored.raw_total,
                       "final_score":scored.score,"threshold":scorer.algorithm.score.correlation_threshold,
                       "gap_to_threshold":scorer.algorithm.score.correlation_threshold-scored.score,
                       "candidate_reason":admission,"conflict_guard":scored.diagnostics["conflicts"],
                       "valid":scored.valid,"rejection_codes":scored.rejection_codes,
                       "relations":scored.diagnostics["relations"],"source_rule":scored.diagnostics["source_rule"],
                       "duplicate_features":scored.diagnostics["duplicate_features"],
                       "why_no_correlation_edge":"below_correlation_threshold; all non-threshold member guards passed; schema replay passed",
                       "schema_replay_passed":True,"production_replay_exact":True,
                       "diagnostic_reference":{"path":snapshot.record.diagnostics_ref,"byte_offset":row["diagnostic_offset"]},
                       "counterfactual":component_counterfactual(scored.values,scored.contributions,snapshot.config)})
    return output


def gt_diagnostic(gt_path,scenario,snapshot,db,masks,mask_path):
    """First GT content read occurs here, after all prediction diagnostics freeze."""
    gt = load_windows(gt_path,scenario)
    mapped = map_windows(gt,snapshot)
    reps = sorted(snapshot.groups)
    positions = {r:i for i,r in enumerate(reps)}
    with gzip.open(mask_path,"rt",encoding="utf-8") as stream:
        non_time = [int(json.loads(line)["non_time_mask_hex"],16) for line in stream]
    windows = []
    union_masks = [0]*len(reps)
    for w in mapped["windows"]:
        ids = sorted(w["representative_alert_ids"])
        bits = sum(1<<positions[i] for i in ids)
        potential = sum((masks[positions[i]]&bits).bit_count() for i in ids)//2
        non_time_count = sum((non_time[positions[i]]&bits).bit_count() for i in ids)//2
        for i in ids:
            union_masks[positions[i]] |= bits & ~(1<<positions[i])
        csv_table(db,"window_reps",{"rep":"VARCHAR"},((i,) for i in ids))
        where = "rep_left IN (SELECT rep FROM window_reps) AND rep_right IN (SELECT rep FROM window_reps)"
        stats = distribution(db,where=where)
        blocked = db.execute("SELECT count(*) FROM selected_scores WHERE " + where + " AND score<?",[snapshot.config.algorithm.score.correlation_threshold]).fetchone()[0]
        windows.append({"window_id":w["window_id"],"attack_name":w["attack"],"temporal_alert_count":w["alert_count"],
                        "temporal_representative_count":len(ids),"all_temporal_group_pairs":len(ids)*(len(ids)-1)//2,
                        "potential_pair":potential,"potential_with_non_time_channel":non_time_count,
                        "time_only_without_non_time_channel":potential-non_time_count,
                        "policy_pruned":potential-stats["count"],"admitted_candidate":stats["count"],
                        "scored_pair":stats["count"],"score_distribution":stats,
                        "threshold_blocked":blocked,"other_guard_blocked":0,"is_gt_positive":False})
    # Exact union across overlapping windows; avoid summing duplicated pairs.
    potential_union = sum((m&u).bit_count() for m,u in zip(masks,union_masks))//2
    non_time_union = sum((m&u).bit_count() for m,u in zip(non_time,union_masks))//2
    alert_windows = mapped["alert_windows"]
    group_windows = {r:sorted({w for aid in snapshot.groups[r] for w in alert_windows.get(aid,[])}) for r in reps}
    csv_table(db,"temporal_group_context",{"rep":"VARCHAR","windows_json":"VARCHAR"},
              ((r,json.dumps(group_windows[r])) for r in reps))
    # Stream frozen scores into a bounded Python window intersection. Avoid
    # native nested-list JSON joins on this Windows DuckDB runtime. Neither GT
    # membership nor the resulting list is passed back to production functions.
    sets={r:set(ids) for r,ids in group_windows.items() if ids}
    scores=[]
    cursor=db.execute("SELECT rep_left,rep_right,score FROM selected_scores ORDER BY rep_left,rep_right")
    while rows:=cursor.fetchmany(8192):
        for left,right,score in rows:
            if left in sets and right in sets and sets[left].intersection(sets[right]):
                scores.append(score)
    csv_table(db,"gt_temporal_scores",{"score":"DOUBLE"},((s,) for s in scores))
    stats = distribution(db,"gt_temporal_scores")
    count = stats["count"]
    return {"ground_truth_kind":gt["granularity"],"capabilities":gt["capabilities"],"gt_sha256":gt["gt_sha256"],
            "true_positive_same_incident_diagnostic":{"status":"unavailable","positive_pair":None,"potential_pair":None,
               "admitted_candidate":None,"scored_pair":None,"threshold_blocked":None,"guard_blocked":None,
               "reason":"labels.csv contains only scenario/attack/start/end; no alert labels or incident memberships"},
            "temporal_proxy_scope":"both full representative groups have some original member in the same [start,end) attack window; selected scoring support members may differ; not pair truth",
            "quality_evaluation_coverage":0.0,"overlap_alert_count":mapped["temporal_overlap_alert_count"],
            "same_window_union":{"potential_pair":potential_union,"potential_with_non_time_channel":non_time_union,
               "time_only_without_non_time_channel":potential_union-non_time_union,"policy_pruned":potential_union-count,
               "admitted_candidate":count,"scored_pair":count,"score_distribution":stats,"threshold_blocked":count,
               "other_guard_blocked":0,"is_gt_positive":False},"windows":windows,
            "production_inputs_unchanged":True,"gt_read_after_prediction_freeze":True}


def diagnose(root,analysis_id,gt_path,scenario,destination=None,progress=lambda _:None):
    root,gt_path = Path(root).resolve(),Path(gt_path).resolve()
    out = protect_output(root,destination or root/"outputs/evaluation/task_06_5",gt_path)
    old_cache = root/"outputs/evaluation"/analysis_id
    # Never allow overwriting a prior evaluation output or current snapshot.
    if out==old_cache or out.is_relative_to(old_cache) or old_cache.is_relative_to(out):
        raise ValueError("diagnostic_output_overlaps_task06_cache")
    out.mkdir(parents=True,exist_ok=True)
    protected = frozen_files(root)
    prior_outputs = {p.relative_to(root).as_posix():file_digest(p) for p in sorted(old_cache.rglob("*")) if p.is_file()}
    raw_inputs = {p.relative_to(root).as_posix():file_digest(p) for p in sorted((root/"data/ait_ads").rglob("*"))
                  if p.is_file() and "raw" in p.parts}
    snapshot = load_snapshot(root,analysis_id)
    progress({"stage":"snapshot_verified","alerts":len(snapshot.alerts),"representatives":len(snapshot.groups)})
    db,cache = bind_scores(snapshot,old_cache)
    progress({"stage":"score_cache_bound_all_decompositions_and_winners_verified"})
    threshold = snapshot.config.algorithm.score.correlation_threshold
    maxima,weights = component_maxima(snapshot.config),snapshot.config.algorithm.score.weights.model_dump()
    stats = distribution(db)
    stats.update(scope="826313 admitted representative pairs; highest valid full member score; unrounded",
                 std_definition="population",quantile_definition="linear interpolation (DuckDB quantile_cont)",
                 edge_threshold=threshold,gap_to_threshold=threshold-stats["max"])
    member_stats = distribution(db,"member_scores")
    members = member_distribution(db,maxima,weights)
    raw_members = member_distribution(db,maxima,weights,"member_scores")
    sensitivity = threshold_scan(db,threshold)
    stats["near_threshold_counts"] = sensitivity
    blocking = blocking_reasons(db,threshold)
    progress({"stage":"score_distributions_and_admission_diagnosed"})
    # Complete extracted CanonicalAlerts are read only for production component
    # replay, proof gates and exact retrieval. No raw payload enters reports.
    index = AlertIndex(snapshot.store.read_records("alerts",parquet=True),snapshot.store.read_records("dedupe_groups",parquet=True),
                       snapshot.store.read_records("entities",parquet=True))
    scorer = CorrelationScorer(index,snapshot.config,snapshot.settings,snapshot.record.config_hash)
    progress({"stage":"full_canonical_fact_index_restored"})
    top = top_candidates(db,snapshot,scorer)
    reach = reachability(index,scorer,snapshot.config,stats["max"])
    witness = formula_witness(snapshot.config)
    if not witness["passes_frozen_threshold"]:
        raise ValueError("formula_reachable_witness_did_not_pass")
    reach.update(mathematically_reachable=True,formula_witness=witness)
    patterns = db.execute("SELECT " + ",".join(k+">0" for k in VALUES) + ",count(*),max(score),avg(score) "
                          "FROM selected_scores GROUP BY ALL ORDER BY count(*) DESC,"+",".join(k+">0" for k in VALUES)).fetchall()
    combinations = [{"nonzero_members":[k for k,v in zip(VALUES,row[:7]) if v],"count":row[7],"max_score":row[8],"mean_score":row[9]} for row in patterns]
    soft = db.execute("SELECT conflict,count(*) FROM member_scores GROUP BY ALL ORDER BY ALL").fetchall()
    progress({"stage":"all_scores_verified","candidate_count":stats["count"],"observed_max":stats["max"],"dataset_upper_bound":reach["dataset_constrained_maximum_reachable_score"]})
    masks,potential = potential_masks(index,snapshot.config,scorer,out/"potential_neighbors.jsonl.gz")
    if potential["unique_potential_pairs"]!=snapshot.manifest["summary"]["potential_pair_stats"]["unique_potential_pairs"]:
        raise ValueError("potential_retrieval_baseline_mismatch")
    summary = snapshot.manifest["summary"]
    baseline = {**summary["potential_pair_stats"],"policy_pruned":summary["policy_pruned_count"],
                "admitted":summary["admitted_candidate_count"],"scored":summary["scored_candidate_count"],
                "resource_truncated":summary["resource_truncated_count"],"correlation_edges":sum(1 for _ in snapshot.records("correlation_edges")),
                "chain_edges":sum(1 for _ in snapshot.records("chain_edges")),"member_pair_count":cache["summary"]["member_pair_count"],
                "canonical_alert_count":len(snapshot.alerts),"source_counts":dict(sorted(Counter(a["source_type"] for a in snapshot.alerts.values()).items())),
                "input_source_counts":summary.get("counts"),"representative_count":len(snapshot.groups),"complete":snapshot.record.is_complete}
    predictions = {"baseline":baseline,"score_distribution":stats,"score_members":members,"blocking":blocking,"reachability":reach,
                   "top":top,"threshold_sensitivity":sensitivity,"potential":potential}
    freeze = {"prediction_digest":content_digest(predictions),"order":"verified completed production snapshot -> full diagnostic prediction freeze -> GT content read",
              "diagnostic_version":"task06.5-v1","config_hash":snapshot.record.config_hash,"analysis_id":analysis_id}
    save(out/"prediction_freeze.json",freeze)
    save(out/"prediction_checkpoint.json",predictions)
    # Persist every completed prediction diagnostic before the only GT loader.
    for name,value in {"production_baseline.json":baseline,"score_distribution.json":stats,
                       "top_candidates.json":top,"blocking_reasons.json":blocking,"reachability.json":reach,
                       "potential_diagnostic.json":potential}.items():
        save(out/name,value)
    csv_save(out/"score_members.csv",members)
    csv_save(out/"threshold_sensitivity.csv",sensitivity)
    progress({"stage":"prediction_frozen_before_gt","potential_pair":potential["unique_potential_pairs"]})
    gt = gt_diagnostic(gt_path,scenario,snapshot,db,masks,out/"potential_neighbors.jsonl.gz")
    snapshot.assert_unchanged()
    if frozen_files(root)!=protected or any(file_digest(root/p)!=d for p,d in {**prior_outputs,**raw_inputs}.items()):
        raise ValueError("protected_files_changed")
    if file_digest(gt_path)!=gt["gt_sha256"]:
        raise ValueError("ground_truth_changed")
    verification = {"all_original_production_and_contract_files_unchanged":True,"all_task06_output_files_unchanged":True,
                    "all_raw_input_files_unchanged":True,"gt_unchanged":True,"cache_binding":cache,
                    "snapshot_identity":snapshot.identity,"protected_hashes":protected,"task06_output_hashes":prior_outputs,
                    "raw_input_hashes":raw_inputs,"production_artifact_hashes":snapshot.artifact_hashes,
                    "all_826313_selected_decompositions_verified":True,"all_member_decompositions_verified":True,
                    "top20_exact_production_replay":True,"potential_retrieval_matches_baseline":True}
    files = {"production_baseline.json":baseline,"score_distribution.json":stats,"member_pair_distribution.json":member_stats,
             "score_combinations.json":{"patterns":combinations,"member_soft_penalty_values":[{"penalty":v,"count":n} for v,n in soft]},
             "top_candidates.json":top,"blocking_reasons.json":blocking,"reachability.json":reach,
             "counterfactual.json":[{"pair_identifier":r["pair_identifier"],**r["counterfactual"]} for r in top],
             "gt_diagnostic.json":gt,"potential_diagnostic.json":potential,"reproducibility.json":verification}
    for name,value in files.items():
        save(out/name,value)
    csv_save(out/"score_members.csv",members)
    csv_save(out/"raw_member_score_members.csv",raw_members)
    csv_save(out/"threshold_sensitivity.csv",sensitivity)
    from evaluation.framework.task_06_5_report import write_report
    write_report(out,baseline,stats,members,top,blocking,reach,sensitivity,gt,verification)
    outputs = {p.name:file_digest(p) for p in sorted(out.iterdir()) if p.is_file() and p.name not in {"deliverable_manifest.json","run.log"}}
    save(out/"deliverable_manifest.json",{"files":outputs,"prediction_digest":freeze["prediction_digest"],
         "implementation_hashes":{p.relative_to(root).as_posix():file_digest(p) for p in sorted((root/"evaluation").rglob("*.py"))},
         "command":f".venv/Scripts/python.exe -m evaluation.framework.task_06_5 --root . --analysis-id {analysis_id} --gt {gt_path.relative_to(root).as_posix()} --scenario {scenario}"})
    db.close()
    return predictions,gt,verification


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",required=True)
    parser.add_argument("--analysis-id",required=True)
    parser.add_argument("--gt",required=True)
    parser.add_argument("--scenario",required=True)
    parser.add_argument("--destination")
    args = parser.parse_args()
    diagnose(args.root,args.analysis_id,args.gt,args.scenario,args.destination,
             progress=lambda row:print(json.dumps(row,sort_keys=True),flush=True))


if __name__=="__main__":
    main()

"""Finalize one report, provenance, integrity receipts and actual pytest counts."""
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from . import ROOT,OUT
from .runner import verify_score_seal, verify_files, load_labels
from evaluation.framework.formula_design import OUT as PARENT, BASELINE
from evaluation.framework.formula_design.runtime import read,save,sha,rows


def tests(path):
    cases=list(ET.parse(path).iter('testcase'))
    failed=[dict(c.attrib) for c in cases if c.find('failure') is not None or c.find('error') is not None]
    skipped=[dict(c.attrib,reason=c.find('skipped').get('message','')) for c in cases if c.find('skipped') is not None]
    return dict(passed=len(cases)-len(failed)-len(skipped),failed=len(failed),skipped=len(skipped),
                failures=failed,skip_details=skipped)


def n(value):
    return 'N/A' if value is None else f'{value:.6f}' if isinstance(value,float) else str(value)


def run():
    verify_score_seal()
    p=read(OUT/'preparation.json')
    verify_files(p['protected_files'])
    dataset_root=Path(r'D:\Code_WorkSpace\TraceBack-Dataset')
    verify_files(p['dataset_files'],dataset_root)
    current={x.relative_to(dataset_root).as_posix() for x in (dataset_root/'data/traceback_semisynthetic_v1').rglob('*') if x.is_file()}
    if current!=set(p['dataset_files']):
        raise ValueError('calibration_dataset_file_set_changed')
    reg=tests(OUT/'regression.xml')
    reg['final_source_supplement']=tests(OUT/'final_tests.xml')
    reg.update(status='PASS' if not reg['failed'] else 'FAIL',historical_integrity='PASS',
        protected_files_verified=len(p['protected_files']),dataset_files_verified=len(p['dataset_files']),
        formula_and_production_bytes_unchanged=True,
        historical_full_v4_reexecution=False,
        historical_compatibility='old snapshot/hash/serialization and synthetic scoring equivalence regression passed; historical artifact hashes verified; original strict executor still rejects current source as before this task')
    save(OUT/'regression_summary.json',reg)
    # Correct descriptive stage metadata from the actual GT schema, never scores.
    alerts={a['alert_id']:a for a in rows(BASELINE/'blind/canonical.jsonl.gz')}
    labels=load_labels(alerts)
    gt=read(OUT/'ground_truth_edge_scores.json')
    for row in gt['edges'].values():
        row['attack_stage_from']=labels['nodes'][row['source']]['stage']
        row['attack_stage_to']=labels['nodes'][row['target']]['stage']
    save(OUT/'ground_truth_edge_scores.json',gt)
    s=read(OUT/'summary.json');sep=s['score_separation'];r=s['representatives']
    chain=read(OUT/'chain_validation.json');hist=chain['historical'];pollution=chain['background_pollution']
    recovered_alerts={aid for c in rows(OUT/'downstream_final/chains.jsonl.gz') for node in c['nodes'] for aid in node['alert_ids']}
    chain.update(GT_alerts_represented=len(labels['attack_ids']&recovered_alerts),
        GT_nodes_with_all_member_alerts_represented=sum(v<=recovered_alerts for v in labels['members'].values()),
        GT_nodes_merged_into_single_steps='not established; representation is not strict matched node recovery')
    save(OUT/'chain_validation.json',chain)
    hard=read(OUT/'hard_negative_validation.json')
    stability=read(OUT/'threshold_stability.json')
    distributions=read(OUT/'score_distribution.json')['distributions']
    original_guard=read(PARENT/'blind/guard_receipt.json')
    projection_guard=read(OUT/'scored/guard_receipt.json')
    if original_guard['rejected_events'] or projection_guard['rejected_events'] or hist['guard']['rejected_events']:
        raise ValueError('completed_worker_has_forbidden_reads')
    save(OUT/'anti_leakage.json',dict(status='PASS_FOR_RECORDED_WORKERS',
        original_blind_seal_sha256=p['parent_seal_sha256'],projection_seal_sha256=sha(OUT/'scored_seal.json'),
        original_worker=original_guard,projection_worker=projection_guard,downstream_worker=hist['guard'],
        production_static_and_runtime_tripwire_tests='passed in regression.xml',
        calibration_used_only_frozen_semisynthetic_development=True,t2_dataset_read=False,
        GT_policy=labels['gt']['evaluation_policy'],
        limitation='Python audit hooks and source/tests establish recorded process boundaries; no OS-level exhaustive access attestation'))
    save(OUT/'attempts.json',dict(score_or_formula_retries=0,tooling_repairs=[
        'Evaluation loader initially required raw_alert_count; added parent count to the verified score receipt. No scoring changed.',
        'Downstream guard denied lazy imports of observation.py and ctypes before output; preloaded those code modules then repeated the unchanged empty-edge reconstruction.',
        'Report stage metadata uses GT node stage, correcting an initially absent category lookup. No labels, scores, gates or thresholds changed.'],
        initial_evaluation_tool_hashes=p['implementation'],
        final_evaluation_tool_hashes={x.relative_to(ROOT).as_posix():sha(x) for x in Path(__file__).parent.glob('*.py')}))
    edge_table='| GT edge | Stage from → to | Score | Global rank bounds | Percentile | Gate |\n|---|---|---:|---:|---:|---|\n'
    for e,v in sorted(gt['edges'].items()):
        edge_table+=f"| {e} | {v['attack_stage_from']} → {v['attack_stage_to']} | {v['score']:.12f} | {v['score_rank_min']}–{v['score_rank_max']} | {v['percentile']:.6f} | {v['gate_passed']} |\n"
    calibration='| Point | Threshold | TP | FP | Unlabelled admitted | Precision | Recall | F1 | Actual longest GT path |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|\n'
    for label,key in [('Historical','historical'),('Highest threshold with max GT recall','highest_threshold_maximum_GT_recall'),('Best F1','best_F1'),('Best actual chain completeness','best_chain_completeness')]:
        v=r[key]
        calibration+='| '+' | '.join(map(str,[label,n(v['threshold']),v['GT_TP'],v['FP'],v['unlabeled_admitted'],n(v['precision']),n(v['recall']),n(v['F1']),v['longest_GT_path_recovered']]))+' |\n'
    calibration+='| Recommended | NONE | — | — | — | — | — | — | — |\n'
    neighbors='| T | GT TP / 6 | Annotated FP | Precision | Candidate volume | Correlation path proxy | Actual chain path |\n|---:|---:|---:|---:|---:|---:|---:|\n'
    for v in stability['rows']:
        neighbors+='| '+' | '.join(map(str,[n(v['threshold']),v['GT_TP'],v['FP'],n(v['precision']),v['total_admitted_edges'],v['correlation_GT_longest_path_proxy'],0]))+' |\n'
    dt='| Population (member pairs) | Count | Min | p05 | p25 | Median | p75 | p95 | Max | Mean | Std |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n'
    for name,v in distributions.items():
        dt+='| '+name+' | '+' | '.join(n(v[k]) for k in ('count','min','p05','p25','median','p75','p95','max','mean','std'))+' |\n'
    identity='\n'.join(f'{k}={p[k]}' for k in ('algorithm_version','implementation_version','config_hash_before','parent_production_config_hash','mapping_digest','dataset_hash','ground_truth_hash'))
    text=f'''# V5 Validation + Threshold Calibration

## 1. Task Result

`TASK_RESULT=V5_THRESHOLD_NO_SAFE_OPERATING_POINT`

Executable evaluation-only F2 exists and was selected/frozen before this task. The production default still uses `v5-preformula-candidate-v1` and the historical v4 scoring formula. This task neither redesigns nor integrates a V5 formula.

The failure is not candidate recall. It is poor score separation for part of the progression, an immutable gate rejection, and incompatible downstream thresholds/serialization. Lowering admission alone cannot restore this attack chain.

## 2. Frozen Identity

```text
{identity}
threshold_before=0.65
git_commit=UNAVAILABLE
working_tree_status=NOT_A_GIT_REPOSITORY
```

The experimental config hash is SHA-256 of canonical JSON of the existing frozen formula policy. Its YAML bytes hash is `{p['policy_sha256']}`. The parent production config hash is reported separately, never presented as an F2 execution identity.

{reg['protected_files_verified']} protected historical/formula/production files and {reg['dataset_files_verified']} calibration dataset files verified unchanged before and after. No t2 source data or future validation set was read. No historical outputs were overwritten.

## 3. Ground Truth Candidate Recall

```text
GT_EDGES=6
GT_CANDIDATES=6
CANDIDATE_RECALL=6/6=1.0
missed_candidate_edges=NONE
score_available=6/6
gate_passed=5/6
```

All original candidate rows were independently rehashed to the original candidate digest. Per-edge candidate channels, reasons, source/target nodes and alert IDs are in ground_truth_edge_scores.json. GT-E01 is `BROKEN_AT_GATE`, not `BROKEN_AT_CANDIDATE`; it remains rejected at threshold zero.

## 4. V5 Score Separation

Primary metrics use the six explicitly positive witness pairs and 179 scored explicitly negative pairs. The other 451 of 630 explicit negatives were not candidates and receive no invented score. Unlisted pairs are unknown under the dataset's frozen evaluation policy. They are excluded from supervised confusion counts.

```text
GT_score_range=0.012329544991..0.631472796749
annotated_negative_range={n(distributions['EXPLICIT_ANNOTATED_NEGATIVE']['min'])}..0.450000000000
hard_touching_range=0..0.581005285003
PR_AUC={sep['annotated_only']['PR_AUC']:.12f}
ROC_AUC={sep['annotated_only']['ROC_AUC']:.12f}
Average_Precision={sep['annotated_only']['Average_Precision']:.12f}
lowest_GT_score={sep['lowest_GT_score']:.12f}
highest_annotated_negative_score={sep['highest_negative_score']:.12f}
score_margin={sep['score_margin']:.12f}
SEPARATION=POOR
```

GT-E05 ranks first; E02–E06 enter the high global percentile region, but several overlap hard negatives. E01 ranks {gt['edges']['GT-E01']['score_rank_min']:,} of 219,504, within the ordinary background body. High percentiles from a huge background population do not establish good separation from hard negatives.

{edge_table}

{dt}

PR-AUC is trapezoidal area on a grouped PR curve; AP uses noninterpolated precision-weighted recall increments. Ties are grouped. Population std uses denominator N. Ranking includes gate rejects and exact, unrounded scores. Main positive/observed-zero/contradiction evidence and the unchanged F2 decomposition are saved for every GT edge.

Supervised coverage: 185/219504={sep['evaluation_coverage']:.9f}; explicit-negative candidate coverage: 179/630={sep['explicit_negative_candidate_coverage']:.9f}. A separate **closed-world diagnostic proxy** treats every other scored member as negative: ROC-AUC {sep['closed_world_proxy']['ROC_AUC']:.9f}, PR-AUC {sep['closed_world_proxy']['PR_AUC']:.9f}, AP {sep['closed_world_proxy']['Average_Precision']:.9f}. These proxy metrics are not labeled population-quality estimates.

## 5. Historical 0.65 Result

```text
threshold=0.65
admitted_candidates=0
GT_edges_admitted=0/6
GT_missed=6/6
precision=null (not_applicable: no predictions)
recall=0
F1=0
annotated_false_positives=0
longest_recovered_GT_path=0/6
```

0.65 is too high for any F2 admission in this frozen score population: even its highest score is 0.631472796749. This does not imply a safe lower operating point exists.

## 6. Threshold Calibration and Pareto Frontier

{s['metrics_row_count']} thresholds were evaluated from exactly the same sealed scores: 0.30–0.90 by 0.01, unique valid-candidate score boundaries, their next representable floats, and 0/1 endpoints. `threshold_metrics.csv` retains all rows. No scoring runs occurred during the sweep.

{calibration}

Primary TP/FP here are **original annotated member pairs**, preserving the exact witness definition; graph edge volume uses one best valid member per representative pair. These units are explicit in CSV. At the max-recall point all five admitted GT witnesses are also their selected representative supports. Its total candidate volume is 234: 5 GT, 65 explicit negatives, 164 unknown. The all-other-pairs-negative proxy FP is 229 and proxy precision 2.136752%; 229 is not a verified false-positive count.

`threshold_pareto.json` contains the annotated Precision/Recall/actual-chain-completeness/FP frontier, retaining the highest threshold per equivalent metric state. Best actual chain completeness ties at zero for every threshold, so the conservative tie-break selects 1.0. This is a representative failure point, not a recommendation.

## 7. Recommended Threshold

```text
OLD_THRESHOLD=0.65
RECOMMENDED_THRESHOLD=NONE
THRESHOLD_CALIBRATION=NO_SAFE_OPERATING_POINT
```

Selection was declared before this experiment loaded GT: prioritize GT recovery and contiguous correlation-path recovery, then minimize explicit FP and unknown/admitted volume, then use the highest threshold. This nominates 0.3074976783886427 only as a diagnostic maximum-recovery point. It is rejected as production advice: E01 never passes the gate, precision is 7.142857% on scored annotated pairs, 130 hard-touching candidates enter, actual chain recovery remains zero, and nonempty V5 formal graphs have no supported serializer/dispatch. No weights or rules were changed to rescue these failures.

## 8. Threshold Stability

`THRESHOLD_UNSTABLE / CLIFF_EDGE` at the diagnostic maximum-recovery point. No recommended threshold exists; sensitivity is therefore explicitly diagnostic.

{neighbors}

At +0.01 one more GT witness disappears. At -0.02 candidate volume rises 234→317. `threshold_stability.json` declares the diagnostic criterion: any GT recovery change within ±0.02, or volume change exceeding max(10,10%). Actual downstream chain path stays zero throughout.

## 9. Hard Negative Result

```text
hard_negative_alerts=30
hard_negative_candidate_pairs={hard['hard_negative_candidate_pairs']}
hard_negative_member_pairs={hard['hard_negative_member_pairs']}
hard_negative_max_score={hard['hard_negative_max_score']:.12f}
hard_negative_p95_score={hard['hard_negative_p95_score']:.12f}
hard_negative_admitted_at_0.65=0
hard_negative_admitted_at_diagnostic_threshold=130
hard_negative_admitted_at_recommended_threshold=null (NONE)
```

Hard-touching counts include any pair incident to a declared distractor; only the explicitly labeled attack-versus-distractor subset is a supervised negative. Other hard-touching pairs remain unknown under the GT policy.

## 10. Attack Chain Result

```text
CorrelationEdges_recovered_at_0.65=0/6
best_diagnostic_correlation_witness_recovery=5/6
ChainEdges_recovered=0/6
Longest_GT_path_recovered=0/6
GT_nodes_with_all_member_alerts_represented={chain['GT_nodes_with_all_member_alerts_represented']}/7
GT_attack_alerts_represented={chain['GT_alerts_represented']}/21
```

All GT alert evidence survives. This representation is not a claim of seven correctly merged/matched GT step nodes. No multi-stage attack chain was reconstructed.

At 0.65, the production `run_reconstruction` actually ran with the exact empty admitted F2 edge set, built incidents/nodes/chains, and passed grounding. The scorer method was replaced with a raising tripwire, proving zero rescoring. The data read allowlist excluded GT and t2.

Across all thresholds, no F2 score reaches the unchanged 0.70 clustering/chain minimum; chain recovery therefore has a strict zero ceiling. Nonempty lower-threshold formal F2 edges additionally cannot satisfy the current ScoreBreakdown v0/v2/v3/v4 contract. We did not forge old breakdowns, bypass model validation, change downstream thresholds, or call an unimplemented F2 end-to-end pipeline. Lower-threshold rows report the proven ceiling and correlation-only proxy separately; a full nonempty graph replay is **blocked**, not claimed complete.

## 11. Background Pollution

```text
representative_alerts={hist['representative_count']}
correlation_edges_at_0.65=0
incidents={hist['incident_count']}
singleton_incidents_by_fact_group={hist['singleton_incident_count']}
multi_fact_group_incidents={hist['multi_alert_incident_count']}
singleton_incidents_by_original_alerts={pollution['singleton_incidents_by_original_alerts']}
multi_original_alert_incidents={pollution['multi_original_alert_incidents']}
chain_edges=0
chain_snapshots={hist['attack_chain_count']}
chains_with_edges=0
largest_incident_representatives={hist['max_incident_representatives']}
largest_incident_original_alerts={hist['max_incident_original_alerts']}
largest_chain_length_edges=0
```

`NORMAL_AT_065`: no giant component/background collapse. The small multi-original-alert incidents are dedupe groups, not correlation merges. At lower admission thresholds, display-candidate pollution rises substantially; no merge is eligible at the unchanged clustering threshold. A production nonempty V5 graph is not claimed evaluated.

## 12. Regression and Integrity

```text
tests_passed={reg['passed']}
tests_failed={reg['failed']}
tests_skipped={reg['skipped']}
historical_artifact_integrity=PASS
dataset_integrity=PASS
ground_truth_integrity=PASS
production_formula_config_changed=false
```

Regression covers canonicalization, candidates/budgets, v4 compatibility, preformula identity, V5 formula semantics, threshold admission, incidents, chains, evidence, Stable ID/Schema and API serialization/isolation. Exact command is in evaluation/framework/threshold_calibration/README.md; actual evidence is regression.xml. A final-source supplement passed {reg['final_source_supplement']['passed']} calibration/metric/integration tests, including the subsequently added delivered-artifact integration check (final_tests.xml). Repeated executions are not added to the main pass count. Existing skip reasons are retained in regression_summary.json. No assertion was deleted or disabled.

Historical v4 artifact bytes and compatibility fixtures are intact. A complete historical-v4 raw-input replay was **not performed**: its strict historical implementation guard already rejects current preformula source, which the compatibility tests explicitly confirm. No claim is made that frozen historical source archives were replayed.

`anti_leakage.json` retains original blind, score-projection and downstream read receipts plus isolation test evidence. Evaluation loader/platform-import tooling repairs are disclosed in attempts.json; no formula, feature, weight, candidate, evidence definition, namespace, data or label changed. Current tooling hashes and original preparation hashes are both retained.

## 13. Final V5 Verdict

```text
V5_VALIDATION=FAIL
V5_THRESHOLD_CALIBRATION=NO_SAFE_OPERATING_POINT
V5_FORMULA_FREEZE=NO_NEW_FREEZE (existing experimental F2 retained unchanged)
V5_THRESHOLD_FREEZE=NO
READY_FOR_EXTERNAL_VALIDATION=NO
```

Failure results are retained. Admission-only calibration cannot fix the immutable E01 gate rejection, score overlap, fixed downstream 0.70 ceiling, or missing production F2 score contract. No production config was modified. t2 external validation and all later stages were not started.
'''
    (OUT/'V5_VALIDATION_THRESHOLD_CALIBRATION_REPORT.md').write_text(text,encoding='utf8')
    files={x.relative_to(OUT).as_posix():sha(x) for x in OUT.rglob('*') if x.is_file()
           and x.name!='manifest.json' and not any(part in x.parts for part in ('pytest_tmp','regression_tmp','final_tmp'))}
    save(OUT/'manifest.json',dict(status='completed_with_failures_and_explicit_downstream_blocker',
        task_result=s['TASK_RESULT'],files=files,frozen_identity={k:v for k,v in p.items() if k not in ('protected_files','implementation','parent_seal')},
        implementation={x.relative_to(ROOT).as_posix():sha(x) for x in Path(__file__).parent.glob('*.py')},
        regression=reg,historical_integrity='PASS',dataset_unchanged=True,ground_truth_unchanged=True,
        scoring_rerun=False,formula_changed=False,threshold_changed=False,production_default_changed=False,
        formal_nonempty_V5_end_to_end='BLOCKED',t2_read=False,
        excluded=['manifest self-reference','disposable pytest_tmp/regression_tmp/final_tmp']))
    print('REPORT_DELIVERED',reg['passed'],reg['failed'],flush=True)


if __name__=='__main__':run()

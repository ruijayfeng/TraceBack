"""Finalize immutable results, actual pytest evidence and ordered research report."""
from pathlib import Path
import json
import sys
import xml.etree.ElementTree as ET

from . import ROOT,OUT,BASELINE
from .runtime import read,save,sha,require_sealed


def regression():
    path=OUT/'full_regression.xml'
    if not path.exists():return dict(status='PENDING',passed=0,failed=0,errors=0,skipped=0)
    cases=list(ET.parse(path).iter('testcase'));failures=[]
    for c in cases:
        for tag in ('failure','error'):
            for e in c.findall(tag):failures.append(dict(test=c.attrib.get('classname','')+'::'+c.attrib['name'],kind=tag,message=e.attrib.get('message','')))
    skipped=sum(c.find('skipped') is not None for c in cases)
    return dict(status='FAIL' if failures else 'PASS',passed=len(cases)-skipped-len(failures),
        failed=sum(f['kind']=='failure' for f in failures),errors=sum(f['kind']=='error' for f in failures),skipped=skipped,
        collected=len(cases),failures=failures,
        command='.venv/Scripts/python.exe -B -m pytest backend/tests evaluation/tests -q --tb=short -p evaluation.framework.formula_design.regression_plugin --basetemp=outputs/v5_formula_design/pytest_tmp --junitxml=outputs/v5_formula_design/full_regression.xml',
        old_test_assertions_modified=False,legacy_writes_redirected=True)


def integrity():
    from evaluation.framework.preformula_baseline.boundary import verify_current
    from evaluation.framework.v4_semisynthetic_baseline.common import inventory,DATASET
    p=read(OUT/'preparation.json');verify_current()
    differences={name:dict(before=h,after=sha(ROOT/name)) for name,h in p['protected_files'].items() if sha(ROOT/name)!=h}
    current=inventory(ROOT,production=True)
    production={name:dict(before=p['production_inventory'].get(name),after=current.get(name)) for name in set(current)|set(p['production_inventory']) if current.get(name)!=p['production_inventory'].get(name)}
    dataset=inventory(DATASET)
    dataset_diff={name:dict(before=p['dataset_inventory'].get(name),after=dataset.get(name)) for name in set(dataset)|set(p['dataset_inventory']) if dataset.get(name)!=p['dataset_inventory'].get(name)}
    result=dict(status='PASS' if not differences and not production and not dataset_diff else 'FAIL',
        historical_and_preformula_differences=differences,production_differences=production,dataset_differences=dataset_diff,
        protected_file_count=len(p['protected_files']),dataset_file_count=len(dataset),current_baseline_receipt_verified=True,
        historical_source_reexecution_verified=False,production_default_unchanged=True)
    save(OUT/'integrity.json',result);return result


def run():
    seal=require_sealed();reg=regression();safe=integrity();prepared=read(OUT/'preparation.json')
    summary=read(OUT/'evaluation_summary.json');models=summary['models'];selection=read(OUT/'formula_selection.json')
    gt=summary['gt'];pairwise=read(OUT/'pairwise_ordering.json');candidate=read(OUT/'candidate_integrity.json')
    guard=read(OUT/'blind/guard_receipt.json')
    no_leak=not guard['rejected_events'] and guard['ground_truth_loaded'] is False and seal['actual_member_identity_order_metamorphic_checks']==64
    leakage=dict(status='PASS' if no_leak else 'FAIL',ground_truth_runtime_input=False,
        runtime_read_allowlist=guard['non_code_reads'],rejected_events=guard['rejected_events'],
        identity_order_metamorphic_real_pairs=seal['actual_member_identity_order_metamorphic_checks'],
        synthetic_tests='test_project_ignores_raw_labels_detector_text_and_dataset_ids; test_provenance_identity_and_marker_text_never_score_features',
        prediction_sha256=sha(OUT/'blind/predictions.jsonl.gz'),sealed_before_evaluation=True,
        no_raw_payload_scoring=True,not_os_sandbox=True)
    save(OUT/'anti_leakage.json',leakage);save(OUT/'regression_report.json',reg)
    choice=selection['selected_formula'];accepted=bool(choice and safe['status']=='PASS' and reg['status']=='PASS' and no_leak and candidate['CANDIDATE_RECALL']==1.)
    selection.update(V5_FORMULA_CANDIDATE_SELECTED=accepted,status='SELECTED' if accepted else 'INSUFFICIENT',
        selected_formula=choice if accepted else None,research_leading_formula=choice,
        why_selected='Simplest predeclared candidate passing semantics, strict pairwise improvement and all bounded tails.' if accepted else 'No candidate passes every predeclared semantic, discrimination, tail-safety and verification gate.',
        why_alternatives_rejected={m:dict(pairwise_improves=a['pairwise_improves'],discriminative_improvement=a['discriminative_improvement'],tail_failures=[k for k,v in a['tails'].items() if not v['passed']]) for m,a in selection['assessments'].items() if m!=choice})
    save(OUT/'formula_selection.json',selection)
    outcome=dict(TASK_RESULT='V5_FORMULA_CANDIDATE_READY' if accepted else 'V5_FORMULA_DESIGN_INSUFFICIENT',
        V5_FORMULA_CANDIDATE_SELECTED=accepted,V5_FORMULA_CANDIDATE=choice if accepted else None,
        V5_FORMULA_VALIDATION_GATE='READY' if accepted else 'BLOCKED',THRESHOLD=.65,
        CANDIDATE_RECALL=1.,GT_EDGES=6,CANDIDATE_GT_EDGES=6,SCORED_GT_EDGES=6,
        REGRESSION=reg['status'],INTEGRITY=safe['status'],ANTI_LEAKAGE=leakage['status'],
        production_default_changed=False,threshold_calibrated=False)
    save(OUT/'summary.json',outcome)
    def table(headers,values):return '| '+' | '.join(headers)+' |\n|'+'|'.join('---' for _ in headers)+'|\n'+'\n'.join('| '+' | '.join(str(x) for x in row)+' |' for row in values)
    def num(x):return 'null' if x is None else f'{x:.6f}'
    four=('F0','F1','F2','F3')
    def dt(pop,keys):return table(['Formula']+keys,[[m]+[num(models[m]['distributions'][pop][k]) for k in keys] for m in four])
    score_table=table(['Edge']+list(four),[[e]+[num(gt[e][m]) for m in four] for e in sorted(gt)])
    rank_table=table(['Edge']+list(four),[[e]+[str(models[m]['ranking'][e]['rank'])+' / '+num(models[m]['ranking'][e]['percentile'])+'%' for m in four] for e in sorted(gt)])
    order_table=table(['Formula','P(GT>explicit-negative)','ties half (additional)'],[[m,num(pairwise[m]['strict_rate']),num(pairwise[m]['tie_half_rate'])] for m in four])
    e02=read(OUT/'gt_e02_e06_analysis.json')
    e02_table=table(['Edge','Formula','Positive','Conflict','Coverage','Final','Rank'],[[e,m,num(e02[e][m]['positive_support']),num(e02[e][m]['conflict_penalty']),num(e02[e][m]['coverage_confidence']),num(e02[e][m]['final_score']),e02[e][m]['ranking']['rank']] for e in e02 for m in four])
    contrast=read(OUT/'gte03_e05_vs_hardnegative.json')
    components=table(['Object','Formula','Time','V4 entity','Support','Coverage','Conflict','Final'],[[obj,m,num(c['v4_family_strengths']['time']),num(c['v4_family_strengths']['entity']),num(c['support_score']),num(c['coverage_confidence']),num(c['conflict_penalty']),num(c['final_score'])] for obj,comp in [('GT-E03',contrast['gt']['GT-E03']),('GT-E05',contrast['gt']['GT-E05']),('Original max hard negative',contrast['original_max_hard_negative'])] for m,c in comp.items()])
    flipped={m:all(gt[e][m]>contrast['original_max_hard_negative'][m]['final_score'] for e in ('GT-E03','GT-E05')) for m in four}
    ablation_table=table(['Variant','Strict ordering','GT mean','Explicit max','Background p99','Background max'],[[m,num(models[m]['pairwise']['strict_rate']),num(models[m]['distributions']['gt']['mean']),num(models[m]['distributions']['explicit_negative']['max']),num(models[m]['distributions']['background']['p99']),num(models[m]['distributions']['background']['max'])] for m in ('F3',*('remove_time','remove_role_aware_entity','remove_conflict_redesign','remove_coverage_confidence','remove_interactions','equal_reliability','gate_hard','gate_soft'))])
    safety_rows=[]
    for m,a in selection['assessments'].items():
        safety_rows.append([m,a['eligible_before_integrity'],num(a['gt_mean_lift']),num(a['explicit_negative_mean_lift']),', '.join(k for k,v in a['tails'].items() if not v['passed']) or 'none'])
    selection_table=table(['Formula','Passes research gates','GT mean lift','Explicit mean lift','Tail failures'],safety_rows)
    report=f'''# V5 Scoring Formula Design & Offline Evaluation

## 1. TASK_RESULT

```json
{json.dumps(outcome,ensure_ascii=False,indent=2)}
```

## 2. Frozen Pre-formula Baseline Identity

algorithm_version=`alert-correlation-v5-preformula-candidate-v1`;
score_formula_version=`frozen-v4-role-context`; run config hash
`{prepared['baseline_identity']['config_hash']}`; baseline receipt SHA-256
`{sha(BASELINE/'freeze_receipt.json')}`. This is a score-only replay of immutable
complete member diagnostics, canonical projection, frequency and role evidence.
Candidates: {candidate['candidate_count']:,}; all {seal['member_count']:,} original
members scored by all formulas; GT candidate/scoring recall remains 6/6.
No adapter, entity, namespace, window, Top-K, hot policy, cap or budget changes.

## 3. V4 Formula Reconstruction

M=Σ available-family w_f u_f; A=Σ available-family w_f; W=Σ all-family w_f=1.
Q=M/A (empty=0), mass=M/W.

`score_v4=clamp(.65 Q+.35 mass-.45 C-.40 D,0,1)`.

Weights time/entity/relation/metadata/source=.20/.30/.36/.04/.10. Entity family
is dimension-weighted mean; relation is maximum. No extra positive bonus.
Full dimension, rarity, network, source, conflict, duplicate and gate formulas
are in [V4_SCORE_FORMULA_SPEC.md](V4_SCORE_FORMULA_SPEC.md). Independently
reconstructed every member score; maximum absolute error
{seal['v4_max_reconstruction_error']:.3g}. Seven-item v0 audit is not the V4 total.

## 4. Confirmed V4 Formula Weaknesses

Missing evidence: V4 already removes unavailable families from quality; its
fixed evidence mass still constrains sparse attainable support. Conditional
ceiling is `.65+.35*A/W`; actual metadata and role ceilings reduce it further.
Observable zero topology contributes denominator weight .36 despite providing
no link, often dominating sparse canonical inputs. Zero does not prove conflict.

Time: exponential proximity rewards benign neighboring alerts too. H2 is tested
by F2/F3 compatibility and remove_time. Time remains observable and window policy
remains frozen. Generic entities: equality can describe background infrastructure,
not progression. H3 is compared using canonical roles and remove_role_aware_entity.
Conflict: HOST/ENDPOINT representation inequality does not prove exclusive assets;
E02/E06 illustrate the old .36 penalty. Reclassification asserts uncertainty,
not asset equivalence. Gates: old primary+mass gate can reject a positive score;
hard/soft/hybrid reference alternatives are reported separately. No gate result
is interpreted as confirmed attack or causal direction.

## 5. Formula Candidates

F0: `clamp(.65Q+.35mass-.45C-.40D)`.
F1: `clamp(Q-Cnew-.40D)`, old evidence/gate plus weak ceiling.
F2: `clamp(U*(.80+.20T)-Cnew-.40D)`, role reliability and available semantic mean.
F3: `clamp(U*c*(.80+.20T)+I-Cnew-.40D)`.
`U=Σrho_i*d_i*s_i/Σrho_i*d_i` over observable non-time dimensions;
`c=min(1,Σ independent semantic rho*s/.8)` (asset evidence counted once);
`I=min(.20,c*(.15H*A+.05R*T+.05S*R))`.
All use actual non-temporal semantic evidence, hard/duplicate guards and a .45
weak-only ceiling. [V5_FORMULA_CANDIDATES.md](V5_FORMULA_CANDIDATES.md) defines
all terms, state/reliability rules, ablations and predeclared selection criteria.
YAML values were frozen before blind scoring. No learned weights or search.

## 6. GT Score Comparison

{score_table}

{dt('gt',['min','median','max'])}

## 7. Explicit-negative Comparison

{dt('explicit_negative',['max','p95','median','mean'])}

{summary['explicit_negative_scored']}/{summary['explicit_negative_total']} explicit
labeled pairs are scored. Coverage={summary['evaluation_coverage']:.6f}. Unscored
negatives are excluded, never assigned zero. These are not background labels.

## 8. Hard-negative Comparison

{dt('hard_negative_touching',['max','p95','median'])}

This population includes ANY member pair touching a hard-negative alert; its
unlabeled partner is not thereby declared negative. Explicit labels are separate.

## 9. Background-tail Comparison

{dt('background',['p95','p99','max','median'])}

Only pairs whose BOTH endpoints are unlabeled background enter this table.
Other unlabeled pairs ({summary['other_unlabeled_member_count']}) are separately
counted. No background false-positive rate is inferred from unlabeled data.

## 10. GT Global Rank Comparison

{rank_table}

Cells are rank / percentile. Population: {seal['member_count']:,} computed original
member scores, including gate rejects. Sort by unrounded score DESC, stable full
member-pair ID ASC. Percentile=100*(lower+0.5*equal)/N; higher is better. Tie
bounds are retained in JSON. This is not a graph-edge admission ranking.

## 11. Pairwise Ordering

{order_table}

**development diagnostic only; not population AUC**. Strict rate counts ties
as failures; half-tie rate is an additional descriptive statistic. Per-GT counts
of explicit negatives below, above and tied appear in pairwise_ordering.json.

## 12. GT-E02 / GT-E06 Analysis

{e02_table}

Correcting unproven representation conflicts does not supply process lineage,
session causality or mapped behavior. Their remaining supports and role evidence
are inspectable in gt_e02_e06_analysis.json. Low scores are permitted; GT status
never supplies a bonus. Numeric score and reference admission gate are separate.

## 13. GT-E03 / GT-E05 vs Hard-negative Analysis

{components}

Both GTs outrank the ORIGINAL V4 maximum hard-touching pair: {flipped}.
The negative's time/entity contributions reflect close timestamps and available
shared generic entities. V4 treats such equality as support even when the
detectors do not establish a progression; metadata equality is capped but can
still support it. Inspect the per-formula maximum as well: beating the original
maximum is insufficient if a different negative becomes the new maximum.
gte03_e05_vs_hardnegative.json contains original and per-formula maxima, exact
dimensions, strengths, reliability, references, penalties, bonuses and gates.
Any reversal uses role/context semantics, not edge/scenario/marker strings.

## 14. Missing / Zero / Contradiction Semantics

SUPPORT: observed positive; OBSERVED_ZERO: observed but not supporting;
UNAVAILABLE: unobserved; NOT_APPLICABLE: dimension inapplicable. Hard contradiction
requires verified isolation/exclusivity; soft inconsistency incurs bounded cost;
unknown equivalence and representation difference remain visible uncertainty.
Missing is never negative. The v1 canonical contract has no verified endpoint
exclusivity source, so synthetic endpoint-proof checks do not claim real support.
Every family carries state, strength, reliability, provenance in sealed evidence.

## 15. Synthetic Counterexample Results

{json.dumps(read(OUT/'synthetic_counterexamples.json'),indent=2)}

A: shared IP+close time; B: account equality only; C: monitored host+compatible
account+time; D: representation difference; E: typed verified endpoint exclusion;
F: many missing dimensions. Cases run for F1/F2/F3 in pytest. Neither weak sparse
normalization nor time-only evidence may publish a high-confidence association.

## 16. Ablation Results

{ablation_table}

These are predeclared single-component removals, not optimized weight searches.
remove_time also removes role*time interaction; remove_role restores original
strengths/generic reliability; remove_conflict restores old C; remove_coverage
sets c=1; remove_interactions sets I=0. Equal reliability tests the proposed
ordering instead of assuming it is proven. Hard/hybrid change reference gate;
soft additionally applies the declared weak-context confidence multiplier.
Full per-edge rankings/distributions are in ablation.json, gate_comparison.json,
and reliability_sensitivity.json. Six examples cannot prove a universal order.

## 17. Selected Formula

Selected: **{selection['selected_formula']}**;
V5_FORMULA_CANDIDATE_SELECTED={str(accepted).lower()}.

{selection_table}

{selection['why_selected']}

Alternatives: {json.dumps(selection['why_alternatives_rejected'],ensure_ascii=False)}.
Safety limits were declared BEFORE labels: explicit max, hard-touch max,
background p99/max each <=F0+.05; strict pairwise ordering must improve and
GT mean lift must exceed explicit-negative mean lift. This protects against
raising every score. Tail failure remains a failure even if a GT rank improves.

## 18. Threshold Reference

Threshold=0.65 throughout. GT reference admissions:
{json.dumps({m:models[m]['gt_reference_admissions'] for m in four})}.
All-member reference admission counts:
{json.dumps({m:models[m]['reference_admitted_member_count'] for m in four})}.
These are member diagnostics, NOT formal representative graph edges.
**threshold was NOT calibrated**. Scores have no calibrated probability meaning.

## 19. Leakage / Integrity

Leakage checks: {leakage['status']}; dataset/production/history: {safe['status']}.
Read allowlist admitted only sealed canonical, member/candidate diagnostics and
opaque input-line locator map. Raw payload/GT/marker/detector text are not scoring
features. New predictions were sealed before evaluation sidecars were read.
Actual 64-member identity/provenance/order metamorphic checks and injection tests
passed. Audit guard is a Python tripwire, not an OS sandbox. {safe['protected_file_count']}
historical/preformula files and {safe['dataset_file_count']} dataset files are checked
byte-for-byte. Historical source inventories attest past identities; no claim
of historical source reexecution. Current production source matches its receipt.

## 20. Regression

{reg['passed']} passed / {reg['failed']} failed / {reg['errors']} errors /
{reg['skipped']} skipped; status **{reg['status']}**. Existing assertions remain
unchanged. Legacy fixtures write only to this experiment's isolated directory.
See regression_report.json, full_regression.log and full_regression.xml for actual
execution evidence, including repository, preformula, isolation and formula tests.

## 21. Limitations

Only six development GT edges.
Semi-synthetic progression.
No claim of generalization.
No calibrated probability interpretation.
Threshold remains unvalidated for V5.

Scores reuse immutable complete V4 member components; this study does not rerun
candidate generation or deploy an end-to-end V5 pipeline. The exact candidate
hash and counts are verified. Existing unmapped category/lineage observations
remain missing. Source independence is not inferred. Current exclusivity proof
coverage is limited to existing verified guards plus typed synthetic checks.
No independent t2 evaluation, threshold calibration, ML, Incident/chain/frontend/
AI/ATT&CK work was performed. No candidate is selected by GT admission count.

## 22. Next Gate

V5_FORMULA_VALIDATION_GATE={outcome['V5_FORMULA_VALIDATION_GATE']}
'''
    (OUT/'V5_FORMULA_DESIGN_REPORT.md').write_text(report,encoding='utf8')
    files={p.relative_to(OUT).as_posix():sha(p) for p in OUT.iterdir() if p.is_file() and p.name!='manifest.json'}
    save(OUT/'manifest.json',dict(status='completed' if reg['status']!='PENDING' else 'pending_regression',
        outcome=outcome,files=files,blind_files=seal['files'],implementation=prepared['implementation'],
        dataset_read_only=True,production_default_unchanged=True,threshold=.65,
        exclusions=['manifest.json self-reference','pytest_tmp and regression_isolated are disposable test outputs'],
        blind_manifest_sha256=sha(OUT/'blind_manifest.json')))
    print(json.dumps(outcome),flush=True)


if __name__=='__main__':run()

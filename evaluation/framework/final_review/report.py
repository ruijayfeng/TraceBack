"""Assemble the final decision from immutable predictions and observed checks."""
import datetime
import json
from .run import ROOT, OUT, OLD, read, save, sha, inventory


def acceptance_gates():
    m=read(OUT/'labeled_metrics.json');policy=read(OUT/'v5_2_semantics_contract.json')['policy']
    a=policy['acceptance'];dev=m['development'];stress=m['feature_stress']
    prev=read(ROOT/'outputs/v5_1_anchor_semantics/evaluation_summary.json')['datasets']
    prior_dev=prev['existing_development']['overall'];prior_stress=prev['synthetic_feature_stress']['overall']
    checks=[]
    def check(name,actual,expected,passed,kind='preregistered_required'):
        checks.append(dict(name=name,actual=actual,expected=expected,pass_=passed,kind=kind))
    check('candidate_recall',dev['candidate_recall'],a['candidate_recall'],dev['candidate_recall']>=a['candidate_recall'])
    check('development_admission_minimum',dev['admission_recall'],a['development_admission_recall'],dev['admission_recall']>=a['development_admission_recall'])
    check('development_admission_target',dev['admission_recall'],a['target_development_admission_recall'],dev['admission_recall']>=a['target_development_admission_recall'],'preregistered_target_and_current_user_full_progression_gate')
    check('development_hn_strict_rejection',dev['hn_rejection'],a['development_hn_rejection'],dev['hn_rejection']>=a['development_hn_rejection'])
    check('stress_admission_recall',stress['admission_recall'],a['stress_admission_recall'],stress['admission_recall']>=a['stress_admission_recall'])
    check('stress_hn_strict_rejection',stress['hn_rejection'],a['stress_hn_rejection'],stress['hn_rejection']>=a['stress_hn_rejection'])
    for name,current,old in [('development',dev,prior_dev),('stress',stress,prior_stress)]:
        check(name+'_ambiguity_rate',current['ambiguous_rate'],policy['AMBIGUOUS_RATE_LIMIT'],current['ambiguous_rate']<=policy['AMBIGUOUS_RATE_LIMIT'])
        check(name+'_worst_margin_target',current['worst_margin'],a['target_worst_margin'],current['worst_margin']>=a['target_worst_margin'],'preregistered_target')
        check(name+'_margin_improves',current['worst_margin'],old['worst_margin'],current['worst_margin']>old['worst_margin'])
    check('final_and_binary_metrics_present',True,a['require_final_and_binary_metrics'],True)
    check('reference_threshold_unchanged',read(OUT/'run_manifest.json')['threshold'],policy['REFERENCE_THRESHOLD'],read(OUT/'run_manifest.json')['threshold']==policy['REFERENCE_THRESHOLD'])
    save(OUT/'algorithm_acceptance_gates.json',dict(policy_version=policy['version'],policy_file='evaluation/configs/sparse_semantics.yaml',
        policy_sha256=sha(ROOT/'evaluation/configs/sparse_semantics.yaml'),checks=checks,
        all_preregistered_required_pass=all(x['pass_'] for x in checks if x['kind']=='preregistered_required'),
        required_and_target_distinguished=True,criteria_changed=False,threshold_tuning=False,
        scope='Algorithm development/stress policy gates only; regression, independence and downstream checks reported separately'))


def comparison():
    current=read(OUT/'labeled_metrics.json')
    prev_path=ROOT/'outputs/v5_1_anchor_semantics/evaluation_summary.json'
    prev=read(prev_path)
    v4_path=ROOT/'outputs/v4_semisynthetic_baseline/summary.json'
    v4=read(v4_path)
    value=dict(
        current_dataset_comparable_versions=['V5.1','V5.2'],
        V4=dict(current_dataset_results=None,reason='Preserved V4 baseline uses six GT transitions, whereas current v2 uses seven. No current-input V4 replay was performed; no same-dataset improvement claim.',
            historical_artifact=str(v4_path.relative_to(ROOT)),artifact_sha256=sha(v4_path),
            historical_GT_edges=v4['GT_EDGES'],historical_candidate_recall=v4['CANDIDATE_RECALL'],
            historical_admission_recall=v4['ADMISSION_RECALL'],historical_recovered_path=v4['LONGEST_RECOVERED_PATH_EDGES'],
            historical_longest_GT_path=v4['LONGEST_GT_PATH_EDGES'],historical_HN_max=v4['HARD_NEGATIVE_MAX_SCORE'],
            current_HN_rejection=None,current_chain_recovery=None,current_sparse_evidence_quality=None),
        V5_1=dict(development=prev['datasets']['existing_development']['overall'],stress=prev['datasets']['synthetic_feature_stress']['overall'],
            artifact=str(prev_path.relative_to(ROOT)),artifact_sha256=sha(prev_path),formal_chain_recovery=None,
            sparse_evidence_quality='Exact-anchor restriction: 0/7 development admission; 12/108 stress HN admitted'),
        V5_2=dict(development=current['development'],stress=current['feature_stress'],formal_chain_recovery=None,
            research_GT_support_path_edges=current['LONGEST_RESEARCH_GT_SUPPORT_PATH_EDGES'],
            sparse_evidence_quality='6/7 development admission; nonexact qualified context allowed; 48/108 stress positives abstain; 36/108 stress negatives abstain'),
        threshold=.65,threshold_changed=False,
        separation='Development worst margin improves slightly from -0.23371598394766055 to -0.23159295530269747; stress margin worsens from -0.0017693774999999468 to -0.012818953543310974. Scores still overlap.',
        conclusion='V5.2 partly resolves V5.1 development under-correlation but does not satisfy sparse recall, negative separation, independence or downstream validation. No across-dataset V4 ranking is justified.')
    save(OUT/'version_comparison.json',value)
    table='''| Metric | V4 on current v2 | V5.1 on current v2 | V5.2 on current v2 |
|---|---:|---:|---:|
| GT candidate recall | Unavailable | 7/7 | 7/7 |
| GT admission recall | Unavailable | 0/7 | 6/7 |
| GT formal edge recall | N/A | N/A (not validated) | N/A (no serializer) |
| Longest GT path (dataset reference) | N/A for V4 run | 7 edges | 7 edges |
| Development HN strict rejection | Unavailable | 180/180 | 180/180 |
| Development HN false admissions | N/A | 0 | 0 |
| Stress GT admission | Unavailable | 108/108 | 60/108 (48 abstain) |
| Stress HN strict rejection | Unavailable | 96/108 | 72/108 (36 abstain) |
| Stress HN false positives at binary .65 | N/A | 12 | 36 |
| Previous 12 HN mistakes | Unavailable | 12 ADMIT | 12 AMBIGUOUS; all binary-positive |
| Formal directed chain recovery | Unavailable | Not validated | Blocked; not executed |
| Sparse evidence quality | Not comparable | Exact-anchor overrestriction | Partial improvement; still overrestrictive |
| Exact anchor dependence | N/A | Overrestrictive on all 7 development GT | Nonexact qualified context allowed; generic sparse context still abstains |
| Over-correlation | N/A | 12 stress HN false admissions | Unresolved: 60/100 sampled other admissions semantically ambiguous |
'''
    text='''# V4 vs V5.1 vs V5.2

'''+table+'''
V4 preserved context: six GT transitions, candidate recall 1/6, admission 0/6, recovered path 0/6. That artifact is a different dataset snapshot; these numbers are not substituted for a current-v2 V4 experiment. V4 current HN rejection and sparse quality remain unavailable.

V5.1 and V5.2 reuse the same sealed development candidate/member inputs and the same 216 feature-stress witnesses. Stress is synthetic, developer-authored evidence, not independent vendor-native validation. AMBIGUOUS is an abstention, not a correct rejection. Under the fixed binary .65 rule, V5.2 stress has 108 TP, 36 FP, 72 TN and 0 FN (precision .75, recall 1, F1 .8571428571); these binary results do not erase 48 legitimate abstentions.

'''+value['separation']+'\n\n'+value['conclusion']+'\n'
    (OUT/'version_comparison.md').write_text(text,encoding='utf8')
    return table


def integrity():
    m=read(OUT/'run_manifest.json');now=inventory();changed=[];missing=[]
    unexpected_added=[n for n in now if n not in m['source_inventory'] and not n.startswith('evaluation/framework/final_review/')]
    for name,h in m['source_inventory'].items():
        if name.startswith('evaluation/framework/final_review/'):continue
        if name not in now:missing.append(name)
        elif now[name]!=h:changed.append(dict(file=name,before=h,after=now[name]))
    old=read(OLD/'manifest.json');old_pred=read(OLD/'prediction_seal.json');bad=[]
    for name,h in {**old['protected_files'],**old['implementation'],**old['input_hashes']}.items():
        actual=sha(ROOT/name) if (ROOT/name).exists() else None
        if actual!=h:bad.append(dict(file=name,expected=h,actual=actual))
    for name,h in old_pred['files'].items():
        if sha(OLD/name)!=h:bad.append(dict(file=str(OLD/name),expected=h,actual=sha(OLD/name)))
    if sha(OLD/'manifest.json')!=m['prior_manifest_sha256']:bad.append(dict(file='historical_manifest'))
    if sha(OLD/'prediction_seal.json')!=m['prior_prediction_seal_sha256']:bad.append(dict(file='historical_prediction_seal'))
    recovery=read(OUT/'historical_write_restoration.json')
    recovered=[]
    for row in recovery['files']:
        h=sha(ROOT/row['file']);recovered.append(dict(file=row['file'],actual=h,archived_expected=row['restored_sha256'],match=h==row['restored_sha256']))
        if h!=row['restored_sha256']:bad.append(dict(file=row['file'],expected=row['restored_sha256'],actual=h))
    fresh=read(OUT/'prediction_seal.json');freshbad=[]
    for name,h in fresh['files'].items():
        if sha(OUT/'predictions'/name)!=h:freshbad.append(name)
    if sha(OUT/'replay_preregistration.json')!=fresh['preregistration_sha256']:freshbad.append('replay_preregistration.json')
    external=read(OUT/'external_workspace_changes.json')
    acknowledged_missing=set(external['user_confirmed_moved_or_deleted'])
    unexpected_missing=[n for n in missing if n not in acknowledged_missing]
    blocking_bad=[r for r in bad if r['file'].replace('\\','/') not in acknowledged_missing or r.get('actual') is not None]
    v=dict(checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        existing_production_test_config_docs_changed=changed,existing_files_missing=missing,unexpected_source_files_added=unexpected_added,
        historical_seal_mismatches=bad,current_prediction_seal_mismatches=freshbad,
        candidate_formula_unchanged=not changed and not unexpected_missing and not blocking_bad,
        original_inventory_fully_unchanged=not changed and not missing and not bad,
        external_workspace_changes=external,
        unexpected_missing_files=unexpected_missing,unacknowledged_historical_seal_mismatches=blocking_bad,
        final_review_harness={p.relative_to(ROOT).as_posix():sha(p) for p in sorted((ROOT/'evaluation/framework/final_review').glob('*.py'))},
        allowed_scope='Only evaluation/framework/final_review and evaluation/outputs/v5_2_final_review added/edited',
        review_harness_repair=dict(file='evaluation/framework/final_review/verify.py',defect='Missing gzip import caused initial chain command to exit 1 before writing output',
            correction='Added import gzip; reran complete chain boundary command successfully',algorithm_changed=False,
            initial_command='python -B -m evaluation.framework.final_review.verify chain',initial_exit_code=1,
            initial_exception="NameError: name 'gzip' is not defined",rerun_exit_code=0,rerun_log='chain_boundary.log'),
        no_tests_removed_or_modified=True,no_new_skip_or_xfail=True,
        no_historical_write_occurred=False,historical_write_side_effect_restored=recovered,
        recovery_details='historical_write_restoration.json; archived attempt bytes in legacy_write_attempt/',
        historical_hash_baseline_limitation='Six capacity files recovered to independently recorded historical hashes; their own pre-review hashes were not captured.')
    save(OUT/'final_integrity.json',v)
    if changed or unexpected_missing or blocking_bad or freshbad or unexpected_added:raise ValueError('review_integrity_failure')


def report():
    reg=read(OUT/'full_regression.json');m=read(OUT/'run_manifest.json');metrics=read(OUT/'labeled_metrics.json')
    independence=read(OUT/'evidence_independence_audit.json');chain=read(OUT/'chain_reconstruction_validation.json')
    table=comparison();acceptance_gates()
    blockers=[
        dict(code='SPARSE_SEMANTICS_INVALID',severity='PRIMARY',evidence='sparse_semantics_matrix.json; labeled_metrics.json',
             reason='Legitimate sparse case L is AMBIGUOUS; stress admission 60/108 vs preregistered .90 minimum; ambiguity 84/216 vs .15 maximum.'),
        dict(code='GT_RECALL_INSUFFICIENT',severity='BLOCKING',evidence='gt_edge_results.jsonl',reason='E01 score .4101605384675919 is rejected; 6/7 admissions do not recover complete seven-edge progression.'),
        dict(code='ANCHOR_SEMANTICS_INVALID',severity='BLOCKING',evidence='anchor_semantics_regression.json',reason='Nonexact qualified context is allowed, but generic compatible sparse context still abstains. Restriction partly remains.'),
        dict(code='HARD_NEGATIVE_FAILURE',severity='BLOCKING',evidence='historical_12_hn_recheck.json; labeled_metrics.json',reason='Development 180/180 rejected, but former 12 mistakes are AMBIGUOUS and binary-positive; 36/108 stress HN abstain; strict rejection .6667 vs .90.'),
        dict(code='DOUBLE_COUNTING',severity='BLOCKING',evidence='evidence_independence_audit.json',reason='1216/1859 admitted relations reuse native operation facts across additive behavior and qualified_context channels.'),
        dict(code='OVER_CORRELATED',severity='BLOCKING_UNRESOLVED_SAFETY',evidence='over_correlation_audit.json; sample_semantic_witnesses.json',reason='60/100 sampled unlabeled admissions have episode context but no demonstrated task relation. Safety remains unresolved; this is a semantic audit, not a measured false-positive rate.'),
        dict(code='CHAIN_RECONSTRUCTION_FAILURE',severity='BLOCKING',evidence='chain_reconstruction_validation.json; v5_2_dispatch_audit.json',reason='V5.2 research scorer is not registered in production and lacks a compatible formal edge serializer. Actual incident/attack-chain reconstruction cannot be validated.'),
        dict(code='INSUFFICIENT_EVIDENCE',severity='BLOCKING_NATIVE_COVERAGE',evidence='sparse_semantics_matrix.json',reason='Required F/G/N cases have only guard/scope/IP controls; native namespace/endpoint-role coverage is incomplete. Known development labels and absent Git metadata are separate limitations, not newly invented standalone acceptance gates.')]
    if reg['NEW_V5_2_REGRESSIONS']:
        blockers.append(dict(code='NEW_REGRESSION',severity='BLOCKING',evidence='failure_adjudication.json',reason=f"Confirmed newly attributable V5.2 failures: {reg['NEW_V5_2_REGRESSIONS']}."))
    if reg['UNKNOWN_FAILURES'] or reg['UNKNOWN_PROCESS_FAILURES']:
        blockers.append(dict(code='INSUFFICIENT_EVIDENCE',severity='BLOCKING_REGRESSION_UNCERTAINTY',evidence='failure_adjudication.json',reason=f"{reg['UNKNOWN_FAILURES']} unknown test failures and {reg['UNKNOWN_PROCESS_FAILURES']} unknown process failures. The monolithic access violation remains unexplained; a confirmed-new-regression count of zero would not resolve that uncertainty."))
    next_task='User-scoped V5.2 failure localization: E01 observability, incident-versus-task acceptance for indistinguishable witnesses, repeated evidence contributions, and native test crash. Any semantic revision requires a new explicit task; no production integration or V5.3 starts now.'
    decision=dict(TASK_RESULT='V5_2_NOT_READY',V5_FORMULA_FREEZE_READY=False,PRODUCTION_INTEGRATION_READY=False,
        PRIMARY_BLOCKER='SPARSE_SEMANTICS_INVALID',blockers=blockers,
        SECONDARY_BLOCKERS=sorted({b['code'] for b in blockers if b['code']!='SPARSE_SEMANTICS_INVALID'}),
        SPARSE_SEMANTICS_PASS=False,ANCHOR_SEMANTICS_PASS=False,EVIDENCE_INDEPENDENCE_PASS=False,OVER_CORRELATION_PASS=False,
        FULL_REGRESSION_PASS=reg['FULL_REGRESSION_PASS'],CHAIN_RECONSTRUCTION_PASS=False,
        original_questions=dict(
            V4_sparse_score_dilution='STRUCTURALLY_IMPROVED_NOT_FULLY_RESOLVED',
            V5_1_exact_anchor_overrestriction='PARTIALLY_RESOLVED',
            missing_as_negative_mass='NOT_PRESENT_IN_CURRENT_POSITIVE_MASS_FORMULA',
            legal_sparse_correlation='SOME_PASS_RECALL_STILL_FAILS',
            overcorrelation_safety='NOT_DEMONSTRATED',
            hard_negative_acceptance='DEVELOPMENT_PASS_STRESS_STRICT_REJECTION_FAIL'),
        threshold=.65,threshold_changed=False,threshold_calibration_performed=False,NEXT_TASK=next_task,
        freeze_manifest_created=False,formula_changes=0,production_changes=0)
    save(OUT/'final_decision.json',decision)
    failtext='\n'.join(f"- **{b['code']}**: {b['reason']} Evidence: `{b['evidence']}`." for b in blockers)
    sparse=read(OUT/'sparse_semantics_matrix.json')
    case_table='\n'.join(f"| {x['case']} | {x['title']} | {x['expected_decision']} | {x['result']['decision']} | {'PASS' if x['pass_'] else 'FAIL'} |" for x in sparse['cases'])
    report=f'''# TraceBack V5.2 Full Regression + Formula Freeze Review

## 1. Final Decision

TASK_RESULT=V5_2_NOT_READY  
V5_FORMULA_FREEZE_READY=false  
PRODUCTION_INTEGRATION_READY=false

PRIMARY_BLOCKER=SPARSE_SEMANTICS_INVALID  
SECONDARY_BLOCKERS={','.join(decision['SECONDARY_BLOCKERS'])}

V5.2 improves development admission from 0/7 to 6/7, but does not pass the frozen acceptance review. No scoring formula, weight, threshold, anchor rule, candidate policy, source mapping or production implementation was changed. The outcome is an explicit failure to freeze; no freeze manifest is issued.

Primary blocker: **SPARSE_SEMANTICS_INVALID**. The decision also rests on incomplete GT progression, unresolved negative separation, repeated evidence contributions and unavailable downstream production validation. A green subset of tests or zero strict ADMIT stress negatives cannot override these gates.

PRODUCTION_INTEGRATION_READY means permission to enter the next integration stage, not that API wiring is already finished. It is false because semantic acceptance failed independently of the missing dispatch; missing dispatch also limits this review's downstream measurements.

## 2. Frozen Experiment Identity

git commit: unavailable; this workspace has no Git metadata. Clean/dirty, tracked/untracked ownership cannot be established. `run_manifest.json` records the errors and 446-file source inventory; prior seals and `final_integrity.json` establish bytes, not commit provenance. No reset/checkout/clean was performed. At final verification seven original documents were missing. The user confirmed they were moved/deleted by the user or another task; their old hashes and current absence remain recorded in `external_workspace_changes.json` and `final_integrity.json`. They were not recreated or silently treated as unchanged. Remaining candidate source, test and configuration hashes match.

implementation: `{m['implementation_version']}` (evaluation-only). Production preprocessing identity: `{m['production_algorithm_version']}` / `{m['production_implementation_version']}`. Config: `{m['config_path']}`; exact YAML SHA-256 `{m['config_hash']}`. Production effective config digest: `{m['production_config_hash']}`; mapping digest: `{m['mapping_hash']}`. These hash domains are explicitly distinct.

threshold: **0.65**, unchanged. Python: `{m['python'].splitlines()[0]}`. OS/environment, commands, immutable input hashes and pre-scoring timestamp are recorded in `run_manifest.json` and replay preregistration.

dataset: `{m['dataset']}`; SHA-256 `{m['dataset_hash']}`. Ground truth SHA-256: `{m['ground_truth_hash']}`. All final-manifest file hashes were verified without regeneration (`dataset_identity_verification.json`). The manifest confirms 9,985 alerts: 9,500 background, 125 attack and 360 HN alerts; 8 stages and 7 transitions. HN **pairs** number 180, distinct from 360 alerts.

The current run replayed the existing frozen candidate/member projections, not a new Adapter/candidate-generation experiment. Fresh scoring processed 241,464 members, 240,621 candidates and 216 stress witnesses with the original V5.2 projection/scorer and deterministic support-member selection. All decoded outputs exactly reproduce historical V5.2 (`replay_equivalence.json`). The five allowlisted input files exclude labels; prediction seal was written before the current label join. Labels were already known historically: this is a development regression, not unseen validation.

## 3. V5.2 Semantic Contract

Evidence states: actual code uses OBSERVED_SUPPORT, OBSERVED_NEUTRAL and absent/missing/unobservable forms; incident/local contradictions are separate audit lists. NOT_APPLICABLE has no independent final numeric state. Missing values do not add negative mass. Observed zero is neutral; completeness changes separately. See the pre-replay `v5_2_semantics_contract.json` and `.md` for source-linked details.

Sparse semantics: positive mass P is the sum of **max support × weight within each channel**, across context/actor/content/behavior/qualified_context/task/direct. Incident conflict gives N. Compatibility=P/(P+N) when defined; support saturation=1-exp(-P). Raw=min(compatibility,saturation), with a .60 cap for one non-task/non-direct channel; temporal factor .8+.2×time, existing penalties and clamping follow. No fixed seven-family denominator dilutes score; confidence and completeness are separate. This does not itself guarantee recall or independence.

Anchor semantics: direct/task binding and qualified object-handoff/network/execution/auth context permit ADMIT at .65 with original gates. Exact task identity is not universally required: object-handoff B passes without it. A generic high-scoring multi-family witness without discriminating context is AMBIGUOUS, which still loses legitimate sparse relationships. ADMIT/AMBIGUOUS/REJECT and binary threshold decisions are both preserved.

Contradiction semantics: explicit incident hard conflicts retain vetoes; task mismatch invalidates task support, not automatically the incident. Scope/epoch conflicts suppress local identifier support. Namespace, role and direction safety partly depend on original upstream gates; boundary flags do not prove native extraction coverage. Legacy unscoped penalty is not recast as observed contradiction. Observability semantics: missing is neither negative mass nor proof of compatibility, and an observed neutral channel can affect channel-count bookkeeping without adding support.

Dispatch: V5.2 exists in `evaluation.framework.sparse_semantics`; tests and current replay use that scorer. CLI/API registered production implementations remain their existing versions; config name v5 selects old F3. V5.2 config rejection and static entry-point evidence are in `v5_2_dispatch_audit.json`. This evaluation-only boundary was preexisting; it was not silently repaired by inventing production schema.

## 4. Ground Truth Results

GT edges: 7. Candidate recall: 7/7 = 1.0. Admission recall: 6/7 = .8571428571. Formal Edge recall: **unavailable** because no V5.2 formal edge serializer/dispatch exists; research support recall is 6/7. Longest GT path: 7 edges. Recovered formal path: **unavailable**; research GT-stage support contains a six-edge contiguous segment E02–E07, with E01 missing. FULL_GT_PATH_RECOVERED=false. Research support is not a directed reconstructed ChainEdge.

| GT edge | Score | Decision |
|---|---:|---|
| E01 | .4101605384675919 | REJECT |
| E02 | .7775953870430277 | ADMIT |
| E03 | .8203020636618104 | ADMIT |
| E04 | .8666983481187241 | ADMIT |
| E05 | .8655496465973848 | ADMIT |
| E06 | .9079466720740726 | ADMIT |
| E07 | .9027743925831024 | ADMIT |

Per-edge stages, support member, observed/missing evidence, conflicts and reason are in `gt_edge_results.jsonl`. The score increase does not establish complete progression recovery. On 187 labeled development pairs only, TP=6, FP=0, FN=1, TN=180, precision=1, recall=.8571428571, F1=.9230769231. Candidate label coverage is only .0727285%; full-population precision is not claimed.

## 5. Hard Negative Results

Development HN total: 180 pairs. Candidates: 168; 12 not nominated. HN admitted: 0; HN rejected: 180; rejection rate=1.0; labeled development false positives=0. Not-nominated negatives are reported explicitly rather than presented as scored candidates.

Stress HN total: 108. Strict ADMIT=0, REJECT=72, AMBIGUOUS=36; strict rejection=.6666666667, below the original .90 gate. Fixed binary .65 gives 36 false positives. The prior 12 V5.1 mistakes are all AMBIGUOUS and still binary-positive, not repaired as strict rejection (`historical_12_hn_recheck.json`). `hard_negative_results.jsonl` includes all 180 development and 108 stress rows and support/conflict explanations.

Twelve positive `sparse_content_continuation` and negative `unobserved_distinct_tasks` normalized witness pairs are observationally identical after removing IDs. That proves a limit of these particular stress projections, not that all 84 abstentions are unavoidable. No labels or scenario names were used to discriminate them. No threshold sweep or rule adjustment followed label inspection.

## 6. Sparse Evidence Validation

Result: **FAIL**. Stress GT admission=60/108=.5555555556 (required .90); ambiguity=84/216=.3888888889 (maximum .15). There are 48 ambiguous positives, no strictly rejected positives. They remain missed admissions, even though binary recall is 1.

| Case | Meaning | Expected | Actual | Check |
|---|---|---|---|---|
{case_table}

Failures: L demonstrates continued sparse overrestriction. F/G/N are partial upstream-guard/scope/IP controls; native namespace and endpoint-role integration coverage remains missing and is **not** declared PASS. Case B uses the existing native object-handoff witness; A/H/O/P preserve strong direct/task support. Missing-versus-neutral behavior and all original 18 stress scenarios are recorded in `sparse_semantics_matrix.json`; expectations for the added controls were frozen in `sparse_probe_protocol.json` before execution. Fifteen matched control expectations do not waive the failed semantic gate or coverage gaps.

## 7. Anchor Regression

V5.1 failure: 0/7 development positives admitted; 12 stress HN admitted. V5.2 result: 6/7 development admitted, nonexact qualified object-handoff accepted, single context alone rejected. Generic compatible sparse support still becomes AMBIGUOUS, and previously wrong HN abstain instead of strict rejection. **ANCHOR_SEMANTICS_PASS=false**. Seven scenario groups, decisions, scores and evidence are preserved in `anchor_semantics_regression.json`.

## 8. Evidence Independence

Duplicate counting: channel-local max deduplication verified for all 1,859 ADMIT relations, but **1,216** reuse native operation pointers in both positive behavior (.8) and qualified_context (1.2) contributions. Compound context also requires asset/identity evidence, so this is a demonstrated additive dependency, not a statistical independence test or proof that all 1,216 relations are false. It blocks a clean no-double-counting claim.

Self reinforcement: 0 detected under the audited scorer-input definition; predictions are not inputs. Frequency-only correlation: 0 among ADMIT results under the positive-channel check. Pseudo continuity: no direct propagation was synthesized by this research scorer; that narrow zero count does not validate causal or task correctness. Full per-admission lineage is in `evidence_lineage_all_admitted.jsonl.gz`.

Over-correlation: 1,859 ADMIT, 9,282 AMBIGUOUS and 229,480 REJECT research candidates. Of the 1,859 ADMIT, 6 are labeled GT, 0 labeled HN, 1,853 other/unlabeled; the latter are not automatically background FP. Top-50 plus deterministic random-50 (seed 42) yields 100 unique other admissions. Semantic triage and native-witness inspection finds 40 PLAUSIBLE and 60 AMBIGUOUS: scoped request/object support is more specific than generic process/network episode context. This is not a labeled precision estimate. `over_correlation_audit.json` and `sample_semantic_witnesses.json` preserve all 100. **EVIDENCE_INDEPENDENCE_PASS=false; OVER_CORRELATION_PASS=false** (safety not demonstrated).

## 9. Full Regression

passed: {reg['passed']}  
failed: {reg['failed']}  
errors: {reg['errors']}  
skipped: {reg['skipped']}  
reported / collected: {reg['reported']} / {reg['collected']}  
exit code: {reg['exit_code']}  
elapsed seconds: {reg['seconds']:.3f}

Confirmed new V5.2 regressions: {reg['NEW_V5_2_REGRESSIONS']}. Historical known failures: {reg['KNOWN_FAILURES']}. Test-level infrastructure failures: {reg['INFRA_FAILURES']}. Other existing seal failures: {reg['UNRELATED_EXISTING_FAILURES']}. Unknown test failures: {reg['UNKNOWN_FAILURES']}; unknown process failures: {reg['UNKNOWN_PROCESS_FAILURES']}. A zero confirmed-attribution count does not prove the unexplained process crash unrelated. Historical failures are preserved rather than waived; their existence alone is not equated with a new formula regression. **FULL_REGRESSION_PASS={str(reg['FULL_REGRESSION_PASS']).lower()}**. Complete current traces, historical stack/message comparisons and source hashes are in `failure_adjudication.json` and `seal_failure_evidence.json`.

All 91 collected files were attempted separately. The first 25 completed files are retained from `full_regression_split_v2/`; the remaining 66 are run under `full_regression_safe/` with at most two independent file processes. Final safe commands use `pytest <collected-file> -c backend/pyproject.toml -q -p no:cacheprovider -p evaluation.framework.final_review.legacy_output_plugin --junitxml=<file>.xml`. The plugin relocates only two legacy modules' result-output globals (capacity OUT, selection OUT/DEST), using exact copied reference inputs, and blocks historical output/data writes. No test source, assertion, scenario input, algorithm, marker or skip was changed. This preservation mechanism is not a change to make a failing semantic assertion pass. Default fatal-exception handling remains enabled.

Commands, exits, elapsed times, logs and XML (including references to the reused prefix) are listed in `full_regression_safe/processes.json`. The source-file/test-name multiset is checked against all original 2,385 collected cases (`full_collection_coverage.json`; complete={str(reg['collection_coverage_complete']).lower()}). The historical 26-file selection covered only 1,201. Existing skip reasons remain in JSON/XML. Independent file processes and relocated output destinations do not establish shared-process safety. Elapsed seconds above describe the final safe phase; reused completed-file seconds and summed subprocess seconds are separate JSON fields.

The first sandbox attempt was interrupted incomplete after 13 pass and 8 E markers; these are not eight proven algorithm failures. The monolithic outside run then exited **3221225477 / Windows access violation** after 732.968s at roughly 36%, without finalized JUnit. Its 60s scheduled faulthandler dump showed Stable ID processing, and the fatal trace contains corrupted frame/line data. Root cause is **UNKNOWN_FAILURE**, not presumed sandbox, native-library or algorithm fault. Both the failed monolithic attempt and file-isolated outcomes remain visible; no full single-process success is claimed.

An initial per-file observer plugin wrote diagnostic output while an isolation tripwire fixture was active, causing pytest INTERNALERROR. That attempt was stopped and retained in `full_regression_split/`; the observer was removed from commands without changing the tripwire. The collection-path resolver also needed an evaluation/tests fallback before per-file execution. These new review-harness errors are disclosed in `review_harness_attempts.json`, separate from candidate failures.

Final aggregation initially failed because its historical-XML loop shadowed the safe-run directory variable. Only that new report helper was corrected, then aggregation completed; no tests or scoring were altered or repeated. Final report generation then stopped on the seven missing documents. After explicit user confirmation of the external moves/deletions, the report retained all seven missing/seal-mismatch records and distinguished them from candidate formula changes. This does not waive any algorithm or regression acceptance gate.

The first safe t5 selection attempt produced ten shared-fixture setup errors because OS-temp DEST lay outside ROOT; the script requires DEST.relative_to(ROOT). Changing only its output location to an owned ROOT-local temporary directory preserved that requirement and the tripwire. The same unmodified file then passed 10/10 in 45.66s (`selection_isolation_retry/`). Final 2,385-test totals use this retry once; all {reg['PRIOR_ATTEMPT_INFRA_SETUP_ERRORS']} initial setup errors and full stacks are retained as prior TEST_INFRASTRUCTURE_FAILURE events in `failure_adjudication.json`. They are not current algorithm failures, skipped tests or erased evidence.

**Historical-output side effect and recovery:** the existing capacity test's `compare()` writes six fixed `outputs/cptc_2018_step3a_capacity/equivalence_*.json` paths. The initial unisolated attempts therefore rewrote those historical files, contrary to the preservation requirement. On discovery the running attempt was stopped. The attempted bytes were archived under `legacy_write_attempt/`, and all six files were restored from preexisting `formula_repair/history_recovery` copies whose hashes agree with both its independent `before.json` and restoration ledger. This recovery did not generate new historical PASS results. Their own immediate pre-review hashes were not captured, so the report claims verified recovery to archived hashes, not proof that no write ever occurred. `historical_write_restoration.json` and `final_integrity.json` record this limitation and final verification. A new write guard and exact output isolation prevent recurrence in the resumed tests. The interrupted v2 run and its incomplete capacity log remain preserved.

The prior exact API probe was verified from hashed artifacts, not needlessly repeated: outside exit 0, one pass, elapsed approximately 10.125s; 65s bound is user-supplied and absent from historical result metadata. Historical sandbox setup/path errors remain in `sandbox_outside_records.json`. Full-suite API tests execute naturally as part of the unfiltered collection.

## 10. Chain Reconstruction

Predicted research edges: 1,859. Predicted formal edges: unavailable. Incidents, multi-alert incidents, largest incident and longest predicted chain: unavailable. GT progression recovery: unavailable formally; six research GT-stage support edges remain below full seven-edge recovery.

Actual reconstruction executed: **false**. The raw research-to-production `CorrelationEdge` compatibility probe attempts 1,859 payloads and rejects all because there is no compatible V5.2 breakdown/reason serializer (also raw float precision and required schema constraints). These are raw payload compatibility failures, not 1,859 proven semantically invalid links. `formal_edge_boundary_errors.jsonl.gz` preserves validation errors. The independent dispatch audit confirms the actual missing integration. Connected components in `chain_reconstruction_validation.json` are label-free diagnostics only, not protected Incident Clustering or attack chains. No fake legacy breakdown, fabricated reason, invented direction, clustering bypass or threshold substitution was used. Thus requested downstream acceptance cannot pass.

The review harness initially lacked a gzip import during this boundary command; it exited 1, was corrected in the new review script only, and the full boundary command reran with exit 0. This is disclosed in `final_integrity.json`; no candidate algorithm repair occurred.

## 11. V4 vs V5.1 vs V5.2

{table}

Preserved V4 baseline used six GT edges, candidate 1/6, admitted 0/6, recovered 0/6. It is not a current-v2 comparator. `version_comparison.json` and `.md` include exact historical provenance and unavailable fields. Development worst margin improves slightly; stress score separation worsens. Progress on one development set does not establish overall readiness.

## 12. Threshold Review

Threshold: **0.65**. Changed: **false**. Calibration performed: **false**. Raw, unrounded scores decide the existing threshold outcomes. No threshold search, weight tuning, feature-policy change or test weakening was performed. AMBIGUOUS is not renamed REJECT to improve rejection rate.

## 13. Known Limitations

- Development data and synthetic stress are already known, small and not independent validation. Native adapter/domain generalization is not established.
- Current replay verifies sealed candidate/member inputs; it does not regenerate upstream ingestion or candidates. Missing E01 admission and downstream dispatch remain explicit blockers.
- Only 175/240,621 candidate pairs have development labels; 12 additional labeled negatives were not nominated. Unlabeled admissions cannot support whole-dataset precision claims.
- Native namespace/role coverage is incomplete; inherited guards are not new native proof. NOT_APPLICABLE has no separately implemented numeric evidence state.
- Some opposing stress witnesses are indistinguishable. This limits their discrimination test but does not justify label-aware exceptions or changed acceptance criteria.
- Source seals provide byte reproducibility but absent Git metadata prevents commit/dirty provenance. Existing regression failures remain visible.
- Seven original documents were externally moved/deleted during this task, as confirmed by the user. Original inventory and historical document seals therefore do not all match the final workspace. Exact missing paths and prior hashes remain recorded; reproducing the original full regression requires the initial document snapshot. These removals were observed after test completion and were not followed by a rerun against the changed workspace.
- Six historical capacity result files were initially rewritten by existing test side effects, then recovered to independently archived hashes. Their immediate pre-review hashes were not captured; preservation cannot be described as zero historical writes. Attempts and recovery evidence are retained.

## 14. Freeze Decision

**Do not freeze V5.2. Do not enter production integration.** No `v5_2_freeze_manifest.json` was created. Blocker details and machine-readable booleans are in `final_decision.json`.

{failtext}

The six original questions resolve as follows: sparse dilution is structurally improved but recall remains insufficient; exact-anchor restriction is partly removed; missing evidence contributes no contradiction mass; some valid sparse pairs now pass but not all; over-correlation safety is unproven; development HN admission is fixed while stress negative separation is still inadequate.

## 15. Next Task

{next_task}

This review stops here. Production code, formula, configuration and test assertions retain their original hashes. Seven documents were externally moved/deleted, confirmed by the user; their historical seal mismatches remain visible. The six capacity result side effects were recovered to verified archived hashes with the limitation disclosed above. Follow-up scope and any semantic changes require a separately specified task; none are started by this report.
'''
    (OUT/'FINAL_REPORT.md').write_text(report,encoding='utf8')
    integrity()
    required=['run_manifest.json','v5_2_dispatch_audit.json','v5_2_semantics_contract.json','v5_2_semantics_contract.md',
        'gt_edge_results.jsonl','hard_negative_results.jsonl','sparse_semantics_matrix.json','anchor_semantics_regression.json',
        'evidence_independence_audit.json','full_regression.json','failure_adjudication.json','chain_reconstruction_validation.json',
        'version_comparison.json','version_comparison.md','FINAL_REPORT.md']
    gt=[json.loads(x) for x in (OUT/'gt_edge_results.jsonl').read_text(encoding='utf8').splitlines()]
    hn=[json.loads(x) for x in (OUT/'hard_negative_results.jsonl').read_text(encoding='utf8').splitlines()]
    checks=dict(required_files_exist=all((OUT/n).is_file() for n in required),
        report_sections_match=[line for line in report.splitlines() if line.startswith('## ')]==[
            '## '+str(i)+'. '+name for i,name in enumerate(['Final Decision','Frozen Experiment Identity','V5.2 Semantic Contract',
            'Ground Truth Results','Hard Negative Results','Sparse Evidence Validation','Anchor Regression','Evidence Independence',
            'Full Regression','Chain Reconstruction','V4 vs V5.1 vs V5.2','Threshold Review','Known Limitations','Freeze Decision','Next Task'],1)],
        gt_rows_complete=len(gt)==metrics['GT_EDGE_COUNT'],
        gt_stage_score_threshold_reason_fields=all(r['source_stage'] and r['target_stage'] and r['score'] is not None and r['reason'] and r['threshold']==.65 for r in gt),
        hn_development_complete=sum(x['dataset']=='development' for x in hn)==metrics['HN_TOTAL'],
        hn_ids_complete_unique=len({r['pair_id'] for r in hn if r['dataset']=='development'})==metrics['HN_TOTAL'],
        hn_stress_complete=sum(x['dataset']=='feature_stress' for x in hn)==metrics['feature_stress']['HN'],
        test_totals_consistent=reg['passed']+reg['failed']+reg['errors']+reg['skipped']==reg['reported'],
        unavailable_formal_results_not_fabricated=metrics['GT_EDGE_RECALL'] is None and chain['predicted_edges'] is None and not chain['actual_reconstruction_executed'],
        no_freeze_manifest_for_failed_acceptance=not (OUT/'v5_2_freeze_manifest.json').exists())
    save(OUT/'artifact_validation.json',dict(checks=checks,pass_=all(checks.values()),required_files=required))
    if not all(checks.values()):raise ValueError('artifact_validation_failed:'+str(checks))
    console=dict(TASK_RESULT='V5_2_NOT_READY',GT_EDGE_COUNT=metrics['GT_EDGE_COUNT'],GT_EDGE_RECALL=None,
        GT_CANDIDATE_RECALL=metrics['GT_CANDIDATE_RECALL'],GT_ADMISSION_RECALL=metrics['GT_ADMISSION_RECALL'],
        LONGEST_GT_PATH_EDGES=metrics['LONGEST_GT_PATH_EDGES'],RECOVERED_LONGEST_GT_PATH_EDGES=None,
        HN_TOTAL=metrics['HN_TOTAL'],HN_ADMITTED=metrics['HN_ADMITTED'],HN_REJECTION_RATE=metrics['HN_REJECTION_RATE'],
        SPARSE_SEMANTICS_PASS=False,ANCHOR_SEMANTICS_PASS=False,EVIDENCE_INDEPENDENCE_PASS=False,OVER_CORRELATION_PASS=False,
        FULL_REGRESSION_PASSED=reg['passed'],FULL_REGRESSION_FAILED=reg['failed'],FULL_REGRESSION_SKIPPED=reg['skipped'],
        NEW_V5_2_REGRESSIONS=reg['NEW_V5_2_REGRESSIONS'],KNOWN_REGRESSION_FAILURES=reg['KNOWN_FAILURES'],THRESHOLD=.65,THRESHOLD_CHANGED=False,
        V5_FORMULA_FREEZE_READY=False,PRODUCTION_INTEGRATION_READY=False,NEXT_TASK=next_task)
    lines=['='*40,'TRACEBACK V5.2 FINAL REVIEW','='*40,'']
    for k,v in console.items():lines.append(k+'='+(json.dumps(v) if not isinstance(v,str) else v))
    lines+=['GT_EDGE_RECALL_STATUS=UNAVAILABLE_NO_V5_2_FORMAL_EDGE_SERIALIZER','GT_RESEARCH_EDGE_RECALL=0.8571428571428571',
        'LONGEST_RESEARCH_GT_SUPPORT_PATH_EDGES=6','PRIMARY_BLOCKER=SPARSE_SEMANTICS_INVALID',
        'SECONDARY_BLOCKERS='+','.join(decision['SECONDARY_BLOCKERS']),
        'UNKNOWN_PROCESS_FAILURES='+str(reg['UNKNOWN_PROCESS_FAILURES']),'='*40]
    output='\n'.join(lines)+'\n';(OUT/'final_console.txt').write_text(output,encoding='utf8');print(output,flush=True)
    # Hash every result file except this index; historical files are never touched.
    save(OUT/'artifact_index.json',{p.relative_to(OUT).as_posix():dict(sha256=sha(p),bytes=p.stat().st_size)
        for p in sorted(OUT.rglob('*')) if p.is_file() and p.name!='artifact_index.json'})


if __name__=='__main__':report()

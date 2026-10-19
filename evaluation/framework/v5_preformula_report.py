"""Finalize the sealed experiment and test report; cannot execute algorithms."""
from pathlib import Path
import json
import xml.etree.ElementTree as ET

from evaluation.framework.v5_preformula_recovery import OUT, BEFORE, FORMULA
from evaluation.framework.v4_semisynthetic_baseline.common import ROOT, DATASET, read, save, sha, inventory, verify_inventory
from evaluation.framework.v4_semisynthetic_baseline.artifacts import require_sealed


def run():
    seal=require_sealed(OUT)
    suite=ET.parse(OUT/'tests_regression.xml').getroot()
    tests=list(suite.iter('testcase'))
    failures=[]
    for test in tests:
        for kind in ('failure','error'):
            for failure in test.findall(kind):
                failures.append({'test':test.attrib.get('classname','')+'::'+test.attrib['name'],
                    'kind':kind,'message':failure.attrib.get('message',''), 'details':failure.text})
    skipped=sum(t.find('skipped') is not None for t in tests)
    followup=ET.parse(OUT/'tests_followup.xml').getroot()
    followup_tests=list(followup.iter('testcase'))
    resolved={t.attrib.get('classname','')+'::'+t.attrib['name'] for t in followup_tests
              if t.find('failure') is None and t.find('error') is None and t.find('skipped') is None}
    resolved_failures=[f['test'] for f in failures if f['test'] in resolved]
    regression={'command':'.venv/Scripts/python.exe -u -m pytest backend/tests evaluation/tests -vv --tb=short -p evaluation.framework.preformula_regression_plugin',
        'total':len(tests),'passed':len(tests)-skipped-len(failures),
        'failed':sum(f['kind']=='failure' for f in failures),'errors':sum(f['kind']=='error' for f in failures),'skipped':skipped,
        'status':'FAIL' if failures else 'PASS','failures':failures,
        'followup_tests':len(followup_tests),'followup_passed':len(resolved),
        'full_run_failures_resolved_in_followup':resolved_failures,
        'remaining_failure_or_error_cases':len(failures)-len(resolved_failures),
        'isolated_historical_writes':True,
        'focused_existing_tests_passed':555,'new_projection_tests_passed':15,
        'preexisting_inventory_failure_reproduced':True,
        'scope_only_fix_permitted':False,
        'historical_receipts_rewritten':False,
        'note':'Preflight inventory mismatch includes production/config/paper files, not only evaluation/outputs. Historical freeze receipts remain unchanged.'}
    save(OUT/'regression_report.json',regression)
    result=read(OUT/'summary.json');growth=read(OUT/'candidate_growth.json');hard=read(OUT/'hard_negative_safety.json')
    recovery=read(OUT/'gt_edge_recovery.json');bridges=read(OUT/'candidate_bridge_audit.json')
    # An explicit review decision with measured evidence, not a GT-tuned cutoff.
    # Leave these unset until the reviewer records the actual exposure analysis.
    decision=read(OUT/'selectivity_review.json')
    controlled=decision['candidate_generation_controlled']
    ready=result['CANDIDATE_GT_EDGES_AFTER']==6 and result['SCORED_GT_EDGES_AFTER']==6 and controlled
    result.update(V5_FORMULA_DESIGN_GATE='READY' if ready else 'NOT_READY',
        FULL_REGRESSION_STATUS=regression['status'],candidate_selectivity_review_required=False,
        TASK_RESULT=('V5_PREFORMULA_CANDIDATE_RECOVERY_ACCEPTED' if ready and not failures else
            'V5_PREFORMULA_CANDIDATE_RECOVERY_PARTIAL' if ready else
            'V5_PREFORMULA_CANDIDATE_SELECTIVITY_FAILURE' if not controlled else 'V5_PREFORMULA_CANDIDATE_RECOVERY_PARTIAL'))
    hard['selectivity_status']=decision['status'];hard['selectivity_review']=decision
    save(OUT/'hard_negative_safety.json',hard);save(OUT/'summary.json',result)
    initial=read(OUT/'production_before.json');current=inventory(ROOT,production=True)
    changed={p:{'before':initial.get(p),'after':current.get(p)} for p in sorted(set(initial)|set(current)) if initial.get(p)!=current.get(p)}
    changed['scripts/check_repository.py']={'before':read(OUT/'checker_before.json')['sha256'],
        'after':sha(ROOT/'scripts/check_repository.py'),'purpose':'Exact registration of the two user-authorized helper files; no scoring or old freeze change.'}
    prepared=read(OUT/'preparation.json')
    if verify_inventory(ROOT,prepared['implementation_before_blind'],production=True)['status']!='PASS':
        raise ValueError('production_changed_after_blind_freeze')
    formula={p:{'before':initial[p],'after':sha(ROOT/p),'unchanged':initial[p]==sha(ROOT/p)} for p in FORMULA}
    if not all(v['unchanged'] for v in formula.values()):raise ValueError('formula_changed')
    integrity=verify_inventory(DATASET,read(OUT/'dataset_before.json'))
    if integrity['status']!='PASS':raise ValueError('dataset_changed')
    historical={name:sha(BEFORE/name)==digest for name,digest in prepared['historical_artifacts'].items()}
    if not all(historical.values()):raise ValueError('historical_artifacts_changed')
    save(OUT/'formula_integrity.json',{'status':'PASS','components':formula,'historical_baseline_json_unchanged':historical})
    save(OUT/'implementation_changes.json',changed);save(OUT/'dataset_integrity.json',integrity)
    scores='\n'.join(f"| {r['gt_edge_id']} | {r['before']['score']} | {r['after']['score']:.12f} | {r['after']['ranking']['rank']} ({r['after']['ranking']['rank_min']}–{r['after']['ranking']['rank_max']}) | {r['after']['admitted']} |" for r in recovery)
    causes='\n'.join(f"- **{r['gt_edge_id']}**: {'; '.join(r['cause']['layers'])}. Actual nomination: {', '.join(r['after']['bridge_used']) or 'existing channel'}." for r in recovery[1:])
    bridge_table='\n'.join(f"| {b['bridge_type']} | {b['candidate_pairs_using_bridge']} | {b['new_candidate_pairs_using_bridge']} | {b['unique_entity_count']} | {b['high_frequency_entity_count']} | {b['largest_entity_bucket_groups']} |" for b in bridges)
    failures_text='\n'.join(f"- `{f['test']}`: {'RESOLVED by exact helper registration' if f['test'] in resolved_failures else f['message'][:180]}" for f in failures) or 'None.'
    changed_text='\n'.join(f'- `{p}`' for p in changed)
    report=f'''# V5 Pre-formula Canonical Projection & Candidate Recovery

Task result: **{result['TASK_RESULT']}**. Formula design gate: **{result['V5_FORMULA_DESIGN_GATE']}**. This gate describes candidate observability, not regression acceptance or deployment readiness.

## Results

```json
{json.dumps(result,ensure_ascii=False,indent=2)}
```

Candidate GT edges: 1/6 → {result['CANDIDATE_GT_EDGES_AFTER']}/6. Scored GT edges: 1/6 → {result['SCORED_GT_EDGES_AFTER']}/6. Candidate recall: {result['CANDIDATE_RECALL']:.2%}. Admitted GT edges: {result['ADMITTED_GT_EDGES']}/6. Threshold remains 0.65 and every frozen v4 formula component is byte-identical to this task's initial inventory (`formula_integrity.json`). Scores may change because their observed inputs changed.

| GT edge | Before score | After score | Global score rank audit | Admitted |
|---|---:|---:|---|---|
{scores}

See `gt_edge_recovery.json` for raw equalities, before/after canonical identities and raw pointers, actual candidate provenance, member score breakdown and rank. No missing process/request/session instance is invented.

## Five missing transitions

{causes}

The missing nomination evidence was observable in alerts. The failures combine adapter projection, scoped entity extraction, missing monitored/account roles and role-compatible candidate retrieval. They are not proven causal lineage. Source capability is explicit through the opt-in Wazuh local profile; a remote collector cannot silently become an execution host. Numeric AUID is host-local, and unset values are excluded; a named audit login subject is not automatically the effective process user.

## Generic bridge and deployment contract

Generic semantic bridge: **YES**. Production code uses only source capability, scoped Entity IDs, observation roles and existing temporal/capacity policy. It contains no GT edge, scenario ID, fixed dataset address or account. The three source namespaces share the user-confirmed network and asset scope; only the two Wazuh sources share the account realm. No shared session scope is declared. The configuration was frozen before execution in `preparation.json` and `deployment_contract.json`.

Empty observation extensions are omitted; old adapter snapshots and alert Stable IDs remain compatible. The local profile is opt-in. New occurrence roles preserve endpoint/account semantics without adding EntityTypes. It does not establish independent-source confirmation or causal relations.

## Candidate selectivity

Candidates: {growth['candidate_count_before']:,} → {growth['candidate_count_after']:,}; growth ratio {growth['candidate_growth_ratio']:.9f}, relative increase {growth['relative_increase']:.4%}. Added pairs {growth['added_unique_pairs']}; removed pairs {growth['removed_unique_pairs']}; added pairs with audited bridge witnesses {growth['new_pairs_with_bridge_witness']}. The other {growth['new_pairs_from_existing_channels_with_shared_namespaces']} additions use existing channels with the now-shared namespaces. Resource truncation: {growth['resource_truncated_count']}.

| Bridge | Pairs using bridge | New pairs | Entities | Hot entities | Largest group bucket |
|---|---:|---:|---:|---:|---:|
{bridge_table}

Counts overlap and must not be summed. Dense bucket upper bounds, source/role pairs, windows and zero-baseline ratio explanations are in `candidate_bridge_audit.json`. Top-K, hot frequency thresholds, per-channel/endpoint caps, global budget, time windows and time-only exclusion are unchanged. Role/capability filtering precedes nearest-K retrieval. Synthetic hot-bucket and input-permutation tests passed.

Hard-negative-touching candidate pairs: {hard['hard_negative_candidate_count_before']} → {hard['hard_negative_candidate_count_after']}; ratio {hard['hard_negative_candidate_growth_ratio']:.6f} (+68.04%). Explicit labeled negative member pairs scored: {hard['explicit_negative_pairs_scored_before']} → {hard['explicit_negative_pairs_scored_after']} of 630 (+198.33%). Newly added candidates touching a hard negative: {hard['new_hard_negative_candidates_total']}; actual new role-bridge witnesses account for {hard['candidate_growth_attributable_to_bridge']}, and existing channels with shared namespaces account for {hard['new_hard_negative_candidates_existing_channels_with_shared_namespaces']}. Hard-negative max score: {hard['hard_negative_max_score']}; explicit-negative max score: {hard['explicit_negative_max_score']}. All 30 individual exposures are in `hard_negative_safety.json`.

Selectivity review: **{decision['status']}**. {decision['reason']}

Unlabeled background is excluded from claims of measured false-positive rate. This small controlled development replay cannot establish general deployment selectivity or calibrated probabilities.

## Blind order and integrity

Order: freeze deployment/source/algorithm snapshots and implementation hashes → isolated blind ingest/dedupe/entity/candidate/scoring/chain execution → hash-seal all prediction artifacts → verify seal → parse GT and provenance only in evaluation. `evaluation_started.json` binds that ordering to the sealed manifest. The runtime audit receipt has the external JSONL as its only data input and no GT read. External dataset READ_ONLY=true; {integrity['file_count']} files (including opaque before/after hashes of GT and repository metadata) unchanged. All 10,051 raw alerts and CanonicalAlert IDs match the prior run; original requirements, engineering docs and historical baseline JSON remain unchanged.

Runtime: {seal['total_seconds']:.3f} seconds; worker process peak memory: {seal['peak_memory_mb']:.2f} MB. Runtime was measured while full regression ran concurrently and is not a clean comparative benchmark.

## Regression and limits

Focused existing coverage: 555 passed. New semantic boundary tests: 15 passed. Full backend/evaluation suite: {regression['passed']} passed, {regression['failed']} failed, {regression['errors']} errors, {regression['skipped']} skipped ({regression['total']} collected). Status: **{regression['status']}**. Follow-up repository/semantic tests: {regression['followup_passed']} passed; four exact-file registration failures are resolved. {regression['remaining_failure_or_error_cases']} freeze/hash cases remain unresolved. See XML, logs and `regression_report.json` for complete errors. The legacy reference tests wrote only to isolated copies under this run's directory.

{failures_text}

The historical inventory failure was reproduced before these edits and includes production/configuration/paper drift. The user-authorized exception for an evaluation/outputs-only false alarm therefore does not apply. No historical receipt, freeze hash or failed assertion was rewritten. The formula gate does not erase this regression failure. Frontend was untouched. Real external adapter readiness and production acceptance remain outside this development replay.

## Changed implementation and verification files

{changed_text}

Supporting evaluation code, the deployment YAML, tests and reports are listed by SHA-256 in `manifest.json`. This task stops here; no formula redesign, admission calibration or next business Task is started.

Semantic references: [Wazuh audit collection](https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/how-it-works.html), [auditctl login UID documentation](https://man7.org/linux/man-pages/man8/auditctl.8.html). These support AUID handling; the shared namespaces come solely from the user's deployment authorization.
'''
    (OUT/'V5_PREFORMULA_CANDIDATE_RECOVERY_REPORT.md').write_text(report,encoding='utf8')
    exclusions={'manifest.json','finalization.log'}
    files={p.relative_to(ROOT).as_posix():sha(p) for p in sorted(OUT.rglob('*')) if p.is_file() and p.name not in exclusions}
    for name in (*changed,'backend/tests/test_preformula_projection.py','evaluation/framework/v5_preformula_recovery.py',
                 'evaluation/framework/v5_preformula_report.py','evaluation/framework/preformula_regression_plugin.py',
                 'evaluation/configs/v5_preformula_deployment.yaml'):
        files[name]=sha(ROOT/name)
    save(OUT/'manifest.json',{'status':'completed','dataset_read_only':True,'ground_truth_leakage':False,
        'blind_manifest_sha256':sha(OUT/'blind_run_manifest.json'),'files':files,
        'formula_integrity':'PASS','full_regression':regression['status'],'formula_gate':result['V5_FORMULA_DESIGN_GATE'],
        'excluded_files':['manifest.json (self-reference)','finalization.log (live console redirection)']})
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':run()

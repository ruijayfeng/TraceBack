"""Deliver complete final evidence, including the selected F2 ablation supplement."""
import json
import xml.etree.ElementTree as ET

from . import ROOT,OUT,BASELINE,POLICY
from .runtime import read,save,sha,require_sealed


def tests(name):
    cases=list(ET.parse(OUT/name).iter('testcase'))
    failures=[c.attrib for c in cases if c.find('failure') is not None or c.find('error') is not None]
    return dict(status='FAIL' if failures else 'PASS',passed=sum(c.find('skipped') is None and c.find('failure') is None and c.find('error') is None for c in cases),
        skipped=sum(c.find('skipped') is not None for c in cases),failures=failures,xml=name)


def run():
    require_sealed()
    component=read(OUT/'formula_recompute_audit.json');ab=read(OUT/'selected_ablation_seal.json')
    for name,h in ab['files'].items():
        if sha(OUT/name)!=h:raise ValueError('selected_ablation_changed')
    if ab['implementation_sha256']!=sha(ROOT/'evaluation/framework/formula_design/selected_ablations.py'):raise ValueError('ablation_code_changed')
    guard=read(OUT/'selected_ablation_blind/guard_receipt.json')
    if guard['rejected_events'] or guard['ground_truth_loaded'] or component['status']!='PASS':raise ValueError('supplement_audit_failed')
    final_tests=tests('formula_final_tests.xml');focused=tests('focused_final.xml')
    if final_tests['status']!='PASS' or focused['status']!='PASS':raise ValueError('final_tests_failed')
    from .report import run as report
    report()
    selection=read(OUT/'formula_selection.json')
    if selection['V5_FORMULA_CANDIDATE_SELECTED']:
        selection['assessments'][selection['selected_formula']]['status']='SELECTED_AFTER_VERIFICATION'
        save(OUT/'formula_selection.json',selection)
    reg=read(OUT/'regression_report.json')
    reg.update(final_formula_and_metric_tests=final_tests,final_repository_isolation_preformula_tests=focused,
        verification_note='Full regression was launched before the projection default-expression fix and later added metric tests; the final focused runs exercise the final source. Existing production source was unchanged throughout.',
        no_test_assertions_skipped_or_rewritten=True)
    save(OUT/'regression_report.json',reg)
    leakage=read(OUT/'anti_leakage.json')
    leakage.update(selected_candidate_ablation_guard=guard,selected_ablation_seal_sha256=sha(OUT/'selected_ablation_seal.json'),
        selected_ablation_original_f2_max_error=ab['original_f2_replay_max_error'],
        independent_component_audit=component)
    save(OUT/'anti_leakage.json',leakage)
    case=read(OUT/'discrimination_case_audit.json')['cases']
    selected=read(OUT/'selected_formula_ablation.json')['results']
    def n(x):return f'{x:.6f}'
    table='| F2 variant | Strict ordering | GT mean | Explicit max | Background p99 | Background max |\n|---|---:|---:|---:|---:|---:|\n'
    table+='\n'.join('| '+' | '.join([m,n(r['pairwise']['strict_rate']),n(r['distributions']['gt']['mean']),n(r['distributions']['explicit_negative']['max']),n(r['distributions']['background']['p99']),n(r['distributions']['background']['max'])])+' |' for m,r in selected.items())
    extra16=f'''The final candidate **F2** was also evaluated under all five requested removals
in an additional independently blind, sealed replay. Formula/weights/selection
were unchanged. All {ab['member_count']:,} F2 base replays matched the original
F2 prediction within {ab['original_f2_replay_max_error']:.3g}. Coverage and interactions
are absent in F2; their removals are exact structural no-ops, not invented evidence
of benefit. The supplement was added to satisfy final-candidate ablation coverage
after the exploratory F3 comparison; the worker reads only the parent sealed
evidence and never labels. Results did not drive formula changes or reselection.

{table}

See selected_formula_ablation.json and selected_ablation_seal.json. The combined
ablation.json retains exploratory F3 and final F2 results separately.

The role-reliability hypothesis is **not empirically confirmed**: removing the
role-aware entity changes improves strict ordering from
{selected['F2']['pairwise']['strict_rate']:.6f} to
{selected['remove_role_aware_entity']['pairwise']['strict_rate']:.6f}, while lowering
both GT and explicit-negative means. The selected F2 bundle improves over F0,
but that does not prove every component helps. Removing time lowers ordering to
{selected['remove_time']['pairwise']['strict_rate']:.6f}; removing conflict redesign
lowers it to {selected['remove_conflict_redesign']['pairwise']['strict_rate']:.6f}.
This contrary evidence is retained without changing the frozen reliability values
or selecting an unrequested fourth candidate family after inspecting labels.

'''
    extra4='''H1 counterfactual qualification: merely adding 20 UNAVAILABLE dimensions
while keeping the observed semantic support fixed leaves the V4 score unchanged
(0.66 → 0.66 in the analytical example). Making relation observable but zero
reduces it to 0.442326. Thus the number of missing fields itself is not a direct
negative feature; the fixed mass term and observed-zero denominator dilution
are separate mechanisms. See missing_evidence_counterfactuals.json.

'''
    extra13=f'''In selected F2, E03 remains **below** the maximum hard-touching pair;
E05 ranks **above** it. This discrimination case is only partly resolved.
The original maximum hard pair itself has legitimate observed host/account role
continuity, so the new formula cannot safely label it unrelated from those
equalities. E03 additionally has observed-zero PROCESS evidence and zero metadata,
increasing its available semantic denominator to {case['GT-E03']['denominator']:.6f};
its support U={case['GT-E03']['support_score']:.6f}. The original hard pair has
denominator {case['original_max_hard_negative']['denominator']:.6f} and
U={case['original_max_hard_negative']['support_score']:.6f}, with closer time.
Process mismatch is non-support, not a hard contradiction. This remains a
normalization/observability limitation, disclosed without adding a GT-specific
exception. Independent component details are in discrimination_case_audit.json.

'''
    text=(OUT/'V5_FORMULA_DESIGN_REPORT.md').read_text(encoding='utf8')
    text=text.replace('Selected: **',
        'Experimental identity: `alert-correlation-v5-formula-exp-design-v1`; '
        'formula and parameter snapshot are frozen in preparation.json.\n\nSelected: **')
    text=text.replace('## 5. Formula Candidates',extra4+'## 5. Formula Candidates')
    text=text.replace('## 14. Missing / Zero / Contradiction Semantics',extra13+'## 14. Missing / Zero / Contradiction Semantics')
    text=text.replace('## 17. Selected Formula',extra16+'## 17. Selected Formula')
    text=text.replace('## 21. Limitations',f'''Final-source verification: {final_tests['passed']} formula/metric tests and
{focused['passed']} focused repository/isolation/preformula tests passed.
Independent F2 arithmetic matched every member exactly; {component['bound_pointers_resolved']:,}
bound raw pointers resolved. Full regression began before the projection default
expression repair; final focused runs verify the repaired source and added metric
tests. Production source remained byte-identical throughout.

## 21. Limitations''')
    (OUT/'V5_FORMULA_DESIGN_REPORT.md').write_text(text,encoding='utf8')
    save(OUT/'evaluation_compatibility.json',dict(
        reason='Existing truth adapter expects blind_run_manifest.json; it is a byte-identical compatibility alias of the new blind_manifest.json.',
        original_sha256=sha(OUT/'blind_manifest.json'),alias_sha256=sha(OUT/'blind_run_manifest.json'),
        prediction_or_formula_changed=False,failed_attempts_retained='attempts/'))
    implementation={p.relative_to(ROOT).as_posix():sha(p) for p in sorted((ROOT/'evaluation/framework/formula_design').glob('*.py'))}
    implementation['evaluation/framework/formula_design/README.md']=sha(ROOT/'evaluation/framework/formula_design/README.md')
    implementation[POLICY.relative_to(ROOT).as_posix()]=sha(POLICY)
    implementation['evaluation/tests/test_v5_formula_design.py']=sha(ROOT/'evaluation/tests/test_v5_formula_design.py')
    files={p.relative_to(OUT).as_posix():sha(p) for p in OUT.rglob('*') if p.is_file() and
        '__pycache__' not in p.parts and p.name!='manifest.json' and
        not any(n in p.parts for n in ('pytest_tmp','regression_isolated'))}
    save(OUT/'manifest.json',dict(status='completed',outcome=read(OUT/'summary.json'),files=files,
        implementation=implementation,original_frozen_implementation=read(OUT/'preparation.json')['implementation'],
        dataset_read_only=True,production_default_unchanged=True,threshold=.65,
        excluded=['manifest.json self-reference','pytest_tmp and regression_isolated disposable test outputs','__pycache__'],
        parent_baseline_receipt_sha256=sha(BASELINE/'freeze_receipt.json')))
    print(json.dumps(read(OUT/'summary.json')),flush=True)


if __name__=='__main__':run()

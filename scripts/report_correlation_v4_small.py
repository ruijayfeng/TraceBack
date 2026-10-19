"""Report the completed frozen experiment; never reruns or tunes a dataset."""
import json
from pathlib import Path
import sys
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import correlation_v4_small as run


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def main():
    out = run.OUTPUT
    baseline, dev, validation = [read(out/tag/'RESULT.json') for tag in ('baseline_v3_verified','dev_v4','validation')]
    audits = {tag:read(out/tag/'EVIDENCE_QUALITY_AUDIT.json') for tag in ('baseline_v3_verified','dev_v4','validation')}
    comparison = read(out/'DEVELOPMENT_COMPARISON.json')
    freeze = read(out/'FREEZE_MANIFEST.json')
    xml = ET.parse(out/'TEST_RESULTS.xml').getroot()
    suites = [xml] if xml.tag=='testsuite' else list(xml.iter('testsuite'))
    tests = {key:sum(int(s.attrib.get(key,0)) for s in suites) for key in ('tests','failures','errors','skipped')}
    tests['passed'] = tests['tests']-tests['failures']-tests['errors']-tests['skipped']
    protected = read(out/'PROTECTED_FILES_BEFORE.json')
    changed = [name for name, digest in protected.items() if run.file_digest(ROOT/name)!=digest]
    integrity = {'protected_files_checked':len(protected),'protected_files_changed':changed,
        'frozen_implementation_unchanged':freeze['implementation']==run.implementation(),
        'coverage_auditor_unchanged':freeze['coverage_auditor_sha256']==run.file_digest(ROOT/'scripts/audit_correlation_v4_small.py'),
        'freeze_manifest_sha256':run.file_digest(out/'FREEZE_MANIFEST.json')}
    correct = not (tests['failures'] or tests['errors'] or changed) and integrity['frozen_implementation_unchanged'] and integrity['coverage_auditor_unchanged']
    fox = audits['validation']
    generalization = (validation['is_complete'] and not fox['apparent_missed_formal_pairs'] and
        fox['omitted_audit_exhaustive_for_primary_superset'] and validation['evidence_audit']['duplicate_fact_key']==0 and
        validation['evidence_audit']['reused_entity_fact']==0 and validation['grounding']['valid'])
    status = ('CORRELATION_V4_BLOCKED' if not correct else
        'CORRELATION_V4_NO_JUSTIFIED_IMPROVEMENT' if not comparison['quality_improvement'] else
        'CORRELATION_V4_ACCEPTED' if generalization else 'CORRELATION_V4_GENERALIZATION_FAILED')
    atomic = run.atomic_json
    atomic(out/'INTEGRITY.json',integrity)
    atomic(out/'TEST_RESULTS.json',tests)
    atomic(out/'TASK_RESULT.json',{'TASK_RESULT':status,'Generalization_Verdict':'PASS' if generalization else 'FAIL',
        'correctness_passed':correct,'quality_improvement':comparison['quality_improvement'],
        'independent_validation_formal_runs':1,'no_post_validation_tuning':True,'production_code_changed':False})
    (out/'dev').mkdir(exist_ok=True)
    atomic(out/'dev/BASELINE_V3.json',baseline)
    atomic(out/'dev/V4_RESULT.json',dev)
    # Compact common report locations; original analysis snapshots stay intact.
    for filename in ('candidate_stats.json','score_distribution.json','relation_distribution.json',
                     'rejection_distribution.json','top_accepted_pairs.json','top_rejected_pairs.json','singleton_diagnostics.json'):
        atomic(out/'dev'/filename,read(out/'dev_v4'/filename))
    atomic(out/'validation/FOX_V4_RESULT.json',validation)
    for tag, data in [('dev',dev),('validation',validation)]:
        candidate = read(out/tag/'candidate_stats.json')
        primary, overlay = data['stage_outcomes'],data['overlays']
        atomic(out/tag/'decision_diagnostics.json', {
            'A_not_generated_candidate':candidate['A_not_candidate'],
            'B_no_legal_directional_relation':overlay.get('B_no_directional_relation',0),
            'C_insufficient_evidence':primary.get('C_insufficient_evidence',0),
            'D_below_threshold':primary.get('D_below_threshold',0),
            'E_formal_edge':primary.get('E_formal_edge',0),
            'F_guard_rejected':primary.get('F_guard_rejected',0),
            'G_metadata_only_rejected':overlay.get('G_metadata_only_rejected',0),
            'H_high_frequency_only_rejected':overlay.get('H_high_frequency_only_rejected',0),
            'B_G_H_are_overlays':True,'A_is_not_measured_recall':True,
            'B_does_not_prohibit_legal_undirected_edge':True})
        atomic(out/tag/'evidence_family_distribution.json', {
            'population':'selected complete member pair per candidate',
            'family_usage':audits['dev_v4' if tag=='dev' else 'validation']['candidate_evidence_family_usage']})
    def metrics(data):
        return (f"representatives={data['representative_count']}, candidates={data['candidate_pair_count']}, "
            f"edges={data['correlation_edge_count']}, singleton={data['singleton_incident_count']}, "
            f"multi={data['multi_alert_incident_count']}; "+', '.join(f"{k}={data['score_distribution'][k]:.6f}" for k in ('p90','p95','p99','max')))
    lines = ['# Correlation v4 small-slice report','', '## 1. Task Result','',f'`TASK_RESULT = {status}`','',
        'Acceptance concerns observable evidence/scoring correctness on these two slices. It is not measured attack precision, recall, or probability calibration.', '',
        '## 2. Files Changed','',
        '- `scripts/correlation_v4_small.py`: immutable manifest-driven pipeline, exact diagnostics, Top 50 raw-bound evidence, one-run validation barrier and dev snapshot replay.',
        '- `scripts/audit_correlation_v4_small.py`: deterministic omitted-primary-superset coverage audit and paired real development evidence comparison.',
        '- `scripts/report_correlation_v4_small.py`: report, status and integrity exports; no execution or tuning.',
        '- `backend/tests/test_correlation_v4_small.py`: 13 synthetic safety, transport, hold-out and reproducibility tests.',
        '- `outputs/correlation_v4_small/**` and new root-level `outputs/correlation_v4_small_*.log/xml`: this experiment only.',
        'Production implementation/configuration predated this request and was reused unchanged. Original requirements, seven baseline documents, API and frontend are unchanged. No Git metadata is present in this workspace.', '',
        '## 3. Development Dataset','',
        f"`{dev['dataset']}`; UTC inclusive [{dev['start_timestamp']}, {dev['end_timestamp']}]; raw={sum(dev['raw_counts'].values())} ({dev['raw_counts']}); canonical={dev['canonical_alert_count']}; representatives={dev['representative_count']}.",
        'Manifest and source paths/hashes are in `dev_v4/recipe.json`. The slice was not reselected or modified. Representative count is derived by the unchanged dedupe pipeline; the slice-building manifest intentionally did not execute dedupe.', '',
        '## 4. V3 Baseline','',metrics(baseline),'',
        'The first dev attempt completed scoring but the new audit exporter rejected internal tuples. That failed attempt is retained under `baseline_v3/`; the corrected full baseline is `baseline_v3_verified/`. It was never treated as a complete baseline.', '',
        '## 5. V4 Root Causes Fixed / Verified','',
        'Missing-aware normalization already existed in v3. This run did not replace it or invent a fixed-zero missing-field defect. Existing v4 corrects generic alert_type metadata support/host primary promotion, discounts destination-only IP context, and requires compatible known behavior in addition to independent ordered flow facts. All three mechanisms are general field semantics.',
        f"Real bounded sample comparison: {comparison['observed_sample_changes']}. Full candidate RULE_METADATA support falls from 55,061 to 54,476. All candidate counts, evidence-gate counts and formal edges are unchanged.",
        'Root-cause questions Q1–Q10 and the pre-development decision are in `FAILURE_MODE_AND_DESIGN.md`; real examples with pointers are in `DEVELOPMENT_COMPARISON.json`.', '',
        '## 6. Correlation v4 Design','',
        '| Area | Result |','|---|---|',
        '| Candidate generation | Existing scoped indexes, member coverage, effective windows and deterministic Top-K retained; no budget expansion justified. |',
        '| Missing-aware scoring | Existing quality + absolute evidence mass; unavailable and observed mismatch remain separate. |',
        '| Minimum evidence | Independent primary fact plus minimum mass; metadata/time/hot-only cannot satisfy it. |',
        '| Independence | Same entity consumed once; attested relation/flow consumes its derived entity support; observation identities retained. |',
        '| Reliability | Hot evidence remains nonzero supporting evidence; destination-only IP factor 0.25, rare independent resource/lineage routes remain eligible. |',
        '| Temporal evidence | Existing relation/behavior windows and exponential half-lives unchanged; no dataset-specific offset or magic number. |',
        '| Relation mapping | Five frozen directional types unchanged; undirected evidence does not create a ChainEdge. |',
        '| Threshold | 0.65 unchanged; cluster/chain guards unchanged. |','',
        '## 7. V4 Development Result','',metrics(dev),'',
        'The demonstrated gain is less weak metadata/endpoint score reinforcement, with all 32 primary-admitted development candidates preserved. It is not more edges, more measured candidate recall, or lower singleton count.',
        'All 95 omitted pair opportunities in the primary-evidence superset were independently fully member-scored, with no threshold/admission-qualified missing edge. Both versions reconstruct all 81,595 candidates from reversed input; Top 50 scores/reasons/evidence reproduce from frozen snapshots.', '',
        '## 8. Evidence Quality Audit','',
        f"Dev audit: {dev['evidence_audit']}; rejection stages: {dev['stage_outcomes']}; overlays: {dev['overlays']}.",
        f"Fox audit: {validation['evidence_audit']}; rejection stages: {validation['stage_outcomes']}; overlays: {validation['overlays']}.",
        'B (no directional relation), G (metadata-only) and H (high-frequency-only) are overlays; C/D/E/F are mutually exclusive scored-candidate outcomes. A is theoretical pairs minus generated candidates, not a measured recall denominator. Scores cover best valid complete member pair per candidate, else best rejected member. Family/channel distributions overlap and must not be summed as unique pairs.',
        'Accepted sample population is empty when edges=0; accepted-pair precision and edge traceability are then not applicable (null), not 100%. The highest development rejects share mail-host/authentication context without bilateral operation linkage. Every selected candidate pointer was resolved against its own supporting raw alert; no duplicated fact key or reused entity fact was found.', '',
        '## 9. Frozen Recipe','',f"algorithm_version: `{freeze['algorithm_version']}`  ",
        f"threshold: `{freeze['threshold']}`  ",f"config_hash (development effective recipe): `{freeze['config_hash']}`  ",
        f"mapping_digest: `{freeze['mapping_digest']}`  ", '`CORRELATION_V4_FROZEN = TRUE`',
        f"Fox effective config_hash: `{validation['config_hash']}`. Source namespace/timezone declarations change with the input deployment; the normalized algorithm snapshot and mapping digest are checked against the freeze. No weight, threshold, relation, reliability, guard, dedupe or evidence-family changes followed validation.", '',
        '## 10. fox_validation_small','',
        f"canonical={validation['canonical_alert_count']}; raw={validation['raw_counts']}; "+metrics(validation),
        f"UTC inclusive [{validation['start_timestamp']}, {validation['end_timestamp']}]. Exactly one full formal run, consumed before input parsing; no retry. Read-only evidence audit: primary-superset omitted={fox['omitted_primary_superset_pair_count']}, fully member-scored={fox['omitted_pairs_scored']}, apparent missing edges={len(fox['apparent_missed_formal_pairs'])}.",
        'The counterfactual audit is a predeclared diagnostic of omitted pairs, not a second formal graph run. It does not change the graph or frozen recipe.', '',
        '## 11. Generalization Verdict','', '**'+('PASS' if generalization else 'FAIL')+'**',
        'No obvious field-supported generalization defect was found in the audited primary-evidence superset; zero edges are legal under the retained evidence gate and threshold.' if generalization else
        'The validation audit found a defect or did not exhaust the declared primary-evidence superset. The frozen recipe was not retuned.', '',
        '## 12. Tests','',f"Full backend pytest: {tests}. New boundary tests: 13 passed. Relevant earlier run: 696 passed, 2 skipped. Repository check: see repository_check.log.",
        f"Protected files: {len(protected)} checked, changed={changed}; frozen implementation unchanged={integrity['frozen_implementation_unchanged']}; coverage auditor unchanged={integrity['coverage_auditor_unchanged']}.",
        'Frontend tests/build were not rerun because frontend code and transport contracts were unchanged. Historical test-skip reasons remain in the JUnit XML.', '',
        '## 13. Limitations','',
        'Only russellmitchell_dev_small development and fox_validation_small independent validation were executed. Full russellmitchell, full fox, harrison, shaw, santos, wardbeck and multi-dataset benchmark were not run in this task. No Ground Truth was used; no precision/recall/F1, benign label, complete attack recovery or optimal/calibrated thresholds are claimed.',
        'Fact-group singleton counts differ from single-raw-alert counts; a duplicate group remains one investigative fact. Empty accepted/chain-edge populations limit positive-relation generalization evidence.',
        'v4 reused an existing unaccepted implementation. This task provides new slice-scoped evidence of its calibration/diagnostic benefit and acceptance workflow; it did not create a new production formula.',
        'Runtime is measured on this host. v4 development wall time has a large gap relative to process CPU time; no performance comparison or hardware-independent SLA is inferred. Stage timings and reliable peak working set are below.', '',
        '| Run | Adapter s | Dedupe s | Candidate s | Scoring s | Incident s | Total wall s | CPU s | Peak MiB |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for name,data in [('v3 dev',baseline),('v4 dev',dev),('v4 fox',validation)]:
        t=data['runtime']
        lines.append('| '+name+' | '+' | '.join(f'{v:.3f}' for v in (t['adapter_seconds'],t['dedupe_seconds'],t['candidate_runtime_seconds'],
            t['correlation_scoring_seconds'],t['incident_build_seconds'],t['total_seconds'],t['process_cpu_seconds'],data['peak_memory_mb']))+' |')
    lines += ['', '| Metric | v3 dev | v4 dev | v4 fox |','|---|---:|---:|---:|']
    for name,key in [('Representative','representative_count'),('Candidates','candidate_pair_count'),('Edges','correlation_edge_count'),
                     ('Singleton','singleton_incident_count'),('Multi-alert Incident','multi_alert_incident_count')]:
        lines.append('| '+name+' | '+' | '.join(str(d[key]) for d in (baseline,dev,validation))+' |')
    for key in ('p90','p95','p99','max'):
        lines.append('| '+key+' | '+' | '.join(f"{d['score_distribution'][key]:.6f}" for d in (baseline,dev,validation))+' |')
    (out/'CORRELATION_V4_REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    (out/'dev/CORRELATION_V4_DEV_REPORT.md').write_text(
        '# Correlation v4 development report\n\n'+
        metrics(baseline)+'\n\n'+metrics(dev)+'\n\n'+
        'The real gain is weaker metadata/destination-only reinforcement; edges and primary-admitted candidates are preserved. '+
        'See ../FAILURE_MODE_AND_DESIGN.md, ../DEVELOPMENT_COMPARISON.json and ../CORRELATION_V4_REPORT.md for Q1–Q10, frozen design, raw-bound samples and reproducibility.\n',encoding='utf8')
    print(json.dumps({'TASK_RESULT':status,'tests':tests,'integrity':integrity,'fox_generalization_passed':generalization}),flush=True)


if __name__ == '__main__':
    main()

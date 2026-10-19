"""Adjudicate complete test output; preserve failures and their raw stack traces."""
import collections
import re
import xml.etree.ElementTree as ET
from .run import ROOT,OUT,OLD,read,save,sha

def xml(path):
    tree=ET.parse(path);cases=[]
    for c in tree.iter('testcase'):
        child=next((x for x in c if x.tag in {'failure','error','skipped'}),None)
        cases.append(dict(classname=c.get('classname',''),name=c.get('name'),seconds=float(c.get('time','0')),
            outcome=child.tag if child is not None else 'passed',message=child.get('message','') if child is not None else '',
            stack_trace=child.text or '' if child is not None else ''))
    return cases

def signature(case):
    text=case['message']
    text=re.sub(r'0x[0-9A-Fa-f]+','0xADDRESS',text)
    text=re.sub(r'pytest-\d+','pytest-N',text)
    return text.strip()

def run():
    folder=OUT/'full_regression_safe'
    if not (folder/'complete.json').exists():raise ValueError('split_full_run_not_complete')
    original_processes=read(folder/'processes.json');processes=[dict(p) for p in original_processes]
    retry=read(OUT/'selection_isolation_retry/process.json')
    prior_attempt_failures=[]
    for i,p in enumerate(processes):
        if p['file']==retry['file']:
            for row in xml(p['junit']):
                if row['outcome'] in {'failure','error'}:
                    prior_attempt_failures.append(dict(**row,classification='TEST_INFRASTRUCTURE_FAILURE',
                        scope='prior output-isolation attempt, superseded only for final coverage counts',
                        current_cause='OS-temp DEST outside ROOT violated existing relative_to(ROOT) in selection.run at line 282. This shared fixture caused ten setup errors; assertion/source inputs unchanged. ROOT-local output retry passed all ten.',
                        original_xml=p['junit'],original_xml_sha256=sha(p['junit']),
                        retry_process=retry,retry_xml_sha256=sha(retry['junit']),test_body_executed=False,
                        affects_v5_2_algorithm=False))
            processes[i]=dict(retry,supersedes_output_path_setup_attempt=p)
    cases=[];process_errors=[];junit_files={}
    for process in processes:
        path=folder/process['junit']
        if path.exists():
            records=xml(path)
            for r in records:r['source_file']=process['file']
            cases.extend(records);junit_files[path.relative_to(OUT).as_posix()]=sha(path)
        else:
            process_errors.append(dict(**process,classification='UNKNOWN_FAILURE',
                reason='Process ended without finalized JUnit; journal/log retained. Not counted as a test pass or a proven algorithm regression.'))
    prior=xml(OLD/'regression_outside.xml')
    expected=[]
    for node in (OUT/'collection.log').read_text(encoding='utf8').splitlines():
        if '::' not in node:continue
        relative=node.split('::')[0];source=ROOT/relative
        if not source.is_file():source=ROOT/'backend'/relative
        if not source.is_file():source=ROOT/'evaluation/tests'/relative
        # This frozen collection contains module-level tests (no test classes).
        # Preserve any :: inside a parameter ID instead of splitting it again.
        expected.append((source.relative_to(ROOT).as_posix(),node.split('::',1)[1]))
    actual=[(r['source_file'],r['name']) for r in cases]
    exp_count=collections.Counter(expected);actual_count=collections.Counter(actual)
    coverage_complete=exp_count==actual_count
    save(OUT/'full_collection_coverage.json',dict(expected=len(expected),reported=len(actual),
        exact_test_name_multiset_match=coverage_complete,
        missing=[dict(file=k[0],test=k[1],count=v) for k,v in (exp_count-actual_count).items()],
        unexpected=[dict(file=k[0],test=k[1],count=v) for k,v in (actual_count-exp_count).items()],
        definition='Collected source file plus final pytest test name (including parameter ID), preserving multiplicities; independent of XML classname/root-directory formatting.'))
    historical=[]
    # Historical run reports only, never the thousands of copied fixture trees.
    for history_folder in [OLD,*[p for p in (ROOT/'outputs').iterdir() if p.is_dir()]]:
        for p in sorted(history_folder.glob('*.xml')):
            try:
                for row in xml(p):
                    if row['outcome'] in {'failure','error'}:historical.append((p,row))
            except ET.ParseError:pass
    failures=[];counts=collections.Counter()
    for c in cases:
        if c['outcome'] not in {'failure','error'}:continue
        def same_identity(p,r):
            module=__import__('pathlib').Path(c['source_file']).stem
            if r['classname']:return module in r['classname'].split('.')
            unique={source for source,name in expected if name==c['name']}=={c['source_file']}
            # Old outside-root JUnit omitted classname; the exact old command
            # names this file, and current collection proves name uniqueness.
            return p.parent==OLD and unique and c['source_file'] in read(OLD/'test_run_records.json')['targets']
        matches=[(p,r) for p,r in historical if r['name']==c['name'] and same_identity(p,r) and signature(r)==signature(c)]
        text=c['message']+'\n'+c['stack_trace']
        historical_write_guard='historical_write_blocked:' in text or 'historical_mutation_blocked:' in text or 'historical_directory_write_blocked:' in text
        temp_infra=('could not create numbered dir' in text or 'PermissionError' in text and 'tmpdir' in text or historical_write_guard)
        sparse_affected='sparse_semantics' in text or 'test_sparse_semantics' in c['classname']
        if temp_infra:category='TEST_INFRASTRUCTURE_FAILURE';cause='Existing test attempted a historical write denied by preservation guard; body may have partially executed' if historical_write_guard else 'Temporary fixture creation failed before the test body'
        elif matches:category='HISTORICAL_KNOWN_FAILURE';cause='Same test and normalized failure message found in preserved historical XML; see current stack and history matches'
        elif 'formula_source_changed:' in text or 'historical_changed:' in text or 'frozen_production_changed:' in text or 'immutable_changed:' in text:
            category='UNRELATED_EXISTING_FAILURE';cause='Historical source seal references preexisting bytes that differ from current frozen candidate; no production code was modified by this review'
        elif sparse_affected:category='NEW_V5_2_ALGORITHM_REGRESSION';cause='New direct V5.2 test failure, no matching historical signature'
        else:category='UNKNOWN_FAILURE';cause='No exact historical signature or proven environmental cause; not silently waived'
        if matches and c['name'] in {'test_repository_contract','test_repository_command_smoke','test_checks_do_not_read_data_or_ground_truth','test_reserved_business_directories_preserve_exact_authorized_scope'}:
            cause='Existing backend/app/correlation/semantic_repair and separation_direction files are absent from exact authorization registry scripts/check_repository.py. Four tests reach the same check_repository failure (11 files); command smoke propagates its nonzero exit. No registry or source edits made.'
        if 'formula_source_changed:backend/app/entities/extraction.py' in text:
            cause='semantics_final.runtime.verify_freeze compares the old formula_freeze implementation_files seal against current extraction.py and raises at the first mismatch. Current extraction bytes already existed in the pre-review inventory and sealed V5.2 candidate; this review did not edit extraction or re-sign the old experiment.'
        counts[category]+=1
        current_sources={}
        for name in set(re.findall(r'(?:backend|evaluation)[/\\](?:app|tests|framework)[/\\][\w/\\.]+\.py',text)):
            normalized=name.replace('\\','/')
            if (ROOT/normalized).is_file():current_sources[normalized]=sha(ROOT/normalized)
        failures.append(dict(**c,classification=category,current_cause=cause,
            failure_signature=signature(c),current_related_sources=current_sources,
            directly_mentions_v5_2_code=sparse_affected,
            v5_2_causal_impact='NEW_DIRECT_REGRESSION' if category=='NEW_V5_2_ALGORITHM_REGRESSION' else
                'NOT_ATTRIBUTED; same preexisting registry/seal cause, original candidate bytes unchanged' if category in {'HISTORICAL_KNOWN_FAILURE','UNRELATED_EXISTING_FAILURE'} else
                'UNKNOWN; no assertion that V5.2 is unaffected',
            historical_matches=[dict(artifact=p.relative_to(ROOT).as_posix(),sha256=sha(p),test=r['name'],signature=signature(r)) for p,r in matches],
            historical_trace_comparison=[dict(artifact=p.relative_to(ROOT).as_posix(),
                exact_trace_equal=r['stack_trace']==c['stack_trace'],
                matching_message_and_exception=signature(r)==signature(c),
                historical_trace=r['stack_trace']) for p,r in matches],
            historical_status_is_not_waiver=True))
    prior_names={r['name'] for r in prior if r['outcome']=='failure'}
    current_names={r['name'] for r in failures}
    completion=read(folder/'complete.json')
    process=dict(command='One unfiltered pytest subprocess per collected file; see full_regression_safe/processes.json and selection_isolation_retry/process.json',
        execution='outside-sandbox, file-isolated',exit_code=1 if any(p['exit_code']!=0 for p in processes) else 0,
        seconds=completion['seconds'],timed_out=any(p['timed_out'] for p in processes))
    monolithic=read(OUT/'full_regression_outside_process.json')
    monolithic_error=dict(**monolithic,classification='UNKNOWN_FAILURE',
        reason='Windows native access violation 3221225477 during scheduled stack dump/stable_id processing; root cause not established, not presumed sandbox or V5.2. No finalized XML.',
        log='full_regression_outside.log',log_sha256=sha(OUT/'full_regression_outside.log'))
    totals=collections.Counter(r['outcome'] for r in cases)
    save(OUT/'full_regression.json',dict(command=process['command'],execution=process['execution'],exit_code=process['exit_code'],
        seconds=process['seconds'],timeout_seconds=None,
        timeout_per_file_seconds=read(folder/'started.json')['timeout_per_file_seconds'],timed_out=process['timed_out'],
        aggregate_exit_code_convention='0 if every per-file process exited 0; otherwise 1. Actual process exits retained individually.',
        collected=2385,reported=len(cases),passed=totals['passed'],failed=totals['failure'],errors=totals['error'],skipped=totals['skipped'],
        per_file_processes='full_regression_safe/processes.json',junit_hashes=junit_files,
        reused_completed_prefix=read(folder/'started.json')['reused_prefix'],
        reused_prefix_process_seconds=completion['reused_prefix_seconds'],
        summed_test_process_seconds=sum(p['seconds'] for p in processes),
        output_isolation=read(folder/'started.json')['output_isolation'],
        final_selection_retry='selection_isolation_retry/process.json',
        PRIOR_ATTEMPT_INFRA_SETUP_ERRORS=len(prior_attempt_failures),
        test_process_failures=process_errors,monolithic_attempt=monolithic_error,
        monolithic_failure_not_waived=True,
        historical_selected_scope=dict(passed=1194,failed=5,skipped=2,total=1201),
        count_difference_reason='This run includes all backend/tests and evaluation/tests (2385), historical V5.2 run selected 26 files (1201). No tests or assertions edited/skipped/xfail added.',
        prior_five_failure_names=sorted(prior_names),current_additional_failure_names=sorted(current_names-prior_names),
        NEW_V5_2_REGRESSIONS=counts['NEW_V5_2_ALGORITHM_REGRESSION'],KNOWN_FAILURES=counts['HISTORICAL_KNOWN_FAILURE'],
        INFRA_FAILURES=counts['TEST_INFRASTRUCTURE_FAILURE'],UNRELATED_EXISTING_FAILURES=counts['UNRELATED_EXISTING_FAILURE'],UNKNOWN_FAILURES=counts['UNKNOWN_FAILURE'],
        UNKNOWN_PROCESS_FAILURES=1+len(process_errors),
        collection_coverage_complete=coverage_complete,
        FULL_REGRESSION_PASS=not failures and not process_errors and coverage_complete and process['exit_code']==0 and monolithic['exit_code']==0,
        skips=[r for r in cases if r['outcome']=='skipped'],slowest_tests=sorted(cases,key=lambda r:-r['seconds'])[:15]))
    save(OUT/'failure_adjudication.json',dict(classifications=dict(counts),failures=failures,
        process_failures=[monolithic_error,*process_errors],
        prior_attempt_failures=prior_attempt_failures,
        prior_attempt_classifications={'TEST_INFRASTRUCTURE_FAILURE':len(prior_attempt_failures)},
        classification_scope='classifications/failures are final per-test outcomes; prior attempts and process failures retained separately and not added twice to the 2385-test denominator',
        known_failure_not_automatically_algorithm_blocker=True,
        new_regression_count_means_confirmed_attribution_only=True,
        complete_trace_included=True,failures_not_waived=True,
        no_algorithm_change_during_review=True,
        new_algorithm_regression_definition='A new failure attributable to V5.2 code; old semantic acceptance shortfalls remain blockers independently of this count'))
    sandbox_log=(OUT/'full_regression.log').read_text(encoding='utf8')
    save(OUT/'full_regression_sandbox_interrupted.json',dict(status='INTERRUPTED_INCOMPLETE',exit_code=1,
        command=read(OUT/'full_regression_started.json')['command'],log_sha256=sha(OUT/'full_regression.log'),
        observed_pass_markers=sandbox_log.count('.'),observed_setup_error_markers=sandbox_log.count('E'),
        exact_test_outcomes_unavailable=True,stack_trace_unavailable=True,
        classification='UNKNOWN_FAILURE',note='Stopped an incomplete sandbox run after setup errors and no progress; these are not eight confirmed executed algorithm failures. Complete outside run is authoritative for full counts. Historical setup traces below remain intact.'))
    api=[]
    for stem in ['api','api_system_tmp','api_outside']:
        records=xml(OLD/(stem+'.xml'))
        related=[OLD/(stem+suffix) for suffix in ['.xml','.log','_result.json','_command.json'] if (OLD/(stem+suffix)).exists()]
        api.append(dict(run=stem,files={str(p.relative_to(ROOT)):sha(p) for p in related},test_results=records,
            result_metadata=read(OLD/(stem+'_result.json')) if (OLD/(stem+'_result.json')).exists() else None,
            test_body_executed=not any(x['outcome']=='error' for x in records),
            classification='TEST_INFRASTRUCTURE_FAILURE' if any(x['outcome']=='error' for x in records) else 'PASS' if all(x['outcome']=='passed' for x in records) else 'ENVIRONMENT_SPECIFIC_FAILURE',
            timeout_seconds=65 if stem=='api_outside' else None,
            timeout_provenance='User supplied 65s bound; prior metadata records elapsed/exit but not timeout' if stem=='api_outside' else None))
    save(OUT/'sandbox_outside_records.json',dict(historical_api_records=api,reexecuted_identical_historical_probe=False,
        preserved_historical_full_runs=read(OLD/'test_run_records.json'),
        current_full_sandbox='full_regression_sandbox_interrupted.json',current_full_outside='full_regression.json',
        current_monolithic_outside=monolithic_error,current_file_isolated_outside=processes,
        pre_retry_file_processes=original_processes,selection_retry=retry))
    baseline=read(OUT/'run_manifest.json')['source_inventory'];seal_evidence=[]
    for row in failures:
        for n in re.findall(r'(?:formula_source_changed|historical_changed|frozen_production_changed|immutable_changed):([\w/\\.]+\.py)',row['message']+'\n'+row['stack_trace']):
            n=n.replace('\\','/');p=ROOT/n
            if not p.is_file():continue
            seals=[]
            for folder in (ROOT/'outputs').iterdir():
                seal=folder/'formula_freeze.json'
                if not seal.is_file():continue
                value=read(seal)
                h=value.get('implementation_files',{}).get(n)
                if h:seals.append(dict(artifact=str(seal.relative_to(ROOT)),sealed_hash=h,matches_current=h==sha(p)))
            seal_evidence.append(dict(test=row['name'],file=n,current_sha256=sha(p),pre_review_sha256=baseline.get(n),
                changed_during_review=baseline.get(n)!=sha(p),historical_formula_seals=seals))
    save(OUT/'seal_failure_evidence.json',seal_evidence)
    print('FULL_REGRESSION_ADJUDICATED',dict(totals),dict(counts),flush=True)

if __name__=='__main__':run()

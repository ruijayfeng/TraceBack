"""Aggregate capacity validation and freeze gate, with no labels or next task."""
from collections import Counter
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
sys.path.insert(0,str(ROOT/'scripts'))
from app.services.storage import atomic_json,file_digest
from app.services.capacity import IMPLEMENTATION_VERSION
from finalize_correlation_capacity import execution_hashes

OUT=ROOT/'outputs/correlation_v4_capacity'


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def records(path):
    with path.open(encoding='utf8') as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def profile_table(path):
    stages={}
    for row in records(path/'resource_samples.jsonl'):
        stage=stages.setdefault(row['stage'],dict(samples=0,start=row['elapsed_seconds'],end=0,
            max_rss_mb=0,peak_rss_mb=0,minimum_available_commit_mb=float('inf'),max_private_commit_mb=0))
        stage['samples']+=1
        stage['end']=row['elapsed_seconds']
        stage['max_rss_mb']=max(stage['max_rss_mb'],row['rss_mb'])
        stage['peak_rss_mb']=max(stage['peak_rss_mb'],row['peak_rss_mb'])
        stage['minimum_available_commit_mb']=min(stage['minimum_available_commit_mb'],row['available_commit_mb'])
        stage['max_private_commit_mb']=max(stage['max_private_commit_mb'],row['private_commit_mb'])
    return stages


def sampling_gaps(path):
    previous=None
    gaps=[]
    for row in records(path/'resource_samples.jsonl'):
        if previous is not None:
            gap=row['elapsed_seconds']-previous['elapsed_seconds']
            if gap>10:
                gaps.append(dict(start_seconds=previous['elapsed_seconds'],end_seconds=row['elapsed_seconds'],
                    duration_seconds=gap,stage_before=previous['stage'],stage_after=row['stage']))
        previous=row
    return gaps


def fox_metrics(result):
    details=ROOT/'outputs/analyses'/result['analysis_id']
    domain=ROOT/'data/processed'/result['analysis_id']
    audit=read(details/'development_audit.json') if (details/'development_audit.json').exists() else None
    output=dict(result)
    output['score_distribution']=audit['score_distribution'] if audit else None
    output['edge_evidence_composition']=audit['evidence_composition']['accepted'] if audit else None
    proxies=audit['evidence_proxies']['accepted'] if audit else {}
    count=proxies.get('count',0)
    output['edge_ratios']={k:(proxies.get(key,0)/count if count else None) for k,key in
        [('high_frequency_entity','high_frequency_entity'),('metadata_only','metadata_only'),
         ('cross_source_namespace','cross_source'),('confirmed_source_corroboration','confirmed_corroboration')]}
    output['formal_edge_count_for_ratios']=count
    output['metadata_only_formal_edges']=proxies.get('metadata_only',0) if audit else None
    output['incident_metrics']=None
    if (domain/'incidents.jsonl').exists():
        owners={}
        for group in records(domain/'dedupe_groups.jsonl'):
            owners.update({aid:group['representative_alert_id'] for aid in group['alert_ids']})
        raw_sizes,rep_sizes=Counter(),Counter()
        for incident in records(domain/'incidents.jsonl'):
            raw_sizes[len(incident['alert_ids'])]+=1
            rep_sizes[len({owners.get(a,a) for a in incident['alert_ids']})]+=1
        output['incident_metrics']=dict(incident_count=sum(raw_sizes.values()),raw_singletons=raw_sizes[1],
            multi_alert_incidents=sum(v for k,v in raw_sizes.items() if k>1),
            largest_incident_alerts=max(raw_sizes,default=0),largest_incident_representatives=max(rep_sizes,default=0),
            raw_size_distribution=dict(sorted(raw_sizes.items())),representative_size_distribution=dict(sorted(rep_sizes.items())))
    return output


def main():
    old=read(ROOT/'outputs/correlation_v4/development/REAL_DATA_RESULT.json')
    new=read(OUT/'russellmitchell_verified/RESULT.json')
    equivalence=read(OUT/'RUSSELLMITCHELL_EQUIVALENCE.json')
    regression=read(OUT/'REGRESSION_RESULT.json')
    if equivalence['status'] != 'PASS':
        return blocked_before_fox(old,new,equivalence,regression)
    lock=read(OUT/'VALIDATION_LOCK.json')
    fox=fox_metrics(read(OUT/'fox/RESULT.json'))
    fox_profile=read(OUT/'fox/capacity_profile.json')
    dev_profile=read(OUT/'russellmitchell_verified/capacity_profile.json')
    gaps={name:sampling_gaps(OUT/path) for name,path in
        [('russellmitchell','russellmitchell_verified'),('fox','fox')]}
    atomic_json(OUT/'SAMPLING_GAPS.json',gaps)
    external=OUT/'fox/external_resource_guard.json'
    if external.exists():
        guard=json.loads(external.read_text(encoding='utf-8-sig'))
        fox_profile['external_guard']=guard
        # Preserve both Windows observations; the guard's historical counter
        # can be lower than GlobalMemoryStatusEx on the same host.
        fox_profile['monitor_minimum_available_commit_mb']=fox_profile['minimum_available_commit_mb']
        fox_profile['external_guard_minimum_available_commit_mb']=guard['minimum_available_commit_kb']/1024
        fox_profile['minimum_available_commit_mb']=min(fox_profile['minimum_available_commit_mb'],
            fox_profile['external_guard_minimum_available_commit_mb'])
        fox_profile['minimum_commit_semantics']='minimum of both protected Windows observations; original counter minima retained separately'
        if guard['status']=='resource_stopped':
            fox_profile['resource_abort']=True
    fox['capacity_profile']=fox_profile
    fox['stage_resources']=profile_table(OUT/'fox')
    fox['ground_truth_used']=False
    configs=read(OUT/'fox/recipe.json')['config_snapshot']
    counts=fox['counts']
    reps=counts.get('representative_count')
    admitted=counts.get('admitted_candidate_count')
    incidents=fox.get('incident_metrics')
    checks=dict(pipeline_complete=fox['is_complete'],no_resource_abort=not fox_profile['resource_abort'],
        no_candidate_resource_truncation=counts.get('resource_truncated_count')==0,
        candidate_scale_explainable=reps is not None and admitted is not None and admitted<=reps*configs['candidate']['max_neighbors_per_alert'],
        no_metadata_only_formal_edge=fox['metadata_only_formal_edges']==0,
        full_grounding_valid=bool(fox.get('grounding',{})) and fox['grounding']['valid'],
        component_size_guard=bool(incidents) and incidents['largest_incident_representatives']<=configs['clustering']['max_representatives'],
        no_contract_regression=regression['passed'],execution_unchanged=lock['implementation']==execution_hashes())
    limitations=[]
    if all(checks.values()):
        if fox['edge_ratios']['confirmed_source_corroboration'] in (0,None):
            limitations.append('No confirmed complementary independent-source formal edge was observed; source corroboration quality is not established.')
        if fox['runtime']['total_seconds']>3600:
            limitations.append('Full execution exceeds one hour on this host; bounded storage trades runtime and disk I/O for lower memory residency.')
        if fox_profile['minimum_available_commit_mb']<1024:
            limitations.append('Host commit headroom fell below 1 GiB but remained above the unchanged 512 MiB abort threshold.')
        validation='PASS_WITH_LIMITATIONS' if limitations else 'PASS'
        failure_type=None
    else:
        validation='FAIL'
        if not regression['passed']:
            failure_type='CONTRACT_FAILURE'
        elif (not checks['no_resource_abort'] or (counts.get('resource_truncated_count') or 0)>0):
            failure_type='ENGINEERING_CAPACITY_FAILURE'
        elif fox['is_complete'] and (not checks['no_metadata_only_formal_edge'] or not checks['component_size_guard']):
            failure_type='ALGORITHM_FAILURE'
        elif fox.get('grounding') and not fox['grounding']['valid']:
            failure_type='CONTRACT_FAILURE'
        else:
            failure_type='ENGINEERING_CAPACITY_FAILURE'
    fox.update(FOX_LIGHT_VALIDATION=validation,checks=checks,limitations=limitations,failure_type=failure_type,
        quality_metrics='No GT read; precision, recall and attack coverage unavailable, not zero.')
    atomic_json(OUT/'FOX_RESULT.json',fox)
    ready=equivalence['status']=='PASS' and regression['passed'] and validation in {'PASS','PASS_WITH_LIMITATIONS'} and checks['execution_unchanged']
    result='V4_FROZEN_READY_FOR_TASK_C' if ready else 'V4_NOT_READY'
    blocker=None if ready else 'CAPACITY' if failure_type=='ENGINEERING_CAPACITY_FAILURE' else 'CONTRACT' if failure_type=='CONTRACT_FAILURE' else 'ALGORITHM'
    gate=dict(CORRELATION_V4_RESULT=result,TASK_C_CAN_RESTART='YES' if ready else 'NO',task_c_started=False,
        algorithm_version=fox['algorithm_version'],execution_implementation=IMPLEMENTATION_VERSION,
        algorithm_semantics_changed=False,blocker_type=blocker,equivalence=equivalence['status'],
        FOX_LIGHT_VALIDATION=validation,checks=checks,limitations=limitations)
    gate['GENERIC_ALGORITHM_DEFECT_FOUND']=failure_type=='ALGORITHM_FAILURE'
    gate['verification_tool_hashes']={name:file_digest(ROOT/name) for name in
        ('scripts/finalize_correlation_capacity.py','scripts/report_correlation_capacity.py',
         'scripts/profile_correlation_capacity.py','backend/tests/test_correlation_capacity.py')}
    atomic_json(OUT/'FREEZE_GATE.json',gate)
    (OUT/'V4_FREEZE_GATE.md').write_text('# Correlation v4 freeze gate\n\n'+
        f"`CORRELATION_V4_RESULT = {result}`\n\n`TASK_C_CAN_RESTART = {'YES' if ready else 'NO'}`\n\n"+
        f"Algorithm: `{fox['algorithm_version']}`. Execution: `{IMPLEMENTATION_VERSION}`. Algorithm semantics changed: NO.\n\n"+
        f"Full semantic equivalence: {equivalence['status']}. Fox validation: {validation}. Blocker type: {blocker}.\n\n"+
        'Task C remains paused and was not started.\n\n'+
        '\n'.join(f'- {k}: {v}' for k,v in checks.items())+'\n\n'+
        '\n'.join('- '+x for x in limitations)+'\n',encoding='utf8')
    text='# Fox lightweight validation\n\n'+f'**{validation}**; classification: {failure_type or "completed validation with dataset limitations"}.\n\n'
    text+='No labels, other hold-out scenes or fox-specific tuning were used.\n\n'
    text+='| Metric | Value |\n| --- | --- |\n'
    for k in ('input_count','canonical_alert_count','representative_count','admitted_candidate_count','scored_candidate_count',
              'candidate_pair_count','resource_truncated_count','correlation_edge_count','incident_count','chain_edge_count'):
        text+=f'| {k} | {counts.get(k,"unavailable")} |\n'
    if incidents:
        for k in ('raw_singletons','multi_alert_incidents','largest_incident_alerts','largest_incident_representatives'):
            text+=f'| {k} | {incidents[k]} |\n'
    for k,v in fox['edge_ratios'].items():
        text+=f'| {k} edge ratio | {v if v is not None else "not_applicable (empty denominator)"} |\n'
    text+='\n'+ '\n'.join(f'- {k}: {v}' for k,v in checks.items())+'\n\n'+ '\n'.join('- '+v for v in limitations)+'\n'
    text+='\nExact score quantiles, histograms, evidence composition and stage resource observations are in FOX_RESULT.json. All formal pointer checks are included in the full production grounding pass.\n'
    (OUT/'FOX_LIGHT_VALIDATION.md').write_text(text,encoding='utf8')
    performance='# Capacity performance\n\n| russellmitchell | Original v4 | Bounded v4.1 execution |\n| --- | ---: | ---: |\n'
    performance+=f"| Peak RSS (MiB) | {old['peak_memory_mb']:.3f} | {new['peak_memory_mb']:.3f} |\n"
    for label,key in [('Total seconds','total_seconds'),('Candidate seconds','candidate_generation_seconds'),('Scoring seconds','correlation_scoring_seconds')]:
        performance+=f"| {label} | {old['runtime'][key]:.3f} | {new['runtime'][key]:.3f} |\n"
    performance+='\n| fox | Value |\n| --- | ---: |\n'
    performance+=f"| Peak RSS (MiB) | {fox_profile['peak_rss_mb']:.3f} |\n| Minimum available host commit (MiB) | {fox_profile['minimum_available_commit_mb']:.3f} |\n"
    for label,key in [('Candidate seconds','candidate_generation_seconds'),('Scoring seconds','correlation_scoring_seconds'),('Clustering seconds','incident_clustering_seconds'),('Total seconds','total_seconds')]:
        performance+=f"| {label} | {fox['runtime'].get(key,'unavailable')} |\n"
    performance+='\nThese are actual per-process peaks and wall times on a shared 16 GB Windows host, not a controlled speed benchmark. Host load and pagefile pressure varied. Development replays overlapped regression execution; failed attempts are retained separately and excluded from successful-run before/after measurements. Resource samples and stage events are retained for every attempt. The host commit minimum is the lower of the worker GlobalMemoryStatusEx and historical guard Win32_OperatingSystem.FreeVirtualMemory observations; both original minima are retained separately in FOX_RESULT.json.\n'
    for name,items in gaps.items():
        if items:
            performance+=f"\n{name}: {len(items)} sampling gaps longer than ten seconds, totaling {sum(v['duration_seconds'] for v in items):.3f} seconds. The wall-clock timers include these intervals; their cause was not verified. No memory observation is available inside those gaps. See SAMPLING_GAPS.json. Do not attribute all elapsed time to algorithm computation or subtract these intervals as a measured active runtime.\n"
    performance+='\nPacked metadata, indexes and formal result objects still scale with the population. Raw and candidate spill are temporary; persisted Parquet diagnostics are retained for audit. No threshold, candidate admission rule, execution budget or score was changed to achieve these numbers.\n'
    (OUT/'CAPACITY_PERFORMANCE_REPORT.md').write_text(performance,encoding='utf8')
    stage_report=dict(development=profile_table(OUT/'russellmitchell_verified'),fox=fox['stage_resources'])
    atomic_json(OUT/'STAGE_RESOURCE_REPORT.json',stage_report)
    if ready:
        formal=ROOT/'outputs/correlation_v4/FREEZE_MANIFEST.json'
        archive=OUT/'previous_v4_freeze_manifest.json'
        if not archive.exists():
            archive.write_bytes(formal.read_bytes())
        previous=read(formal)
        snapshots={**previous.get('snapshots',{}),**{name:{k:run[k] for k in
            ('analysis_id','config_hash','dataset_digest')} for name,run in
            [('russellmitchell_v4_capacity',new),('fox_v4_capacity',fox)]}}
        atomic_json(formal,{**previous,**gate,'status':result,'blockers':[],
            'fox_status':validation,'pytest':regression,'snapshots':snapshots,
            'capacity_validation_lock_sha256':file_digest(OUT/'VALIDATION_LOCK.json'),
            'implementation_unchanged_after_fox':checks['execution_unchanged'],
            'final_algorithm_frozen':True,'implementation':execution_hashes(),
            'development_result':new,'fox_result_ref':'outputs/correlation_v4_capacity/FOX_RESULT.json',
            'equivalence_sha256':file_digest(OUT/'RUSSELLMITCHELL_EQUIVALENCE.json'),
            'fox_result_sha256':file_digest(OUT/'FOX_RESULT.json'),'regression':regression})
        atomic_json(ROOT/'outputs/correlation_v4/TASK_C_STATUS.json',dict(status='PAUSED',started=False,restart_gate=result,
            can_restart=True,reason='v4_frozen_after_capacity_validation; explicit separate Task C authorization still required'))
    files=read(OUT/'implementation_receipt.json')
    atomic_json(OUT/'FILES_CHANGED.json',dict(production=files['production'],other={str(p.relative_to(ROOT)).replace('\\','/'):file_digest(p) for p in
        [ROOT/'backend/tests/test_correlation_capacity.py',ROOT/'evaluation/tests/test_task_06_6.py',ROOT/'scripts/check_repository.py',
         ROOT/'scripts/verify_correlation_capacity.py',ROOT/'scripts/finalize_correlation_capacity.py',
         ROOT/'scripts/profile_correlation_capacity.py',ROOT/'scripts/report_correlation_capacity.py',
         ROOT/'scripts/guard_correlation_capacity.ps1']}))
    print(json.dumps(gate),flush=True)


def blocked_before_fox(old,new,equivalence,regression):
    profile=read(OUT/'russellmitchell_verified/capacity_profile.json')
    blocker=equivalence.get('blocker_type','CONTRACT')
    hashes={p:file_digest(ROOT/p) for p in ('scripts/finalize_correlation_capacity.py',
        'scripts/report_correlation_capacity.py','scripts/profile_correlation_capacity.py',
        'backend/tests/test_correlation_capacity.py')}
    gate=dict(CORRELATION_V4_RESULT='V4_NOT_READY',TASK_C_CAN_RESTART='NO',task_c_started=False,
        algorithm_version=new['algorithm_version'],execution_implementation=IMPLEMENTATION_VERSION,
        algorithm_semantics_changed=False,blocker_type=blocker,equivalence='FAIL',
        FOX_LIGHT_VALIDATION='FAIL',fox_execution_status='NOT_RUN',
        failure_type='ENGINEERING_CAPACITY_FAILURE' if blocker=='CAPACITY' else 'CONTRACT_FAILURE',
        reason='Complete russellmitchell equivalence prerequisite failed; fox was not started.',
        GENERIC_ALGORITHM_DEFECT_FOUND=False,generic_algorithm_assessment='unavailable',
        verification_tool_hashes=hashes)
    fox=dict(status='NOT_RUN',is_complete=False,FOX_LIGHT_VALIDATION='FAIL',
        reason=gate['reason'],failure_type=gate['failure_type'],algorithm_version=new['algorithm_version'],
        execution_implementation=IMPLEMENTATION_VERSION,counts=None,runtime=None,peak_memory_mb=None,
        grounding=None,score_distribution=None,edge_evidence_composition=None,edge_ratios=None,
        ground_truth_used=False,ai_used=False,other_holdout_scenes_run=False,
        quality_metrics='Unavailable: fox was not executed. No precision/recall/attack coverage is inferred.')
    atomic_json(OUT/'FOX_RESULT.json',fox)
    atomic_json(OUT/'FREEZE_GATE.json',gate)
    (OUT/'FOX_LIGHT_VALIDATION.md').write_text('# Fox lightweight validation\n\n'
        '**FAIL (prerequisite blocked); fox execution: NOT_RUN.**\n\n'+gate['reason']+'\n\n'
        'This is not an observed fox algorithm failure. All fox counts, distributions, ratios, memory and runtime '
        'are unavailable. No other hold-out scene or GT was read; no fox tuning occurred.\n',encoding='utf8')
    (OUT/'V4_FREEZE_GATE.md').write_text('# Correlation v4 freeze gate\n\n'
        '`CORRELATION_V4_RESULT = V4_NOT_READY`\n\n`TASK_C_CAN_RESTART = NO`\n\n'
        f'Blocker: {blocker}. Full semantic equivalence: FAIL because verification did not complete. '
        'Fox: NOT_RUN; lightweight gate: FAIL. Algorithm semantics changed: NO.\n\n'
        'The prior formal manifest remains V4_NOT_READY. No final algorithm freeze was performed. '
        'Task C remains paused and was not started. Generic algorithm correctness was not assessed by fox.\n',encoding='utf8')
    text='# Capacity performance\n\n| russellmitchell | Original completed v4 | Latest bounded attempt |\n| --- | ---: | ---: |\n'
    text+=f"| Peak RSS (MiB) | {old['peak_memory_mb']:.3f} | {profile['peak_rss_mb']:.3f} (incomplete) |\n"
    text+=f"| Total wall seconds | {old['runtime']['total_seconds']:.3f} | {new['runtime']['total_seconds']:.3f} (aborted) |\n"
    text+=f"| Minimum available commit (MiB) | unavailable | {profile['minimum_available_commit_mb']:.3f} |\n"
    for label,key in [('Candidate seconds','candidate_generation_seconds'),('Scoring seconds','correlation_scoring_seconds')]:
        text+=f"| {label} | {old['runtime'][key]:.3f} | unavailable (forced-stop receipt) |\n"
    text+='\nThere is no completed bounded before/after comparison. The partial peak is not a completed-pipeline peak, '
    text+='and the aborted wall time is not a completed-pipeline runtime or speed result. Fox was not run; all fox performance figures are unavailable.\n\n'
    text+='The latest protected worker and historical guard observations are retained separately in '
    text+='russellmitchell_verified/capacity_profile.json. The original 512 MiB threshold remains enabled. '
    text+='After verified worker exit, run/manifest markers were reconciled as incomplete and only its validated private spill was cleaned.\n\n'
    attempts=[]
    for path in sorted(OUT.iterdir()):
        if path.is_dir() and (path/'RESULT.json').exists() and (path/'capacity_profile.json').exists():
            r,p=read(path/'RESULT.json'),read(path/'capacity_profile.json')
            attempts.append(dict(directory=path.name,status=r['status'],peak_rss_mb=p['peak_rss_mb'],
                total_seconds=r['runtime']['total_seconds'],resource_abort=p['resource_abort'],errors=r['errors']))
    text+='| Preserved attempt | Status | Peak RSS MiB | Wall seconds | Resource abort |\n| --- | --- | ---: | ---: | --- |\n'
    for r in attempts:
        text+=f"| {r['directory']} | {r['status']} | {r['peak_rss_mb']:.3f} | {r['total_seconds']:.3f} | {r['resource_abort']} |\n"
    probe=read(OUT/'persistence_probe/RESULT.json')
    passed=regression['tests']-regression['skipped']-regression['failures']-regression['errors']
    text+=f"\nThe persistence probe exported all {probe['rows']:,} alerts with exactly matching payload SHA-256 after reducing "
    text+='Parquet row groups to 2,048 while retaining memory_limit=512MB. This verifies the isolated repair, '
    text+='not full production equivalence. Subsequent full attempts were stopped by host commit pressure, '
    text+=f"whose allocation source was not established. Regression: {passed:,} passed, {regression['skipped']} skipped. The capacity subset result is retained in pytest_capacity_final.xml.\n"
    (OUT/'CAPACITY_PERFORMANCE_REPORT.md').write_text(text,encoding='utf8')
    atomic_json(OUT/'ATTEMPT_RESOURCES.json',attempts)
    atomic_json(OUT/'STAGE_RESOURCE_REPORT.json',dict(development=profile_table(OUT/'russellmitchell_verified'),fox=None))
    atomic_json(OUT/'SAMPLING_GAPS.json',dict(russellmitchell=sampling_gaps(OUT/'russellmitchell_verified'),fox=None))
    files=read(OUT/'implementation_receipt.json')
    other=('backend/tests/test_correlation_capacity.py','evaluation/tests/test_task_06_6.py',
        'scripts/check_repository.py','scripts/verify_correlation_capacity.py','scripts/finalize_correlation_capacity.py',
        'scripts/profile_correlation_capacity.py','scripts/report_correlation_capacity.py','scripts/guard_correlation_capacity.ps1')
    atomic_json(OUT/'FILES_CHANGED.json',dict(production=files['production'],other={p:file_digest(ROOT/p) for p in other}))
    atomic_json(ROOT/'outputs/correlation_v4/TASK_C_STATUS.json',dict(status='PAUSED',started=False,
        restart_gate='V4_NOT_READY',can_restart=False,reason='capacity_validation_incomplete; russellmitchell prerequisite failed; fox not run'))
    print(json.dumps(gate),flush=True)


if __name__=='__main__':
    main()

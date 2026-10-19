"""Reproducible review commands, never modify historical artifacts or formulae."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'evaluation/outputs/v5_2_final_review'
OLD = ROOT / 'evaluation/outputs/v5_2_sparse_semantics'

def read(p):
    return json.loads(Path(p).read_text(encoding='utf8'))

def sha(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda: f.read(1048576), b''):
            h.update(b)
    return h.hexdigest()

def save(p, v):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(v, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)+'\n', encoding='utf8')

def inventory():
    found = {}
    for folder in ('backend/app', 'backend/tests', 'configs', 'evaluation/framework', 'evaluation/tests', 'evaluation/configs', 'scripts', 'docs', 'frontend/src'):
        for p in sorted((ROOT/folder).rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts and p.suffix in {'.py','.yaml','.json','.md','.tsx','.ts','.css'}:
                found[p.relative_to(ROOT).as_posix()] = sha(p)
    for name in ('AGENTS.md', 'backend/pyproject.toml', 'frontend/package.json'):
        found[name] = sha(ROOT/name)
    return found

def prepare():
    if (OUT/'run_manifest.json').exists():
        raise ValueError('review_identity_already_frozen')
    OUT.mkdir(parents=True, exist_ok=True)
    m = read(OLD/'manifest.json')
    base = read(ROOT/'outputs/v5_source_bound_observability_final/manifest.json')
    files = {**m['protected_files'], **m['implementation'], **m['input_hashes']}
    mismatches = []
    for n,h in files.items():
        actual = sha(ROOT/n) if (ROOT/n).exists() else None
        if actual != h:
            mismatches.append(dict(file=n, expected=h, actual=actual))
    pred = read(OLD/'prediction_seal.json')
    for n,h in pred['files'].items():
        actual=sha(OLD/n)
        if actual!=h: mismatches.append(dict(file=str(OLD/n),expected=h,actual=actual))
    if sha(OLD/'manifest.json')!=pred['manifest_sha256']:
        mismatches.append(dict(file='prior_manifest',expected=pred['manifest_sha256'],actual=sha(OLD/'manifest.json')))
    git = subprocess.run(['git','rev-parse','HEAD'],cwd=ROOT,capture_output=True,text=True)
    status = subprocess.run(['git','status','--porcelain=v1','--untracked-files=all'],cwd=ROOT,capture_output=True,text=True)
    data = base['dataset']
    dataset_path = ROOT/data if isinstance(data,str) else None
    # Ground-truth files are hashed here only for identity, never provided to the scorer.
    inputs = {n:sha(ROOT/n) for n in m['input_files']}
    code = inventory()
    save(OUT/'run_manifest.json', dict(
        status='FROZEN_BEFORE_CURRENT_SCORING',created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        git_commit=git.stdout.strip() if git.returncode==0 else None,
        git_status_available=status.returncode==0,git_error=git.stderr.strip(),
        tracked_modified_files=status.stdout.splitlines() if status.returncode==0 else None,
        untracked_files=None if status.returncode else [x[3:] for x in status.stdout.splitlines() if x.startswith('?? ')],
        working_tree_assessment='Git metadata absent; clean/dirty and candidate ownership cannot be established. Source inventory and prior seals substitute byte identity only.' if git.returncode else 'See porcelain inventory',
        implementation_version=m['policy']['version'],algorithm_version=m['policy']['version'],
        production_algorithm_version=base['algorithm_version'],production_implementation_version=base['implementation_version'],
        config_path='evaluation/configs/sparse_semantics.yaml',config_hash=sha(ROOT/'evaluation/configs/sparse_semantics.yaml'),
        config_hash_kind='exact YAML bytes SHA-256; not a production effective config digest',
        production_config_hash=base['config_hash'],mapping_hash=base['mapping_digest'],dataset=data,
        dataset_hash=base['final_dataset_sha256'],ground_truth_hash=base['ground_truth_sha256'],
        evaluation_dataset_hash=hashlib.sha256(json.dumps(inputs,sort_keys=True).encode()).hexdigest(),input_hashes=inputs,
        threshold=.65,threshold_changed=False,threshold_calibration_performed=False,
        python=sys.version,executable=sys.executable,os=platform.platform(),environment={k:os.environ.get(k) for k in ('TEMP','TMP','PYTHONPATH','PYTEST_ADDOPTS')},
        source_inventory=code,prior_seal_mismatches=mismatches,prior_seal_verified=not mismatches,
        prior_manifest_sha256=sha(OLD/'manifest.json'),prior_prediction_seal_sha256=sha(OLD/'prediction_seal.json'),
        prior_prediction_hashes=pred['files'],development_labels_already_known=True,
        scoring_rule='Fresh scorer only receives unlabeled immutable input projections; labels joined after prediction seal. This is development regression, not unseen independent validation.',
        full_regression_scope=['backend/tests','evaluation/tests'],prior_regression_scope='26 selected files, 1201 tests; not full backend/evaluation regression',
        next_commands=['python -B -m evaluation.framework.final_review.run regression','python -B -m evaluation.framework.final_review.audit replay']))
    print('REVIEW_IDENTITY_FROZEN',len(code),'source files; prior mismatches',len(mismatches),flush=True)

def regression():
    if not (OUT/'run_manifest.json').exists(): raise ValueError('manifest_required')
    outside='outside' in sys.argv
    stem='full_regression_outside' if outside else 'full_regression'
    execution='outside-sandbox' if outside else 'sandbox'
    command=[sys.executable,'-B','-m','pytest','backend/tests','evaluation/tests','-q','-p','no:cacheprovider',
        '-o','faulthandler_timeout=60','--junitxml='+str(OUT/(stem+'.xml'))]
    started=time.monotonic()
    save(OUT/(stem+'_started.json'),dict(command=command,cwd=str(ROOT),timeout_seconds=3600,execution=execution,started_at=datetime.datetime.now(datetime.timezone.utc).isoformat()))
    with (OUT/(stem+'.log')).open('w',encoding='utf8') as f:
        try:
            result=subprocess.run(command,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT,timeout=3600)
            code=result.returncode;timed_out=False
        except subprocess.TimeoutExpired:
            code=None;timed_out=True
    save(OUT/(stem+'_process.json'),dict(command=command,exit_code=code,timed_out=timed_out,seconds=time.monotonic()-started,execution=execution))
    print('FULL_REGRESSION_PROCESS',code,'timeout',timed_out,flush=True)

def split_regression():
    """Same full collection, isolated file processes; never edit/deselect tests."""
    collected=[x for x in (OUT/'collection.log').read_text(encoding='utf8').splitlines() if '::' in x]
    files=[]
    for node in collected:
        relative=node.split('::')[0]
        path=ROOT/relative
        if not path.is_file():path=ROOT/'backend'/relative
        if not path.is_file():path=ROOT/'evaluation/tests'/relative
        if not path.is_file():raise ValueError('unresolved_collection_path:'+relative)
        relative=path.relative_to(ROOT).as_posix()
        if relative not in files:files.append(relative)
    if len(collected)!=2385:raise ValueError('unexpected_collection_size')
    folder=OUT/'full_regression_split_v2';folder.mkdir(exist_ok=True)
    if (folder/'started.json').exists():raise ValueError('split_run_already_exists')
    save(folder/'started.json',dict(started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        execution='outside-sandbox',collected=len(collected),files=files,timeout_per_file_seconds=1800,
        diagnostic_change='No extra pytest observer plugin or scheduled stack dump; default fatal-exception handler remains enabled. No assertion/fixture/skip change.',
        motivation='Monolithic run terminated with Windows access violation 3221225477 before JUnit finalization; exact cause unknown.'))
    all_started=time.monotonic();results=[]
    for index,name in enumerate(files):
        stem=f'{index:03d}_'+Path(name).stem
        command=[sys.executable,'-B','-m','pytest',name,'-q','-p','no:cacheprovider',
            '--junitxml='+str(folder/(stem+'.xml'))]
        env=os.environ.copy()
        start=time.monotonic()
        with (folder/(stem+'.log')).open('w',encoding='utf8') as f:
            try:
                process=subprocess.run(command,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=1800)
                code=process.returncode;timed_out=False
            except subprocess.TimeoutExpired:
                code=None;timed_out=True
        item=dict(file=name,command=command,exit_code=code,timed_out=timed_out,seconds=time.monotonic()-start,
            log=stem+'.log',junit=stem+'.xml',journal=stem+'.jsonl')
        results.append(item);save(folder/'processes.json',results)
        print('SPLIT_FILE_COMPLETE',index+1,len(files),name,code,flush=True)
    save(folder/'complete.json',dict(seconds=time.monotonic()-all_started,files=len(files),
        execution='outside-sandbox',all_files_attempted=True))
    print('FULL_SPLIT_COMPLETE',len(files),flush=True)


def safe_regression():
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import tempfile
    import shutil
    folder=OUT/'full_regression_safe';folder.mkdir(exist_ok=True)
    if (folder/'started.json').exists():raise ValueError('safe_run_already_exists')
    previous=OUT/'full_regression_split_v2'
    if (previous/'started.json').exists() and (previous/'processes.json').exists():
        files=read(previous/'started.json')['files'];completed=read(previous/'processes.json')
    else:
        files=[];completed=[]
        for node in (OUT/'collection.log').read_text(encoding='utf8').splitlines():
            if '::' not in node:continue
            name=node.split('::')[0];p=ROOT/name
            if not p.is_file():p=ROOT/'backend'/name
            if not p.is_file():p=ROOT/'evaluation/tests'/name
            if not p.is_file():raise ValueError('unresolved_collection_path:'+name)
            relative=p.relative_to(ROOT).as_posix()
            if relative not in files:files.append(relative)
    if any(p['exit_code']!=0 for p in completed):raise ValueError('unsafe_reuse_of_failed_process')
    results=[]
    for p in completed:
        row=dict(p,reused_completed_prefix=True)
        for name in ('log','junit'):row[name]=str(previous/p[name])
        row['journal']=None;results.append(row)
    legacy=Path(tempfile.mkdtemp(prefix='traceback-v52-legacy-'))
    started=time.monotonic()
    save(folder/'started.json',dict(files=files,collected=2385,reused_prefix=len(results),parallel_file_processes=2,
        execution='outside-sandbox',legacy_output_root=str(legacy),timeout_per_file_seconds=2400,
        started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        output_isolation='Exact preexisting output-relocation pattern; same four copied reference inputs and unchanged assertions. Historical outputs/data protected by audit write guard. Temporary artifacts archived after each file.',
        config='backend/pyproject.toml',observer_plugin_enabled=False))
    save(folder/'processes.json',results)
    done={p['file'] for p in results}
    def execute(index,name):
        stem=f'{index:03d}_'+Path(name).stem;temp=legacy/stem;temp.mkdir()
        command=[sys.executable,'-B','-m','pytest',name,'-c','backend/pyproject.toml','-q','-p','no:cacheprovider',
            '-p','evaluation.framework.final_review.legacy_output_plugin','--junitxml='+str(folder/(stem+'.xml'))]
        env=os.environ.copy();env['TRACEBACK_REVIEW_LEGACY_OUTPUT']=str(temp)
        start=time.monotonic()
        with (folder/(stem+'.log')).open('w',encoding='utf8') as f:
            try:
                process=subprocess.run(command,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=2400)
                code=process.returncode;timed_out=False
            except subprocess.TimeoutExpired:code=None;timed_out=True
        if any(temp.iterdir()):shutil.copytree(temp,folder/'legacy_outputs'/stem)
        return dict(file=name,command=command,exit_code=code,timed_out=timed_out,seconds=time.monotonic()-start,
            log=str(folder/(stem+'.log')),junit=str(folder/(stem+'.xml')),journal=None,
            relocated_legacy_output=str(temp),reused_completed_prefix=False)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures={pool.submit(execute,index,name):name for index,name in enumerate(files) if name not in done}
        for future in as_completed(futures):
            row=future.result();results.append(row);results.sort(key=lambda p:files.index(p['file']))
            save(folder/'processes.json',results)
            print('SAFE_FILE_COMPLETE',len(results),len(files),row['file'],row['exit_code'],flush=True)
    save(folder/'complete.json',dict(seconds=time.monotonic()-started,files=len(files),execution='outside-sandbox',
        all_files_attempted=True,reused_prefix_seconds=sum(p['seconds'] for p in completed)))
    print('FULL_SAFE_COMPLETE',len(files),flush=True)


def retry_selection():
    import tempfile
    import shutil
    folder=OUT/'selection_isolation_retry';folder.mkdir(exist_ok=False)
    legacy=Path(tempfile.mkdtemp(prefix='traceback-v52-selection-'))
    command=[sys.executable,'-B','-m','pytest','backend/tests/test_cptc_t5_dev_10k.py','-c','backend/pyproject.toml',
        '-q','-p','no:cacheprovider','-p','evaluation.framework.final_review.legacy_output_plugin',
        '--junitxml='+str(folder/'result.xml')]
    env=os.environ.copy();env['TRACEBACK_REVIEW_LEGACY_OUTPUT']=str(legacy)
    start=time.monotonic()
    save(folder/'started.json',dict(command=command,execution='outside-sandbox',timeout_seconds=600,
        correction='Only selection output destination moves to an owned ROOT-local temporary directory to meet existing relative_to(ROOT) and path tripwire requirements; archived and cleaned after session.',
        original_failed_attempt='full_regression_safe/029_test_cptc_t5_dev_10k.xml'))
    with (folder/'result.log').open('w',encoding='utf8') as f:
        try:
            r=subprocess.run(command,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=600)
            code=r.returncode;timeout=False
        except subprocess.TimeoutExpired:code=None;timeout=True
    if any(legacy.iterdir()):shutil.copytree(legacy,folder/'legacy_outputs')
    save(folder/'process.json',dict(file='backend/tests/test_cptc_t5_dev_10k.py',command=command,execution='outside-sandbox',
        exit_code=code,timed_out=timeout,seconds=time.monotonic()-start,
        log=str(folder/'result.log'),junit=str(folder/'result.xml'),journal=None,
        output_location_only_changed=True,source_assertion_input_unchanged=True))
    print('SELECTION_ISOLATION_RETRY',code,flush=True)


if __name__=='__main__':
    {'prepare':prepare,'regression':regression,'split_regression':split_regression,'safe_regression':safe_regression,'retry_selection':retry_selection}[sys.argv[1]]()

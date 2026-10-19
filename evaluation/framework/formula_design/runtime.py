"""Blind score-only replay of immutable preformula members. No truth imports."""
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import yaml

from . import ROOT, OUT, BASELINE, POLICY
from .model import project, score


def read(path): return json.loads(Path(path).read_text(encoding='utf8'))


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n',encoding='utf8')


def rows(path):
    with gzip.open(path,'rt',encoding='utf8') as f:
        for line in f:yield json.loads(line)


@contextmanager
def guard(allowed, destination):
    allowed={Path(p).resolve() for p in allowed};destination=destination.resolve()
    active=[True];events=[];reads=set()
    def audit(event,args):
        if not active[0]:return
        if event in {'subprocess.Popen','os.system','socket.connect'}:
            events.append(dict(event=event));raise PermissionError('blind_process_or_network')
        if event!='open':return
        name,mode,flags=args
        if isinstance(name,int):raise PermissionError('blind_fd')
        p=Path(os.fsdecode(name)).resolve();writing=bool(flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
        permitted=p.is_relative_to(destination) if writing else p in allowed or p.is_relative_to(destination)
        if not permitted:
            events.append(dict(event=event,path=str(p),writing=writing));raise PermissionError('blind_non_allowlisted:'+str(p))
        if not writing:reads.add(str(p))
    sys.addaudithook(audit)
    try:yield events,reads
    finally:active[0]=False


ABLATIONS=('remove_time','remove_role_aware_entity','remove_conflict_redesign','remove_coverage_confidence','remove_interactions')
VARIANTS=('F0','F1','F2','F3')+ABLATIONS+('gate_hard','gate_soft','equal_reliability')


def prepare():
    from evaluation.framework.preformula_baseline.boundary import verify_current
    from evaluation.framework.preformula_baseline.replay import seal as baseline_seal
    from evaluation.framework.v4_semisynthetic_baseline.common import inventory,DATASET
    if (OUT/'preparation.json').exists():raise ValueError('immutable_preparation_exists')
    receipt=verify_current();seal=baseline_seal()
    old=read(BASELINE/'manifest.json')
    # Historical artifacts, including all blind files, are hash-checked read-only.
    paths={BASELINE/name:h for name,h in old['files'].items()}
    paths.update({BASELINE/name:h for name,h in seal['files'].items()})
    # The existing history verifier writes its report; reproduce its byte checks here.
    anchors=read(BASELINE/'integration_before.json')['historical_files']
    anchors.update(read(BASELINE/'historical_additional.json'))
    for name,h in anchors.items():
        if sha(ROOT/name)!=h:raise ValueError('historical_changed:'+name)
        paths[ROOT/name]=h
    for p,h in paths.items():
        if sha(p)!=h:raise ValueError('baseline_artifact_changed:'+str(p))
    files={p.relative_to(ROOT).as_posix():sha(p) for p in sorted((ROOT/'evaluation/framework/formula_design').glob('*.py'))}
    files[POLICY.relative_to(ROOT).as_posix()]=sha(POLICY)
    from evaluation.tests.test_v5_formula_design import counterexamples
    safety=counterexamples(yaml.safe_load(POLICY.read_text(encoding='utf8')))
    save(OUT/'synthetic_counterexamples.json',safety)
    if not all(v['pass_'] for v in safety.values()):raise ValueError('synthetic_safety_failed')
    save(OUT/'preparation.json',dict(baseline_identity=receipt,baseline_seal_sha256=sha(BASELINE/'blind_run_manifest.json'),
        protected_files={p.relative_to(ROOT).as_posix():h for p,h in paths.items()},
        dataset_inventory=inventory(DATASET),production_inventory=inventory(ROOT,production=True),
        implementation=files,policy=yaml.safe_load(POLICY.read_text(encoding='utf8')),
        variants=VARIANTS,selection_policy='semantic safety first; strict pairwise improvement; all four tails within F0 + 0.05; no tuning',
        input_kind='immutable sealed canonical, candidate/member diagnostics; no candidate regeneration',
        planned_score_only_replay=True,ground_truth_loaded=False))
    print('PREPARED',flush=True)


def require_sealed():
    m=read(OUT/'blind_manifest.json')
    if m['status']!='completed' or m['ground_truth_loaded'] or m['threshold']!=.65:raise ValueError('unsealed')
    for name,h in m['files'].items():
        p=(OUT/name).resolve()
        if not p.is_relative_to((OUT/'blind').resolve()) or sha(p)!=h:raise ValueError('prediction_changed:'+name)
    if sha(OUT/'preparation.json')!=m['preparation_sha256']:raise ValueError('preparation_changed')
    prepared=read(OUT/'preparation.json')
    for name,h in prepared['implementation'].items():
        if sha(ROOT/name)!=h:raise ValueError('experimental_implementation_changed:'+name)
    return m


def blind():
    if (OUT/'blind_manifest.json').exists() or (OUT/'evaluation_started.json').exists():raise ValueError('single_use_before_truth')
    prepared=read(OUT/'preparation.json');policy=prepared['policy']
    for name,h in prepared['implementation'].items():
        if sha(ROOT/name)!=h:raise ValueError('experimental_implementation_changed:'+name)
    paths=[BASELINE/'blind'/n for n in ('canonical.jsonl.gz','diagnostics.jsonl.gz','input_line_map.json')]
    destination=OUT/'blind';destination.mkdir(parents=True,exist_ok=False)
    started=time.perf_counter();count=0;candidates=set();scored=set();max_error=0.;digest=hashlib.sha256();metamorphic=0
    with guard(paths,destination) as (events,reads):
        alerts={a['alert_id']:a for a in rows(paths[0])}
        save(destination/'input_line_map.json',read(paths[2]))
        with gzip.open(destination/'predictions.jsonl.gz','wt',encoding='utf8',compresslevel=1) as f:
            for row in rows(paths[1]):
                if row['stage']=='candidate':
                    candidates.add(tuple(row['support_key']))
                    digest.update(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
                if row['stage']!='member_score':continue
                env=project(row,alerts,policy);audit=row['evidence']['evidence_v2']
                if count<64:
                    from dataclasses import replace
                    changed=replace(env,evidence=tuple(replace(e,provenance=({'alert_id':'arbitrary-marker','pointer':'/GT-label'},)) for e in reversed(env.evidence)))
                    for model in ('F0','F1','F2','F3'):
                        if abs(score(env,policy,model)['final_score']-score(changed,policy,model)['final_score'])>1e-12:raise ValueError('identity_or_order_leakage')
                    metamorphic+=1
                # Independent reconstruction from the original dimensions, before role changes.
                weights=audit['family_weights'];fs={};available=[]
                for family,w in weights.items():
                    ds=[d for d in audit['dimensions'] if d['family']==family and d['state'].startswith('AVAILABLE')]
                    if ds:
                        available.append(family);den=sum(d['weight'] for d in ds)
                        fs[family]=max(d['strength'] for d in ds) if family=='relation' else sum(d['weight']*d['strength'] for d in ds)/den
                aw=sum(weights[k] for k in available);mw=sum(weights[k]*fs[k] for k in available)
                expected=max(0.,min(1.,.65*mw/aw+.35*mw/sum(weights.values())-policy['conflict_weight']*row['values']['conflict']-policy['duplicate_weight']*row['values']['duplicate']))
                max_error=max(max_error,abs(expected-row['score']))
                if max_error>1e-12:raise ValueError('v4_reconstruction_mismatch')
                results={m:score(env,policy,m) for m in ('F0','F1','F2','F3')}
                results.update({a:score(env,policy,'F3',ablation=a) for a in ABLATIONS})
                results.update({f'gate_{g}':score(env,policy,'F3',gate_mode=g) for g in ('hard','soft')})
                from dataclasses import replace
                equal=replace(env,evidence=tuple(replace(e,reliability=1.) for e in env.evidence))
                results['equal_reliability']=score(equal,policy,'F3')
                # One full evidence envelope per member. Each formula has numerical decomposition;
                # explain() reconstructs exact evidence partitions without another scoring run.
                shared={k:results['F3'][k] for k in ('supporting_evidence','weak_evidence','unavailable_evidence','observed_zero_evidence','contradictions')}
                compact={m:{k:v for k,v in r.items() if k not in shared} for m,r in results.items()}
                out=dict(support_pair=row['support_pair'],support_key=row['support_key'],results=compact,
                         evidence=shared,v4_family_strengths=audit['family_strengths'],v4_available_weight=aw,
                         v4_dimensions=audit['dimensions'])
                f.write(json.dumps(out,separators=(',',':'),allow_nan=False)+'\n')
                scored.add(tuple(row['support_key']));count+=1
                if count%25000==0:print(json.dumps(dict(stage='formula_blind',members=count,seconds=time.perf_counter()-started)),flush=True)
        if candidates!=scored:raise ValueError('candidate_members_incomplete')
        save(destination/'guard_receipt.json',dict(rejected_events=events,non_code_reads=sorted(reads),ground_truth_loaded=False,guard_type='Python audit tripwire; not an OS sandbox'))
    save(OUT/'blind_manifest.json',dict(status='completed',ground_truth_loaded=False,threshold=policy['threshold'],
        algorithm_version=policy['version'],preparation_sha256=sha(OUT/'preparation.json'),
        candidate_count=len(candidates),scored_candidate_count=len(scored),member_count=count,
        raw_alert_count=len(alerts),
        candidate_digest=digest.hexdigest(),v4_max_reconstruction_error=max_error,
        actual_member_identity_order_metamorphic_checks=metamorphic,
        elapsed_seconds=time.perf_counter()-started,
        files={p.relative_to(OUT).as_posix():sha(p) for p in destination.iterdir() if p.is_file()}))
    print('BLIND_SEALED',count,flush=True)


if __name__=='__main__':
    {'prepare':prepare,'blind':blind}[sys.argv[1]]()

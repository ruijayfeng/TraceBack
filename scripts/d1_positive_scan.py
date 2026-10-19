"""D.1: bounded, label-free multiscale diagnosis of the frozen production v4.

The scan policy is published before computation. Each subprocess runs the
unchanged adapters, dedupe, entities, Candidate v1.1, scoring and reconstruction.
Only diagnostic transport is implemented here; no algorithm overrides exist.
"""
import argparse
from array import array
import builtins
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import io
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
sys.path.insert(0, str(ROOT / 'scripts'))
from find_demo_dataset import adapter, records, stamp, frozen, atomic_json
from app.services.datasets import load_dataset
from app.services.storage import file_digest
from app.utils.stable_id import content_digest, utc_text

OUT = ROOT / 'outputs/d1_positive_scan'
CUTS = (.65, .67, .68, .69, .70, .75)
EXPECTED = dict(algorithm_version='alert-correlation-v4-role-context-candidate-v1.1',
    config_hash='750985ec85a32c2c2619cc1bbfb259fcabe1c8874a57663ada071f2d6d23ae55',
    mapping_digest='aba87d612711cc4cb67998df9604b62b61a3fb72b01c165d1745594b8a538658',
    edge_threshold=.65, cluster_threshold=.70)
POLICY = dict(version='d1-bounded-multiscale-v1', scales_seconds=[900,1800,3600,7200,14400],
    stride_seconds=900, windows_per_scenario_per_scale=2, min_raw=20, max_raw=2500,
    nomination=['highest account/resource field coverage per record', 'highest bilateral source balance; temporal median fallback'],
    known_replay=dict(scenario='wilson', start='2022-02-03T20:15:00.000000Z'),
    known_replay_expansion='same start at each scale; retain all records',
    optional_8h='only if complete known-replay 4h has a formal edge >=0.68 and max_raw permits',
    worker_timeout_seconds=180, worker_concurrency=1, labels_used=False,
    window_semantics='[start,end)', top_n=20, production_candidate_budget='unchanged frozen config')


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


@contextmanager
def no_truth_reads():
    """Runtime tripwire covers Path.open as well as builtins.open."""
    old_builtin, old_io = builtins.open, io.open
    def wrap(original):
        def guarded(path, *args, **kwargs):
            if isinstance(path, (str, Path)):
                normalized = str(path).replace('\\', '/').lower()
                if '/evaluation/' in normalized or Path(normalized).name in {'labels.csv','attacks.log'}:
                    raise PermissionError('D1_ground_truth_read_forbidden:' + normalized)
            return original(path, *args, **kwargs)
        return guarded
    builtins.open, io.open = wrap(old_builtin), wrap(old_io)
    try:
        yield
    finally:
        builtins.open, io.open = old_builtin, old_io


def freeze_check():
    loaded = load_dataset(ROOT, scene_id='russellmitchell', config_version='v4')
    receipt = frozen(loaded)
    actual = {k:receipt[k] for k in ('algorithm_version','config_hash','mapping_digest')}
    actual.update(edge_threshold=loaded.config.algorithm.score.correlation_threshold,
                  cluster_threshold=loaded.config.algorithm.clustering.edge_threshold)
    basis = {'algorithm':receipt['algorithm_snapshot'],
             'sources':{v['source_namespace']:v for v in receipt['source_settings'].values()}}
    if actual != EXPECTED or content_digest(basis) != EXPECTED['config_hash']:
        raise ValueError('D1_INVALID_ALGORITHM_MODIFIED')
    return actual


def protected_files():
    files = [ROOT/'AGENTS.md', ROOT/'data/ait_ads/dataset.yaml']
    for folder in ('backend/app','configs','docs','frontend/src','scripts'):
        files.extend(p for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    return {p.relative_to(ROOT).as_posix():file_digest(p) for p in sorted(set(files))}


def epoch(text):
    return int(datetime.fromisoformat(text.replace('Z','+00:00')).timestamp())


def utc(seconds):
    return utc_text(datetime.fromtimestamp(seconds, timezone.utc))


def in_window(when, window):
    # datetime comparison keeps subsecond boundaries intact.
    return datetime.fromisoformat(window['start_time'].replace('Z','+00:00')) <= when < datetime.fromisoformat(window['end_time'].replace('Z','+00:00'))


def inventory_window(scene, bins, start, duration, nomination):
    counts, fields = Counter(), Counter()
    for b, value in bins.items():
        if start <= int(b) < start+duration:
            counts.update(value['raw_counts'])
            fields.update(value['fields'])
    return dict(scenario=scene,start_time=utc(start),end_time=utc(start+duration),duration_seconds=duration,
        expected_raw_count=sum(counts.values()), raw_source_counts=dict(counts), field_counts=dict(fields),
        nomination=nomination)


def nominate(inventory):
    windows = []
    for scene, entry in sorted(inventory.items()):
        bins = entry.get('bins',{})
        for duration in POLICY['scales_seconds']:
            options = [inventory_window(scene,bins,int(b),duration,'inventory') for b in sorted(bins,key=int)]
            options = [w for w in options if POLICY['min_raw'] <= w['expected_raw_count'] <= POLICY['max_raw']]
            ranked = sorted(options,key=lambda w:(-(w['field_counts'].get('account',0)+w['field_counts'].get('resource_or_flow',0))/w['expected_raw_count'],w['start_time']))
            selected = ranked[:1]
            remaining = [w for w in options if w not in selected]
            mixed = sorted((w for w in remaining if all(w['raw_source_counts'].get(s,0) for s in ('aminer','wazuh'))),
                key=lambda w:(-min(w['raw_source_counts'].values())/w['expected_raw_count'],w['start_time']))
            if selected:
                selected[0]['nomination']='structured_field_coverage'
            if mixed:
                mixed[0]['nomination']='bilateral_source_balance'
                selected.append(mixed[0])
            elif remaining:
                remaining.sort(key=lambda w:w['start_time'])
                w=remaining[(len(remaining)-1)//2]
                w['nomination']='temporal_median'
                selected.append(w)
            windows.extend(selected)
    known = POLICY['known_replay']
    for duration in POLICY['scales_seconds']:
        windows.append(inventory_window(known['scenario'],inventory[known['scenario']]['bins'],epoch(known['start']),duration,'user_required_replay_and_continuous_expansion'))
    unique = {}
    for w in windows:
        key=(w['scenario'],w['start_time'],w['end_time'])
        unique[key]=w
    return sorted(unique.values(),key=lambda w:(w['scenario']!='wilson',w['scenario'],w['duration_seconds'],w['start_time']))


def quantiles(values):
    ordered=sorted(values)
    def q(fraction):
        if not ordered:
            return None
        at=(len(ordered)-1)*fraction
        lo,hi=math.floor(at),math.ceil(at)
        return ordered[lo]+(ordered[hi]-ordered[lo])*(at-lo)
    return dict(max_score=ordered[-1] if ordered else None,P99=q(.99),P95=q(.95),P90=q(.90),
                cutoffs={str(c):sum(v>=c for v in values) for c in CUTS})


class Observer:
    """One complete member winner per candidate, using production's tie-break."""
    def __init__(self, alerts):
        self.alerts=alerts
        self.scores=array('d')
        self.valid_scores=array('d')
        self.top=[]
        self.formal=[]
        self.cluster=[]
        self.winner=None
        self.observed=None
        self.candidate=None
        self.member_count=0
        self.decisions=Counter()
    def __call__(self,row):
        stage=row.get('stage')
        if stage=='candidate':
            self.candidate=row
            self.winner=self.observed=None
        elif stage=='member_score':
            self.member_count+=1
            a,b=row['support_pair']
            key=(-row['score'],self.alerts[a].timestamp,self.alerts[b].timestamp,a,b)
            if self.observed is None or key<self.observed[0]:
                self.observed=(key,row)
            if row['valid'] and (self.winner is None or key<self.winner[0]):
                self.winner=(key,row)
        elif stage=='correlation_decision':
            member=(self.winner or self.observed)[1]
            self.scores.append(member['score'])
            if member['valid']:
                self.valid_scores.append(member['score'])
            self.decisions[member['evidence']['evidence_v2']['decision']]+=1
            packed=dict(member=member,candidate=self.candidate,decision=row)
            self.top.append(packed)
            self.top.sort(key=lambda r:(-r['member']['score'],r['member']['support_pair']))
            del self.top[20:]
            if row['decision']=='accept':
                self.formal.append(packed)
        elif stage=='clustering':
            self.cluster.append(row)


def pair_detail(packed,index,scorer,window):
    row,candidate,decision=packed['member'],packed['candidate'],packed['decision']
    a,b=[index.alerts[i] for i in row['support_pair']]
    evidence=row['evidence']['evidence_v2']
    shared=sorted(set(a.entity_ids)&set(b.entity_ids))
    refs=[]
    for fact in evidence['evidence']:
        for ref in fact['evidence_refs']:
            from app.models.base import resolve_pointer
            if ref['alert_id'] not in row['support_pair']:
                raise ValueError('evidence_outside_support_pair')
            value=resolve_pointer(index.alerts[ref['alert_id']].raw_alert,ref['pointer'])
            refs.append({**ref,'resolved_value':value})
    relations,_=scorer.verify_relations(a,b)
    types=sorted({r.relation_type for r in relations},key=scorer.algorithm.chain.relation_priority.index)
    return dict(scenario=window['scenario'],window_start=window['start_time'],window_end=window['end_time'],
        alert_a_id=a.alert_id,alert_b_id=b.alert_id,timestamp_a=a.timestamp,timestamp_b=b.timestamp,
        time_delta_seconds=abs((datetime.fromisoformat(a.timestamp.replace('Z','+00:00'))-datetime.fromisoformat(b.timestamp.replace('Z','+00:00'))).total_seconds()),
        score=row['score'],support_key=row['support_key'],relation_type=types or [],
        relation_mapping_result=scorer.algorithm.chain.relation_type_mapping[types[0]] if types else 'REJECT_NO_RELATION',
        shared_entities=[index.entities[e].model_dump(mode='json') for e in shared],
        entity_roles={x.alert_id:[o.model_dump(mode='json') for o in x.entity_occurrences] for x in (a,b)},
        context_evidence=evidence.get('entity_reliability',[]),primary_evidence=evidence['primary_evidence'],
        supporting_evidence=evidence['supporting_evidence'],evidence_families=evidence['evidence_families'],
        independent_evidence_count=evidence['strong_evidence_count'],source_independence=row['source_independence'],
        sources=[dict(alert_id=x.alert_id,source_type=x.source_type.value,rule_id=x.rule_id,signature=x.signature,category=x.category.value,sensor=x.sensor) for x in (a,b)],
        candidate_admission_reason=candidate,guard_result=dict(valid=row['valid'],rejection_codes=row['rejection_codes'],gate=evidence['gate_reason']),
        formal_edge_accepted=decision['decision']=='accept',edge_id=decision.get('edge_id'),
        cluster_eligible=decision['decision']=='accept' and row['score']>=EXPECTED['cluster_threshold'],
        reasons=row['reasons'],values=row['values'],contributions=row['contributions'],raw_total=row['raw_total'],
        evidence=evidence,resolved_evidence_refs=refs,
        raw_alerts={x.alert_id:dict(raw_alert=x.raw_alert,raw_fingerprint=x.raw_fingerprint,source_namespace=x.source_namespace,source_record_id=x.source_record_id) for x in (a,b)},
        evidence_traceable=True)


def graph_diagnostic(index,edges,incidents):
    owner={rep:rep for rep in index.representatives}
    components={rep:{rep} for rep in index.representatives}
    for edge in edges:
        a,b=owner[edge.source_alert_id],owner[edge.target_alert_id]
        if a!=b:
            root=min(a,b)
            merged=components.pop(a)|components.pop(b)
            components[root]=merged
            for rep in merged:
                owner[rep]=root
    multi=sorted((sorted(c) for c in components.values() if len(c)>1),key=lambda c:(-len(c),c))
    return dict(number_of_nodes=index.N,number_of_edges=len(edges),connected_components=len(components),
        singleton_count=sum(len(c)==1 for c in components.values()),multi_node_component_count=len(multi),
        largest_component_size=max(map(len,components.values()),default=0),non_singleton_components=multi,
        degree_distribution=dict(Counter(Counter([x for e in edges for x in (e.source_alert_id,e.target_alert_id)]).values())),
        incident_sizes=dict(Counter(len({index.owner[a] for a in i.alert_ids}) for i in incidents)))


def analyze(window,raw,loaded,score_file=None):
    from app.dedup import deduplicate
    from app.entities.extraction import extract_entities
    from app.correlation.edges import run_correlation
    from app.correlation.index import AlertIndex
    from app.correlation.scoring import CorrelationScorer
    from app.chains.assembly import run_reconstruction
    frozen(loaded)
    started=time.perf_counter()
    settings={k:s for k,(_,s) in loaded.sources.items()}
    by_id,rejected={},[]
    for source,items in sorted(raw.items()):
        batch=adapter(loaded,source).batch(items)
        rejected.extend(str(r) for r in batch.rejected)
        by_id.update({a.alert_id:a for a in batch.alerts})
    alerts=[by_id[k] for k in sorted(by_id)]
    if not alerts:
        return {**window,'status':'INPUT_REJECTED','rejected':rejected}
    dedupe=deduplicate(alerts,loaded.config,settings)
    extracted=extract_entities(alerts,settings)
    alerts,entities=extracted.alerts,extracted.entities
    obs=Observer({a.alert_id:a for a in alerts})
    cor=run_correlation(alerts,dedupe.groups,entities,loaded.config,settings,diagnostic_sink=obs)
    reconstruction=run_reconstruction(alerts,dedupe.groups,entities,cor.edges,loaded.config,settings,
        upstream_record=cor.record,diagnostic_sink=obs)
    idx=AlertIndex(alerts,dedupe.groups,entities)
    scorer=CorrelationScorer(idx,loaded.config,settings,cor.record.config_hash)
    # Formal positives are always retained, even if rejected high scores occupy Top20.
    chosen={tuple(p['member']['support_key']):p for p in obs.top+obs.formal}
    details=[pair_detail(p,idx,scorer,window) for p in sorted(chosen.values(),key=lambda p:(-p['member']['score'],p['member']['support_key']))]
    # Multi-fact incidents exclude groups containing only duplicate observations.
    multi=[i for i in reconstruction.incidents if len({idx.owner[a] for a in i.alert_ids})>1]
    result={**window,'status':'COMPLETE' if not rejected and dedupe.is_complete and reconstruction.record.is_complete else 'RESOURCE_LIMITED',
        'raw_alert_count':sum(map(len,raw.values())),'canonical_alert_count':len(alerts),'representative_alert_count':idx.N,
        'candidate_pair_count':cor.summary['admitted_candidate_count'],'scored_pair_count':cor.summary['scored_candidate_count'],
        'scored_member_pair_count':obs.member_count,'accepted_edge_count':len(cor.edges),'formal_edge_count':len(cor.edges),
        'cluster_eligible_edge_count':sum(p['member']['score']>=.70 for p in obs.formal),
        'incident_count':len(reconstruction.incidents),'multi_alert_incident_count':len(multi),
        'raw_multi_alert_incident_count':sum(len(i.alert_ids)>1 for i in reconstruction.incidents),
        **quantiles(obs.scores),'valid_pair_distribution':quantiles(obs.valid_scores),'decision_distribution':dict(obs.decisions),
        'formal_edge_cutoffs':{str(c):sum(p['member']['score']>=c for p in obs.formal) for c in CUTS},
        'gap_formal_edge_count':sum(.65<=p['member']['score']<.70 for p in obs.formal),
        'graph':graph_diagnostic(idx,cor.edges,reconstruction.incidents),'clustering_diagnostics':obs.cluster,
        'formal_edges':[e.model_dump(mode='json') for e in cor.edges],
        'multi_alert_incidents':[i.model_dump(mode='json') for i in multi],
        'top_relation_types':dict(Counter(d['relation_mapping_result'] for d in details if d['formal_edge_accepted'])),
        'sources_present':dict(Counter(a.source_type.value for a in alerts)),
        'cross_source_formal_edge_count':sum(idx.alerts[e.support_pair.alert_id_src].source_type!=idx.alerts[e.support_pair.alert_id_dst].source_type for e in cor.edges),
        'evidence_quality_summary':dict(traceable=all(d['evidence_traceable'] for d in details),primary_families=sorted({f['family'] for d in details if d['formal_edge_accepted'] for f in d['evidence']['evidence'] if f['role']=='primary'})),
        'top_pairs':details,'grounding':reconstruction.grounding.json_data(),
        'analysis_id':cor.record.analysis_id,'reconstruction_analysis_id':reconstruction.record.analysis_id,
        'config_hash':cor.record.config_hash,'mapping_digest':loaded.config.mapping_digest,
        'dataset_digest':cor.record.dataset_digest,'input_alert_ids_digest':content_digest(sorted(by_id)),
        'formal_result_digest':content_digest({'edges':[e.model_dump(mode='json') for e in cor.edges],
            'incidents':[i.model_dump(mode='json') for i in reconstruction.incidents],
            'chains':[c.model_dump(mode='json') for c in reconstruction.chains]}),
        'policy_pruned_count':cor.summary['policy_pruned_count'],'resource_truncated_count':cor.summary['resource_truncated_count'],
        'rejected_count':len(rejected),'rejected':rejected[:3],'runtime_seconds':time.perf_counter()-started,
        'frequency_snapshot':idx.frequency_snapshot() if cor.edges else None}
    if not reconstruction.grounding.valid:
        raise ValueError('D1_IMPLEMENTATION_DEFECT_FOUND:grounding')
    if score_file is not None:
        with Path(score_file).open('wb') as handle:
            obs.scores.tofile(handle)
    return result


def worker(args):
    window=read_json(args.window)
    raw={'aminer':[],'wazuh':[]}
    with no_truth_reads():
        loaded=load_dataset(ROOT,scene_id=window['scenario'],config_version='v4')
        for row in records(args.raw):
            when=stamp(row['raw'],row['source'],adapter(loaded,row['source']))
            if not in_window(when,window):
                raise ValueError('non_continuous_window_record')
            raw[row['source']].append(row['raw'])
        if sum(map(len,raw.values()))!=window['expected_raw_count']:
            raise ValueError('raw_window_count_mismatch')
        result=analyze(window,raw,loaded,args.scores)
        atomic_json(Path(args.result),result)


def execute_worker(window,raw_path,tmp,*,repeat=False,pooled_scores=None):
    key=content_digest([window['scenario'],window['start_time'],window['end_time']])[:16]
    spec=tmp/(key+'.window.json')
    result=tmp/(key+('.repeat' if repeat else '')+'.result.json')
    score_file=tmp/(key+'.scores.bin')
    atomic_json(spec,window)
    command=[sys.executable,str(Path(__file__).resolve()),'worker','--window',str(spec),'--raw',str(raw_path),'--result',str(result),'--scores',str(score_file)]
    started=time.perf_counter()
    try:
        process=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,encoding='utf8',timeout=POLICY['worker_timeout_seconds'])
    except subprocess.TimeoutExpired:
        return {**window,'status':'RESOURCE_LIMITED','resource_reason':'worker_timeout','runtime_seconds':time.perf_counter()-started}
    if process.returncode:
        raise ValueError('D1_worker_failure:'+process.stderr[-3000:])
    value=read_json(result)
    if pooled_scores is not None and value['status']=='COMPLETE':
        with score_file.open('rb') as handle:
            pooled_scores.fromfile(handle,score_file.stat().st_size//8)
    return value


def scan():
    OUT.mkdir(parents=True,exist_ok=True)
    if (OUT/'scan_summary.json').exists():
        raise ValueError('D1_completed_scan_cannot_be_overwritten')
    before=freeze_check()
    protected=protected_files()
    atomic_json(OUT/'freeze_before.json',{'frozen':before,'protected_files':protected})
    inventory=read_json(ROOT/'outputs/final_demo/time_index.json')
    windows=nominate(inventory)
    plan=dict(policy=POLICY,windows=windows,inventory_digest=content_digest(inventory),
        inventory_basis='timestamp/volume/structured field availability only; verify raw source SHA256 before reuse',
        source_files={s:e['sources'] for s,e in inventory.items()})
    atomic_json(OUT/'search_plan.json',plan)
    results=[]
    pooled_scores=array('d')
    replay=None
    # Temporary artifacts live strictly inside this task's output directory.
    with tempfile.TemporaryDirectory(prefix='d1-temporary-',dir=OUT) as temporary:
        tmp=Path(temporary)
        for scene in sorted(inventory,key=lambda s:(s!='wilson',s)):
            loaded=load_dataset(ROOT,scene_id=scene,config_version='v4')
            frozen(loaded)
            scene_windows=[w for w in windows if w['scenario']==scene]
            # Pre-extract the conditional 8h interval, but do not analyze unless the published rule qualifies.
            extra=inventory_window(scene,inventory[scene]['bins'],epoch(POLICY['known_replay']['start']),28800,'conditional_8h_extension') if scene=='wilson' else None
            extract=scene_windows+([extra] if extra and extra['expected_raw_count']<=POLICY['max_raw'] else [])
            handles={}
            paths={}
            counts=Counter()
            for n,w in enumerate(extract):
                path=tmp/(scene+f'-{n}.jsonl')
                paths[(w['start_time'],w['end_time'])]=path
                handles[(w['start_time'],w['end_time'])]=path.open('w',encoding='utf8')
            try:
                for item in loaded.inputs:
                    src,path=item['source'],ROOT/item['path']
                    origin=inventory[scene]['sources'][src]
                    if file_digest(path)!=origin['sha256']:
                        raise ValueError('inventory_source_changed:'+str(path))
                    ad=adapter(loaded,src)
                    total=0
                    with no_truth_reads():
                        for raw in records(path):
                            when=stamp(raw,src,ad)
                            line=None
                            for w in extract:
                                if in_window(when,w):
                                    key=(w['start_time'],w['end_time'])
                                    if line is None:
                                        line=json.dumps({'source':src,'raw':raw},ensure_ascii=False)+'\n'
                                    handles[key].write(line)
                                    counts[key]+=1
                            total+=1
                    if total!=origin['count'] or file_digest(path)!=origin['sha256']:
                        raise ValueError('source_changed_during_extraction')
                    print(json.dumps({'extracted':scene,'source':src,'records':total}),flush=True)
            finally:
                for handle in handles.values():
                    handle.close()
            for w in scene_windows:
                key=(w['start_time'],w['end_time'])
                if counts[key]!=w['expected_raw_count']:
                    raise ValueError('inventory_interval_count_mismatch')
                r=execute_worker(w,paths[key],tmp,pooled_scores=pooled_scores)
                results.append(r)
                if scene=='wilson' and w['start_time']==POLICY['known_replay']['start'] and w['duration_seconds']==900:
                    repeated=execute_worker(w,paths[key],tmp,repeat=True)
                    replay=dict(scenario=scene,start_time=w['start_time'],first=r['formal_result_digest'],second=repeated.get('formal_result_digest'),
                        deterministic=r['formal_result_digest']==repeated.get('formal_result_digest'),prior_expected_score=.6587452232136708,
                        observed_formal_max=max((d['score'] for d in r['top_pairs'] if d['formal_edge_accepted']),default=None))
                    if not replay['deterministic']:
                        raise ValueError('D1_IMPLEMENTATION_DEFECT_FOUND:nondeterministic')
                checkpoint(results,replay,pooled_scores=pooled_scores)
                print(json.dumps({k:r.get(k) for k in ('scenario','duration_seconds','start_time','status','raw_alert_count','max_score','formal_edge_count','multi_alert_incident_count','runtime_seconds')}),flush=True)
            known4=[r for r in results if r['scenario']=='wilson' and r['start_time']==POLICY['known_replay']['start'] and r['duration_seconds']==14400 and r['status']=='COMPLETE']
            if extra and extra['expected_raw_count']<=POLICY['max_raw'] and known4 and any(d['formal_edge_accepted'] and d['score']>=.68 for d in known4[0]['top_pairs']):
                atomic_json(OUT/'conditional_extension.json',dict(window=extra,reason='published 8h rule satisfied',parent_plan_digest=content_digest(plan)))
                r=execute_worker(extra,paths[(extra['start_time'],extra['end_time'])],tmp,pooled_scores=pooled_scores)
                results.append(r)
                checkpoint(results,replay,pooled_scores=pooled_scores)
                print(json.dumps({'conditional_8h':r['status'],'edges':r.get('formal_edge_count'),'multi':r.get('multi_alert_incident_count')}),flush=True)
            for path in paths.values():
                path.unlink()
    after=freeze_check()
    changed=[p for p,h in protected.items() if file_digest(ROOT/p)!=h]
    original_unchanged=all(file_digest(ROOT/f['path'])==f['sha256'] for e in inventory.values() for f in e['sources'].values())
    atomic_json(OUT/'freeze_after.json',dict(frozen=after,before_equals_after=before==after,protected_file_changes=changed,
        original_sources_unchanged=original_unchanged,labels_read=False))
    if before!=after or changed or not original_unchanged:
        raise ValueError('D1_INVALID_ALGORITHM_MODIFIED')
    checkpoint(results,replay,finished=True,pooled_scores=pooled_scores)


def checkpoint(results,replay,finished=False,pooled_scores=()):
    complete=[r for r in results if r['status']=='COMPLETE']
    positives=[r for r in complete if r['formal_edge_count']]
    def rank(r):
        return (-bool(r['multi_alert_incident_count']),-bool(r['cross_source_formal_edge_count']),
            -min(r['formal_edge_count'],10),r['representative_alert_count'],r['duration_seconds'],r['scenario'],r['start_time'])
    positives.sort(key=rank)
    strong=[r for r in positives if r['multi_alert_incident_count'] and r['evidence_quality_summary']['traceable']]
    status='D1_STRONG_POSITIVE_FOUND' if strong else 'D1_EDGE_POSITIVE_ONLY' if positives else 'D1_NO_STRONG_REAL_POSITIVE'
    best=(strong or positives or sorted(complete,key=lambda r:-(r['max_score'] or 0)))[:1]
    pair_rows=[d for r in complete for d in r['top_pairs']]
    formal=[d for d in pair_rows if d['formal_edge_accepted']]
    summary=dict(status=status if finished else 'SCAN_IN_PROGRESS',finished=finished,frozen=EXPECTED,modified=False,
        scenarios=sorted({r['scenario'] for r in results}),window_scales_seconds=sorted({r['duration_seconds'] for r in results}),
        windows_attempted=len(results),windows_evaluated=len(complete),resource_limited_windows=len(results)-len(complete),
        score_population='one best valid complete member pair per admitted candidate, best rejected if none valid; overlapping windows count again',
        cutoffs={str(c):sum(r['cutoffs'][str(c)] for r in complete) for c in CUTS},
        pooled_score_distribution=quantiles(pooled_scores),
        valid_pair_cutoffs={str(c):sum(r['valid_pair_distribution']['cutoffs'][str(c)] for r in complete) for c in CUTS},
        formal_edge_cutoffs={str(c):sum(r['formal_edge_cutoffs'][str(c)] for r in complete) for c in CUTS},
        max_score=max((r['max_score'] or 0 for r in complete),default=None),max_formal_score=max((d['score'] for d in formal),default=None),
        candidate_pair_count=sum(r['candidate_pair_count'] for r in complete),scored_pair_count=sum(r['scored_pair_count'] for r in complete),
        formal_edges=sum(r['formal_edge_count'] for r in complete),unique_formal_edges=len({e['edge_id'] for r in complete for e in r['formal_edges']}),
        cluster_eligible_edges=sum(r['cluster_eligible_edge_count'] for r in complete),multi_alert_incidents=sum(r['multi_alert_incident_count'] for r in complete),
        unique_multi_alert_incidents=len({i['incident_id'] for r in complete for i in r['multi_alert_incidents']}),
        gap_formal_edges=sum(r['gap_formal_edge_count'] for r in complete),known_replay=replay,
        recommended_candidate={k:v for k,v in best[0].items() if k not in ('top_pairs','frequency_snapshot')} if best and positives else None,
        best_formal_pair=max(formal,key=lambda d:d['score']) if formal else None,
        best_scored_pair=max(pair_rows,key=lambda d:d['score']) if pair_rows else None,
        checks=dict(grounding_all_complete=all(r['grounding']['valid'] for r in complete),
            admitted_fully_scored=all(r['candidate_pair_count']==r['scored_pair_count'] for r in complete),
            formal_threshold=all(d['score']>=.65 for d in formal),label_runtime_tripwire=True,
            real_window_replay=replay['deterministic'] if replay else None),
        final_recommendation='PROCEED_TO_DEMO_FREEZE' if strong else 'REAL_DATA_INSUFFICIENT_FOR_FULL_DEMO')
    # Keep per-window statistics, graphs and formal edges; full Top20 transport is separate.
    summary['windows']=[{k:v for k,v in r.items() if k not in ('top_pairs','frequency_snapshot')} for r in results]
    atomic_json(OUT/'scan_summary.json' if finished else OUT/'scan_progress.json',summary)
    atomic_json(OUT/'positive_windows.json',dict(status='RECOMMENDED_DEMO_CANDIDATE' if positives else 'NO_CANDIDATE',
        windows=[{k:v for k,v in r.items() if k!='top_pairs'} for r in positives]))
    atomic_json(OUT/'top_pairs.json',dict(population=summary['score_population'],windows=[dict(scenario=r['scenario'],start_time=r['start_time'],end_time=r['end_time'],pairs=r['top_pairs']) for r in complete]))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['scan','worker'])
    parser.add_argument('--window')
    parser.add_argument('--raw')
    parser.add_argument('--result')
    parser.add_argument('--scores')
    args=parser.parse_args()
    if args.action=='worker':
        worker(args)
    else:
        scan()


if __name__=='__main__':
    main()

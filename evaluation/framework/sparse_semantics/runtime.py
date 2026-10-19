"""One preregistered V5.2 development experiment; all writes stay in evaluation/."""
import collections
import gzip
import json
from pathlib import Path
import sys
import time
import yaml
from .model import project, score
from evaluation.framework.scoring_calibration.model import project as legacy_project
from evaluation.framework.formula_design.runtime import guard
from evaluation.framework.anchor_semantics.runtime import read, save, sha, digest, rows, dump

ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/'evaluation/outputs/v5_2_sparse_semantics'
PREVIOUS=ROOT/'outputs/v5_1_anchor_semantics'
BASE=ROOT/'outputs/v5_source_bound_observability_final'
CAL=ROOT/'outputs/v5_scoring_calibration'
POLICY=ROOT/'evaluation/configs/sparse_semantics.yaml'


def load_policy():
    p=yaml.safe_load(POLICY.read_text(encoding='utf8'))
    if set(p)!={'version','DEVELOPMENT_ONLY','deployment','REFERENCE_THRESHOLD','AMBIGUOUS_RATE_LIMIT','acceptance','formula'}:
        raise ValueError('unknown_or_missing_policy_key')
    if p['deployment'] or not p['DEVELOPMENT_ONLY'] or p['REFERENCE_THRESHOLD']!=.65:
        raise ValueError('scope_or_threshold_changed')
    if not 0<=p['AMBIGUOUS_RATE_LIMIT']<=1:raise ValueError('invalid_ambiguity_limit')
    f=p['formula']
    if set(f)!={'mass_scale','confidence_scale','behavior_weight','qualified_context_weight','task_weight','direct_weight',
        'weak_ceiling','minimum_groups','parent_factor','time_floor','dimensions','contradiction_matrix','paths',
        'operation_classes','compatible_operations','qualified_operation_pairs'}:raise ValueError('unknown_or_missing_formula_key')
    for k in ['mass_scale','confidence_scale','behavior_weight','qualified_context_weight','task_weight','direct_weight']:
        if type(f[k]) not in {int,float} or not 0<f[k]<=2:raise ValueError('invalid_positive_weight')
    for k in ['weak_ceiling','parent_factor','time_floor']:
        if type(f[k]) not in {int,float} or not 0<=f[k]<=1:raise ValueError('invalid_fraction')
    if set(f['dimensions'])!={'context','actor','content','behavior','qualified_context','task','direct'} or len(f['dimensions'])!=7:
        raise ValueError('invalid_dimension_contract')
    if type(f['minimum_groups']) is not int or f['minimum_groups']<2:raise ValueError('invalid_group_count')
    if set(f['qualified_operation_pairs'])!={'execution_context','authentication_context','network_context'}:raise ValueError('invalid_qualified_matrix')
    expected={'request':'TASK_CONTRADICTION','process_start':'IDENTITY_CONTRADICTION','epoch':'CONTEXT_CONTRADICTION',
              'scope':'CONTEXT_CONTRADICTION','temporal':'DIRECTION_CONTRADICTION','original_hard_guard':'INCIDENT_CONTRADICTION'}
    if {k:v['scope'] for k,v in f['contradiction_matrix'].items()}!=expected:raise ValueError('invalid_scope_matrix')
    return p


def audit():
    """Explicitly authorized development-label audit, not a blind validation."""
    if (OUT/'development_audit.json').exists():raise ValueError('audit_exists')
    data=read(PREVIOUS/'labeled_decomposition.json')['existing_development']
    alerts={r['alert_id']:r for r in rows(BASE/'blind_A/canonical.jsonl.gz')}
    save(OUT/'development_audit.json',dict(development_labels_known=True,formula_scored=False,
        GT=[dict(id=r['id'],v5_1=r['result'],alerts=[alerts[i] for i in r['result']['support_pair']]) for r in data if r['positive']]))
    print('AUDITED_DEVELOPMENT_GT',7)


def prepare():
    if (OUT/'manifest.json').exists():raise ValueError('immutable_manifest_exists')
    policy=load_policy();prior=read(PREVIOUS/'manifest.json')
    paths={ROOT/n for n in prior['protected_files']}|{ROOT/n for n in prior['implementation']}
    paths|={p for p in PREVIOUS.iterdir() if p.is_file()}
    paths|={p for p in (PREVIOUS/'predictions').iterdir() if p.is_file()}
    paths|={p for p in (ROOT/'frontend/src').rglob('*') if p.is_file()}
    paths|={p for p in (ROOT/'frontend').iterdir() if p.is_file()}
    paths|={ROOT/'evaluation/tests/test_anchor_semantics.py'}
    implementation={str(p.relative_to(ROOT)):sha(p) for p in Path(__file__).parent.glob('*.py')}
    implementation.update({str(POLICY.relative_to(ROOT)):sha(POLICY),
        'evaluation/tests/test_sparse_semantics.py':sha(ROOT/'evaluation/tests/test_sparse_semantics.py')})
    inputs=[BASE/'blind_A/canonical.jsonl.gz',BASE/'blind_A/entities.jsonl.gz',
            BASE/'blind_A/candidate_pairs.json',CAL/'predictions/member_features.jsonl.gz',PREVIOUS/'stress_input.json']
    save(OUT/'manifest.json',dict(status='PREREGISTERED_BEFORE_SCORING',policy=policy,implementation=implementation,
        protected_files={str(p.relative_to(ROOT)):sha(p) for p in sorted(paths)},
        input_files=[str(p.relative_to(ROOT)) for p in inputs],
        input_hashes={str(p.relative_to(ROOT)):sha(p) for p in inputs},
        candidate_digest=read(BASE/'blind_A/receipt.json')['candidate_digest'],
        development_audit_sha256=sha(OUT/'development_audit.json'),development_labels_already_known=True,
        old_independent_validation_used=False,new_independent_validation=False,
        baseline_metrics=read(PREVIOUS/'evaluation_summary.json')['datasets'],
        acceptance_semantics='Final ADMIT recall and strict REJECT HN rate, plus unchanged score-threshold binary metrics; ambiguity never counts as HN rejection.',
        no_post_evaluation_revision=True))
    print('PREREGISTERED')


def verify():
    m=read(OUT/'manifest.json')
    for n,h in (m['protected_files']|m['implementation']|m['input_hashes']).items():
        if sha(ROOT/n)!=h:raise ValueError('immutable_changed:'+n)
    if sha(OUT/'development_audit.json')!=m['development_audit_sha256']:raise ValueError('audit_changed')
    return m


def verify_predictions():
    m=verify();s=read(OUT/'prediction_seal.json')
    if sha(OUT/'manifest.json')!=s['manifest_sha256']:raise ValueError('manifest_changed')
    for n,h in s['files'].items():
        if sha(OUT/n)!=h:raise ValueError('prediction_changed')
    return m


def predict():
    m=verify();p=m['policy'];policy=p['formula'];threshold=p['REFERENCE_THRESHOLD']
    if (OUT/'prediction_seal.json').exists() or (OUT/'evaluation_started.json').exists():raise ValueError('single_experiment_only')
    dest=OUT/'predictions';dest.mkdir(exist_ok=False)
    inputs=[ROOT/n for n in m['input_files']];count=candidates=0;seen=set();previous=None;best=fallback=None
    started=time.monotonic()
    with guard(inputs,dest) as (denied,reads):
        alerts={r['alert_id']:r for r in rows(inputs[0])};entities={r['entity_id']:r for r in rows(inputs[1])}
        expected={tuple(r) for r in read(inputs[2])}
        with gzip.open(dest/'members.jsonl.gz','wt',encoding='utf8',compresslevel=1) as members,gzip.open(dest/'candidates.jsonl.gz','wt',encoding='utf8',compresslevel=1) as pairs:
            def flush():
                nonlocal candidates
                if previous is not None:
                    candidates+=1;dump(pairs,dict(support_key=previous,result=best or fallback,candidate=True))
            for row in rows(inputs[3]):
                key=tuple(row['support_key'])
                if key!=previous:
                    flush()
                    if key in seen or key not in expected:raise ValueError('INVALID_EXPERIMENT_SCOPE')
                    seen.add(key);previous=key;best=fallback=None
                count+=1;a,b=[alerts[i] for i in row['support_pair']]
                env,bindings=legacy_project(dict(support_pair=row['support_pair'],valid=row['valid'],evidence={'evidence_v5':row['baseline']}),alerts,entities)
                behavior=row['values']['behavior'] if all(x['category']!='unknown' for x in (a,b)) else None
                projection,bound=project(env,bindings,a,b,entities,behavior,policy)
                result=score(projection,policy,threshold)
                tie=[a['timestamp'],b['timestamp'],*row['support_pair']]
                result.update(projection=projection,audit=bound,source_pair=sorted([row['source_a'],row['source_b']]),
                    support_pair=row['support_pair'],tie=tie,observable_dimensions=row['observable_dimensions'],
                    original_gate=env['gate'],original_values=row['values'])
                dump(members,dict(support_key=key,result=result))
                if fallback is None or (-result['score'],tie)<(-fallback['score'],fallback['tie']):fallback=result
                if result['gate'] and (best is None or (-result['score'],tie)<(-best['score'],best['tie'])):best=result
                if count%50000==0:print('MEMBERS',count,round(time.monotonic()-started),flush=True)
            flush()
        if seen!=expected or digest(sorted(seen))!=m['candidate_digest'] or (candidates,count)!=(240621,241464):raise ValueError('INVALID_EXPERIMENT_SCOPE')
        stress=[]
        for row in read(inputs[4]):
            projection,bound=project(row['env'],row['bindings'],row['a'],row['b'],row['entities'],row['behavior'] if row['behavior']>0 else None,policy)
            stress.append(dict(id=row['id'],candidate=row['candidate'],source_pair=row['source_pair'],projection=projection,
                projection_digest=digest(projection),audit=bound,result=score(projection,policy,threshold)))
        save(dest/'stress.json',stress)
        save(dest/'receipt.json',dict(candidate_digest=digest(sorted(seen)),candidates=candidates,members=count,
            ground_truth_read=False,read_paths=sorted(reads),denied=denied,seconds=time.monotonic()-started,
            guard='Python audit tripwire, not OS sandbox'))
    save(OUT/'prediction_seal.json',dict(status='SEALED_BEFORE_EVALUATION_JOIN',manifest_sha256=sha(OUT/'manifest.json'),
        files={str(p.relative_to(OUT)):sha(p) for p in dest.iterdir()}))
    print('SEALED',candidates,count,flush=True)


def metrics(items):
    positive=[r for r in items if r['positive']];negative=[r for r in items if not r['positive']]
    low=min((r['result']['score'] for r in positive),default=None);high=max((r['result']['score'] for r in negative),default=None)
    counts={group:{decision:sum(r['result']['decision']==decision for r in records) for decision in ['ADMIT','AMBIGUOUS','REJECT']}
            for group,records in [('GT',positive),('HN',negative)]}
    return dict(GT=len(positive),HN=len(negative),counts=counts,
        candidate_recall=sum(r['candidate'] for r in positive)/len(positive) if positive else None,
        admission_recall=counts['GT']['ADMIT']/len(positive) if positive else None,
        hn_rejection=counts['HN']['REJECT']/len(negative) if negative else None,
        binary_gt_admission_recall=sum(r['result']['binary_admit'] for r in positive)/len(positive) if positive else None,
        binary_hn_rejection=sum(not r['result']['binary_admit'] for r in negative)/len(negative) if negative else None,
        ambiguous_rate=sum(r['result']['decision']=='AMBIGUOUS' for r in items)/len(items) if items else None,
        min_gt=low,max_hn=high,worst_margin=low-high if low is not None and high is not None else None)


def anonymized_witness(row):
    """Remove record handles only; retain every actual raw field, feature and scope."""
    value=json.loads(json.dumps(row));value.pop('id')
    for side in ['a','b']:value[side].pop('alert_id')
    return value


def stratify(items):
    result={}
    for field in ['scenario','anchor_category','source_pair','source_mode']:
        groups=collections.defaultdict(list)
        for r in items:
            key=r['scenario'] if field=='scenario' else r['result'].get('audit',r.get('audit',{})).get('anchor_category','NONE') if field=='anchor_category' else '+'.join(r['source_pair']) if field=='source_pair' else 'same_source' if len(set(r['source_pair']))==1 else 'cross_source'
            groups[key].append(r)
        result[field]={k:metrics(v) for k,v in sorted(groups.items())}
    return result


def evaluate():
    m=verify_predictions()
    if (OUT/'evaluation_started.json').exists():raise ValueError('already_evaluated')
    save(OUT/'evaluation_started.json',dict(seal_sha256=sha(OUT/'prediction_seal.json'),independent_validation=False))
    prior=read(PREVIOUS/'labeled_decomposition.json')['existing_development']
    # Preserve original representative support keys for all development labels.
    wanted={}
    for positive,records in [(True,read(BASE/'gt_edge_evaluation.json')['edges']),(False,read(BASE/'hard_negative_evaluation.json')['pairs'])]:
        for i,r in enumerate(records):
            key=tuple(r['support_key']) if r['support_key'] else ('absent',positive,i)
            wanted[key]=dict(id=r.get('edge_id',r.get('pair_id',str(i))),positive=positive,scenario=str(r.get('scenario_id','development_GT' if positive else 'development_HN')))
    found={}
    for r in rows(OUT/'predictions/candidates.jsonl.gz'):
        key=tuple(r['support_key'])
        if key in wanted:found[key]=r['result']
    missing=dict(score=0.,gate=False,binary_admit=False,decision='REJECT',source_pair=['unknown','unknown'])
    development=[dict(**v,candidate=k in found,result=found.get(k,missing),source_pair=found.get(k,missing)['source_pair']) for k,v in wanted.items()]
    answers={r['id']:r for r in read(PREVIOUS/'stress_answers.json')}
    stress=[dict(**r,positive=answers[r['id']]['positive'],scenario=answers[r['id']]['scenario']) for r in read(OUT/'predictions/stress.json')]
    datasets={'existing_development':development,'anchor_feature_stress':stress}
    summary={n:dict(overall=metrics(v),by=stratify(v)) for n,v in datasets.items()}
    equivalent=[]
    groups=collections.defaultdict(list)
    for r in stress:groups[r['projection_digest']].append(r)
    for h,records in groups.items():
        if {r['positive'] for r in records}=={True,False}:
            if not all(r['projection']==records[0]['projection'] and r['result']==records[0]['result'] for r in records):raise ValueError('invalid_equivalence_proof')
            equivalent.append(dict(projection_digest=h,projection=records[0]['projection'],pairs=[dict(id=r['id'],positive=r['positive'],decision=r['result']['decision']) for r in records],scope='Exact numeric decision-input equivalence, not all raw telemetry equivalence.'))
    full_groups=collections.defaultdict(list)
    for r in read(PREVIOUS/'stress_input.json'):
        witness=anonymized_witness(r)
        full_groups[digest(witness)].append((r,witness))
    full_proofs=[]
    for h,records in full_groups.items():
        if {answers[r['id']]['positive'] for r,_ in records}=={True,False}:
            assert all(w==records[0][1] for _,w in records)
            full_proofs.append(dict(input_digest=h,normalized_full_input=records[0][1],
                normalized_full_stress_inputs_equal=True,removed_fields=['id','a.alert_id','b.alert_id'],
                pairs=[dict(id=r['id'],positive=answers[r['id']]['positive']) for r,_ in records]))
    p=m['policy'];criteria=p['acceptance'];dev=summary['existing_development']['overall'];st=summary['anchor_feature_stress']['overall']
    candidate_ok=dev['candidate_recall']==1.
    recall_ok=dev['admission_recall']>=criteria['development_admission_recall'] and st['admission_recall']>=criteria['stress_admission_recall']
    negative_ok=dev['hn_rejection']>=criteria['development_hn_rejection'] and st['hn_rejection']>=criteria['stress_hn_rejection']
    binary_ok=dev['binary_gt_admission_recall']>=criteria['development_admission_recall'] and dev['binary_hn_rejection']>=criteria['development_hn_rejection'] and st['binary_gt_admission_recall']>=criteria['stress_admission_recall'] and st['binary_hn_rejection']>=criteria['stress_hn_rejection']
    ambiguity_ok=all(v['overall']['ambiguous_rate']<=p['AMBIGUOUS_RATE_LIMIT'] for v in summary.values())
    margins_ok=all(summary[n]['overall']['worst_margin']>m['baseline_metrics'][old]['overall']['worst_margin'] for n,old in [('existing_development','existing_development'),('anchor_feature_stress','synthetic_feature_stress')])
    accepted=candidate_ok and recall_ok and negative_ok and binary_ok and ambiguity_ok and margins_ok
    result=('INVALID_EXPERIMENT_SCOPE' if not candidate_ok else 'V5_2_SEMANTICS_REPAIR_ACCEPTED_FOR_REGRESSION' if accepted else
        'V5_2_SPARSE_EVIDENCE_STILL_OVER_RESTRICTIVE' if not recall_ok else 'V5_2_CORRELATION_OVER_CORRELATED')
    save(OUT/'evaluation_summary.json',dict(TASK_RESULT=result,FULL_BACKEND_REGRESSION_VERIFIED=False,
        NEW_INDEPENDENT_VALIDATION_READY=False,V5_PRODUCTION_INTEGRATION_READY=False,V5_FREEZE_READY=False,
        datasets=summary,acceptance=dict(candidate=candidate_ok,recall=recall_ok,negative=negative_ok,binary=binary_ok,ambiguity=ambiguity_ok,margins=margins_ok),
        OBSERVABILITY_LIMIT=bool(full_proofs),observability_limit_is_not_overall_acceptance=True))
    save(OUT/'equivalence_proofs.json',equivalent)
    save(OUT/'full_input_equivalence_proofs.json',full_proofs)
    save(OUT/'development_gt_decomposition.json',[dict(**r,v5_1=next(old['result'] for old in prior if old['positive'] and old['id']==r['id'])) for r in development if r['positive']])
    save(OUT/'labeled_decomposition.json',datasets)
    save(OUT/'failure_decomposition.json',[dict(dataset=n,**r) for n,items in datasets.items() for r in items if r['result']['decision']=='AMBIGUOUS' or (r['positive'] and r['result']['decision']!='ADMIT') or (not r['positive'] and (r['result']['decision']!='REJECT' or r['result']['binary_admit']))])
    print(result);print(json.dumps({n:s['overall'] for n,s in summary.items()},indent=2))


if __name__=='__main__':
    {'audit':audit,'prepare':prepare,'predict':predict,'evaluate':evaluate,'verify':verify_predictions}[sys.argv[1]]()

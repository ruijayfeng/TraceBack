"""Recover contracts first, then replay frozen V5.2 without label access."""
import collections
import gzip
import json
import sys
import time
from pathlib import Path
from .run import ROOT, OUT, OLD, read, save, sha
from evaluation.framework.sparse_semantics import runtime as sparse
from evaluation.framework.sparse_semantics.model import project, score
from evaluation.framework.scoring_calibration.model import project as legacy_project
from evaluation.framework.formula_design.runtime import guard
from evaluation.framework.anchor_semantics.runtime import rows, dump, digest

BASE=ROOT/'outputs/v5_source_bound_observability_final'
CAL=ROOT/'outputs/v5_scoring_calibration'
PREV=ROOT/'outputs/v5_1_anchor_semantics'

def contract():
    p=sparse.load_policy()
    c=dict(version=p['version'],source='evaluation/framework/sparse_semantics/model.py',
        source_hash=sha(Path(sparse.__file__).with_name('model.py')),policy=p,
        evidence_states=dict(OBSERVED_SUPPORT='positive measured feature',OBSERVED_NEUTRAL='observed zero, no conflict',
            MISSING='unobserved feature, ignored in support arithmetic',UNOBSERVABLE='unobserved capability, ignored',
            UNKNOWN='unobserved behavior or relation, null',CONTRADICTED='scoped comparison conflicts',
            NOT_APPLICABLE='may exist in upstream features; V5.2 does not preserve a distinct N/A scoring channel'),
        support_formula='u_j=max(support*weight within channel); P=sum(u_j); N=incident_conflict; compatibility=P/(P+N) or null',
        sparse_formula='min(compatibility or 0,1-exp(-P/mass_scale))*temporal - N - legacy_unscoped_penalty - duplicate_penalty; clamp; guards may zero',
        normalization='No fixed absent-family denominator. Absolute support saturation prevents one weak channel getting 1.0; a lone non-task/direct channel is capped .60.',
        neutral='Observed zero adds an observed channel but no mass; len(channels), including zero, controls minimum_groups. Record as semantic risk, not silently reinterpret.',
        confidence='P/(P+confidence_scale), separately reported; not multiplied by compatibility',
        completeness='observed channel count/7, separate from score; absent channels are not negative evidence',
        temporal='time_floor+(1-time_floor)*observed_temporal, attenuation only',
        sufficient_support=['attested direct plus original guards and threshold','scoped request + asset support plus guards and threshold','qualified object/network/execution/auth context plus guards and threshold'],
        contextual_support=['scoped session identity','complete process identity','host/account/content/behavior observations'],
        weak_support=['ordinary IP/host/domain coincidences','transport metadata','time','source names do not enter score'],
        admission='gate and score>=.65 and discriminating_context => ADMIT; same binary score without discriminating_context => AMBIGUOUS; otherwise REJECT',
        exact_anchor='No universal exact-identity requirement. Object handoff can qualify without exact session/process; ordinary multi-family context remains AMBIGUOUS.',
        contradiction_matrix=p['formula']['contradiction_matrix'],hard_reject=['invalid pair','original hard_contradiction','duplicate_observation','original gate failed','empty channels'],
        limitations=['legacy_unscoped_penalty may lack archived reasons; not proven explicit contradiction',
            'qualified_context and behavior can share operation facts; seven channels are not proven statistically independent',
            'local identity/time contradiction recorded but only epoch/scope suppress session/process here; direct lineage remains upstream responsibility',
            'no dedicated incompatible endpoint role/namespace inference in this model; inherits verified upstream gate',
            'N/A versus UNOBSERVED is not fully represented in final numeric projection'],
        recovered_before_current_replay=True,no_rule_inferred_from_current_result=True)
    save(OUT/'v5_2_semantics_contract.json',c)
    lines=['# V5.2 actual semantic contract','',f"Version: `{p['version']}`. Development only, deployment=false. Threshold 0.65.",'']
    for k in ('support_formula','sparse_formula','normalization','neutral','confidence','completeness','temporal','admission','exact_anchor'):
        lines += [f'**{k}**: {c[k]}','']
    lines += ['Evidence states: '+json.dumps(c['evidence_states'],ensure_ascii=False),'','Contradictions: '+json.dumps(c['contradiction_matrix'],ensure_ascii=False),'','Limitations:']
    lines += ['- '+x for x in c['limitations']]
    (OUT/'v5_2_semantics_contract.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    sys.path.insert(0,str(ROOT/'backend'))
    from app.config import AlgorithmConfig, load_config
    errors=[]
    for payload in [dict(version='v4',implementation_version=p['version']),p]:
        try: AlgorithmConfig.model_validate(payload)
        except Exception as e: errors.append(str(e))
    configs=[]
    for name in ['algorithm-v4.yaml','algorithm-v5.yaml','algorithm-v5-evidence-semantics.yaml']:
        config=load_config(ROOT/'configs'/name)
        configs.append(dict(config=name,version=config.algorithm.version,
            implementation=config.algorithm.implementation_version,config_hash=config.config_hash,
            mapping_hash=config.mapping_digest,threshold=config.algorithm.score.correlation_threshold))
    evidence=[]
    for name,terms in {
        'backend/app/config.py':['implementation_version: Literal'],
        'backend/app/main.py':["configs['v5']", "configs['v4']"],
        'backend/app/correlation/scoring.py':["implementation_version in",'from .evidence_v5 import evaluate','ScoreBreakdownV5'],
        'backend/app/services/datasets.py':['config_version not in'],
        'backend/app/models/correlation_v5.py':['algorithm_version:','implementation_version:']}.items():
        for i,line in enumerate((ROOT/name).read_text(encoding='utf8').splitlines(),1):
            if any(t in line for t in terms): evidence.append(dict(file=name,line=i,code=line.strip()))
    dispatch=dict(selected_review_implementation=p['version'],selected_review_config='evaluation/configs/sparse_semantics.yaml',
        scorer_identity='evaluation.framework.sparse_semantics.model.project/score',threshold_identity=.65,
        config_hash=sha(sparse.POLICY),hash_identity=read(OUT/'run_manifest.json')['input_hashes'],
        entry_points=[dict(entry='evaluation sparse runtime prepare/predict/evaluate',selected_implementation=p['version'],
            prepare='load_policy + immutable source/input seal',candidate_generation='reuse sealed BASE/blind_A/candidate_pairs.json, no regeneration',
            feature_extraction='legacy_project then sparse project',evidence_semantics='sparse model.project',scoring='sparse model.score',
            admission='ADMIT/AMBIGUOUS/REJECT',edge_creation='research JSON only',incident_construction='not registered'),
            dict(entry='pytest test_sparse_semantics',selected_implementation=p['version'],uses='same project and score with synthetic witnesses'),
            dict(entry='production CLI CorrelationScorer',selected_implementation='v4 or registered v5 F3/evidence-semantics, by config',v5_2_registered=False),
            dict(entry='production API default config registry',selected_implementation='v0/v2/v3/v4/v5 existing configs; v5 means old F3',v5_2_registered=False)],
        production_configs=configs,validation_errors=errors,source_evidence=evidence,
        conclusion='V5.2 is evaluation-only by design; absence of production dispatch is a downstream validation blocker, not evidence tests execute production V5.2.',
        formula_semantics_changed=False)
    save(OUT/'v5_2_dispatch_audit.json',dispatch)
    print('CONTRACT_AND_DISPATCH_RECORDED',flush=True)

def replay():
    contract()
    m=read(OLD/'manifest.json');p=sparse.load_policy();policy=p['formula'];threshold=p['REFERENCE_THRESHOLD']
    if (OUT/'prediction_seal.json').exists(): raise ValueError('immutable_review_predictions_exist')
    dest=OUT/'predictions';dest.mkdir(exist_ok=False)
    inputs=[ROOT/n for n in m['input_files']]
    for n,h in m['input_hashes'].items():
        if sha(ROOT/n)!=h: raise ValueError('input_changed:'+n)
    harness={x.relative_to(ROOT).as_posix():sha(x) for x in Path(__file__).parent.glob('*.py')}
    save(OUT/'replay_preregistration.json',dict(harness=harness,policy_hash=sha(sparse.POLICY),
        contract_hash=sha(OUT/'v5_2_semantics_contract.json'),input_hashes=m['input_hashes'],
        manifest_hash=sha(OUT/'run_manifest.json'),threshold=threshold,scorer=sparse.__name__+'.model.score',labels_loaded=False))
    count=0;candidate_count=0;seen=set();previous=None;best=fallback=None
    started=time.monotonic();comparison=dict(members=0,candidates=0,stress=0,mismatches=[])
    with guard(inputs,dest) as (denied,reads):
        alerts={a['alert_id']:a for a in rows(inputs[0])};entities={e['entity_id']:e for e in rows(inputs[1])}
        expected={tuple(x) for x in read(inputs[2])}
        with gzip.open(dest/'members.jsonl.gz','wt',encoding='utf8',compresslevel=1) as mf,gzip.open(dest/'candidates.jsonl.gz','wt',encoding='utf8',compresslevel=1) as cf:
            def flush():
                nonlocal candidate_count
                if previous is not None:
                    dump(cf,dict(support_key=previous,result=best or fallback,candidate=True));candidate_count+=1
            for row in rows(inputs[3]):
                key=tuple(row['support_key'])
                if key!=previous:
                    flush()
                    if key in seen or key not in expected: raise ValueError('candidate_scope_changed')
                    previous=key;seen.add(key);best=fallback=None
                a,b=[alerts[i] for i in row['support_pair']]
                env,bindings=legacy_project(dict(support_pair=row['support_pair'],valid=row['valid'],evidence={'evidence_v5':row['baseline']}),alerts,entities)
                behavior=row['values']['behavior'] if all(x['category']!='unknown' for x in (a,b)) else None
                projection,audit=project(env,bindings,a,b,entities,behavior,policy)
                r=score(projection,policy,threshold)
                tie=[a['timestamp'],b['timestamp'],*row['support_pair']]
                r.update(projection=projection,audit=audit,source_pair=sorted([row['source_a'],row['source_b']]),
                    support_pair=row['support_pair'],tie=tie,observable_dimensions=row['observable_dimensions'],original_gate=env['gate'],original_values=row['values'])
                dump(mf,dict(support_key=key,result=r));count+=1
                if fallback is None or (-r['score'],tie)<(-fallback['score'],fallback['tie']): fallback=r
                if r['gate'] and (best is None or (-r['score'],tie)<(-best['score'],best['tie'])): best=r
                if count%50000==0: print('REPLAY_MEMBERS',count,round(time.monotonic()-started),flush=True)
            flush()
        if seen!=expected or digest(sorted(seen))!=m['candidate_digest']:raise ValueError('candidate_digest_changed')
        stress=[]
        for row in read(inputs[4]):
            projection,audit=project(row['env'],row['bindings'],row['a'],row['b'],row['entities'],row['behavior'] if row['behavior']>0 else None,policy)
            stress.append(dict(id=row['id'],candidate=row['candidate'],source_pair=row['source_pair'],projection=projection,
                projection_digest=digest(projection),audit=audit,result=score(projection,policy,threshold)))
        save(dest/'stress.json',stress)
        save(dest/'receipt.json',dict(candidate_digest=digest(sorted(seen)),candidates=candidate_count,members=count,
            ground_truth_read=False,read_paths=sorted(reads),denied=denied,seconds=time.monotonic()-started,
            guard='Python audit tripwire, not OS sandbox; scorer sees only unlabeled projections'))
    save(OUT/'prediction_seal.json',dict(status='SEALED_BEFORE_CURRENT_EVALUATION_JOIN',
        preregistration_sha256=sha(OUT/'replay_preregistration.json'),files={x.name:sha(x) for x in dest.iterdir()}))
    from itertools import zip_longest
    for name in ['members','candidates']:
        for current,old in zip_longest(rows(dest/(name+'.jsonl.gz')),rows(OLD/'predictions'/(name+'.jsonl.gz'))):
            comparison[name]+=1
            if current!=old:
                comparison['mismatches'].append(dict(kind=name,index=comparison[name]))
    prior=read(OLD/'predictions/stress.json')
    for a,b in zip_longest(stress,prior):
        comparison['stress']+=1
        if a!=b:comparison['mismatches'].append(dict(kind='stress',index=comparison['stress']))
    comparison['exact_semantic_reproduction']=not comparison['mismatches']
    save(OUT/'replay_equivalence.json',comparison)
    print('PREDICTIONS_SEALED',count,candidate_count,comparison,flush=True)

if __name__=='__main__':
    {'contract':contract,'replay':replay}[sys.argv[1]]()

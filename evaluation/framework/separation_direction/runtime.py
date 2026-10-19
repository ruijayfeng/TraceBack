"""Single prospective candidate and complete member replay, under a read tripwire."""
from collections import Counter
from pathlib import Path
import gzip,hashlib,json,time
from . import ROOT,OUT,BASE,INPUT
from evaluation.framework.formula_design.runtime import read,save,rows,sha,guard

POLICY=ROOT/'configs/algorithm-v5-separation-direction.yaml'


def freeze():
    from app.config import read_yaml
    from app.correlation.separation_direction.models import Policy
    from app.utils.stable_id import content_digest
    from evaluation.framework.semantics_final.runtime import verify_freeze,verify_seal
    if (OUT/'formula_freeze.json').exists():raise ValueError('immutable_freeze_exists')
    if not read(OUT/'audit_complete.json')['production_code_changed'] is False:raise ValueError('A_G_required')
    old=verify_freeze();seal=verify_seal()
    p=Policy.model_validate(read_yaml(POLICY)).model_dump(by_alias=True)
    files={f.relative_to(ROOT).as_posix():sha(f) for f in sorted((ROOT/'backend/app/correlation/separation_direction').glob('*.py'))}
    files[POLICY.relative_to(ROOT).as_posix()]=sha(POLICY)
    for f in sorted((ROOT/'evaluation/framework/separation_direction').glob('*.py')):
        files[f.relative_to(ROOT).as_posix()]=sha(f)
    identity=content_digest(dict(baseline=old['formula_hash'],files=files,policy=p))
    save(OUT/'formula_freeze.json',dict(algorithm_version=p['version'],formula_hash=identity,
        implementation_hash=content_digest(files),implementation_files=files,
        config_hash=content_digest(dict(baseline_config_hash=old['config_hash'],candidate_policy=p)),
        mapping_digest=old['mapping_digest'],policy=p,policy_hash=content_digest(p),
        baseline_identity={k:old[k] for k in ('algorithm_version','formula_hash','config_hash','implementation_hash','mapping_digest')},
        baseline_freeze_sha256=sha(BASE/'formula_freeze.json'),baseline_seal_sha256=sha(BASE/'score_seal.json'),
        baseline_diagnostics_sha256=seal['files']['blind/diagnostics.jsonl.gz'],
        baseline_sources=old['implementation_files'],canonical_inputs=old['canonical_inputs'],
        dataset_files=read(BASE/'historical_before.json')['dataset_files'],
        expected_candidate_digest=seal['candidate_digest'],expected_candidate_count=seal['candidate_count'],
        expected_member_count=seal['member_count'],audit_sha256=sha(OUT/'audit_complete.json'),
        formula_revision_count=1,parameters_selected_by='Prospective field semantics and synthetic witnesses, no score sweep/optimizer',
        historical_integrity_start=dict(status='PASS',historical_count=66070,dataset_count=13,
            verified_by='semantics_final.runtime.verify_history; executed before any candidate implementation'),
        candidate_scope='Opt-in development candidate schema 5.2; not registered in production API/storage',
        replay_scope='All 10051 alerts, all existing admitted candidates and complete G1xG2 member pairs; unchanged candidate policy reuses hash-verified nominations',
        gt_already_seen_for_development_audit=True,final_threshold=None,t2_executed=False))
    print('CANDIDATE_FROZEN',identity,flush=True)


def verify_freeze():
    frozen=read(OUT/'formula_freeze.json')
    for p,h in {**frozen['implementation_files'],**frozen['baseline_sources']}.items():
        if sha(ROOT/p)!=h:raise ValueError('implementation_changed:'+p)
    for p,h in frozen['canonical_inputs'].items():
        if sha(Path(p))!=h:raise ValueError('canonical_input_changed')
    if sha(BASE/'score_seal.json')!=frozen['baseline_seal_sha256']:raise ValueError('baseline_seal_changed')
    return frozen


def verify_seal():
    frozen=verify_freeze();seal=read(OUT/'score_seal.json')
    if seal['ground_truth_loaded'] or seal['formula_freeze_sha256']!=sha(OUT/'formula_freeze.json'):
        raise ValueError('unsealed_predictions')
    for name,h in seal['files'].items():
        if sha(OUT/name)!=h:raise ValueError('sealed_prediction_changed:'+name)
    return frozen,seal


def blind():
    if (OUT/'score_seal.json').exists() or (OUT/'evaluation_started.json').exists():raise ValueError('single_use_blind')
    frozen=verify_freeze();policy=frozen['policy']
    # Preload production modules before the data read tripwire starts.
    from app.adapters.base import AdapterSettings
    from app.models import CanonicalAlert,DedupeGroup,Entity
    from app.correlation.index import AlertIndex
    from app.correlation.scoring import CorrelationScorer
    from app.correlation.formula_v5 import aggregate as old_aggregate
    from app.services.storage import restore_config
    from app.correlation.evidence_v4 import EvidenceV4Evaluator
    from app.dedup.observation import ObservationMatcher
    from app.services.capacity import AlertSequence,execution_state
    from app.correlation import entity_bridges
    from app.correlation.separation_direction.evidence import transition,alias_groups,value
    from app.correlation.separation_direction.formula import aggregate
    from app.correlation.separation_direction.direction import decide
    from app.correlation.separation_direction.models import PairResult,CandidateCorrelationEdge
    from app.correlation.separation_direction.graph import reconstruct
    from app.utils.stable_id import id_for,content_digest
    destination=OUT/'blind';destination.mkdir(exist_ok=False)
    inputs=[INPUT/n for n in ('canonical.jsonl.gz','dedupe.jsonl.gz','entities.jsonl.gz')]
    allowed=[*inputs,BASE/'blind/diagnostics.jsonl.gz',BASE/'formula_freeze.json']
    count=members=0;digest=hashlib.sha256();counts=Counter();best={};started=time.perf_counter()
    def write(stream,row):stream.write(json.dumps(row,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n')
    with guard(allowed,destination) as (events,reads):
        baseline_freeze=read(BASE/'formula_freeze.json');config=restore_config(baseline_freeze['effective']['algorithm'])
        settings={k:AdapterSettings(**v) for k,v in baseline_freeze['effective']['sources'].items()}
        alerts=[CanonicalAlert.model_validate(r) for r in rows(inputs[0])]
        groups=[DedupeGroup.model_validate(r) for r in rows(inputs[1])]
        entities=[Entity.model_validate(r) for r in rows(inputs[2])]
        if len(alerts)!=10051:raise ValueError('incomplete_dataset')
        index=AlertIndex(alerts,groups,entities)
        scorer=CorrelationScorer(index,config,settings)
        pairpath=destination/'pair_scores.jsonl.gz';directionpath=destination/'direction_evidence.jsonl.gz'
        with gzip.open(pairpath,'wt',encoding='utf8',compresslevel=1) as pairs,gzip.open(directionpath,'wt',encoding='utf8',compresslevel=1) as directions:
            for row in rows(allowed[3]):
                if row['stage']=='candidate':
                    count+=1;digest.update(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
                if row['stage']!='member_score':continue
                members+=1;a,b=[index.alerts[i] for i in row['support_pair']]
                v=row['evidence']['evidence_v5']
                old=old_aggregate(v['features'],v['policy'],hard=v['gate']['hard_contradiction'],
                    duplicate_risk=v['gate']['duplicate_observation'],duplicate=v['duplicate'])
                if abs(old['final_score']-row['score'])>1e-12:raise ValueError('baseline_recomputation_drift')
                baseline={k:old[k] for k in ('group_support','direct_support','temporal_factor','weak_only','conflict_penalty','duplicate_penalty','gate','quality','evidence_mass')}
                ordered=sorted((a,b),key=lambda x:(index.times[x.alert_id],x.alert_id))
                t=transition(*ordered,index,settings,policy,config.algorithm.entity)
                gs=alias_groups(old['group_support'],a,b,index)
                result=aggregate(baseline,gs,t,policy)
                d=decide(a,b,index,policy,hard=not old['gate']['passed'],explicit_relations=row['evidence']['relations'])
                obj=PairResult.model_validate(dict(support_pair=row['support_pair'],support_key=row['support_key'],
                    baseline_score=row['score'],valid=row['valid'],baseline=baseline,policy_hash=frozen['policy_hash'],
                    groups=gs,transition=t,score_breakdown={**result,'policy':policy},score=result['final_score'],direction=d))
                # Full pointer resolution is checked against the bound member,
                # not whichever alert happens to contain a similarly named key.
                proofs=[] if not t else t['provenance']
                proofs=proofs+[p for c in d['forward_evidence']+d['reverse_evidence'] for p in c['provenance']]
                for p in proofs:
                    if value(index.alerts[p['alert_id']],p['pointer']) is None:raise ValueError('grounding_failure')
                write(pairs,obj.model_dump(mode='json'))
                write(directions,dict(support_pair=row['support_pair'],support_key=row['support_key'],**d))
                counts['transitions']+=bool(t);counts['directions']+=d['status']=='DERIVED_VERIFIED_DIRECTION'
                counts['alias_merges']+=gs!=old['group_support'];counts['gate_passed']+=old['gate']['passed']
                if obj.valid:
                    key=tuple(obj.support_key);tie=(-obj.score,a.timestamp,b.timestamp,a.alert_id,b.alert_id)
                    if key not in best or tie<best[key][0]:
                        best[key]=(tie,obj if obj.score>=min(policy['diagnostic_operating_points']) else None,
                                   obj.score,obj.direction.status)
                if members%25000==0:print(json.dumps(dict(stage='blind',members=members,seconds=time.perf_counter()-started)),flush=True)
        if count!=frozen['expected_candidate_count'] or members!=frozen['expected_member_count'] or digest.hexdigest()!=frozen['expected_candidate_digest']:
            raise ValueError('candidate_or_member_coverage_changed')
        edges=[]
        for key,(_,obj,score,status) in sorted(best.items()):
            if obj is None:continue
            data=dict(source_alert_id=key[0],target_alert_id=key[1],score=score,support=obj)
            data['edge_id']=id_for('CorrelationEdge',data);edges.append(CandidateCorrelationEdge.model_validate(data))
        with gzip.open(destination/'correlation_edges.jsonl.gz','wt',encoding='utf8',compresslevel=1) as f:
            for e in edges:write(f,e.model_dump(mode='json'))
        with gzip.open(destination/'selected_scores.jsonl.gz','wt',encoding='utf8',compresslevel=1) as f:
            for key,(tie,_,score,status) in sorted(best.items()):write(f,dict(support_key=key,support_pair=list(tie[-2:]),score=score,direction_status=status))
        for threshold in policy['diagnostic_operating_points']:
            es=[e for e in edges if e.score>=threshold]
            inc,ns,chains,diags=reconstruct(index,es,scorer,policy)
            prefix='point_'+str(threshold).replace('.','_');folder=destination/prefix;folder.mkdir()
            for name,records in [('incidents',inc),('nodes',ns),('chain_edges',chains),('diagnostics',diags)]:
                with gzip.open(folder/(name+'.jsonl.gz'),'wt',encoding='utf8',compresslevel=1) as f:
                    for r in records:write(f,r.model_dump(mode='json') if hasattr(r,'model_dump') else r)
            save(folder/'summary.json',dict(diagnostic_threshold=threshold,correlation_edges=len(es),incidents=len(inc),
                multi_alert_incidents=sum(len(i.alert_ids)>1 for i in inc),chain_edges=len(chains),
                original_alerts_retained=len({a for n in ns for a in n.alert_ids}),
                schema_version='5.2-candidate',candidate_objects_not_published_to_legacy_api=True))
            print('GRAPH_SEALED',threshold,len(es),len(chains),flush=True)
        save(destination/'summary.json',dict(raw_alert_count=len(alerts),representatives=index.N,candidate_count=count,
            member_count=members,candidate_digest=digest.hexdigest(),counts=dict(counts),elapsed_seconds=time.perf_counter()-started,
            pipeline_kind='complete frozen member-pair replay plus candidate graph; nomination unchanged',
            baseline_score_recomputed_count=members,final_threshold=None))
        save(destination/'guard_receipt.json',dict(rejected_events=events,non_code_reads=sorted(reads),ground_truth_loaded=False,
            t2_read=False,guard_type='Python audit tripwire; no child processes or network',
            canonical_alerts_mutated=False,all_member_pointers_resolved=True))
    save(OUT/'score_seal.json',dict(status='completed',ground_truth_loaded=False,formula_freeze_sha256=sha(OUT/'formula_freeze.json'),
        prediction_kinds=['PairScore','DirectionEvidence','CorrelationEdge','ChainEdge'],candidate_digest=digest.hexdigest(),
        candidate_count=count,member_count=members,files={p.relative_to(OUT).as_posix():sha(p) for p in sorted(destination.rglob('*')) if p.is_file()}))
    print('SCORES_AND_GRAPHS_SEALED',flush=True)


if __name__=='__main__':
    import sys
    {'freeze':freeze,'blind':blind}[sys.argv[1]]()

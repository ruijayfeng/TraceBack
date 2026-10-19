"""Post-seal analysis only. No runtime scoring, candidate or production calls."""
from array import array
from bisect import bisect_left,bisect_right
from collections import Counter
import copy
import hashlib
import json
import math
import sys

from . import ROOT,OUT,BASELINE
from .runtime import read,save,sha,rows,require_sealed,VARIANTS,ABLATIONS


def dist(values):
    values=sorted(values);n=len(values)
    def q(p):
        if not n:return None
        x=(n-1)*p;l=math.floor(x);u=math.ceil(x)
        return values[l]+(values[u]-values[l])*(x-l)
    return dict(count=n,min=q(0),median=q(.5),mean=math.fsum(values)/n if n else None,
                p95=q(.95),p99=q(.99),max=q(1),status='available' if n else 'not_applicable')


def ordering(positive,negative):
    negatives=sorted(negative);details={}
    for name,s in positive.items():
        lo,hi=bisect_left(negatives,s),bisect_right(negatives,s)
        details[name]=dict(score=s,above=lo,below=len(negatives)-hi,tied=hi-lo,negative_count=len(negatives))
    den=len(positive)*len(negatives)
    return dict(strict_rate=sum(x['above'] for x in details.values())/den if den else None,
                tie_half_rate=sum(x['above']+.5*x['tied'] for x in details.values())/den if den else None,
                gt_count=len(positive),negative_count=len(negatives),denominator=den,
                interpretation='development diagnostic only; not population AUC',per_gt=details)


def explain(prediction,model,policy):
    result=copy.deepcopy(prediction['results'][model])
    result.update(copy.deepcopy(prediction['evidence']))
    dims={d['dimension']:d for d in prediction['v4_dimensions']}
    for name in ('supporting_evidence','weak_evidence','unavailable_evidence','observed_zero_evidence'):
        for e in result[name]:
            if model in {'F0','F1','remove_role_aware_entity'} and e['family']=='entity':
                e.update(strength=dims[e['name']]['strength'],reliability=policy['reliability']['generic'][e['name'][7:]],role='generic')
            if model=='equal_reliability':e['reliability']=1.
        if model=='remove_time':result[name]=[e for e in result[name] if e['family']!='time']
    result['algorithm_version']=policy['version']+'-'+model.lower()
    result['support_pair']=prediction['support_pair'];result['support_key']=prediction['support_key']
    result['v4_family_strengths']=prediction['v4_family_strengths']
    return result


def evaluate():
    seal=require_sealed() # must precede truth imports and every truth sidecar read
    save(OUT/'evaluation_started.json',dict(blind_manifest_sha256=sha(OUT/'blind_manifest.json'),
         order='frozen formulas -> blind member replay -> sealed predictions -> evaluation',production_replay_forbidden=True))
    from evaluation.framework.v4_semisynthetic_baseline import truth
    prepared=read(OUT/'preparation.json');policy=prepared['policy']
    alerts={r['alert_id']:r for r in rows(BASELINE/'blind/canonical.jsonl.gz')}
    old_out,old_seal=truth.OUT,truth.require_sealed
    try:
        truth.OUT=OUT;truth.require_sealed=require_sealed;labels=truth.load(alerts)
    finally:truth.OUT=old_out;truth.require_sealed=old_seal
    witnesses={e:next(iter(ws)) for e,ws in labels['witnesses'].items()}
    targets=set(witnesses.values());negative=labels['negative_pairs'];hard_ids=labels['hard_ids'];background=labels['background_ids']
    scores={m:array('d') for m in VARIANTS};admitted={m:0 for m in VARIANTS}
    pairs=[];populations=[];detail={};top_hard={};top_background={};top_explicit={};conflicts=Counter();states=Counter();missing=Counter()
    family_stats={p:Counter() for p in ('gt','explicit_negative','hard_touch','background','other_unlabeled')};candidate_digest=hashlib.sha256()
    for row in rows(OUT/'blind/predictions.jsonl.gz'):
        pair=tuple(sorted(row['support_pair']));pairs.append(pair)
        population='gt' if pair in targets else 'explicit_negative' if pair in negative else 'hard_touch' if set(pair)&hard_ids else 'background' if set(pair)<=background else 'other_unlabeled'
        populations.append(population)
        if pair in targets:detail[pair]=row
        for m,r in row['results'].items():
            scores[m].append(r['final_score']);admitted[m]+=r['reference_admitted']
            if set(pair)&hard_ids and (m not in top_hard or r['final_score']>top_hard[m]['results'][m]['final_score'] or r['final_score']==top_hard[m]['results'][m]['final_score'] and pair<tuple(sorted(top_hard[m]['support_pair']))):top_hard[m]=row
            if population=='background' and (m not in top_background or r['final_score']>top_background[m]['results'][m]['final_score']):top_background[m]=row
            if population=='explicit_negative' and (m not in top_explicit or r['final_score']>top_explicit[m]['results'][m]['final_score']):top_explicit[m]=row
        for c in row['evidence']['contradictions']:conflicts[c['kind']+':'+c['rule']]+=1
        for d in row['v4_dimensions']:states[d['state']]+=1
        missing[len(row['evidence']['unavailable_evidence'])]+=1
        for f,s in row['v4_family_strengths'].items():family_stats[population][f]+=s
    if len(set(pairs))!=len(pairs):raise ValueError('duplicate_member_rows')
    if set(detail)!=targets:raise ValueError('six_witnesses_not_scored')
    indices={p:[i for i,v in enumerate(populations) if v==p] for p in set(populations)}
    hard_indices=[i for i,p in enumerate(pairs) if set(p)&hard_ids]
    per_model={};rankings={};pairwise={};pair_index={p:i for i,p in enumerate(pairs)}
    for m in VARIANTS:
        vector=scores[m];v=sorted(vector);n=len(v)
        populations_dist={p:dist(vector[i] for i in ids) for p,ids in indices.items()}
        populations_dist['hard_negative_touching']=dist(vector[i] for i in hard_indices)
        ranks={}
        for e,p in sorted(witnesses.items()):
            s=vector[pair_index[p]];lo,hi=bisect_left(v,s),bisect_right(v,s)
            lexical=sum(1 for i,q in enumerate(pairs) if vector[i]==s and q<p)
            ranks[e]=dict(score=s,rank=n-hi+1+lexical,rank_min=n-hi+1,rank_max=n-lo,percentile=100*(lo+.5*(hi-lo))/n)
        rankings[m]=ranks
        pairwise[m]=ordering({e:vector[pair_index[p]] for e,p in witnesses.items()},[vector[i] for i in indices.get('explicit_negative',[])])
        per_model[m]=dict(algorithm_version=policy['version']+'-'+m.lower(),distributions=populations_dist,ranking=ranks,
             pairwise=pairwise[m],reference_admitted_member_count=admitted[m],threshold=.65,
             gt_reference_admissions={e:detail[p]['results'][m]['reference_admitted'] for e,p in witnesses.items()},
             rank_scope='all computed original member pairs incl gate/guard rejects; score DESC, full member pair ID ASC',
             percentile='100*(count(lower)+0.5*count(equal))/N; higher is better',
             not_formal_edges=True,threshold_was_not_calibrated=True)
        if m in {'F0','F1','F2','F3'}:save(OUT/(m.lower()+'_results.json'),per_model[m])
    gt={e:{m:dict(explain(detail[p],m,policy),ranking=rankings[m][e]) for m in ('F0','F1','F2','F3')} for e,p in witnesses.items()}
    save(OUT/'gt_comparison.json',gt)
    save(OUT/'gt_global_rank_comparison.json',rankings)
    for name,pop in (('explicit_negative_comparison','explicit_negative'),('background_tail_comparison','background'),('hard_negative_comparison','hard_negative_touching')):
        save(OUT/(name+'.json'),{m:per_model[m]['distributions'].get(pop,dist([])) for m in VARIANTS})
    save(OUT/'pairwise_ordering.json',pairwise)
    save(OUT/'gt_e02_e06_analysis.json',{e:gt[e] for e in ('GT-E02','GT-E06')})
    save(OUT/'gte03_e05_vs_hardnegative.json',dict(gt={e:gt[e] for e in ('GT-E03','GT-E05')},
         original_max_hard_negative={m:explain(top_hard['F0'],m,policy) for m in ('F0','F1','F2','F3')},
         per_formula_max_hard_negative={m:explain(top_hard[m],m,policy) for m in ('F0','F1','F2','F3')}))
    save(OUT/'ablation.json',{m:per_model[m] for m in ABLATIONS})
    save(OUT/'gate_comparison.json',{m:per_model[m] for m in ('F3','gate_hard','gate_soft')})
    save(OUT/'reliability_sensitivity.json',{m:per_model[m] for m in ('F3','equal_reliability')})
    save(OUT/'conflict_semantics_audit.json',dict(classification_counts=dict(conflicts),
         no_raw_endpoint_proof_interface=True,gt_e02_e06={e:gt[e] for e in ('GT-E02','GT-E06')}))
    save(OUT/'missing_evidence_audit.json',dict(v4_dimension_states=dict(states),unavailable_count_distribution=dict(missing),
         conditional_v4_ceiling='0.65+0.35*A/W',v4_unavailable_removed_from_quality=True,v4_fixed_mass_denominator=True,
         missing_is_negative=False,synthetic_counterexamples='synthetic_counterexamples.json',
         family_mean_strengths={p:{f:s/len(indices[p]) for f,s in d.items()} for p,d in family_stats.items() if p in indices},
         note='Observed-zero topology dilutes quality; unavailable families constrain only mass. Removing unavailable evidence leaves F3 exactly unchanged.'))
    # Candidate equality is mechanically inherited from immutable score replay,
    # independently hash the baseline candidates, without regenerating a candidate.
    for r in rows(BASELINE/'blind/diagnostics.jsonl.gz'):
        if r['stage']=='candidate':candidate_digest.update(json.dumps(r,sort_keys=True,separators=(',',':')).encode()+b'\n')
    if candidate_digest.hexdigest()!=seal['candidate_digest']:raise ValueError('candidate_policy_changed')
    save(OUT/'candidate_integrity.json',dict(status='PASS',candidate_count=seal['candidate_count'],
         scored_candidate_count=seal['scored_candidate_count'],GT_EDGES=6,CANDIDATE_GT_EDGES=6,SCORED_GT_EDGES=6,
         CANDIDATE_RECALL=1.,unchanged_digest=seal['candidate_digest'],candidate_generation_rerun=False))
    # Freeze all decisions independently of regression; finalize can only veto.
    synthetic=read(OUT/'synthetic_counterexamples.json');assessments={}
    f0=per_model['F0'];tail_keys=(('explicit_negative','max'),('hard_negative_touching','max'),('background','p99'),('background','max'))
    for m in ('F1','F2','F3'):
        f=per_model[m];tail={p+'.'+k:dict(baseline=f0['distributions'][p][k],candidate=f['distributions'][p][k],
            limit=f0['distributions'][p][k]+policy['safety']['max_tail_absolute_increase'],
            passed=f['distributions'][p][k]<=f0['distributions'][p][k]+policy['safety']['max_tail_absolute_increase']) for p,k in tail_keys}
        gt_lift=f['distributions']['gt']['mean']-f0['distributions']['gt']['mean']
        neg_lift=f['distributions']['explicit_negative']['mean']-f0['distributions']['explicit_negative']['mean']
        ranking_improves=pairwise[m]['strict_rate']>pairwise['F0']['strict_rate']
        # Shared typed counterexamples are tested against all candidates separately
        # in pytest; F1 keeps the old overly restrictive gate as an explicit limit.
        eligible=all(v['passed'] for v in tail.values()) and ranking_improves and gt_lift>neg_lift and all(v['pass_'] for v in synthetic.values())
        assessments[m]=dict(eligible_before_integrity=eligible,tails=tail,pairwise_improves=ranking_improves,
             gt_mean_lift=gt_lift,explicit_negative_mean_lift=neg_lift,
             discriminative_improvement=ranking_improves and gt_lift>neg_lift,
             status='ELIGIBLE_PENDING_REGRESSION' if eligible else 'NO_DISCRIMINATIVE_IMPROVEMENT_OR_SAFETY_FAILURE')
    selected=next((m for m in ('F1','F2','F3') if assessments[m]['eligible_before_integrity']),None)
    save(OUT/'formula_selection.json',dict(selected_formula=selected,V5_FORMULA_CANDIDATE_SELECTED=False,
         status='PENDING_INTEGRITY_AND_REGRESSION',priority='semantic correctness, ranking, tail safety, sparse robustness, explainability, simplicity',
         assessments=assessments,selection_rule_predeclared=True,threshold=.65,not_population_auc=True))
    save(OUT/'evaluation_summary.json',dict(models=per_model,gt={e:{m:gt[e][m]['final_score'] for m in ('F0','F1','F2','F3')} for e in gt},
         other_unlabeled_member_count=len(indices.get('other_unlabeled',[])),
         explicit_negative_scored=len(indices.get('explicit_negative',[])),explicit_negative_total=len(negative),
         unscored_negative_policy='excluded from score distributions and ordering; never imputed zero',
         evaluation_coverage=len(indices.get('explicit_negative',[]))/len(negative),
         all_member_count=len(pairs),candidate_count=seal['candidate_count']))
    print(json.dumps(dict(selected_pending_regression=selected,pairwise={m:pairwise[m]['strict_rate'] for m in ('F0','F1','F2','F3')},assessments=assessments)),flush=True)


if __name__=='__main__':evaluate()

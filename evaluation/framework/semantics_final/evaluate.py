"""Truth is loaded only after implementation and all blind predictions seal."""
from bisect import bisect_left,bisect_right
from collections import Counter,defaultdict
import csv,math
from . import ROOT,OUT
from .runtime import verify_seal
from evaluation.framework.formula_design import BASELINE
from evaluation.framework.formula_design.runtime import read,save,rows,sha
from evaluation.framework.threshold_calibration.metrics import distribution,longest_path,ranking_metrics

def quantiles(values):
    values=sorted(values)
    def q(p):
        if not values:return None
        x=(len(values)-1)*p;a=math.floor(x);b=math.ceil(x)
        return values[a]+(values[b]-values[a])*(x-a)
    return {k:q(p) for k,p in [('min',0),('p50',.5),('p90',.9),('p95',.95),('p99',.99),('p999',.999),('max',1)]}

def labels(alerts):
    from evaluation.framework.formula_repair import evaluate as old
    old.OUT=OUT;old.verify_seal=verify_seal
    return old.labels(alerts)

def winner_rows(alerts):
    best={}
    for row in rows(OUT/'blind/members.jsonl.gz'):
        if not row['valid']: continue
        pair=row['support_pair'];key=tuple(row['support_key'])
        tie=(-row['score'],alerts[pair[0]]['timestamp'],alerts[pair[1]]['timestamp'],*pair)
        if key not in best or tie<best[key][0]:best[key]=(tie,row)
    return {k:v[1] for k,v in best.items()}

def run():
    if (OUT/'calibration.json').exists():raise ValueError('single_use_evaluation')
    seal=verify_seal()
    alerts={r['alert_id']:r for r in rows(BASELINE/'blind/canonical.jsonl.gz')}
    # Label-free score distribution written before reading truth.
    members=list(rows(OUT/'blind/members.jsonl.gz'))
    values=[r['score'] for r in members]
    histogram=[dict(left=i/20,right=(i+1)/20,count=sum(i/20<=s<(i+1)/20 or i==19 and s==1 for s in values)) for i in range(20)]
    save(OUT/'blind_score_distribution.json',dict(candidate_count=seal['candidate_count'],scored_count=len(members),
        gate_rejected_count=sum(not r['gate']['passed'] for r in members),score_quantiles=quantiles(values),histogram=histogram,
        ground_truth_used=False,score_scope='all complete original-member pair scores, including rejected scores=0'))
    lab=labels(alerts)
    save(OUT/'evaluation/label_projection.json',dict(hard_ids=sorted(lab['hard_ids']),attack_ids=sorted(lab['attack_ids']),background_ids=sorted(lab['background_ids']),
        nodes={k:sorted(v) for k,v in lab['members'].items()},
        node_stages={k:v['stage'] for k,v in lab['nodes'].items()},ids=lab['ids'],gt_edges=lab['gt']['edges']))
    witnesses={k:tuple(sorted(next(iter(v)))) for k,v in lab['witnesses'].items()}
    gt_pairs={p:k for k,p in witnesses.items()}; definitions={e['edge_id']:e for e in lab['gt']['edges']}
    by_pair={tuple(sorted(r['support_pair'])):r for r in members}
    selected=winner_rows(alerts);selected_by_pair={tuple(sorted(r['support_pair'])):r for r in selected.values()}
    sorted_scores=sorted(r['score'] for r in selected.values())
    gt={}; details={};gt_member_scores=[]
    for eid,pair in witnesses.items():
        row=by_pair.get(pair);score=row['score'] if row else None
        gt[eid]=dict(edge_id=eid,candidate_present=row is not None,gate_pass=bool(row and row['gate']['passed']),
            score=score,rank=1+len(sorted_scores)-bisect_right(sorted_scores,score) if score is not None else None,
            selected_support=pair in selected_by_pair,from_node=definitions[eid]['from'],to_node=definitions[eid]['to'],
            source_alert_id=lab['ids'][definitions[eid]['witness_alert_ids']['from']],target_alert_id=lab['ids'][definitions[eid]['witness_alert_ids']['to']])
        if score is not None:gt_member_scores.append(score)
    per_hard=[]
    for h in sorted(lab['hard_ids']):
        explicit=[r for p,r in by_pair.items() if h in p and p in lab['negative_pairs']]
        touching=[r for p,r in by_pair.items() if h in p]
        valid=[r for p,r in selected_by_pair.items() if h in p and p in lab['negative_pairs']]
        per_hard.append(dict(alert_id=h,external_alert_id=lab['metadata'][h]['alert_id'],
            candidate_negative_pairs=len(explicit),explicit_negative_max=max((r['score'] for r in explicit),default=None),
            selected_explicit_negative_max=max((r['score'] for r in valid),default=None),
            all_touching_max=max((r['score'] for r in touching),default=None),
            max_explicit_pair=max(explicit,key=lambda r:r['score'])['support_pair'] if explicit else None,
            max_touching_pair=max(touching,key=lambda r:r['score'])['support_pair'] if touching else None))
    explicit_scores=[r['score'] for p,r in by_pair.items() if p in lab['negative_pairs']]
    hard_scores=[r['explicit_negative_max'] for r in per_hard if r['explicit_negative_max'] is not None]
    touching_scores=[r['score'] for p,r in by_pair.items() if set(p)&lab['hard_ids']]
    backgrounds=[r for p,r in selected_by_pair.items() if set(p)<=lab['background_ids']]
    non_gt=[r for p,r in selected_by_pair.items() if p not in gt_pairs]
    top_background=sorted(backgrounds,key=lambda r:(-r['score'],r['support_key']))[:100]
    top_non_gt=sorted(non_gt,key=lambda r:(-r['score'],r['support_key']))[:100]
    chosen_pairs={tuple(sorted(r['support_pair'])) for r in top_background+top_non_gt}
    chosen_pairs.update(tuple(sorted(p)) for r in per_hard for p in (r['max_explicit_pair'],r['max_touching_pair']) if p)
    wanted=chosen_pairs|set(witnesses.values())
    for row in rows(OUT/'blind/diagnostics.jsonl.gz'):
        if row['stage']!='member_score': continue
        pair=tuple(sorted(row['support_pair']))
        if pair in wanted: details[pair]=row
    for eid,pair in witnesses.items():
        if pair not in details:continue
        row=details[pair];v=row['evidence']['evidence_v5']
        gt[eid].update(support_families=[f['name'] for f in v['features'] if f['state']=='OBSERVED_SUPPORT'],
            contradiction_families=[f['name'] for f in v['features'] if f['state']=='OBSERVED_CONTRADICTION'],
            evidence_mass=v['evidence_mass'],semantic_agreement=v['quality'],independent_support_count=len(v['group_support']),
            group_support=v['group_support'],verified_relation_count=len(row['evidence']['relations']),breakdown=v,
            rejected_relation_reasons=row['evidence']['refused_relations'])
    save(OUT/'ground_truth_edge_scores.json',dict(edges=gt,candidate_recall=sum(r['candidate_present'] for r in gt.values())/6,
        gate_recall=sum(r['gate_pass'] for r in gt.values())/6,min=min(gt_member_scores),max=max(gt_member_scores),median=distribution(gt_member_scores)['median']))
    def explain_pair(pair):
        row=details[pair];v=row['evidence']['evidence_v5']
        return dict(support_pair=list(pair),score=row['score'],valid=row['valid'],groups=v['group_support'],
            support=[f for f in v['features'] if f['state']=='OBSERVED_SUPPORT'],gate=v['gate'],
            semantic_agreement=v['quality'],evidence_mass=v['evidence_mass'],temporal_factor=v['temporal_factor'],
            duplicate_penalty=v['duplicate_penalty'],conflict_penalty=v['conflict_penalty'],relations=row['evidence']['relations'],
            alerts=[{k:alerts[a][k] for k in ('alert_id','source_namespace','timestamp','category','rule_id','signature','src_ip','dst_ip','host','account','domain','url')} for a in pair])
    negative_explanations={':'.join(pair):explain_pair(pair) for pair in sorted(chosen_pairs) if set(pair)&lab['hard_ids']}
    save(OUT/'hard_negative_scores.json',dict(unit='30 hard-negative alerts, each max over explicitly labelled not-related links to 21 attack alerts; unknown background touching pairs kept separate',
        alerts=per_hard,per_alert_max_distribution=distribution(hard_scores),explicit_pair_distribution=distribution(explicit_scores),
        all_hard_touching_distribution=distribution(touching_scores),explicit_negative_total=630,scored_explicit_negative_pairs=len(explicit_scores),
        missing_pair_policy='No candidate => absent prediction, not fabricated zero score; pipeline TN allowed at positive thresholds',highest_pair_explanations=negative_explanations))
    def review(row):
        pair=tuple(sorted(row['support_pair']));x=explain_pair(pair);v=details[pair]['evidence']['evidence_v5'];a,b=(alerts[p] for p in pair)
        context=[f for f in v['features'] if f['state']=='OBSERVED_SUPPORT' and f['family'] in {'entity','relation'}]
        dup=details[pair]['evidence']['duplicate_features'].get('observation_identity',{})
        if dup.get('equivalent'):
            category='DUPLICATE_OBSERVATION';why='Existing observation verifier identifies one underlying observation.'
        elif context and all(f['hot'] for f in context):
            category='HOT_ENTITY_ARTIFACT';why='All affirmative semantic context is hot; recurrence does not prove shared attack.'
        elif x['relations']:
            category='LIKELY_CORRELATED';why='Existing field verifier attests explicit propagation; still not ground-truth confirmation.'
        elif len(v['group_support'])>=2:
            category='PLAUSIBLE';why='Multiple dependency-separated contextual clues and temporal compatibility; no causal proof.'
        elif context and all(f['name']=='entity.IP' for f in context):
            category='LIKELY_FALSE';why='Only shared address context; detector/time/transport recurrence adds no independent support.'
        else:
            category='AMBIGUOUS';why='Single contextual component or noncausal flow; insufficient labels for a firm verdict.'
        x.update(classification=category,reason=why,semantic_only_review=True,
            same_detector=bool(a['rule_id'] is not None and a['rule_id']==b['rule_id'] and a['source_namespace']==b['source_namespace']),
            same_signature=bool(a['signature'] is not None and a['signature']==b['signature']),
            repeated_observation=bool(dup.get('equivalent')),
            temporal_only=not context,transport_only=False)
        return x
    reviews=[review(r) for r in top_background];other_reviews=[review(r) for r in top_non_gt]
    suspicious={'LIKELY_FALSE','DUPLICATE_OBSERVATION','HOT_ENTITY_ARTIFACT'}
    suspicious_scores=[r['score'] for r in reviews if r['classification'] in suspicious]
    save(OUT/'top_background_pairs_review.json',dict(scope='Top100 valid representative winners with BOTH endpoints in the real CPTC t5 background',
        method='Deterministic semantic review using complete sealed evidence; heuristic diagnostic categories, not human ground-truth labels; never fed back to scoring',
        pairs=reviews,counts=dict(Counter(r['classification'] for r in reviews)),top100_non_gt_including_hard_and_attack=other_reviews,
        max_background_suspicious_score=max(suspicious_scores,default=None)))
    scores=sorted(set(sorted_scores));thresholds={round(.4+.02*i,2) for i in range(21)}|{.65,.7}
    thresholds.update(gt_member_scores)
    for s in gt_member_scores:thresholds.add(math.nextafter(s,math.inf))
    thresholds.update(r['explicit_negative_max'] for r in per_hard if r['explicit_negative_max'] is not None)
    rows_out=[]
    for t in sorted(thresholds):
        recovered=[e for e,r in gt.items() if r['selected_support'] and r['gate_pass'] and r['score']>=t]
        negative_admitted=[r for p,r in selected_by_pair.items() if p in lab['negative_pairs'] and r['score']>=t]
        hard_fp={h for h in lab['hard_ids'] if any(h in r['support_pair'] for r in negative_admitted)}
        bg=sum(r['score']>=t for r in backgrounds)
        tp=len(recovered);fp=len(negative_admitted)
        rows_out.append(dict(threshold=t,GT_TP=tp,GT_FN=6-tp,GT_Recall=tp/6,
            Hard_Negative_FP=len(hard_fp),Hard_Negative_TN=30-len(hard_fp),hard_negative_FPR=len(hard_fp)/30,
            annotated_pair_FP=fp,annotated_pair_TN=630-fp,pair_precision=tp/(tp+fp) if tp+fp else None,
            F1=2*tp/(6+tp+fp) if 6+tp+fp else None,
            alert_balanced_accuracy=((tp/6)+(30-len(hard_fp))/30)/2,
            total_admitted_edges=sum(r['score']>=t for r in selected.values()),background_admitted_edges=bg,
            hard_touching_admitted_edges=sum(r['score']>=t and bool(set(r['support_pair'])&lab['hard_ids']) for r in selected.values()),
            correlation_GT_path_proxy=longest_path([(gt[e]['from_node'],gt[e]['to_node']) for e in recovered])))
    positives=min(gt_member_scores);maximum=max(hard_scores) if hard_scores else None
    safe=[r for r in rows_out if r['GT_TP']==6 and r['Hard_Negative_FP']==0 and r['background_admitted_edges']<=1000]
    # Distinct sample maxima define the admissible interval; no selected edge hack.
    lower=max([maximum or 0.,*[r['score'] for r in reviews if r['classification'] in suspicious]],default=0.)
    upper=positives
    stable=bool(safe and upper-lower>=.02)
    selected_threshold=(lower+upper)/2 if stable else None
    save(OUT/'calibration.json',dict(formula_hash=read(OUT/'formula_freeze.json')['formula_hash'],formula_frozen=True,
        GT_MIN_SCORE=positives,MAX_HARD_NEGATIVE_SCORE=maximum,MAX_ALL_HARD_TOUCHING_SCORE=max(touching_scores,default=None),
        MAX_BACKGROUND_SUSPICIOUS_SCORE=max(suspicious_scores,default=None),GT_NEGATIVE_MARGIN=positives-maximum if maximum is not None else None,
        SCORE_OVERLAP=bool(maximum is not None and positives<=maximum),selected_threshold=selected_threshold,
        production_threshold_frozen=False,diagnostic_threshold=.65,all_GT_threshold=positives,
        prospective_safe_points=safe,stable_interval=[lower,upper] if stable else None,
        decision='Stable score interval nominated; end-to-end/regressions still required' if stable else 'FORMULA_NOT_READY_FOR_PRODUCTION_THRESHOLD: overlap or background burden; formula remains frozen',
        ranking_annotated_only=ranking_metrics(gt_member_scores,explicit_scores),evaluation_coverage=(len(gt_member_scores)+len(explicit_scores))/len(members),
        unlabelled_pairs_excluded=True,threshold_sweep=rows_out,
        graph_threshold_policy='Admission swept; existing clustering .70, chain .70, direction .75 and all guards remain fixed',
        dataset_limitation='6 positive witness edges and 30 designed negative alerts; 630 labelled negative links, only candidate-covered links have scores. No population precision claims.'))
    save(OUT/'score_histogram.json',dict(histogram=histogram,quantiles=quantiles(values)))
    print('POST_SEAL_EVALUATION_COMPLETE',flush=True)

def write_csv(table):
    with (OUT/'threshold_sweep.csv').open('w',newline='',encoding='utf8') as f:
        writer=csv.DictWriter(f,fieldnames=list(table[0]));writer.writeheader();writer.writerows(table)

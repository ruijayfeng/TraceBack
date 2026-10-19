"""Post-seal labels, distributions and threshold calibration. Never rescoring."""
from bisect import bisect_left
from collections import defaultdict
import csv
import json
import math
from . import ROOT,OUT
from .runtime import verify_seal
from evaluation.framework.formula_design import BASELINE
from evaluation.framework.formula_design.runtime import read,save,sha,rows
from evaluation.framework.threshold_calibration.metrics import distribution,ranking_metrics,classification,longest_path


def labels(alerts):
    verify_seal()
    save(OUT/'evaluation_started.json',dict(score_seal_sha256=sha(OUT/'score_seal.json'),
        order='prospective rule -> formula freeze -> GT-denied production scoring -> sealed scores -> labels -> calibration',
        scoring_after_truth=False,split='frozen semi-synthetic development; not independent validation'))
    from evaluation.framework.v4_semisynthetic_baseline import truth
    dest=OUT/'evaluation';(dest/'blind').mkdir(parents=True,exist_ok=True)
    (dest/'blind/input_line_map.json').write_bytes((BASELINE/'blind/input_line_map.json').read_bytes())
    (dest/'blind_run_manifest.json').write_bytes((OUT/'score_seal.json').read_bytes())
    old,oldverify=truth.OUT,truth.require_sealed
    try:
        truth.OUT=dest
        truth.require_sealed=lambda:{**verify_seal(),'raw_alert_count':len(alerts)}
        return truth.load(alerts)
    finally:
        truth.OUT,truth.require_sealed=old,oldverify


def run():
    if (OUT/'evaluation_summary.json').exists():raise ValueError('evaluation_already_delivered')
    seal=verify_seal()
    alerts={a['alert_id']:a for a in rows(BASELINE/'blind/canonical.jsonl.gz')}
    lab=labels(alerts)
    witnesses={e:next(iter(p)) for e,p in lab['witnesses'].items()}
    by_pair={tuple(sorted(p)):e for e,p in witnesses.items()}
    negative=lab['negative_pairs'];hard=lab['hard_ids']
    best={};pop=defaultdict(list);gt={};annotated={};pos=[];neg=[];hard_values=[]
    for row in rows(OUT/'blind/members.jsonl.gz'):
        pair=tuple(sorted(row['support_pair']));key=tuple(row['support_key']);s=row['score']
        population='GT' if pair in by_pair else 'HARD_TOUCHING' if set(pair)&hard else 'UNLABELLED_OTHER'
        pop[population].append(s)
        if pair in by_pair:gt[by_pair[pair]]=row;pos.append(s)
        if pair in negative:neg.append(s)
        if set(pair)&hard:hard_values.append(s)
        if pair in negative or pair in by_pair:annotated[pair]=row
        if row['valid']:
            tie=(-s,alerts[pair[0]]['timestamp'],alerts[pair[1]]['timestamp'],*row['support_pair'])
            # Pair endpoint ordering in the score stream is the frozen tie order.
            tie=(-s,alerts[row['support_pair'][0]]['timestamp'],alerts[row['support_pair'][1]]['timestamp'],*row['support_pair'])
            if key not in best or tie<best[key][0]:best[key]=(tie,row)
    selected=[v[1] for v in best.values()]
    selected_scores=sorted(r['score'] for r in selected)
    selected_unknown=sorted(r['score'] for r in selected if tuple(sorted(r['support_pair'])) not in annotated)
    negative_scores=sorted(r['score'] for p,r in annotated.items() if p in negative and r['valid'])
    hard_scores=sorted(r['score'] for r in selected if set(r['support_pair'])&hard)
    gt_defs={e['edge_id']:e for e in lab['gt']['edges']}
    def count_ge(values,t):return len(values)-bisect_left(values,t)
    def measure(t):
        recovered={e for e,r in gt.items() if r['valid'] and r['score']>=t
            and best[tuple(r['support_key'])][1]['support_pair']==r['support_pair']}
        return dict(threshold=t,**classification(len(recovered),count_ge(negative_scores,t)),
            total_edges=count_ge(selected_scores,t),unlabelled_admitted=count_ge(selected_unknown,t),
            hard_touching_admitted=count_ge(hard_scores,t),
            correlation_path_proxy=longest_path([(gt_defs[e]['from'],gt_defs[e]['to']) for e in recovered]))
    thresholds={i/200 for i in range(201)}
    for r in gt.values():thresholds.update({r['score'],math.nextafter(r['score'],math.inf)})
    metrics=[measure(t) for t in sorted(thresholds)]
    with (OUT/'threshold_metrics.csv').open('w',encoding='utf8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(metrics[0]));writer.writeheader();writer.writerows(metrics)
    diagnostic=max(metrics,key=lambda r:(r['GT_TP'],-r['FP'],-r['unlabelled_admitted'],r['threshold']))
    # Conservative operating region: recover all witnesses without known FP,
    # then require a neighborhood; downstream still has to pass independently.
    safe=[r for r in metrics if r['GT_TP']==6 and r['FP']==0 and r['hard_touching_admitted']==0]
    stability=[measure(max(0.,min(1.,diagnostic['threshold']+delta))) for delta in (-.05,-.02,-.01,0.,.01,.02,.05)]
    detail={}
    target_keys={tuple(r['support_key']) for r in gt.values()}
    candidate_evidence={}
    for row in rows(OUT/'blind/diagnostics.jsonl.gz'):
        if row['stage']=='candidate' and tuple(row['support_key']) in target_keys:
            candidate_evidence[tuple(row['support_key'])]=row
        if row['stage']=='member_score' and tuple(sorted(row['support_pair'])) in by_pair:
            e=by_pair[tuple(sorted(row['support_pair']))]
            detail[e]=dict(**gt[e],candidate_channels=candidate_evidence.get(tuple(row['support_key'])),
                breakdown=row['evidence']['evidence_v5'],relations=row['evidence']['relations'],
                conflicts=row['evidence']['conflicts'],gt_from=gt_defs[e]['from'],gt_to=gt_defs[e]['to'],
                gt_source_alert_id=lab['ids'][gt_defs[e]['witness_alert_ids']['from']],
                gt_target_alert_id=lab['ids'][gt_defs[e]['witness_alert_ids']['to']])
    stats=ranking_metrics(pos,neg)
    f2=read(ROOT/'outputs/v5_validation_threshold_calibration/summary.json')['score_separation']['annotated_only']
    save(OUT/'ground_truth_edge_scores.json',dict(candidate_recall=len(detail)/6,gate_pass=sum(r['valid'] for r in gt.values()),edges=detail))
    save(OUT/'score_distribution.json',dict(distributions={k:distribution(v) for k,v in pop.items()},
        annotated_negative=distribution(neg),hard_negative=distribution(hard_values),ranking=stats,F2_ranking=f2,
        evaluation_coverage=(len(pos)+len(neg))/seal['member_count'],explicit_negative_candidate_coverage=len(neg)/len(negative),
        unlabelled_excluded=True,hard_touching_is_not_all_verified_negative=True,
        GT_hard_overlap_count=sum(s<=max(hard_values) for s in pos),
        F2_GT_hard_overlap_count=sum(r['score']<=read(ROOT/'outputs/v5_validation_threshold_calibration/summary.json')['score_separation']['highest_hard_touching_score']
            for r in read(ROOT/'outputs/v5_validation_threshold_calibration/ground_truth_edge_scores.json')['edges'].values())))
    save(OUT/'threshold_stability.json',dict(diagnostic_threshold=diagnostic['threshold'],rows=stability,
        recommended_threshold=None,production_recommendation=False))
    save(OUT/'evaluation_summary.json',dict(candidate_count=seal['candidate_count'],member_count=seal['member_count'],
        GT_candidates=len(detail),GT_gate_pass=sum(r['valid'] for r in gt.values()),GT_score_range=[min(pos),max(pos)],
        ranking=stats,F2_ranking=f2,hard_negative=distribution(hard_values),historical=measure(.65),
        stricter=measure(.70),diagnostic=diagnostic,safe_region=safe,recommended_admission_threshold=None,
        recommended_clustering_threshold=None,recommended_chain_threshold=None,
        threshold_policy='no region with all six witnesses and zero known/hard-touching negatives; NONE rather than force choice',
        threshold_grid='0..1 step 0.005 plus witness exact/nextafter boundaries; same sealed scores',
        new_formula_GT_evaluation_count=1,formula_revisions=1,t2_read=False))
    extend_stability()
    print(json.dumps(read(OUT/'evaluation_summary.json')),flush=True)


def extend_stability():
    """Summarize predeclared threshold neighborhoods from the same CSV only."""
    with (OUT/'threshold_metrics.csv').open(encoding='utf8',newline='') as f:
        table=list(csv.DictReader(f))
    current=read(OUT/'threshold_stability.json')
    neighborhoods={}
    for center in (.65,.70):
        nearby=[]
        for delta in (-.05,-.02,-.01,0.,.01,.02,.05):
            t=round(center+delta,3)
            row=next(r for r in table if abs(float(r['threshold'])-t)<1e-14)
            nearby.append({k:None if v=='' else float(v) for k,v in row.items()})
        neighborhoods[str(center)]=nearby
    current['predeclared_threshold_neighborhoods']=neighborhoods
    current['source']='existing threshold_metrics.csv only; no scoring, formula changes or new label load'
    save(OUT/'threshold_stability.json',current)


if __name__=='__main__':run()

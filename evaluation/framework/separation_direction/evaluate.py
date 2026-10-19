"""Post-seal development diagnostics. No calibration and no scoring feedback."""
from collections import Counter
from itertools import product
from statistics import median
from . import OUT,BASE,INPUT
from .runtime import verify_seal
from evaluation.framework.formula_design.runtime import read,save,rows,sha
from evaluation.framework.threshold_calibration.metrics import longest_path


def run():
    frozen,seal=verify_seal()  # Must precede every GT read.
    if (OUT/'evaluation_started.json').exists():raise ValueError('single_use_evaluation')
    save(OUT/'evaluation_started.json',dict(score_seal_sha256=sha(OUT/'score_seal.json'),
        predictions_sealed_first=True,development_audit_previously_saw_GT=True))
    lab=read(BASE/'evaluation/label_projection.json')
    old=read(BASE/'ground_truth_edge_scores.json')['edges']
    attack,hard,background=(set(lab[k]) for k in ('attack_ids','hard_ids','background_ids'))
    negative={tuple(sorted(p)) for p in product(attack,hard)}
    reverse_ids={v:k for k,v in lab['ids'].items()}
    gt_pairs={tuple(sorted((v['source_alert_id'],v['target_alert_id']))):eid for eid,v in old.items()}
    selected=list(rows(OUT/'blind/selected_scores.jsonl.gz'))
    winners={tuple(r['support_key']):r for r in selected}
    topbg=sorted((r for r in selected if set(r['support_pair'])<=background),
        key=lambda r:(-r['score'],r['support_pair']))[:100]
    wanted=set(gt_pairs)|{tuple(sorted(r['support_pair'])) for r in topbg}
    details={};negatives={};touching={h:dict(count=0,maximum=None,pair=None) for h in hard}
    statuses=Counter();hist=[0]*20;total=0
    for r in rows(OUT/'blind/pair_scores.jsonl.gz'):
        total+=1;hist[min(19,int(r['score']*20))]+=1;statuses[r['direction']['status']]+=1
        pair=tuple(sorted(r['support_pair']))
        if pair in wanted:details[pair]=r
        if pair in negative:negatives[pair]=r
        for h in set(pair)&hard:
            x=touching[h];x['count']+=1
            if x['maximum'] is None or r['score']>x['maximum']:x.update(maximum=r['score'],pair=pair)
    if total!=seal['member_count']:raise ValueError('evaluation_coverage_drift')
    def is_winner(r):
        w=winners.get(tuple(r['support_key']))
        return bool(w and tuple(sorted(w['support_pair']))==tuple(sorted(r['support_pair'])))
    gt={}
    for pair,eid in gt_pairs.items():
        r=details.get(pair);base=old[eid]
        gt[eid]=dict(edge_id=eid,correlation_candidate=r is not None,gate_pass=bool(r and r['valid']),
            old_score=base['score'],correlation_score=r['score'] if r else None,
            selected_support=bool(r and is_winner(r)),source_alert_id=base['source_alert_id'],target_alert_id=base['target_alert_id'],
            from_node=base['from_node'],to_node=base['to_node'],
            direction_status=r['direction']['status'] if r else 'NO_CANDIDATE',
            direction_confidence=r['direction']['direction_confidence'] if r else 0,
            direction_matches_GT=bool(r and r['direction']['source_alert_id']==base['source_alert_id'] and r['direction']['target_alert_id']==base['target_alert_id']),
            forward_evidence=r['direction']['forward_evidence'] if r else [],reverse_evidence=r['direction']['reverse_evidence'] if r else [],
            full_pair_result=r)
    perhard=[]
    for h in sorted(hard):
        rs=[r for pair,r in negatives.items() if h in pair]
        best=max(rs,key=lambda r:r['score']) if rs else None
        perhard.append(dict(alert_id=h,external_alert_id=reverse_ids.get(h),explicit_candidate_pairs=len(rs),
            explicit_negative_max=best['score'] if best else None,max_pair=best['support_pair'] if best else None,
            all_touching=touching[h]))
    save(OUT/'hard_negative_results.json',dict(alerts=perhard,explicit_negative_total=630,
        explicit_scored_count=len(negatives),unscored_policy='Absent candidate; no fabricated score. Absent prediction at positive diagnostic points.',
        pairs=[dict(support_pair=p,candidate=p in negatives,score=negatives[p]['score'] if p in negatives else None)
            for p in sorted(negative)],
        top20_decomposition=sorted(negatives.values(),key=lambda r:(-r['score'],r['support_pair']))[:20],
        all_touching_is_not_explicit_negative=True))
    reviews=[]
    for w in topbg:
        r=details[tuple(sorted(w['support_pair']))];groups=r['score_breakdown']['group_support']
        label='PLAUSIBLE' if len(groups)>=2 else 'AMBIGUOUS'
        if r['direction']['status']=='DERIVED_VERIFIED_DIRECTION':label='SUPPORTED_DIRECTION'
        reviews.append(dict(classification=label,reason='Deterministic evidence audit; unlabelled background, not a negative truth label.',pair_result=r))
    save(OUT/'top_background_pairs.json',dict(scope='Top100 selected pairs with both endpoints in real t5 background',
        labelled=False,counts=dict(Counter(x['classification'] for x in reviews)),pairs=reviews))
    point_results=[];primary={}
    for threshold in frozen['policy']['diagnostic_operating_points']:
        folder=OUT/'blind'/('point_'+str(threshold).replace('.','_'))
        summary=read(folder/'summary.json');nodes=list(rows(folder/'nodes.jsonl.gz'));chains=list(rows(folder/'chain_edges.jsonl.gz'))
        node_by_alert={a:n for n in nodes for a in n['alert_ids']};chain_keys={(e['source_node_id'],e['target_node_id']) for e in chains}
        peredge={}
        for eid,g in gt.items():
            a,b=g['source_alert_id'],g['target_alert_id'];na,nb=node_by_alert[a],node_by_alert[b]
            admitted=bool(g['gate_pass'] and g['selected_support'] and g['correlation_score']>=threshold)
            direction=g['direction_status']=='DERIVED_VERIFIED_DIRECTION' and g['direction_matches_GT']
            created=(na['node_id'],nb['node_id']) in chain_keys
            if not g['correlation_candidate']:failure='BROKEN_AT_CANDIDATE'
            elif not g['gate_pass']:failure='BROKEN_AT_GATE'
            elif not g['selected_support']:failure='BROKEN_AT_MEMBER_SELECTION'
            elif not admitted:failure='BROKEN_AT_SCORE'
            elif not direction:failure='BROKEN_AT_DIRECTION'
            elif na['incident_id']!=nb['incident_id']:failure='BROKEN_AT_CLUSTERING'
            elif not created:failure='BROKEN_AT_CHAIN_GUARD'
            else:failure=None
            peredge[eid]=dict(correlation_admitted=admitted,chain_edge_created=created,failure_layer=failure,
                source_node_id=na['node_id'],target_node_id=nb['node_id'],same_incident=na['incident_id']==nb['incident_id'])
        corr=sum(r['correlation_admitted'] for r in peredge.values());chain=sum(r['chain_edge_created'] for r in peredge.values())
        recovered=[(g['from_node'],g['to_node']) for eid,g in gt.items() if peredge[eid]['chain_edge_created']]
        admitted_rows=[r for r in selected if r['score']>=threshold]
        result=dict(**summary,GT_CORRELATION_EDGES_RECOVERED=corr,
            GT_DIRECTION_EDGES_RECOVERED=sum(g['direction_status']=='DERIVED_VERIFIED_DIRECTION' and g['direction_matches_GT'] for g in gt.values()),
            GT_CHAIN_EDGES_RECOVERED=chain,GT_LONGEST_PATH_RECOVERED=longest_path(recovered),
            background_admitted_edges=sum(set(r['support_pair'])<=background for r in admitted_rows),
            explicit_negative_admitted_pairs=sum(tuple(sorted(r['support_pair'])) in negative for r in admitted_rows),GT_edges=peredge)
        point_results.append(result)
        if threshold==.65:primary=result
    for eid,g in gt.items():g.update(primary['GT_edges'][eid])
    values=[g['correlation_score'] for g in gt.values() if g['correlation_score'] is not None]
    hn=max((r['score'] for r in negatives.values()),default=None)
    save(OUT/'gt_direction_results.json',dict(diagnostic_threshold=.65,edges=gt))
    save(OUT/'separation_results.json',dict(GT_MIN_SCORE=min(values),GT_MEDIAN_SCORE=median(values),GT_MAX_SCORE=max(values),
        HARD_NEGATIVE_MAX_SCORE=hn,GT_NEGATIVE_MARGIN=min(values)-hn if hn is not None else None,
        SCORE_OVERLAP=bool(hn is not None and min(values)<=hn),
        MAX_ALL_HARD_TOUCHING_SCORE=max(x['maximum'] for x in touching.values() if x['maximum'] is not None),
        candidate_recall=sum(g['correlation_candidate'] for g in gt.values())/6,gate_recall=sum(g['gate_pass'] for g in gt.values())/6,
        annotated_pair_coverage=(len(values)+len(negatives))/total,unlabelled_pairs_excluded=True,
        diagnostic_points=point_results,primary=primary,final_threshold=None,formula_revisions_after_seal=0))
    save(OUT/'score_distribution.json',dict(scored_members=total,histogram=hist,direction_status_counts=dict(statuses)))
    print('POST_SEAL_DIAGNOSTICS_COMPLETE',flush=True)


if __name__=='__main__':run()

"""Phase B joins frozen predictions only. This module never imports a scorer."""
import collections
import gzip
import hashlib
import json
import random
from . import ROOT, OUT, DATA
from .seal import verify
from evaluation.framework.scoring_calibration.snapshot import read, save, sha


def rows(path):
    with gzip.open(path,'rt',encoding='utf8') as f:
        for line in f: yield json.loads(line)


def metrics(positives, negatives, candidates, variant='frozen', threshold=.65):
    def get(item):
        row=candidates.get(tuple(item['support_key']))
        return row['variants'][variant] if row else None
    gs=[get(p) for p in positives];hs=[get(p) for p in negatives]
    g=[r['score'] for r in gs if r is not None];h=[r['score'] for r in hs if r is not None]
    admitted=lambda r: r is not None and r['gate'] and r['score']>=threshold
    gt_admitted=sum(map(admitted,gs));hn_admitted=sum(map(admitted,hs))
    pairwise=sum(x>y for x in g for y in h)
    return dict(gt_edges=len(gs),gt_candidates=len(g),gt_admitted=gt_admitted,
        gt_candidate_recall=len(g)/len(gs) if gs else None,gt_admission_recall=gt_admitted/len(gs) if gs else None,
        hn_total=len(hs),hn_candidates=len(h),hn_admitted=hn_admitted,
        hn_rejection_rate=1-hn_admitted/len(hs) if hs else None,
        hn_scored_rejected=sum(r is not None and not admitted(r) for r in hs),hn_not_nominated=len(hs)-len(h),
        min_gt_score=min(g) if g else None,max_hn_score=max(h) if h else None,
        worst_margin=min(g)-max(h) if g and h else None,
        gt_gt_missing_scores=len(gs)-len(g),pairwise_ordering_rate=pairwise/(len(g)*len(h)) if g and h else None,
        pairwise_ordering_numerator=pairwise,pairwise_ordering_denominator=len(g)*len(h),
        pairwise_possible_denominator=len(gs)*len(hs),variant=variant,threshold=threshold)


def verify_predictions():
    verify();seal=read(OUT/'prediction_seal.json')
    if seal['status']!='SEALED_BEFORE_LABELS' or seal['labels_read']: raise ValueError('predictions_not_blind')
    for path,h in seal['files'].items():
        if sha(path)!=h: raise ValueError('prediction_changed:'+path)
    for name,key in [('validation_formula_seal.json','formula_seal_sha256'),('validation_parameter_seal.json','parameter_seal_sha256'),('preprocessing_seal.json','preprocessing_seal_sha256')]:
        if sha(OUT/name)!=seal[key]: raise ValueError('seal_changed:'+name)
    for path,h in seal['worker_sources'].items():
        if sha(path)!=h: raise ValueError('prediction_worker_changed:'+path)
    pre=read(OUT/'preprocessing_seal.json')
    if sha(pre['input_path'])!=pre['input_sha256']: raise ValueError('input_changed')
    for path,h in pre['files'].items():
        if sha(path)!=h: raise ValueError('preprocessing_changed:'+path)
    return seal


def background_audit(background, alerts):
    ranked=sorted(background,key=lambda p:(-p['variants']['frozen']['score'],p['support_key']))
    chosen=set();samples=[]
    near=sorted(background,key=lambda p:(abs(p['variants']['frozen']['score']-.65),p['support_key']))
    randomized=sorted(background,key=lambda p:p['support_key']);random.Random(73198261).shuffle(randomized)
    for stratum,pool in [('high_score',ranked),('near_threshold',near),('random_admitted',randomized)]:
        accepted=0
        for row in pool:
            key=tuple(row['support_key'])
            if key in chosen: continue
            chosen.add(key);accepted+=1
            r=row['variants']['frozen'];a,b=[alerts[i] for i in r['support_pair']]
            action_a=a['raw_alert'].get('action');action_b=b['raw_alert'].get('action')
            if action_a==action_b and r['anchor']['has_anchor']:
                classification='likely legitimate correlation'
                reason='Same observed activity token and action across sensor views; no progression asserted'
            elif 'session' in r['result']['anchor_types']:
                classification='shared infrastructure'
                reason='Shared transport/login/request context with different observed actions; independent tasks unresolved'
            elif 'process' in r['result']['anchor_types']:
                classification='weak ambiguous relation'
                reason='Shared complete long-lived process instance; action causality absent'
            else:
                classification='unknown';reason='Observable fields insufficient for independent adjudication'
            samples.append(dict(stratum=stratum,support_key=key,support_pair=r['support_pair'],score=r['score'],
                anchor=r['anchor'],classification=classification,rationale=reason,action_a=action_a,action_b=action_b,
                near_threshold_distance=abs(r['score']-.65),human_adjudicated=False))
            if accepted==50: break
    return dict(requested_per_stratum=50,actual_counts=dict(collections.Counter(s['stratum'] for s in samples)),
        classifications=dict(collections.Counter(s['classification'] for s in samples)),samples=samples,
        qualification='Provisional observable-semantics audit; no unlabeled background pair is automatically FP. Near means nearest available scores; distance disclosed.',
        categories=['likely legitimate correlation','duplicate/repeated observation','shared infrastructure','weak ambiguous relation','progression-compatible','likely over-correlation','unknown'])


def run():
    seal=verify_predictions()
    if (OUT/'evaluation_started.json').exists(): raise ValueError('single_use_evaluation')
    save(OUT/'evaluation_started.json',dict(prediction_seal_sha256=sha(OUT/'prediction_seal.json'),
        protocol='Labels opened only after all frozen/sensitivity predictions; no scorer invocation in Phase B'))
    truth=read(DATA/'evaluation/answers.json');manifest=read(DATA/'build_manifest.json')
    for name,h in manifest['files'].items():
        if sha(DATA/name)!=h: raise ValueError('dataset_manifest_changed:'+name)
    pre=OUT/'preprocessing';alerts={a['alert_id']:a for a in rows(pre/'canonical.jsonl.gz')}
    entities={e['entity_id']:e for e in rows(pre/'entities.jsonl.gz')}
    locator={a['raw_alert']['event_id']:i for i,a in alerts.items()};owner=read(pre/'owner.json')
    def bind(item):
        aids=[locator[i] for i in item['event_ids']]
        return dict(item,alert_ids=aids,support_key=sorted(owner[i] for i in aids))
    positives=list(map(bind,truth['positives']));negatives=list(map(bind,truth['hard_negatives']));controls=list(map(bind,truth['repeat_controls']))
    for group in (positives,negatives,controls):
        if len({tuple(x['support_key']) for x in group})!=len(group): raise ValueError('label_pairs_collapsed_or_duplicate')
    candidates={tuple(r['support_key']):r for r in rows(OUT/'validation_predictions/candidates.jsonl.gz')}
    gtkeys={tuple(p['support_key']) for p in positives};hnkeys={tuple(p['support_key']) for p in negatives}
    if gtkeys & hnkeys: raise ValueError('contradictory_labels')
    roles={locator[k]:v for k,v in truth['roles'].items()}
    admitted=[p for p in candidates.values() if p['variants']['frozen']['admitted']]
    bg=lambda r:all(roles[i]=='background' for i in r['variants']['frozen']['support_pair'])
    background=[p for p in admitted if bg(p)]
    baseline_bg=[p for p in candidates.values() if bg(p) and p['production']['gate'] and p['production']['score']>=.65]
    primary=metrics(positives,negatives,candidates)
    byfamily={f:metrics([], [n for n in negatives if n['family']==f], candidates) for f in sorted({n['family'] for n in negatives})}
    gt_byfamily={f:metrics([p for p in positives if p['family']==f],[],candidates) for f in sorted({p['family'] for p in positives})}
    save(OUT/'metrics.json',dict(primary=primary,hard_negative_families=byfamily,gt_families=gt_byfamily,
        evaluation_coverage=len((gtkeys|hnkeys) & set(candidates))/len(candidates),
        label_scope='72 authored progression pairs and 180 explicit correlation negatives; controls separate; all other pairs unknown',
        positive_details=[dict(p,prediction=candidates.get(tuple(p['support_key']))) for p in positives]))
    # Selected anchor classes are disjoint; any-qualified-type counts also show
    # overlapping SESSION/PROCESS pathways rather than hiding competing anchors.
    anchor_classes={k:collections.Counter() for k in ('session','process','attested_relation','no-anchor')}
    any_anchor=collections.Counter();same_c=same_a=0
    for key,row in candidates.items():
        r=row['variants']['frozen'];c=anchor_classes[r['anchor']['anchor_type']]
        c['candidate_count']+=1;c['admitted_count']+=r['admitted'];c['GT_count']+=key in gtkeys;c['HN_count']+=key in hnkeys;c['background_count']+=bg(row)
        for k in r['result']['anchor_types']: any_anchor[k]+=1
        same=r['source_a']==r['source_b'];same_c+=same;same_a+=same and r['admitted']
    save(OUT/'anchor_metrics.json',dict(selected_classes={k:dict(v) for k,v in anchor_classes.items()},any_qualified_type=dict(any_anchor)))
    save(OUT/'source_metrics.json',dict(same_source_candidates=same_c,cross_source_candidates=len(candidates)-same_c,
        same_source_admitted=same_a,cross_source_admitted=len(admitted)-same_a,
        source_definition='native observed product type; canonical OTHER sources distinguished',CROSS_SOURCE_REQUIRED=False))
    failures=[];exact_hn=0;hn_details=[]
    classifications={'HNX01':['ANCHOR_LIFECYCLE_FAILURE','IDENTITY_REUSE_FAILURE'],
        'HNX02':['CONTEXT_INSUFFICIENT','ANCHOR_LIFECYCLE_FAILURE'], 'HNX03':['ANCHOR_SCOPE_FAILURE'],
        'HNX04':['ROLE_SEMANTICS_FAILURE','CONTEXT_INSUFFICIENT'], 'HNX05':['IDENTITY_REUSE_FAILURE'],
        'HNX06':['ROLE_SEMANTICS_FAILURE','CONTEXT_INSUFFICIENT']}
    for item in negatives:
        row=candidates.get(tuple(item['support_key']));r=row['variants']['frozen'] if row else None
        hn_details.append(dict(item,candidate=bool(row),prediction=r))
        if not r or not r['admitted']: continue
        exact_hn+=r['anchor']['has_anchor'];v=r['result'];tf=v['temporal_factor']
        failures.append(dict(item,why_anchor_qualified=r['anchor']['why_anchor_qualified'],anchor=r['anchor'],
            which_context_supported=v['groups'],score_before_time=v['positive']/tf if tf else None,
            time_factor=tf,final_score=r['score'],penalties=dict(conflict=v['conflict_penalty'],duplicate=v['duplicate_penalty']),
            why_current_guard_did_not_reject=dict(gate=v['gate'],rejection_codes=r['rejection_codes'],
                explanation='Frozen guard checks observed contradiction/duplicate validity; no task/lifecycle exclusion for a valid shared anchor; context_floor=0.90 permits little contextual corroboration.'),
            classification=classifications[item['family']],winning_member=r['support_pair'],feature_decomposition=v['decomposition']))
    control_rows=[]
    for item in controls:
        row=candidates.get(tuple(item['support_key']));r=row['variants']['frozen'] if row else None
        control_rows.append(dict(item,candidate=bool(row),correlation_admitted=bool(r and r['admitted']),
            verified_direct_relation=bool(r and 'attested_relation' in r['result']['anchor_types']),
            classification='EXPECTED_CORRELATION_NOT_PROGRESSION',score=r['score'] if r else None))
    save(OUT/'exact_anchor_failures.json',dict(failures=failures,HN_details=hn_details,exact_anchor_hn_admitted=exact_hn,
        HNX07=dict(total=len(controls),correlation_admitted=sum(c['correlation_admitted'] for c in control_rows),
            direct_relation_supported=sum(c['verified_direct_relation'] for c in control_rows),pairs=control_rows,
            progression_accuracy=None,limitation='Chain reconstruction prohibited by this task. Correlation admission is expected; no claim of measured production chain accuracy.')))
    spec=read(OUT/'validation_formula_seal.json')
    sensitivity=[]
    variants=read(OUT/'validation_predictions/receipt.json')['variants']
    for variant in variants:
        m=metrics(positives,negatives,candidates,variant)
        sensitivity.append(dict(m,gt_recall_change=m['gt_admission_recall']-primary['gt_admission_recall'],
            hn_admitted_change=m['hn_admitted']-primary['hn_admitted'],worst_margin_change=m['worst_margin']-primary['worst_margin']))
    thresholds=[metrics(positives,negatives,candidates,threshold=t) for t in spec['thresholds']]
    save(OUT/'parameter_robustness.json',dict(experiments=sensitivity,selection_performed=False,
        predictions_computed_before_labels=True,threshold=.65))
    save(OUT/'threshold_robustness.json',dict(experiments=thresholds,selection_performed=False,frozen_threshold=.65))
    save(OUT/'background_audit.json',background_audit(background,alerts))
    degree=collections.Counter();anchor_edges=collections.Counter()
    for row in background:
        r=row['variants']['frozen'];degree.update(row['support_key'])
        for binding in r['typed_bindings']: anchor_edges[binding['entity_id']]+=1
    background_stats=dict(background_alerts=truth['background'],background_admitted=len(background),
        production_background_admitted=len(baseline_bg),ratio_vs_same_slice_production=len(background)/len(baseline_bg) if baseline_bg else None,
        mean_degree=2*len(background)/truth['background'],max_degree=max(degree.values(),default=0),
        edge_density=len(background)/(truth['background']*(truth['background']-1)/2),
        top_anchor_edge_counts=[dict(entity=entities[k],admitted_edges=v) for k,v in anchor_edges.most_common(20)],
        qualification='New synthetic composition differs from development; raw edge counts across slices do not measure growth. Same-slice baseline and degree are diagnostic, not background FP labels.')
    save(OUT/'background_statistics.json',background_stats)
    # Compare input observations/identities rather than reading development labels.
    dev_path=ROOT.parent/'TraceBack-Dataset/data/traceback_semisynthetic_v2/final/traceback_demo_v2.jsonl'
    development=[json.loads(line) for line in dev_path.open(encoding='utf8')]
    validation=[json.loads(line) for line in (DATA/'input/alerts.jsonl').open(encoding='utf8')]
    fingerprint=lambda r:hashlib.sha256(json.dumps(r['event'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    dev_ids={r['event_id'] for r in development};val_ids={r['event_id'] for r in validation}
    overlap=len({fingerprint(r) for r in development}&{fingerprint(r) for r in validation})
    independence=dict(new_generator=True,seed=truth['seed'],scorer_feedback_used=manifest['scorer_feedback_used'],
        shared_observation_ids=len(dev_ids&val_ids),shared_native_bodies=overlap,
        authored_progression='12 branching episodes, 6 edge families; independently authored, not renamed development chain',
        independent=not overlap and not dev_ids&val_ids, synthetic=True,scope='record/scenario-instance independent; same operator/schema, no third-party adjudication',
        dataset_manifest_sha256=sha(DATA/'build_manifest.json'),generator_sha256=manifest['generator_sha256'],
        first_attempt='Schema-only failure before predictions; preserved as *_schema_attempt1. Added native EDR executable for name-only provenance; no formula or label-based changes.')
    save(OUT/'independence_audit.json',independence)
    result=dict(TASK_RESULT='V5_EXACT_ANCHOR_OVER_CORRELATED' if failures else ('V5_VALIDATION_UNDER_CORRELATED' if primary['gt_admission_recall']<.8 else 'V5_VALIDATION_LIMITED_BUT_PROMISING'),
        VALIDATION_DATASET=str(DATA),VALIDATION_INDEPENDENT=independence['independent'],
        SCORING_FORMULA='C_STRONG_ANCHOR_CONTEXT_V1_RESEARCH',THRESHOLD=.65,
        GT_EDGES=len(positives),GT_CANDIDATE_RECALL=f"{primary['gt_candidates']}/{len(positives)}",GT_ADMISSION_RECALL=f"{primary['gt_admitted']}/{len(positives)}",
        HN_TOTAL=len(negatives),HN_ADMITTED=primary['hn_admitted'],EXACT_ANCHOR_HN_ADMITTED=exact_hn,
        MIN_GT_SCORE=primary['min_gt_score'],MAX_HN_SCORE=primary['max_hn_score'],WORST_MARGIN=primary['worst_margin'],
        BACKGROUND_ADMITTED=len(background),SAME_SOURCE_ADMITTED=same_a,CROSS_SOURCE_ADMITTED=len(admitted)-same_a,
        TOTAL_ADMITTED=len(admitted),CANDIDATES=len(candidates),
        PARAMETER_ROBUSTNESS='FROZEN_LOCAL_SENSITIVITY_ONLY_SEE_REPORT',THRESHOLD_ROBUSTNESS='DIAGNOSTIC_ONLY_SEE_REPORT',
        DEVELOPMENT_OVERFIT_RISK='HIGH_NEGATIVE_COVERAGE_GAP' if failures else 'UNRESOLVED_LIMITED_VALIDATION',
        V5_PRODUCTION_INTEGRATION_READY=False,V5_FREEZE_READY=False,
        PRIMARY_REMAINING_BLOCKER='SYSTEMATIC_EXACT_ANCHOR_ACCEPTANCE_OF_UNRELATED_ACTIONS' if failures else 'LIMITED_SYNTHETIC_VALIDATION',
        limitations=truth['limitations']+['No retuning or scorer rerun after label access. Background review provisional. HNX07 correlation and progression denominators separated.'])
    save(OUT/'result.json',result)
    verify_predictions()
    print(json.dumps(result,ensure_ascii=False,indent=2),flush=True)


if __name__=='__main__': run()

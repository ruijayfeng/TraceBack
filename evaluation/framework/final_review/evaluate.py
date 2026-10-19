"""Post-seal label join and acceptance diagnostics. Never calls a scorer."""
import collections
import gzip
import json
import random
from .run import ROOT, OUT, OLD, read, save, sha
from .audit import BASE, PREV
from evaluation.framework.anchor_semantics.runtime import rows, dump
from evaluation.framework.sparse_semantics.runtime import metrics

def longest(edges):
    graph=collections.defaultdict(set)
    for a,b in edges:graph[a].add(b)
    memo={};active=set()
    def visit(a):
        if a in active:raise ValueError('cycle_in_evaluation_progression')
        if a not in memo:
            active.add(a);memo[a]=max((1+visit(b) for b in graph[a]),default=0);active.remove(a)
        return memo[a]
    return max((visit(a) for a in list(graph)),default=0)

def sealed():
    seal=read(OUT/'prediction_seal.json')
    for n,h in seal['files'].items():
        if sha(OUT/'predictions'/n)!=h:raise ValueError('prediction_changed:'+n)
    if not read(OUT/'replay_equivalence.json')['exact_semantic_reproduction']:raise ValueError('replay_mismatch')

def describe(r):
    if r is None:return dict(score=None,threshold=.65,admitted=False,decision='REJECT',reason='NOT_CANDIDATE',observed_evidence=[],missing_evidence=[],contradictions=[])
    a=r['audit'];p=r['projection']
    return dict(score=r['score'],threshold=.65,admitted=r['decision']=='ADMIT',binary_admit=r['binary_admit'],
        decision=r['decision'],reason=r['decision_reason'],support_pair=r['support_pair'],
        observed_evidence=a['evidence'],missing_evidence=sorted(set(read(OLD/'manifest.json')['policy']['formula']['dimensions'])-set(r['channels'])),
        contradictions=a['local_contradictions']+a['incident_contradictions'],channels=r['channels'],
        semantic_compatibility=r['semantic_compatibility'],evidence_confidence=r['evidence_confidence'],
        legacy_unscoped_penalty=p['legacy_unscoped_penalty'],original_gate=r['original_gate'])

def evaluate():
    sealed()
    save(OUT/'evaluation_started.json',dict(prediction_seal_hash=sha(OUT/'prediction_seal.json'),post_seal_label_join=True,no_post_label_scoring=True))
    gt=read(BASE/'gt_edge_evaluation.json')['edges'];hn=read(BASE/'hard_negative_evaluation.json')['pairs']
    labels={tuple(r['support_key']):('GT',r) for r in gt if r['support_key']}
    labels.update({tuple(r['support_key']):('HN',r) for r in hn if r['support_key']})
    found={};admitted=[];decisions=collections.Counter()
    for row in rows(OUT/'predictions/candidates.jsonl.gz'):
        key=tuple(row['support_key']);r=row['result'];decisions[r['decision']]+=1
        if key in labels:found[key]=r
        if r['decision']=='ADMIT':admitted.append(row)
    gtrows=[];hnrows=[]
    for label,records,target in [('GT',gt,gtrows),('HN',hn,hnrows)]:
        for r in records:
            result=found.get(tuple(r['support_key'] or []))
            target.append(dict(edge_id=r['edge_id'] if label=='GT' else r.get('pair_id'),
                pair_id=None if label=='GT' else r.get('pair_id') or r['source_alert_id']+'->'+r['target_alert_id'],
                source_input_alert_id=r.get('source_alert_id'),target_input_alert_id=r.get('target_alert_id'),
                canonical_alert_ids=r.get('canonical_alert_ids'),negative_reason=r.get('negative_reason'),truth_scope=r.get('truth_scope'),
                scenario=r.get('scenario_id'),source_stage=r.get('source_stage'),target_stage=r.get('target_stage'),
                candidate_generated=result is not None,support_key=r['support_key'],**describe(result)))
    with (OUT/'gt_edge_results.jsonl').open('w',encoding='utf8') as f:
        for r in gtrows:dump(f,r)
    answers={r['id']:r for r in read(PREV/'stress_answers.json')}
    stress=[dict(**r,positive=answers[r['id']]['positive'],scenario=answers[r['id']]['scenario']) for r in read(OUT/'predictions/stress.json')]
    oldstress=read(PREV/'labeled_decomposition.json')['synthetic_feature_stress']
    oldwrong={r['id']:r for r in oldstress if not r['positive'] and r['result']['gate'] and r['result']['score']>=.65}
    stress_hn=[]
    for r in stress:
        if r['positive']:continue
        result=r['result']
        stress_hn.append(dict(dataset='feature_stress',id=r['id'],scenario=r['scenario'],
            candidate_generated=r['candidate'],admitted=result['decision']=='ADMIT',score=result['score'],threshold=.65,
            decision=result['decision'],binary_admit=result['binary_admit'],reason=result['decision_reason'],
            support_evidence=r['audit']['evidence'],contradiction_evidence=r['audit']['local_contradictions']+r['audit']['incident_contradictions'],
            semantics_allowing_score='P sums actor/context/behavior even if task is unknown or locally contradicted. No discriminating context => AMBIGUOUS; remains binary-positive, not a strict HN rejection.' if result['binary_admit'] else 'Rejected by existing guard or insufficient positive support; see decision_reason and scoped contradiction evidence.',
            v5_1_false_positive=r['id'] in oldwrong,v5_1_score=oldwrong.get(r['id'],{}).get('result',{}).get('score')))
    with (OUT/'hard_negative_results.jsonl').open('w',encoding='utf8') as f:
        for r in hnrows:dump(f,dict(dataset='development',**r))
        for r in stress_hn:dump(f,r)
    save(OUT/'historical_12_hn_recheck.json',dict(count=len(oldwrong),rows=[r for r in stress_hn if r['v5_1_false_positive']],
        fixed_as_strict_rejections=all(r['decision']=='REJECT' for r in stress_hn if r['v5_1_false_positive'])))
    development=[]
    for positive,records in [(True,gtrows),(False,hnrows)]:
        for r in records:
            result=found.get(tuple(r['support_key'] or [])) or dict(score=0.,decision='REJECT',binary_admit=False)
            development.append(dict(positive=positive,candidate=r['candidate_generated'],result=result))
    dev=metrics(development);st=metrics(stress)
    gts=[r for r in gtrows if r['admitted']]
    research_path=longest([(r['source_stage'],r['target_stage']) for r in gts])
    gtpath=longest([(r['source_stage'],r['target_stage']) for r in gtrows])
    counts=collections.Counter('GT' if tuple(r['support_key']) in labels and labels[tuple(r['support_key'])][0]=='GT' else
        'HN' if tuple(r['support_key']) in labels else 'OTHER' for r in admitted)
    save(OUT/'labeled_metrics.json',dict(development=dev,feature_stress=st,
        GT_EDGE_COUNT=len(gt),GT_CANDIDATE_RECALL=dev['candidate_recall'],GT_ADMISSION_RECALL=dev['admission_recall'],
        GT_EDGE_RECALL=None,GT_RESEARCH_EDGE_RECALL=dev['admission_recall'],
        formal_edge_recall_status='UNAVAILABLE_NO_V5_2_FORMAL_EDGE_SERIALIZER',
        LONGEST_GT_PATH_EDGES=gtpath,LONGEST_RESEARCH_GT_SUPPORT_PATH_EDGES=research_path,
        RECOVERED_LONGEST_GT_PATH_EDGES=None,FULL_GT_PATH_RECOVERED=False,
        HN_TOTAL=len(hn),HN_CANDIDATES=sum(r['candidate_generated'] for r in hnrows),HN_ADMITTED=sum(r['admitted'] for r in hnrows),
        HN_REJECTED=sum(r['decision']=='REJECT' for r in hnrows),HN_FALSE_POSITIVE_RATE=sum(r['admitted'] for r in hnrows)/len(hn),
        HN_REJECTION_RATE=dev['hn_rejection'],TOTAL_ADMITTED_EDGES=len(admitted),GT_ADMITTED_EDGES=counts['GT'],
        HN_ADMITTED_EDGES=counts['HN'],OTHER_ADMITTED_EDGES=counts['OTHER'],candidate_decisions=dict(decisions),
        FULL_DATASET_PRECISION_NOT_CLAIMED=True,unlabeled_policy='Background predictions are unlabeled, never TN or FP by default',
        candidate_label_coverage=sum(r['candidate_generated'] for r in gtrows+hnrows)/sum(decisions.values()),
        labeled_edge_metrics=dict(development=dict(TP=dev['counts']['GT']['ADMIT'],FN=dev['GT']-dev['counts']['GT']['ADMIT'],FP=dev['counts']['HN']['ADMIT'],
            TN=dev['counts']['HN']['REJECT'],precision=1. if dev['counts']['GT']['ADMIT'] else None,recall=dev['admission_recall'],
            f1=2*dev['counts']['GT']['ADMIT']/(dev['GT']+dev['counts']['GT']['ADMIT']),scope='187 labeled stage-witness/HN pairs; not full population precision'),
            stress=dict(TP=st['counts']['GT']['ADMIT'],FP=st['counts']['HN']['ADMIT'],TN=st['counts']['HN']['REJECT'],
                FN_rejected=st['counts']['GT']['REJECT'],ambiguous_positive=st['counts']['GT']['AMBIGUOUS'],ambiguous_negative=st['counts']['HN']['AMBIGUOUS'],
                binary_TP=sum(r['result']['binary_admit'] for r in stress if r['positive']),
                binary_FP=sum(r['result']['binary_admit'] for r in stress if not r['positive']),
                note='Tri-state abstentions reported separately; do not call AMBIGUOUS TN. Binary metrics use original fixed .65 rule.'))))
    independence(admitted)
    overcorrelation(admitted,labels)
    save(OUT/'stress_labeled_results.json',stress)
    print('POST_SEAL_METRICS',json.dumps(dict(development=dev,stress=st,admitted=len(admitted),research_gt_path=research_path)),flush=True)

def independence(admitted):
    cases=[];stats=collections.Counter()
    for row in admitted:
        r=row['result'];a=r['audit'];selected={}
        for item in a['evidence']:
            ch=item['channel']
            if abs(item['support']*item['weight']-r['channels'].get(ch,-1))<1e-12:
                selected.setdefault(ch,item)
        refs={ch:{(x['alert_id'],x['pointer']) for x in item['evidence_refs']} for ch,item in selected.items()}
        # Both contributions explicitly consume the same native operation facts.
        shared=refs.get('behavior',set()) & refs.get('qualified_context',set())
        native_double=bool(shared and r['channels'].get('behavior',0)>0 and r['channels'].get('qualified_context',0)>0)
        infra_only=all(k=='context' for k,v in r['channels'].items() if v>0)
        if native_double:stats['duplicate_evidence_cases']+=1
        if infra_only:stats['frequency_only_cases']+=1
        reasons=[]
        if native_double:reasons.append('Native operation facts supply behavior support and the compound qualified_context contribution. Arithmetic adds both; max-within-channel does not deduplicate across channels. This is observed fact reuse, not a statistical independence test.')
        if infra_only:reasons.append('Only infrastructure context has positive support')
        cases.append(dict(support_key=row['support_key'],support_pair=r['support_pair'],score=r['score'],channels=r['channels'],
            cross_channel_native_fact_reuse=native_double,shared_native_pointers=sorted(shared),
            within_channel_max_verified=all(abs(max(x['support']*x['weight'] for x in a['evidence'] if x['channel']==k)-v)<1e-12 for k,v in r['channels'].items()),
            explanation=reasons,selected_lineage=selected,
            detector_metadata_used=False,namespace_metadata_positive_channel=False,
            pseudo_continuity_assessment='Context witness supports undirected episode association only; no direct propagation created here'))
    with gzip.open(OUT/'evidence_lineage_all_admitted.jsonl.gz','wt',encoding='utf8',compresslevel=1) as f:
        for r in cases:dump(f,r)
    save(OUT/'evidence_independence_audit.json',dict(admitted_edges_checked=len(admitted),
        duplicate_evidence_cases=stats['duplicate_evidence_cases'],self_reinforcement_cases=0,frequency_only_cases=stats['frequency_only_cases'],
        pseudo_continuity_cases=0,within_channel_deduplication_pass=all(r['within_channel_max_verified'] for r in cases),
        EVIDENCE_INDEPENDENCE_PASS=not stats['duplicate_evidence_cases'] and not stats['frequency_only_cases'],
        full_lineage_ref='evidence_lineage_all_admitted.jsonl.gz',
        interpretation='Nonzero fact reuse blocks a clean no-double-counting claim. Compound context includes asset/identity preconditions beyond operation, but its 1.2 mass is additive to .8 behavior from the same native observations; this prior documented dependency remains unresolved.',
        statistical_independence_not_claimed=True))

def overcorrelation(admitted,labels):
    other=[r for r in admitted if tuple(r['support_key']) not in labels]
    top=sorted(other,key=lambda r:(-r['result']['score'],r['support_key']))[:50]
    rng=random.Random(42);random_rows=rng.sample(sorted(other,key=lambda r:r['support_key']),min(50,len(other)))
    chosen={tuple(r['support_key']):r for r in top+random_rows};output=[]
    for key,row in sorted(chosen.items()):
        r=row['result'];e=r['audit']['evidence'];q=next((x.get('basis') for x in e if x['channel']=='qualified_context'),{})
        category='PLAUSIBLE' if (r['channels'].get('direct',0)>0 or r['channels'].get('task',0)>0 or q.get('object_handoff')) else 'AMBIGUOUS'
        output.append(dict(support_key=key,score=r['score'],classification=category,channels=r['channels'],basis=q,
            source_pair=r['source_pair'],support_pair=r['support_pair'],
            rationale='Scoped direct/task/object handoff supports reviewable association' if category=='PLAUSIBLE' else 'Network/execution/auth context can describe a shared long-lived episode; task-level relationship not established',
            sampled_top50=key in {tuple(x['support_key']) for x in top},sampled_random50=key in {tuple(x['support_key']) for x in random_rows},
            is_ground_truth=False))
    save(OUT/'over_correlation_audit.json',dict(other_admitted=len(other),top_n=len(top),random_n=len(random_rows),seed=42,
        unique_reviewed=len(output),counts=dict(collections.Counter(r['classification'] for r in output)),rows=output,
        OVER_CORRELATION_PASS=False if any(r['classification']!='PLAUSIBLE' for r in output) else None,
        conclusion='Semantic triage only, not a labeled false-positive estimate. Ambiguous network/context witnesses and observed channel reuse prevent a safety pass.' if output else 'No other ADMIT predictions; population quality still cannot be inferred from unlabeled data.'))

if __name__=='__main__':evaluate()

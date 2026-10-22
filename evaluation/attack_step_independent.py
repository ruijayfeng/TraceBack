"""Post-seal evaluator. Never imports or executes the semantic prototype.

All outputs go to a new independent evaluation directory. GT cannot be decoded
until the frozen semantic output, manifests and upstream digests are verified.
"""
from collections import Counter,defaultdict
from datetime import datetime,timezone
from itertools import combinations
from pathlib import Path
import argparse
import hashlib
import json
import math
import statistics
import sys

EXPECTED_SHA='21405c45e5be606ee381fc45fd9e2fbd315fb1cbcf7254f15826805bfcaa0cba'
STATUSES=('CONFIRMED','CANDIDATE','UNRESOLVED','REJECTED')

def require(condition,message):
    if not condition: raise ValueError(message)
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def utc(): return datetime.now(timezone.utc).isoformat()
def save(out,name,value):
    with (out/name).open('x',encoding='utf8') as f:
        json.dump(value,f,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False); f.write('\n')

class Inputs:
    def __init__(self,prototype):
        self.prototype=Path(prototype).resolve(); self.events=[]; self.verified=False
        self.sealed_at=None
    def read(self,path,gt=False,jsonl=False,text=False):
        path=Path(path).resolve()
        require(not gt or self.verified,'GT_read_before_seal_verification')
        now=utc()
        if gt: require(now>self.sealed_at,'GT_read_not_after_seal')
        payload=path.read_bytes()
        self.events.append(dict(path=str(path),sha256=hashlib.sha256(payload).hexdigest(),read_at=now,gt=gt))
        if text:return payload.decode('utf-8-sig')
        if jsonl: return [json.loads(line) for line in payload.decode('utf-8-sig').splitlines() if line.strip()]
        return json.loads(payload.decode('utf-8-sig'))

    def verify(self):
        p=self.prototype
        seal=self.read(p/'acceptance_seal.json')
        require(sha(p/'artifact_manifest.json')==seal['artifact_manifest_sha256'],'artifact_manifest_digest_mismatch')
        manifest=self.read(p/'artifact_manifest.json')
        for name,digest in manifest.items():
            path=(p/name).resolve()
            require(path.is_relative_to(p) and sha(path)==digest,'prototype_artifact_changed:'+name)
        require(sha(p/'attack_step_semantic_output.json')==EXPECTED_SHA==seal['semantic_output_sha256'],'STOP_semantic_output_SHA_mismatch')
        for name,run_seal in seal['run_seals'].items():
            require(sha(p/name/'attack_step_semantic_output.json')==run_seal['sha256']==EXPECTED_SHA,'sealed_run_mismatch')
        self.sealed_at=seal['sealed_at']
        output=self.read(p/'attack_step_semantic_output.json')
        ledger=self.read(p/'candidate_ledger.jsonl',jsonl=True)
        descriptors=self.read(p/'stage_descriptors.json')
        input_manifest=self.read(p/'input_manifest.json')
        schema=self.read(p/'schema_validation.json'); trace=self.read(p/'evidence_trace_validation.json')
        require(schema['valid'] is True and set(trace['checks'].values())=={'PASS'},'prior_validation_not_passed')
        for name,path in input_manifest['paths'].items():
            require(sha(path)==input_manifest['digests'][name],'upstream_input_changed:'+name)
        source=self.read(input_manifest['paths']['stage8'])
        chains=self.read(input_manifest['paths']['stage9'])
        require(set(g['semantic_step_id'] for g in output['semantic_groups'])==set(l['candidate_id'] for l in ledger),'ledger_group_identity_mismatch')
        require(len(ledger)==len(output['semantic_groups']),'duplicate_or_missing_proposal_ledger')
        require({s['stage_id'] for s in descriptors}=={s['stage_id'] for s in source['stages']['stages']},'descriptor_population_mismatch')
        self.verified=True
        return dict(output=output,ledger=ledger,descriptors=descriptors,manifest=input_manifest,source=source,chains=chains,seal=seal)

def inspect_inputs(root,out):
    inputs=Inputs(root/'outputs/attack_step_offline_prototype_20261022')
    data=inputs.verify()
    gtroot=Path('D:/Code_WorkSpace/TraceBack-Dataset/data/attack125/ground_truth')
    results={}
    for name in ['ground_truth.json','stages.json','observations.json','observation_bindings.json']:
        value=inputs.read(gtroot/name,gt=True)
        results[name]=dict(type=type(value).__name__,keys=list(value) if isinstance(value,dict) else None,
            first=value[:1] if isinstance(value,list) else {k:(v[:1] if isinstance(v,list) else v) for k,v in value.items()})
    mapping=inputs.read(root/'outputs/stage6_oversegmentation_audit_20261022/gt_stage_fragment_mapping.json',gt=True)
    results['audit_mapping']=dict(first=mapping[0],count=len(mapping))
    results['canonical_alert_sample']={k:data['source']['alerts'][0].get(k) for k in ['alert_id','source_namespace','origin_namespace','source_record_id','origin_record_id']}
    save(out,'inspection_read_log.json',dict(verified_seal=True,events=inputs.events))
    print(json.dumps(results,ensure_ascii=False,indent=2)[:19000])

def ratio(numerator,denominator,reason='ZERO_DENOMINATOR'):
    return dict(status='EVALUABLE' if denominator else 'NOT_EVALUABLE',
                value=numerator/denominator if denominator else None,
                numerator=numerator,denominator=denominator,reason=None if denominator else reason)

def pairs(members): return set(combinations(sorted(set(members)),2))

def pair_metrics(universe,truth,predicted):
    require(truth<=universe and predicted<=universe,'pair_outside_population')
    tp=len(predicted&truth); fp=len(predicted-truth); fn=len(truth-predicted); tn=len(universe-truth-predicted)
    return dict(TP=tp,FP=fp,FN=fn,TN=tn,predicted_positive_count=len(predicted),universe_count=len(universe),
        PRECISION=ratio(tp,tp+fp,'NO_PREDICTED_POSITIVES'),RECALL=ratio(tp,tp+fn,'NO_GT_POSITIVE_PAIRS'),
        F1=ratio(2*tp,2*tp+fp+fn,'NO_POSITIVE_PAIRS'))

def mapping_from_native(alerts,stages,native,gt,audit):
    obs_by_id=defaultdict(list); native_by_id=defaultdict(list); native_by_payload=defaultdict(list)
    payload_key=lambda value:json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
    for x in native:
        native_by_id[x['event_id']].append(x)
        native_by_payload[payload_key(x['event'])].append(x)
    for ob in gt['observations']: obs_by_id[ob['alert_id']].append(ob)
    gt_stages={x['stage_id']:x for x in gt['stages']}
    missing=[];duplicates=[];failures=[]; mapped={}; rows=[]
    used_native=Counter()
    for al in alerts:
        native_id=al.get('source_record_id') or al.get('origin_record_id')
        method='CANONICAL_RECORD_ID'
        if native_id is None:
            # Some adapters retain raw events but not the dataset envelope ID.
            # Resolve the exact full payload in the sealed native input; never
            # match on timestamp/title/GT labels or select among duplicates.
            payload_matches=native_by_payload.get(payload_key(al['raw_alert']),[])
            if len(payload_matches)>1:
                duplicates.append(dict(alert_id=al['alert_id'],reason='AMBIGUOUS_COMPLETE_NATIVE_PAYLOAD',native_matches=len(payload_matches)));continue
            if len(payload_matches)==1:
                native_id=payload_matches[0]['event_id']; method='UNIQUE_COMPLETE_NATIVE_PAYLOAD'
        matches=obs_by_id.get(native_id,[]); sources=native_by_id.get(native_id,[])
        if not matches or not sources:
            missing.append(dict(alert_id=al['alert_id'],native_id=native_id)); continue
        if len(matches)!=1 or len(sources)!=1:
            duplicates.append(dict(alert_id=al['alert_id'],native_id=native_id,gt_matches=len(matches),native_matches=len(sources)));continue
        ob=matches[0]; source=sources[0]
        if ob['stage_id'] not in gt_stages or source['source_type']!=ob['source_type'] or source['event']!=al['raw_alert']:
            failures.append(dict(alert_id=al['alert_id'],native_id=native_id,reason='SOURCE_TYPE_PAYLOAD_OR_GT_STAGE_MISMATCH'));continue
        used_native[native_id]+=1; mapped[al['alert_id']]=ob['stage_id']
        rows.append(dict(alert_id=al['alert_id'],source_namespace=al['source_namespace'],source_record_id=native_id,
            native_source_type=source['source_type'],gt_stage_id=ob['stage_id'],raw_payload_identical=True,identity_resolution=method))
    duplicate_native=[key for key,value in used_native.items() if value>1]
    duplicates.extend(dict(native_id=key,reason='MULTIPLE_CANONICAL_ALERTS_FOR_GT_OBSERVATION') for key in duplicate_native)
    for st in gt['stages']:
        declared=set(st['member_alert_ids']); observed={ob['alert_id'] for ob in gt['observations'] if ob['stage_id']==st['stage_id']}
        if declared!=observed: failures.append(dict(gt_stage_id=st['stage_id'],reason='GT_STAGE_OBSERVATION_MEMBERSHIP_MISMATCH'))
    stage_labels={}; mixed=[]; unmapped=[]
    for st in stages:
        labels={mapped[a] for a in st['alert_ids'] if a in mapped}
        stage_labels[st['stage_id']]=sorted(labels)
        if any(a not in mapped for a in st['alert_ids']):unmapped.append(st['stage_id'])
        if len(labels)>1:mixed.append(st['stage_id'])
    actual_gt=defaultdict(set)
    for sid,labels in stage_labels.items():
        for label in labels: actual_gt[label].add(sid)
    audit_gt={g['gt_stage_id']:{x['stage_id'] for x in g['algorithm_stages']} for g in audit}
    audit_alert_gt={a:g['gt_stage_id'] for g in audit for x in g['algorithm_stages'] for a in x['member_alert_ids']}
    audit_differences=[dict(alert_id=aid,recomputed=label,audit=audit_alert_gt.get(aid)) for aid,label in mapped.items() if audit_alert_gt.get(aid)!=label]
    audit_differences.extend(dict(gt_stage_id=label,reason='AUDIT_ACTION_STAGE_SET_MISMATCH') for label,ids in actual_gt.items() if ids!=audit_gt.get(label,set()))
    failures.extend(audit_differences)
    complete=not (missing or duplicates or failures or mixed or unmapped) and len(mapped)==len(alerts)
    report=dict(complete=complete,population_alert_count=len(alerts),mapped_alert_count=len(mapped),
        mapping_completeness=ratio(len(mapped),len(alerts),'EMPTY_POPULATION'),GT_ALERT_MAPPING_MISSING=len(missing),
        GT_ALERT_MAPPING_DUPLICATE=len(duplicates),MIXED_GT_STAGE_ALGORITHM_STAGE_COUNT=len(mixed),
        missing=missing,duplicates=duplicates,failures=failures,mixed_action_stage_ids=mixed,unmapped_action_stage_ids=unmapped,
        gt_observations_not_in_population=sorted(set(obs_by_id)-set(used_native)),
        mapping_basis='Exact canonical record ID; if adapter omitted envelope ID, unique equality of the COMPLETE raw payload in the sealed native input resolves the original event_id. No time/title/GT-stage guessing. Native source_type and full payload checked; namespace retained; cross-check against sealed audit mapping.',
        identity_resolution_counts=dict(Counter(r['identity_resolution'] for r in rows)),
        alert_mapping=rows,stage_labels=stage_labels,
        gt_stages=[dict(gt_stage_id=k,name=gt_stages[k]['name'],action_stage_ids=sorted(actual_gt[k]),action_stage_count=len(actual_gt[k]),
                    alert_count=sum(v==k for v in mapped.values())) for k in sorted(gt_stages)])
    return report,mapped,{sid:labels[0] for sid,labels in stage_labels.items() if len(labels)==1},dict(actual_gt)

def classify_proposal(g,stage_gt,gt_sets):
    members=set(g['member_stage_ids']); missing=members-stage_gt.keys()
    labels={stage_gt[x] for x in members if x in stage_gt}
    exact=not missing and len(labels)==1 and members==gt_sets[next(iter(labels))]
    if missing: category='UNMAPPABLE'
    elif len(members)==1: category='SINGLE_STAGE'
    elif len(labels)>1: category='CROSS_GT_MIXED'
    elif exact: category='EXACT_GT_STEP'
    else: category='PURE_GT_SUBSET'
    return dict(proposal_id=g['semantic_step_id'],status=g['membership_status'],classification=category,
        member_stage_ids=sorted(members),gt_stage_ids=sorted(labels),unmappable_member_ids=sorted(missing),
        exact_set_match=exact,nontrivial_exact_recovery=exact and len(members)>1,
        gt_intersections={label:sorted(members&gt_sets[label]) for label in sorted(labels)},
        evidence_level=g['evidence_level'],source_relation_ids=g['source_relation_ids'],
        supporting_alert_count=len(g['supporting_alert_ids']),accepted_relation_count=len(g['source_relation_ids']),
        cross_chain=len(g['member_chain_ids'])>1,disconnected=g['disconnected_members'])

def recovery(groups,gt_sets):
    result=[]
    for label,truth in sorted(gt_sets.items()):
        eligible=[g for g in groups if g['membership_status']!='REJECTED' and set(g['member_stage_ids'])&truth]
        ranked=sorted(eligible,key=lambda g:(-len(set(g['member_stage_ids'])&truth)/len(truth),
            -len(set(g['member_stage_ids'])&truth)/len(set(g['member_stage_ids'])),g['semantic_step_id']))
        best=ranked[0] if ranked else None
        pure=[g for g in eligible if set(g['member_stage_ids'])<=truth]
        pure.sort(key=lambda g:(-len(g['member_stage_ids']),g['semantic_step_id']))
        exact=[g for g in eligible if set(g['member_stage_ids'])==truth]
        nontrivial=len(truth)>1
        def details(g):
            return dict(BEST_PROPOSAL_ID=g['semantic_step_id'],BEST_PROPOSAL_STATUS=g['membership_status'],
                BEST_COVERAGE=len(set(g['member_stage_ids'])&truth)/len(truth),
                BEST_PURITY=len(set(g['member_stage_ids'])&truth)/len(set(g['member_stage_ids'])),member_stage_ids=g['member_stage_ids']) if g else None
        result.append(dict(gt_stage_id=label,action_stage_ids=sorted(truth),action_stage_count=len(truth),
            multi_action=nontrivial,nontrivial_exact_recovered=nontrivial and bool(exact),
            exact_set_covered=bool(exact),trivial_singleton_covered=not nontrivial and bool(exact),
            exact_proposal_ids=[g['semantic_step_id'] for g in exact],exact_statuses=[g['membership_status'] for g in exact],
            confirmed_exact=any(g['membership_status']=='CONFIRMED' for g in exact),
            best_proposal=details(best),best_pure_proposal=details(pure[0]) if pure else None))
    count=sum(r['nontrivial_exact_recovered'] for r in result); multi=sum(r['multi_action'] for r in result)
    return dict(definition='Non-rejected multi-Action exact proposal presence, not CONFIRMED recovery; singleton set coverage separately reported.',
        GT_STEP_EXACT_RECOVERED_COUNT=count,GT_STEP_EXACT_RECOVERY_RATE=ratio(count,len(result)),
        MULTI_ACTION_GT_STAGE_COUNT=multi,MULTI_ACTION_GT_EXACT_RECOVERED_COUNT=count,
        MULTI_ACTION_GT_EXACT_RECOVERY_RATE=ratio(count,multi),
        all_gt_exact_set_coverage=ratio(sum(r['exact_set_covered'] for r in result),len(result)),
        trivial_singleton_set_coverage_count=sum(r['trivial_singleton_covered'] for r in result),
        confirmed_exact_recovery=ratio(sum(r['confirmed_exact'] for r in result),len(result)),stages=result)

def evaluate_pairs(groups,stage_gt):
    universe=pairs(stage_gt); truth={p for p in universe if stage_gt[p[0]]==stage_gt[p[1]]}
    results={}
    for name,statuses in [('CONFIRMED_ONLY',{'CONFIRMED'}),('CONFIRMED_CANDIDATE',{'CONFIRMED','CANDIDATE'}),
                           ('ANY_NON_REJECTED',{'CONFIRMED','CANDIDATE','UNRESOLVED'})]:
        predicted=set().union(*(pairs(g['member_stage_ids']) for g in groups if g['membership_status'] in statuses))
        results[name]=pair_metrics(universe,truth,predicted)
    return dict(unit='UNORDERED_ACTION_STAGE_PAIR',population_count=len(stage_gt),gt_positive_count=len(truth),
        gt_negative_count=len(universe-truth),baseline_gt_positive_rate=ratio(len(truth),len(universe)),
        overlap_handling='Union, deduplicate, no transitive closure.',scenarios=results,
        pair_details=[dict(stage_a_id=a,stage_b_id=b,gt_stage_a=stage_gt[a],gt_stage_b=stage_gt[b],gt_positive=(a,b) in truth,
            proposal_ids={status:[g['semantic_step_id'] for g in groups if g['membership_status']==status and {a,b}<=set(g['member_stage_ids'])] for status in STATUSES}) for a,b in sorted(universe)])

def candidate_truth(classified):
    candidates=[c for c in classified if c['status']=='CANDIDATE']; rows=[]
    names={'EXACT_GT_STEP':'GT_TRUE_POSITIVE_CANDIDATE','PURE_GT_SUBSET':'PARTIAL_GT_CANDIDATE','CROSS_GT_MIXED':'GT_FALSE_POSITIVE_CANDIDATE'}
    for c in candidates: rows.append(dict(**c,candidate_truth_class=names.get(c['classification'],c['classification'])))
    counts=Counter(r['candidate_truth_class'] for r in rows); true=counts['GT_TRUE_POSITIVE_CANDIDATE']; false=counts['GT_FALSE_POSITIVE_CANDIDATE']; partial=counts['PARTIAL_GT_CANDIDATE']
    return dict(CANDIDATE_GT_TRUE_COUNT=true,CANDIDATE_GT_FALSE_COUNT=false,PARTIAL_GT_CANDIDATE_COUNT=partial,
        CANDIDATE_GT_TRUE_RATE=ratio(true,len(candidates)),candidate_pure_including_partial_rate=ratio(true+partial,len(candidates)),
        candidate_false_rate=ratio(false,len(candidates)),definition='Strict TRUE means exact multi-Action GT step; partial pure subsets are separately counted.',candidates=rows)

def hypergeom_tail(population,positive,selected,hits):
    denominator=math.comb(population,selected)
    return sum(math.comb(positive,k)*math.comb(population-positive,selected-k)
        for k in range(hits,min(positive,selected)+1) if 0<=selected-k<=population-positive)/denominator

def calibration(classified,pairwise,groups,stage_gt):
    proposal={status:dict(GT_SAME_STAGE=0,GT_CROSS_STAGE=0,SINGLE_STAGE=0,UNMAPPABLE=0,TOTAL=0) for status in STATUSES}
    for c in classified:
        row=proposal[c['status']]; row['TOTAL']+=1
        category=c['classification']
        row['GT_SAME_STAGE' if category in {'EXACT_GT_STEP','PURE_GT_SUBSET'} else
            'GT_CROSS_STAGE' if category=='CROSS_GT_MIXED' else category]+=1
    universe=pairs(stage_gt); truth={p for p in universe if stage_gt[p[0]]==stage_gt[p[1]]}
    pair_rows={}
    for status in STATUSES:
        predicted=set().union(*(pairs(g['member_stage_ids']) for g in groups if g['membership_status']==status))
        pair_rows[status]=dict(GT_SAME_STAGE=len(predicted&truth),GT_CROSS_STAGE=len(predicted-truth),
            TOTAL=len(predicted),positive_rate=ratio(len(predicted&truth),len(predicted)))
    selected=pair_rows['CANDIDATE']['TOTAL']; hits=pair_rows['CANDIDATE']['GT_SAME_STAGE']
    base=len(truth)/len(universe); rate=hits/selected if selected else None
    return dict(proposal_matrix=proposal,pair_union_matrix=pair_rows,rows_may_overlap_at_pair_level=True,
        singleton_excluded_from_same_stage_success=True,
        candidate_enrichment=dict(pair_baseline=base,candidate_pair_purity=rate,
            enrichment_factor=rate/base if rate is not None and base else None,
            hypergeometric_one_sided_p=hypergeom_tail(len(universe),len(truth),selected,hits) if selected else None,
            null='Random subset of the fixed Action Stage pair population; descriptive only.',
            limitations=['Pairs share Stage endpoints; proposal retrieval is structured, not randomized.',
                        'ATTACK125 was seen during contract design; no claim of out-of-sample statistical significance.']))

def auc(positive,negative):
    if not positive or not negative:return dict(status='NOT_EVALUABLE',reason='ONE_CLASS_ABSENT',value=None)
    wins=sum(1 if a>b else .5 if a==b else 0 for a in positive for b in negative)
    return dict(status='EVALUABLE',value=wins/(len(positive)*len(negative)),positive_count=len(positive),negative_count=len(negative))

def ranking(classified):
    rows=[r for r in classified if r['classification'] in {'EXACT_GT_STEP','PURE_GT_SUBSET','CROSS_GT_MIXED'}]
    positives=[r for r in rows if r['classification']!='CROSS_GT_MIXED']; negatives=[r for r in rows if r['classification']=='CROSS_GT_MIXED']
    grades={'NONE':0,'E4':1,'E3':2,'E2':3,'E1':4}
    features={'evidence_level':lambda r:grades[r['evidence_level']],
        'accepted_relation_count':lambda r:r['accepted_relation_count'],
        'supporting_alert_count':lambda r:r['supporting_alert_count'],
        'connected_flag':lambda r:int(not r['disconnected']),'same_chain_flag':lambda r:int(not r['cross_chain'])}
    result={}
    for name,feature in features.items():
        p=[feature(x) for x in positives]; n=[feature(x) for x in negatives]
        result[name]=dict(positive_values=p,negative_values=n,positive_mean=statistics.mean(p) if p else None,
            negative_mean=statistics.mean(n) if n else None,auc_higher_value_predicts_pure_gt=auc(p,n))
    return dict(status='AVAILABLE_AS_EXISTING_FIELD_DIAGNOSTICS',features=result,
        direct_binding_count=dict(status='NOT_AVAILABLE',reason='No explicit general direct_binding_count field in sealed output; no new score invented.'),
        no_combined_or_gt_trained_score=True,positive_definition='Exact or pure multi-Action subset; singleton excluded.',
        caveat='Per-feature descriptive AUC on overlapping proposals, not a deployable calibrated ranking model.')

def evidence_diagnosis(groups,classified,ledger,source,policy):
    by_group={g['semantic_step_id']:g for g in groups}; by_ledger={l['candidate_id']:l for l in ledger}
    alerts={a['alert_id']:a for a in source['alerts']}; stages={s['stage_id']:s for s in source['stages']['stages']}
    claims={c['claim_id']:c for c in source['evidence']['claims']}; decisions={d['candidate_id']:d for d in source['evidence']['decisions']}
    features=defaultdict(list)
    for feature in source['candidates']['features']:features[feature['stage_id']].append(feature)
    request_ops=set(policy['request_operations']); response_ops=set(policy['response_operations'])
    diagnoses=[]
    for c in classified:
        if c['classification'] not in {'EXACT_GT_STEP','PURE_GT_SUBSET'}:continue
        g=by_group[c['proposal_id']]; l=by_ledger[c['proposal_id']]; members=set(c['member_stage_ids'])
        member_alerts={a for sid in members for a in stages[sid]['alert_ids']}
        selected=[decisions[r] for r in g['source_relation_ids']]
        selected_claims={cid:claims[cid] for d in selected for cid in d['relation_claim_ids']}
        valid_direct=[x for x in selected_claims.values() if x['valid'] and x['semantic_class'] in {'DIRECTIONAL_RELATION','DIRECT_ASSOCIATIVE_RELATION'}]
        rr=[x for x in valid_direct if x['evidence_type']=='REQUEST_RESPONSE']
        operations=sorted({alerts[a]['alert_type'] for a in member_alerts if alerts[a].get('alert_type') is not None})
        request_roles=bool(set(operations)&request_ops); response_roles=bool(set(operations)&response_ops)
        # Independently check existing feature identities/witness coverage. This
        # is a diagnostic; it does not generate or modify any grouping proof.
        identity_witnesses=defaultdict(set); identity_members=defaultdict(set)
        for sid in members:
            for feature in features[sid]:
                if feature['kind']!='request':continue
                identity=json.dumps(feature['identity'],sort_keys=True,separators=(',',':'))
                identity_members[identity].add(sid)
                identity_witnesses[identity].update(w['alert_id'] for w in feature['witnesses'])
        complete_requests=[identity for identity in identity_members if identity_members[identity]==members and
                           member_alerts<=identity_witnesses[identity]]
        proof=l['whole_group_check']['p1']; covered=set(proof['covered_alert_ids'])
        flags=[]
        if not rr:flags.append('MISSING_REQUEST_RESPONSE')
        if not valid_direct:flags.append('MISSING_DIRECT_BINDING')
        if not selected:flags.append('MISSING_RELATION')
        if c['cross_chain']:flags.append('CROSS_CHAIN')
        if c['disconnected']:flags.append('DISCONNECTED')
        if g['contradictions'] or l['contradictions']:flags.append('WHOLE_GROUP_CONFLICT')
        if covered!=member_alerts or l['whole_group_check']['unresolved_reference_count']:flags.append('INSUFFICIENT_EVIDENCE')
        if not (request_roles and response_roles):flags.append('OTHER')
        sole=(not rr and len(complete_requests)==1 and bool(valid_direct) and request_roles and response_roles and
              not c['cross_chain'] and not c['disconnected'] and not g['contradictions'] and
              not l['whole_group_check']['unresolved_reference_count'])
        diagnoses.append(dict(proposal_id=c['proposal_id'],status=c['status'],classification=c['classification'],
            gt_stage_ids=c['gt_stage_ids'],member_stage_ids=c['member_stage_ids'],missing_condition_categories=flags,
            valid_request_response_claim_ids=[x['claim_id'] for x in rr],
            valid_direct_claim_ids=[x['claim_id'] for x in valid_direct],existing_relation_ids=g['source_relation_ids'],
            observable_operation_values=operations,request_roles_observed=request_roles,response_roles_observed=response_roles,
            all_member_shared_request_identity_count=len(complete_requests),
            purpose_covered_alert_count=len(covered),required_alert_count=len(member_alerts),
            original_p1_failures=proof['failures'],
            blocked_only_by_missing_request_response=sole,
            other_explanation='No complementary REQUEST/RESPONSE operations under the unchanged upstream policy.' if 'OTHER' in flags else None))
    exact_candidate=[d for d in diagnoses if d['status']=='CANDIDATE' and d['classification']=='EXACT_GT_STEP']
    sole=[d['proposal_id'] for d in exact_candidate if d['blocked_only_by_missing_request_response']]
    return dict(total_request_response_claim_count=sum(c['evidence_type']=='REQUEST_RESPONSE' for c in claims.values()),
        global_observable_request_role_alert_count=sum(a.get('alert_type') in request_ops for a in alerts.values()),
        global_observable_response_role_alert_count=sum(a.get('alert_type') in response_ops for a in alerts.values()),
        gt_positive_definition='Nontrivial exact or pure-subset proposal; singleton excluded.',
        category_counting='Nonexclusive; one proposal can miss several requirements. OTHER records profile/operation-role mismatch.',
        reason_counts={reason:sum(reason in d['missing_condition_categories'] for d in diagnoses) for reason in [
            'MISSING_REQUEST_RESPONSE','MISSING_DIRECT_BINDING','MISSING_RELATION','CROSS_CHAIN','DISCONNECTED',
            'WHOLE_GROUP_CONFLICT','INSUFFICIENT_EVIDENCE','OTHER']},
        reason_dependency_note='Flags are nonexclusive and logically dependent. Zero recorded P1 coverage can be a consequence of having no REQUEST_RESPONSE claim, not an independent causal deficit. Sole-gate attribution instead checks full existing request-binding coverage and complementary native operations.',
        GT_TRUE_CANDIDATE_BLOCKED_BY_P1_COUNT=len(sole),GT_TRUE_CANDIDATE_BLOCKED_BY_P1_IDS=sole,
        sole_missing_definition='All other P1 requirements independently demonstrated; absence/unknown does not count as sole causation.',
        exact_true_candidate_p1_ineligible_count=sum(not d['valid_request_response_claim_ids'] for d in exact_candidate),
        exact_true_candidate_p1_ineligible_ids=[d['proposal_id'] for d in exact_candidate if not d['valid_request_response_claim_ids']],
        pure_candidate_p1_ineligible_count=sum(d['status']=='CANDIDATE' and not d['valid_request_response_claim_ids'] for d in diagnoses),
        diagnoses=diagnoses)

def cross_gt_risks(classified,groups,ledger,source):
    by_group={g['semantic_step_id']:g for g in groups}; by_log={l['candidate_id']:l for l in ledger}
    claims={c['claim_id']:c for c in source['evidence']['claims']}
    decisions={d['candidate_id']:d for d in source['evidence']['decisions']}
    rows=[]; stages={s['stage_id']:s for s in source['stages']['stages']}
    def seconds(value):return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
    for c in classified:
        if c['classification']!='CROSS_GT_MIXED':continue
        g=by_group[c['proposal_id']]; l=by_log[c['proposal_id']]; shared=l['whole_group_check']['shared_context']
        selected=[decisions[rid] for rid in g['source_relation_ids']]
        types=sorted({claims[cid]['evidence_type'] for d in selected for cid in d['relation_claim_ids']})
        label_by_stage={sid:label for label,ids in c['gt_intersections'].items() for sid in ids}
        cross_pairs=[(a,b) for a,b in pairs(c['member_stage_ids']) if label_by_stage[a]!=label_by_stage[b]]
        flags=dict(shared_session=bool(shared['session_bindings']),same_flow=bool(shared['flow_bindings']),
            process_lineage='PARENT_CHILD_PROCESS' in types,
            authentication_lifecycle='AUTH_ESTABLISH_USE' in types,
            incoming_ssh='CONNECTION_ESTABLISH_ACCEPT' in types,
            outbound_connection='SAME_TRUSTED_CONNECTION' in types,
            temporal_interval_overlap=shared['time_overlap'],same_host=bool(shared['host_entities']),same_account=bool(shared['account_entities']))
        rows.append(dict(**c,risk_context_flags=flags,accepted_evidence_types=types,
            minimum_observed_stage_gap_seconds=min(max(0,max(seconds(stages[a]['start_time']),seconds(stages[b]['start_time']))-
                min(seconds(stages[a]['end_time']),seconds(stages[b]['end_time']))) for a,b in cross_pairs),
            original_claim_ids=sorted({cid for d in selected for cid in d['relation_claim_ids']}),
            grouping_reason=g['grouping_basis']['reason_codes']))
    return dict(CROSS_GT_CONFIRMED_COUNT=sum(r['status']=='CONFIRMED' for r in rows),
        CROSS_GT_CANDIDATE_COUNT=sum(r['status']=='CANDIDATE' for r in rows),
        CROSS_GT_UNRESOLVED_COUNT=sum(r['status']=='UNRESOLVED' for r in rows),
        contexts_by_status={status:{key:sum(r['status']==status and r['risk_context_flags'][key] for r in rows)
            for key in (rows[0]['risk_context_flags'] if rows else [])} for status in STATUSES},
        temporal_proximity_policy='Report observed gaps and nearest cases; no new proximity threshold or grouping rule.',
        smallest_cross_gt_time_gaps=[dict(proposal_id=r['proposal_id'],status=r['status'],gt_stage_ids=r['gt_stage_ids'],
            gap_seconds=r['minimum_observed_stage_gap_seconds']) for r in sorted(rows,key=lambda r:(r['minimum_observed_stage_gap_seconds'],r['proposal_id']))[:10]],
        risk_flags_are_context_or_typed_relation_observations_not_same_step_proof=True,proposals=rows)

def observation_binding_review(gt,native,mapping,stage_gt):
    originals={r['event_id']:r for r in native}
    alert_stage={aid:st['stage_id'] for st in mapping['_action_stage_members'] for aid in st['member_alert_ids']}
    native_stage={row['source_record_id']:alert_stage[row['alert_id']] for row in mapping['alert_mapping']}
    def field(record,path):
        value=record
        for part in path.split('.'):
            value=value[part]
        return value
    rows=[]
    for binding in gt['observation_bindings']:
        source=binding['source_alert_id']; target=binding['target_alert_id']
        if source not in native_stage or target not in native_stage:continue
        a,b=native_stage[source],native_stage[target]
        if a==b:continue
        try:
            left=field(originals[source],binding['source_field']);right=field(originals[target],binding['target_field'])
            status='RESOLVED_EQUAL' if left==right==binding['value'] else 'RESOLVED_VALUES_DIFFER'
        except (KeyError,TypeError):left=right=None;status='UNRESOLVED_NATIVE_PATH'
        rows.append(dict(**binding,source_action_stage=a,target_action_stage=b,
            source_gt_stage=stage_gt[a],target_gt_stage=stage_gt[b],native_resolution_status=status,
            actual_source_value=left,actual_target_value=right))
    labels=sorted({g['stage_id'] for g in gt['stages']})
    return dict(scope='GT-declared cross-Action observation bindings, independently checked against sealed native records. They are evaluation evidence only, never grouping inputs.',
        by_gt_stage={label:dict(within_gt_cross_action_binding_count=sum(r['source_gt_stage']==r['target_gt_stage']==label for r in rows),
            binding_types=dict(Counter(r['binding_type'] for r in rows if r['source_gt_stage']==r['target_gt_stage']==label)),
            resolution_counts=dict(Counter(r['native_resolution_status'] for r in rows if r['source_gt_stage']==r['target_gt_stage']==label))) for label in labels},
        cross_gt_binding_type_counts=dict(Counter(r['binding_type'] for r in rows if r['source_gt_stage']!=r['target_gt_stage'])),
        rows=rows)

def baseline_comparison(groups,source,stage_gt):
    universe=pairs(stage_gt);truth={p for p in universe if stage_gt[p[0]]==stage_gt[p[1]]}
    accepted={tuple(sorted([d['stage_a_id'],d['stage_b_id']])) for d in source['evidence']['decisions'] if d['relation_type']!='NO_RELATION'}
    retrieved={tuple(sorted([d['stage_a_id'],d['stage_b_id']])) for d in source['candidates']['candidates']}
    candidate=set().union(*(pairs(g['member_stage_ids']) for g in groups if g['membership_status']=='CANDIDATE'))
    return dict(unit='ACTION_STAGE_PAIR',existing_stage8_relation_pair_baseline=pair_metrics(universe,truth,accepted),
        existing_stage7_retrieval_pair_baseline=pair_metrics(universe,truth,retrieved),
        semantic_candidate_pairs=pair_metrics(universe,truth,candidate),
        candidate_pairs_not_in_accepted_relations=dict(TP=len((candidate-accepted)&truth),FP=len((candidate-accepted)-truth),pair_count=len(candidate-accepted)),
        interpretation='Association-graph pairs and semantic-step pairs have different intended meanings; compare retrieval signal, never call valid cross-step graph edges algorithm errors. Semantic proposal pairs are not added graph edges.')

def recoverability(gt_sets,source,recovery_result,diagnosis):
    rows=[]; decisions=source['evidence']['decisions']
    for label,members in sorted(gt_sets.items()):
        accepted=[d for d in decisions if d['relation_type']!='NO_RELATION' and {d['stage_a_id'],d['stage_b_id']}<=members]
        if len(members)==1:
            status='SINGLE_ACTION_BASELINE_NO_AGGREGATION_REQUIRED'; not_observable=False
            reason='Already one Action Stage; does not test multi-action aggregation or validate a GT semantic label.'
        elif not accepted:
            status='GT_STAGE_IS_NOT_OBSERVABLY_RECOVERABLE'; not_observable=True
            reason='No accepted cross-action relation and no frozen whole-purpose proof. Shared context cannot establish the GT episode boundary.'
        else:
            status='ASSOCIATION_OBSERVABLE_PURPOSE_UNPROVEN'; not_observable=False
            reason='Existing accepted relation supplies cross-action association. Its activity boundary/purpose is not independently established; no P1 proof.'
        rows.append(dict(gt_stage_id=label,status=status,GT_SEMANTIC_NOT_OBSERVABLE=not_observable,
            observable_accepted_relation_ids=[d['candidate_id'] for d in accepted],reason=reason,
            scope='Relative to these sealed observables and the frozen proof contract; not a claim the underlying scenario never occurred.'))
    return dict(GT_SEMANTIC_NOT_OBSERVABLE_COUNT=sum(r['GT_SEMANTIC_NOT_OBSERVABLE'] for r in rows),
        gt_membership_is_not_evidence_of_observable_same_step_binding=True,stages=rows)

def four_cases(recovery_result,classified,diagnosis,recoverability_result):
    result=[]
    rec={r['gt_stage_id']:r for r in recovery_result['stages']}
    obs={r['gt_stage_id']:r for r in recoverability_result['stages']}
    diag={d['proposal_id']:d for d in diagnosis['diagnoses']}
    for label in ['GT-S02','GT-S04','GT-S05','GT-S07']:
        exact=[r for r in classified if r['gt_stage_ids']==[label] and r['classification']=='EXACT_GT_STEP']
        subset=[r for r in classified if r['gt_stage_ids']==[label] and r['classification']=='PURE_GT_SUBSET']
        result.append(dict(gt_stage_id=label,recovery=rec[label],exact_proposals=exact,
            EXACT_GT_STEP_BUT_NOT_CONFIRMED=bool(exact) and not any(r['status']=='CONFIRMED' for r in exact),
            subset_proposal_ids=[r['proposal_id'] for r in subset],
            exact_gate_diagnoses=[diag[r['proposal_id']] for r in exact],observability=obs[label],
            interpretation=({'GT-S02':'Multi-request Web activity may be an episode hypothesis. The common flow also crosses other GT stages and does not prove the full GT episode boundary.',
                'GT-S04':'Exact ApplicationRequest/Child Shell candidate has parent-child evidence, but no approved same-purpose confirmation proof.',
                'GT-S05':'Exact credential-related candidate retains read/use differences; path and lineage do not prove key material identity or successful use.',
                'GT-S07':'Exact proposal remains unresolved: the missing transport→auth→process link cannot be supplied by GT story knowledge.'}[label])))
    return dict(cases=result)

def frozen_alert_metrics(groups,stage_alerts,alert_gt):
    universe=pairs(alert_gt); truth={p for p in universe if alert_gt[p[0]]==alert_gt[p[1]]}
    predicted=set().union(*(pairs({a for sid in g['member_stage_ids'] for a in stage_alerts[sid]})
        for g in groups if g['membership_status']=='CONFIRMED'))
    return dict(unit='UNORDERED_CANONICAL_ALERT_PAIR',contract='attack-step-evaluation-v1.1',
        comparison_role='Frozen contract metric; Action Stage pair diagnostics do not replace promotion criteria.',
        CONFIRMED_ONLY=pair_metrics(universe,truth,predicted),
        promotion_status='NOT_READY',no_threshold_changes=True,
        note='No CONFIRMED groups: precision/mixed-group rate/evidence-completeness are N/E, recall and F1 zero. No independent held-out dataset was evaluated.')

def verify_preservation(root,out):
    before=json.loads((out/'protected_before.json').read_text('utf8')); changed=[];missing=[]
    for name,digest in before.items():
        p=Path(name)
        if not p.exists(): missing.append(name)
        elif sha(p)!=digest: changed.append(name)
    require(not changed and not missing,'protected_file_modified')
    return dict(protected_file_count=len(before),changed_files=changed,missing_files=missing,
        PROTOTYPE_CODE_MODIFIED=False,CONTRACT_MODIFIED=False,DATASET_MODIFIED=False,GROUND_TRUTH_MODIFIED=False,
        STAGES_1_TO_9_MODIFIED=False,semantic_output_not_regenerated=True,
        note='Byte preservation includes frozen prototype runs and contract; only new independent evaluator/tests/output files are allowed.')

def run_evaluation(root,out):
    inputs=Inputs(root/'outputs/attack_step_offline_prototype_20261022'); data=inputs.verify()
    output=data['output']; source=data['source']; groups=output['semantic_groups']; ledger=data['ledger']
    native=inputs.read(data['manifest']['paths']['dataset'],jsonl=True)
    gtroot=Path('D:/Code_WorkSpace/TraceBack-Dataset/data/attack125/ground_truth')
    gt=inputs.read(gtroot/'ground_truth.json',gt=True)
    for key,name in [('stages','stages.json'),('observations','observations.json'),('observation_bindings','observation_bindings.json'),('edges','edges.json')]:
        require(inputs.read(gtroot/name,gt=True)==gt[key],'GT_combined_split_file_mismatch:'+name)
    audit=inputs.read(root/'outputs/stage6_oversegmentation_audit_20261022/gt_stage_fragment_mapping.json',gt=True)
    # Policy is only read for diagnostics; it is never changed or applied to
    # regenerate source decisions or output memberships.
    import yaml
    policy=yaml.safe_load(inputs.read(root/'configs/stage-evidence-v1.yaml',text=True))
    mapping,alert_gt,stage_gt,gt_sets=mapping_from_native(source['alerts'],source['stages']['stages'],native,gt,audit)
    save(out,'gt_stage_action_stage_mapping.json',mapping)
    if not mapping['complete']:
        save(out,'input_verification.json',dict(PROTOTYPE_OUTPUT_SHA_VERIFIED=True,GT_READ_AFTER_OUTPUT_SEAL=True,events=inputs.events))
        save(out,'task_result.json',dict(TASK_RESULT='PARTIAL',EVALUATION_MODE='POST_SEAL_INDEPENDENT',
            all_gt_metrics='NOT_EVALUABLE:INCOMPLETE_GT_MAPPING',mapping_failures=mapping['failures'],
            NEXT_ACTION='RESOLVE_MAPPING_WITHOUT_DROPPING_SAMPLES'))
        return
    require(set(stage_gt)=={st['stage_id'] for st in source['stages']['stages']},'missing_action_stage_population')
    classified=[classify_proposal(g,stage_gt,gt_sets) for g in groups]
    with (out/'proposal_gt_classification.jsonl').open('x',encoding='utf8') as f:
        for row in classified:f.write(json.dumps(row,ensure_ascii=False,sort_keys=True)+'\n')
    recovery_result=recovery(groups,gt_sets); pairwise=evaluate_pairs(groups,stage_gt)
    candidates=candidate_truth(classified); diag=evidence_diagnosis(groups,classified,ledger,source,policy)
    candidates.update({k:diag[k] for k in ['GT_TRUE_CANDIDATE_BLOCKED_BY_P1_COUNT','GT_TRUE_CANDIDATE_BLOCKED_BY_P1_IDS',
                                           'exact_true_candidate_p1_ineligible_count','exact_true_candidate_p1_ineligible_ids']})
    risks=cross_gt_risks(classified,groups,ledger,source)
    mapping_for_bindings={**mapping,'_action_stage_members':[dict(stage_id=s['stage_id'],member_alert_ids=s['alert_ids']) for s in source['stages']['stages']]}
    bindings=observation_binding_review(gt,native,mapping_for_bindings,stage_gt)
    baselines=baseline_comparison(groups,source,stage_gt)
    matrix=calibration(classified,pairwise,groups,stage_gt)
    observable=recoverability(gt_sets,source,recovery_result,diag)
    cases=four_cases(recovery_result,classified,diag,observable)
    rank=ranking(classified)
    frozen=frozen_alert_metrics(groups,{s['stage_id']:s['alert_ids'] for s in source['stages']['stages']},alert_gt)
    classification_counts={status:dict(Counter(c['classification'] for c in classified if c['status']==status)) for status in STATUSES}
    for name,value in [('exact_step_recovery.json',recovery_result),('pairwise_evaluation.json',pairwise),
            ('candidate_truth_analysis.json',candidates),('p1_gate_diagnosis.json',diag),('four_case_evaluation.json',cases),
            ('cross_gt_risk_analysis.json',risks),('status_calibration_matrix.json',matrix),('recoverability_analysis.json',observable),
            ('ranking_evaluation.json',rank),('frozen_contract_alert_evaluation.json',frozen),('proposal_classification_summary.json',classification_counts),
            ('observation_binding_review.json',bindings),('baseline_comparison.json',baselines)]:save(out,name,value)
    integrity=verify_preservation(root,out)
    save(out,'integrity_verification.json',integrity)
    gt_reads=[r for r in inputs.events if r['gt']]
    inspection=json.loads((out/'inspection_read_log.json').read_text('utf8')) if (out/'inspection_read_log.json').exists() else None
    all_gt=gt_reads+([r for r in inspection['events'] if r['gt']] if inspection else [])
    require(all(r['read_at']>data['seal']['sealed_at'] for r in all_gt),'GT_read_timing_violation')
    verification=dict(PROTOTYPE_OUTPUT_SHA_VERIFIED=True,expected_output_sha256=EXPECTED_SHA,
        actual_output_sha256=sha(inputs.prototype/'attack_step_semantic_output.json'),GT_READ_AFTER_OUTPUT_SEAL=True,
        acceptance_sealed_at=data['seal']['sealed_at'],first_gt_decoded_read=min(r['read_at'] for r in all_gt),
        input_files=inputs.events,inspection_read_log_included=bool(inspection),
        gt_artifact_digests={r['path']:r['sha256'] for r in gt_reads},
        required_sealed_inputs_verified=['attack_step_semantic_output.json','candidate_ledger.jsonl','stage_descriptors.json',
            'input_manifest.json','schema_validation.json','evidence_trace_validation.json'],
        evaluator_isolation='No imports or execution of app.attack_steps or upstream generation modules; GT read only in this standalone evaluator.',
        original_chain_correctness='Not re-scored as causal GT correctness; exact source integrity preserved separately.')
    save(out,'input_verification.json',verification)
    a=pairwise['scenarios']['CONFIRMED_ONLY']; b=pairwise['scenarios']['CONFIRMED_CANDIDATE']
    candidate_total=sum(c['status']=='CANDIDATE' for c in classified)
    # Interpret measured majority contamination, not a new production threshold.
    conclusion=('OVER_GROUPING_RISK_HIGH' if risks['CROSS_GT_CANDIDATE_COUNT']>candidate_total/2 and b['FP']>b['TP']
                else 'PROMISING_BUT_EVIDENCE_LIMITED')
    def value(metric):return metric['value'] if metric['status']=='EVALUABLE' else 'NOT_EVALUABLE'
    rec={r['gt_stage_id']:r for r in recovery_result['stages']}
    status_strings={label:('NO_EXACT_PROPOSAL' if not rec[label]['exact_proposal_ids'] else
        'EXACT_PROPOSAL_'+('_'.join(sorted(set(rec[label]['exact_statuses']))))) for label in ['GT-S02','GT-S04','GT-S05','GT-S07']}
    result=dict(TASK_RESULT='PASS',EVALUATION_MODE='POST_SEAL_INDEPENDENT',PROTOTYPE_OUTPUT_SHA_VERIFIED=True,
        GT_READ_AFTER_OUTPUT_SEAL=True,GT_STAGE_COUNT=len(gt_sets),ACTION_STAGE_COUNT=len(stage_gt),
        MULTI_ACTION_GT_STAGE_COUNT=recovery_result['MULTI_ACTION_GT_STAGE_COUNT'],
        GT_STEP_EXACT_RECOVERED_COUNT=recovery_result['GT_STEP_EXACT_RECOVERED_COUNT'],
        GT_STEP_EXACT_RECOVERY_RATE=value(recovery_result['GT_STEP_EXACT_RECOVERY_RATE']),
        MULTI_ACTION_GT_EXACT_RECOVERED_COUNT=recovery_result['MULTI_ACTION_GT_EXACT_RECOVERED_COUNT'],
        MULTI_ACTION_GT_EXACT_RECOVERY_RATE=value(recovery_result['MULTI_ACTION_GT_EXACT_RECOVERY_RATE']),
        PAIRWISE_CONFIRMED_PRECISION=value(a['PRECISION']),PAIRWISE_CONFIRMED_RECALL=value(a['RECALL']),PAIRWISE_CONFIRMED_F1=value(a['F1']),
        PAIRWISE_CONFIRMED_CANDIDATE_PRECISION=value(b['PRECISION']),PAIRWISE_CONFIRMED_CANDIDATE_RECALL=value(b['RECALL']),
        PAIRWISE_CONFIRMED_CANDIDATE_F1=value(b['F1']),CANDIDATE_GT_TRUE_COUNT=candidates['CANDIDATE_GT_TRUE_COUNT'],
        CANDIDATE_GT_FALSE_COUNT=candidates['CANDIDATE_GT_FALSE_COUNT'],CANDIDATE_GT_TRUE_RATE=value(candidates['CANDIDATE_GT_TRUE_RATE']),
        PARTIAL_GT_CANDIDATE_COUNT=candidates['PARTIAL_GT_CANDIDATE_COUNT'],
        CROSS_GT_CONFIRMED_COUNT=risks['CROSS_GT_CONFIRMED_COUNT'],CROSS_GT_CANDIDATE_COUNT=risks['CROSS_GT_CANDIDATE_COUNT'],
        CROSS_GT_UNRESOLVED_COUNT=risks['CROSS_GT_UNRESOLVED_COUNT'],
        GT_TRUE_CANDIDATE_BLOCKED_BY_P1_COUNT=diag['GT_TRUE_CANDIDATE_BLOCKED_BY_P1_COUNT'],
        GT_TRUE_CANDIDATE_P1_INELIGIBLE_COUNT=diag['exact_true_candidate_p1_ineligible_count'],
        GT_S02_RECOVERY=status_strings['GT-S02'],GT_S04_RECOVERY=status_strings['GT-S04'],GT_S05_RECOVERY=status_strings['GT-S05'],GT_S07_RECOVERY=status_strings['GT-S07'],
        GT_SEMANTIC_NOT_OBSERVABLE_COUNT=observable['GT_SEMANTIC_NOT_OBSERVABLE_COUNT'],
        PROTOTYPE_CODE_MODIFIED=False,CONTRACT_MODIFIED=False,DATASET_MODIFIED=False,GROUND_TRUTH_MODIFIED=False,STAGES_1_TO_9_MODIFIED=False,
        EVALUATION_CONCLUSION=conclusion,NEXT_ACTION='STOP_FORMAL_INTEGRATION; REVIEW_CANDIDATE_CONTAMINATION_AND_OBSERVABLE_PURPOSE_REQUIREMENTS')
    save(out,'task_result.json',result)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return dict(result=result,mapping=mapping,recovery=recovery_result,pairwise=pairwise,candidates=candidates,diagnosis=diag,
        risks=risks,matrix=matrix,recoverability=observable,cases=cases,ranking=rank,frozen=frozen,verification=verification,integrity=integrity)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--inspect',action='store_true')
    args=parser.parse_args(); root=Path(__file__).resolve().parents[1]
    require(args.output.exists(),'Create new independent evaluation directory and preservation baseline first.')
    if args.inspect: inspect_inputs(root,args.output)
    else: run_evaluation(root,args.output)

if __name__=='__main__': main()

"""Explicit boundary probes derived from the existing V5.2 synthetic suite.

No formula changes. Expectations are saved before executing any new probe.
Native Adapter coverage is never inferred from a numeric guard witness.
"""
import copy
import gzip
import json
import sys
from pathlib import Path
from .run import ROOT, OUT, OLD, read, save, sha
from .audit import PREV, BASE
from evaluation.framework.sparse_semantics import runtime, model
from evaluation.framework.anchor_semantics.runtime import feature, rows

def probes():
    witnesses=read(PREV/'stress_input.json')
    def existing(name):return copy.deepcopy(next(x for x in witnesses if x['id']==name+':0'))
    def thin(name,features,behavior=None):
        r=existing(name);r['env']['features']=features;r['bindings']=[];r['entities']={};r['behavior']=behavior
        return r
    time=feature('time.distance',.99,.1,family='time')
    direct=feature('topology.attested_relation',.95,1.,anchor='attested_relation',role='direct',family='relation')
    cases=[]
    def add(letter,title,r,expected,coverage='feature-level',why=''):
        cases.append(dict(case=letter,title=title,input=r,expected_decision=expected,coverage=coverage,expected_semantics=why))
    add('A','strong evidence + many missing families',thin('cross_source_attested',[time,direct]),'ADMIT',why='Attested relation support may survive absent unrelated families')
    obj=existing('long_lived_session');obj['a']['host']=obj['b']['host']='asset'
    obj['a']['raw_alert'].update(application_id='application',response_object_id='opaque-object')
    obj['b']['raw_alert'].update(application_id='application',request_object_id='opaque-object');obj['behavior']=None
    add('B','valid contextual relation + sparse evidence',obj,'ADMIT',why='Exact existing object-handoff regression, no directional relation inferred')
    add('C','only weak coincidence',thin('long_lived_session',[time,feature('HOST',.1,.1)]),'REJECT',why='One weak context is insufficient')
    add('D','high time proximity only',thin('long_lived_session',[time]),'REJECT',why='Time adds no positive channel')
    add('E','same IP but unrelated semantics',thin('long_lived_session',[time,feature('IP',.8,.1)]),'REJECT',why='IP alone is insufficient')
    namespace=thin('shared_login_context',[time,feature('ACCOUNT',.95,.75)])
    namespace['env']['gate']['hard_contradiction']=True
    add('F','same account + namespace conflict',namespace,'REJECT','upstream guard boundary only; native namespace evidence not represented',why='Original verified guard must veto support')
    add('G','same host + incompatible role',existing('sensor_local_collision'),'REJECT','scope-conflict witness only; endpoint-role-specific native coverage missing',why='Conflicting context must not create a binding')
    add('H','explicit binding support',existing('request_worker_binding'),'ADMIT',why='Preexisting attested direct witness')
    contradiction=existing('cross_source_attested');contradiction['env']['gate']['hard_contradiction']=True
    add('I','explicit incident contradiction',contradiction,'REJECT',why='Hard incident contradiction veto')
    add('J','all evidence absent',thin('long_lived_session',[]),'REJECT',why='No channels => gate false and score zero')
    add('K','one strong context anchor only',thin('long_lived_session',[time,feature('SESSION',.98,.9,anchor='session')]),'REJECT',why='Session identity alone is not task evidence')
    add('L','multiple weak families / missing task',existing('missing_task_multiple_weak_signals'),'ADMIT',why='Existing labeled legitimate sparse witness; recall must not be hidden as ambiguity')
    add('M','transport-only evidence',thin('persistent_connection',[time,feature('IP',.9,.1),feature('SESSION',.9,.8,anchor='session')]),'REJECT',why='Correlated transport views collapse to one context')
    add('N','destination role continuity',thin('long_lived_session',[time,feature('IP',.9,.1)]),'REJECT','IP-only boundary control; native destination-role transition coverage missing',why='Endpoint continuity alone cannot infer causal relation')
    add('O','cross-source progression support',existing('cross_source_attested'),'ADMIT',why='Same-source names never affect attested support')
    same=next(copy.deepcopy(x) for x in witnesses if x['id']=='short_request_continuation:1')
    add('P','same-source legitimate progression support',same,'ADMIT',why='Existing same-source task witness remains eligible')
    protocol=dict(source='evaluation/tests/test_sparse_semantics.py and immutable V5.1 stress_input.json',
        witness_hash=sha(PREV/'stress_input.json'),threshold=.65,expectations_frozen_before_probe_execution=True,cases=cases,
        note='Additional boundary controls remove existing observations or set an existing hard-guard flag. They test negatives symmetrically and cannot prove native scope/role extraction coverage.')
    save(OUT/'sparse_probe_protocol.json',protocol)
    p=runtime.load_policy()['formula'];results=[]
    for c in cases:
        r=c['input'];projection,audit=model.project(r['env'],r['bindings'],r['a'],r['b'],r['entities'],r['behavior'],p)
        v=model.score(projection,p,.65)
        results.append({k:x for k,x in c.items() if k!='input'} | dict(result=v,projection=projection,audit=audit,
            pass_=v['decision']==c['expected_decision']))
    stress=read(OUT/'stress_labeled_results.json')
    by={}
    for r in stress:by.setdefault(r['scenario'],[]).append(r)
    summary={k:dict(count=len(v),decisions=dict(__import__('collections').Counter(x['result']['decision'] for x in v)),
        score_min=min(x['result']['score'] for x in v),score_max=max(x['result']['score'] for x in v)) for k,v in by.items()}
    missing=existing('missing_task_multiple_weak_signals')
    a,_=model.project(missing['env'],missing['bindings'],missing['a'],missing['b'],missing['entities'],None,p)
    b,_=model.project(missing['env'],missing['bindings'],missing['a'],missing['b'],missing['entities'],0.,p)
    ar,br=model.score(a,p,.65),model.score(b,p,.65)
    save(OUT/'sparse_semantics_matrix.json',dict(cases=results,archived_stress_scenarios=summary,
        observed_zero_vs_unobserved=dict(absent=ar,neutral=br,score_equal=ar['score']==br['score'],
            completeness_distinct=ar['evidence_completeness']!=br['evidence_completeness']),
        missing_not_contradiction_pass=ar['semantic_compatibility']==1 and br['semantic_compatibility']==1,
        all_cases_pass=all(x['pass_'] for x in results),native_scope_role_coverage_complete=False,
        SPARSE_SEMANTICS_PASS=False,reason='Legitimate sparse multi-signal case remains AMBIGUOUS; full stress recall and ambiguity gates fail. F/G/N have only boundary controls, not new native integration coverage.'))
    patterns=[('exact anchor present','short_request_continuation','ADMIT'),
        ('exact anchor absent, compatible contextual evidence','missing_task_multiple_weak_signals','ADMIT'),
        ('weak-only context','long_lived_session','REJECT'),('contradictory anchor','identifier_reuse','REJECT'),
        ('ambiguous anchor','unobserved_distinct_tasks','REJECT'),('cross-source binding','cross_source_attested','ADMIT'),
        ('same-source continuity','transaction_continuation','ADMIT')]
    anchor=[]
    for title,name,expected in patterns:
        rr=by[name]
        anchor.append(dict(scenario=title,ids=[x['id'] for x in rr],expected_decision=expected,
            scores=[x['result']['score'] for x in rr],decisions=[x['result']['decision'] for x in rr],
            pass_=all(x['result']['decision']==expected for x in rr),evidence=rr[0]['audit'],why=rr[0]['result']['decision_reason']))
    save(OUT/'anchor_semantics_regression.json',dict(cases=anchor,no_exact_anchor_object_handoff=results[1],
        allows_nonexact_qualified_context=results[1]['result']['decision']=='ADMIT',
        allows_generic_multiple_compatible_context=False,ANCHOR_SEMANTICS_PASS=all(x['pass_'] for x in anchor),
        ordinary_coincidence_safety='A single context channel is capped; generic multiple-family high scores are AMBIGUOUS, not strictly rejected. Original guards remain mandatory.',
        conclusion='V5.1 all-exact-anchor restriction partly removed; broad legitimate sparse context overrestriction remains.'))
    print('SPARSE_AND_ANCHOR_REVIEW_COMPLETE',flush=True)

def inputs():
    manifest=read(OUT/'run_manifest.json')
    dataset=Path(manifest['dataset']);folder=dataset.parents[1];final=read(folder/'manifests/final_manifest.json')
    verification=[]
    for name,h in final['file_hashes'].items():
        actual=sha(folder/name)
        verification.append(dict(file=name,expected=h,actual=actual,match=actual==h))
    save(OUT/'dataset_identity_verification.json',dict(manifest_sha256=sha(folder/'manifests/final_manifest.json'),
        dataset_root=str(folder),statistics=final['statistics'],files=verification,
        all_match=all(x['match'] for x in verification),dataset_match=sha(dataset)==manifest['dataset_hash'],
        ground_truth_match=sha(folder/'ground_truth/ground_truth.json')==manifest['ground_truth_hash'],
        no_dataset_regeneration=True,hashes_only_identity_no_scoring=True))

def witnesses():
    audit=read(OUT/'over_correlation_audit.json')
    wanted={i for r in audit['rows'] for i in r['support_pair']}
    alerts={r['alert_id']:r for r in rows(BASE/'blind_A/canonical.jsonl.gz') if r['alert_id'] in wanted}
    output=[]
    for row in audit['rows']:
        native=[]
        for i in row['support_pair']:
            a=alerts[i]
            native.append(dict(alert_id=i,source=a['source_namespace'],host=a['host'],category=a['category'],
                session=a['session'],process=a['process'],timestamp=a['timestamp'],
                raw_fields={k:v for k,v in a['raw_alert'].items() if k not in {'payload','packet'}},
                field_provenance=a['field_provenance'],
                canonical_ref='outputs/v5_source_bound_observability_final/blind_A/canonical.jsonl.gz'))
        output.append(dict(**row,native_witnesses=native,
            annotation_method='Deterministic preliminary semantic triage from existing channel basis, followed by native-witness inspection; not independent human labels or GT'))
    save(OUT/'sample_semantic_witnesses.json',output)
    print('NATIVE_SAMPLE_WITNESSES',len(output),flush=True)


def chain():
    # Attempt the actual production boundary. Do not invent a compatible schema,
    # replace the V5.2 score by a V4 score, or pass unvalidated objects downstream.
    sys.path.insert(0,str(ROOT/'backend'))
    from app.models import CorrelationEdge
    from app.utils.stable_id import id_for
    errors=[];admitted=[]
    for row in rows(OUT/'predictions/candidates.jsonl.gz'):
        if row['result']['decision']=='ADMIT':admitted.append(row)
    for row in admitted:
        key=row['support_key'];r=row['result']
        payload=dict(edge_id=id_for('CorrelationEdge',dict(source_alert_id=key[0],target_alert_id=key[1])),
            source_alert_id=key[0],target_alert_id=key[1],score=r['score'],score_breakdown=r,
            support_pair=dict(alert_id_src=r['support_pair'][0],alert_id_dst=r['support_pair'][1]),reasons=[])
        try:CorrelationEdge.model_validate(payload)
        except Exception as e:errors.append(dict(support_key=key,error_type=type(e).__name__,details=str(e)))
    with gzip.open(OUT/'formal_edge_boundary_errors.jsonl.gz','wt',encoding='utf8',compresslevel=1) as f:
        for e in errors:f.write(json.dumps(e)+'\n')
    # Pure graph diagnostics use no GT and do not masquerade as protected incidents.
    parent={};sizes={}
    def find(x):
        parent.setdefault(x,x)
        if parent[x]!=x:parent[x]=find(parent[x])
        return parent[x]
    for row in admitted:
        a,b=map(find,row['support_key'])
        if a!=b:parent[max(a,b)]=min(a,b)
    for x in parent:sizes[find(x)]=sizes.get(find(x),0)+1
    save(OUT/'chain_reconstruction_validation.json',dict(status='BLOCKED_NO_V5_2_FORMAL_EDGE_SCHEMA_OR_DISPATCH',
        predicted_research_edges=len(admitted),predicted_edges=None,predicted_incidents=None,multi_alert_incidents=None,
        largest_incident_nodes=None,longest_predicted_chain_edges=None,GT_longest_path_edges=read(OUT/'labeled_metrics.json')['LONGEST_GT_PATH_EDGES'],
        recovered_GT_longest_path_edges=None,FULL_GT_PATH_RECOVERED=False,actual_reconstruction_executed=False,
        production_boundary_attempted=True,formal_edge_validation_attempts=len(admitted),formal_edge_validation_failures=len(errors),
        first_validation_error=errors[0] if errors else None,
        upstream_reason='Research output has no V5.2 ScoreBreakdown/Reason serializer or config dispatch; production constructor rejects it. Creating wrappers or forging legacy breakdowns would change the authorized boundary.',
        label_free_graph_diagnostic=dict(connected_nontrivial_components=len(sizes),largest_component_nodes=max(sizes.values(),default=0),
            definition='Unprotected connected components of research ADMIT support keys. This is not production Incident Clustering, direction, or AttackChain.'),
        CHAIN_RECONSTRUCTION_PASS=False,formula_semantics_changed=False))
    print('DOWNSTREAM_FORMAL_BOUNDARY_CHECKED',len(admitted),len(errors),flush=True)

if __name__=='__main__':
    {'probes':probes,'inputs':inputs,'chain':chain,'witnesses':witnesses}[sys.argv[1]]()

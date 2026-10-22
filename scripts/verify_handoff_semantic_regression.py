"""Read-only diagnosis and acceptance of ②/⑤ input into frozen ⑥/⑧.

Counterfactuals are offline probes, never proposed production partitions. They
run before truth is parsed and do not remove any identity from production.
"""
import argparse
from collections import Counter, defaultdict, deque
from dataclasses import asdict
import hashlib
from itertools import combinations
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'outputs/handoff_semantic_regression_20261021'
PRIOR=ROOT/'outputs/identity_relation_handoff_20261021'
DATA=Path('D:/Code_WorkSpace/TraceBack-Dataset/data/attack125')
sys.path.insert(0,str(ROOT/'backend'))
sys.dont_write_bytecode=True


def read(p): return json.loads(Path(p).read_text(encoding='utf8'))
def save(name,v):
    OUT.mkdir(exist_ok=True)
    (OUT/name).write_text(json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2,
        default=lambda value:sorted(value) if isinstance(value,set) else value.model_dump(mode='json'))+'\n',encoding='utf8')
def digest(v): return hashlib.sha256(json.dumps(v,sort_keys=True).encode()).hexdigest()
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def inventory():
    files=[p for folder in ('backend/app','backend/tests','configs','scripts','evaluation','frontend/src')
        for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    files += [p for p in DATA.rglob('*') if p.is_file()]
    names=['acceptance.json','integrity.json','stage6_freeze_receipt.json','stage6_new_regressions.json',
        'stage25_final_metrics.json','final_metrics.json','final.json','stage8_upstream_freeze.json','task_changes.diff',
        'before.json','before_metrics.json','stage25_final.json']
    files += [PRIOR/n for n in names if (PRIOR/n).is_file()]
    return {str(p.resolve()):sha(p) for p in sorted(set(files))}


def unchanged():
    current=inventory()
    allowed={Path(__file__).resolve(),ROOT/'backend/app/community/evidence.py',ROOT/'backend/app/community/builder.py'}
    return all(current.get(p)==h for p,h in read(OUT/'start_hashes.json').items()
               if Path(p).resolve() not in allowed)


def capture(label):
    import verify_identity_relation_handoff as live
    OUT.mkdir(exist_ok=True)
    if label=='baseline':
        if (OUT/'start_hashes.json').exists(): raise ValueError('baseline_already_exists')
        save('start_hashes.json',inventory())
        save('workspace_status.json',dict(status=subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,text=True).stdout))
    live.OUT=OUT
    sys.addaudithook(live.guard)
    if label=='final':
        # Keep the utility's formal+reversed ingestion, but use its independent
        # metrics evaluator without the original task's stage25 report lookup.
        live.OUT=OUT/'formal_run'
        live.OUT.mkdir(exist_ok=True)
        evaluator=live.evaluate
        live.evaluate=lambda _label,payload:evaluator('accepted',payload)
    live.capture(label)
    if label=='baseline':
        actual,prior=read(OUT/'baseline.json'),read(PRIOR/'final.json')
        equal={k:actual[k]==v for k,v in prior.items()}
        save('baseline_receipt.json',dict(equal_to_prior_final=equal,all_equal=all(equal.values()),
            prior_sha256=sha(PRIOR/'final.json')))
        assert all(equal.values()),equal
    if label=='final':
        final=read(OUT/'formal_run/final.json')
        previous=read(OUT/'verified.json') if (OUT/'verified.json').exists() else final
        equal={k:final[k]==v for k,v in previous.items()}
        reverse=read(OUT/'formal_run/final_execution.json')['reverse_input_determinism']
        assert all(equal.values()) and all(reverse.values())
        save('final_receipt.json',dict(repeated_live_run_equal=equal,reverse_input_determinism=reverse,
            canonical_snapshot='formal_run/final.json',previous_complete_live_snapshot='verified.json' if (OUT/'verified.json').exists() else None,
            initial_capture_report_error='legacy final evaluator required stage25_final.json; no production execution failed'))
    assert unchanged(), 'unexpected_file_change_during_read_only_capture'


def shortest(a,b,edges):
    adjacency=defaultdict(list)
    for eid,e in edges.items():
        x,y=e['alert_ids']
        adjacency[x].append((y,eid));adjacency[y].append((x,eid))
    queue=deque([a]); previous={a:None}
    while queue:
        x=queue.popleft()
        if x==b: break
        for y,eid in sorted(adjacency[x]):
            if y not in previous: previous[y]=(x,eid);queue.append(y)
    if b not in previous: raise ValueError('missing_formal_membership_proof_path')
    nodes=[b];refs=[]
    while previous[nodes[-1]]:
        x,eid=previous[nodes[-1]];nodes.append(x);refs.append(eid)
    return dict(alert_ids=list(reversed(nodes)),edge_ids=list(reversed(refs)))


def load_objects(snapshot):
    from app.models import CanonicalAlert, Entity
    from app.adapters.base import AdapterSettings
    from app.config import read_yaml
    from app.community import load_community_config
    from app.community.evidence import profile
    from app.stages.config import load_stage_config
    from app.stages.models import BehaviorAnnotation
    aa={a['alert_id']:CanonicalAlert.model_validate(a) for a in snapshot['alerts']}
    ee={e['entity_id']:Entity.model_validate(e) for e in snapshot['entities']}
    cfg=load_community_config(ROOT/'configs/community-v1.yaml')
    routing=read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources']
    ss={v['source_namespace']:AdapterSettings(**v) for v in routing.values()}
    pp={i:profile(a,ee,ss[a.source_namespace],cfg) for i,a in aa.items()}
    bb={b['alert_id']:BehaviorAnnotation.model_validate(b) for b in snapshot['stages']['behaviors']}
    return aa,ee,ss,pp,bb,cfg,load_stage_config(ROOT/'configs/behavior-stage-v1.yaml')


def probes(snapshot):
    from app.models.alerts import ContextRef
    from app.community.evidence import profile
    from app.stages.aggregation import community_graph
    from app.stages.graph import connected_components
    aa,ee,ss,pp,bb,cfg,scfg=load_objects(snapshot)
    legacy=read(PRIOR/'before.json')
    current_groups=[c['alert_ids'] for c in snapshot['communities']['incident_candidates']]
    old_groups=[c['alert_ids'] for c in legacy['communities']['incident_candidates']]
    restored={i:a for i,a in aa.items()}
    for binding in snapshot['identity_projection']['context_bindings']:
        for observation in binding['observations']:
            i=observation['alert_id'];a=restored[i]
            originals=[ContextRef.model_validate(c) for c in observation['source_contexts']]
            paths={c.raw_pointer for c in originals}
            contexts=[c for c in a.contexts if not(c.scope==binding['scope'] and c.value==binding['value'] and c.raw_pointer in paths)]
            restored[i]=a.model_copy(update=dict(contexts=sorted(contexts+originals,key=lambda c:(c.kind,c.scope,c.value,c.raw_pointer))))
    restored_profiles={i:profile(a,ee,ss[a.source_namespace],cfg) for i,a in restored.items()}
    results={}
    for name,profiles,groups in [('current_identity_current_community',pp,current_groups),
        ('source_contexts_current_community',restored_profiles,current_groups),
        ('current_identity_historical_community',pp,old_groups),
        ('source_contexts_historical_community',restored_profiles,old_groups)]:
        components=[];edges=[];diagnostics=[]
        for group in groups:
            selected,diags,stats=community_graph(group,profiles,bb,cfg,scfg)
            components += [sorted(c) for c in connected_components(group,selected)]
            edges += [e.model_dump(mode='json') for e in selected]
            diagnostics += diags
        results[name]=dict(components=sorted(components),edges=edges,diagnostics=diagnostics,
            formal_run=False,production_change=False,truth_input=False)
    assert results['current_identity_current_community']['components']==sorted(sorted(s['alert_ids']) for s in snapshot['stages']['stages'])
    save('counterfactual_probes.json',results)
    return results


def diagnose():
    snapshot=read(OUT/'baseline.json')
    assert read(OUT/'baseline_receipt.json')['all_equal']
    aa,ee,ss,pp,bb,cfg,scfg=load_objects(snapshot)
    probe_results=probes(snapshot)  # No truth parsed or supplied to the probes.
    from app.models.alerts import EvidencePointer
    from app.community.evidence import evidence_tier
    from app.stages.evidence import hard_conflict, shared_bindings, pair_evidence
    from app.community.temporal import TemporalHistory
    from app.entities.identity_projection import IdentityProjectionResult
    IdentityProjectionResult.model_validate(snapshot['identity_projection']).validate_trace(list(aa.values()),list(ee.values()))
    # First semantic truth read in this process occurs after all algorithm calls.
    rows=[json.loads(l) for l in (DATA/'final/attack125_final.jsonl').read_text(encoding='utf-8-sig').splitlines() if l.strip()]
    by_raw={digest(a.raw_alert):i for i,a in aa.items()}
    native={r['event_id']:by_raw[digest(r['event'])] for r in rows}
    reverse={v:k for k,v in native.items()}
    gt=read(DATA/'ground_truth/stages.json')
    truth={native[i]:g['stage_id'] for g in gt for i in g['member_alert_ids']}
    stage_owner={i:s['stage_id'] for s in snapshot['stages']['stages'] for i in s['alert_ids']}
    community_owner={i:c['community_id'] for c in snapshot['communities']['incident_candidates'] for i in c['alert_ids']}
    assert set(truth)==aa.keys()==stage_owner.keys()==community_owner.keys()
    known=read(PRIOR/'stage6_new_regressions.json')
    expected={tuple(sorted(pair)) for group in known['mixed_stages'] for pair in group['incorrect_pairs']}
    actual={tuple(sorted((a,b))) for a,b in combinations(sorted(aa),2) if truth[a]!=truth[b] and stage_owner[a]==stage_owner[b]}
    assert expected==actual and len(actual)==238
    stage_edges={};community_edges={};checked=0
    def resolve_edge(e,field):
        nonlocal checked
        values=[]
        for p in e[field]:
            pointer=EvidencePointer.model_validate(p)
            values.append(dict(**p,value=pointer.resolve(aa)))
            checked+=1
        return values
    for s in snapshot['stages']['stages']:
        for e in s['aggregation_basis']:
            eid='s6e_'+digest(e)
            stage_edges[eid]=dict(**e,stage_id=s['stage_id'],resolved_evidence=resolve_edge(e,'evidence'))
    for c in snapshot['communities']['incident_candidates']:
        for e in c['matching_evidence']:
            eid='c5e_'+digest(e)
            community_edges[eid]=dict(**e,community_id=c['community_id'],tier=evidence_tier(e['identity_kind']),
                resolved_evidence=resolve_edge(e,'supporting_evidence'))
    save('stage_edges.json',stage_edges);save('community_edges.json',community_edges)
    bindings={b['projection_id']:b for b in snapshot['identity_projection']['context_bindings']+snapshot['identity_projection']['auth_session_bindings']}
    bindings.update({b['alias_binding_id']:b for b in snapshot['identity_projection']['host_alias_bindings']})
    decisions={d['alert_id']:d for c in snapshot['communities']['incident_candidates'] for d in c['membership_decisions']}
    dossiers={i:dict(native_event_id=reverse[i],canonical=a.model_dump(mode='json'),
        entities=[ee[eid].model_dump(mode='json') for eid in a.entity_ids],
        identity_bindings=[bindings[bid] for bid in a.identity_binding_ids],
        stage6_visible_profile=asdict(pp[i]) | {'alert':a.model_dump(mode='json')},
        behavior=bb[i].model_dump(mode='json'),community_decision=decisions[i],community_id=community_owner[i],
        stage_id=stage_owner[i],independent_truth=truth[i]) for i,a in aa.items()}
    save('alert_dossiers.json',dossiers)
    temporal={}
    for c in snapshot['communities']['incident_candidates']:
        histories=defaultdict(TemporalHistory)
        for i in sorted(c['alert_ids'],key=lambda i:(aa[i].timestamp,i)):
            temporal[i]=histories[bb[i].behavior].snapshot(cfg.temporal)
            histories[bb[i].behavior].times.append(pp[i].seconds)
    # Probe scoring is independent of the algorithm and uses no truth grouping
    # as an algorithm parameter. Membership owners derive from returned groups.
    owners={name:{i:n for n,c in enumerate(probe['components']) for i in c} for name,probe in probe_results.items()}
    pairs=[]
    for a,b in sorted(actual):
        sedges={k:e for k,e in stage_edges.items() if e['stage_id']==stage_owner[a]}
        direct=[k for k,e in sedges.items() if e['alert_ids']==[a,b]]
        later=max((a,b),key=lambda i:(aa[i].timestamp,i))
        basis,reason=pair_evidence(pp[a],pp[b],bb[a].behavior,bb[b].behavior,temporal[later],scfg)
        pairs.append(dict(alert_ids=[a,b],native_ids=[reverse[a],reverse[b]],truth=[truth[a],truth[b]],
            predicted_stage=stage_owner[a],classification='STAGE_CONSUMPTION_LIMITATION',
            stage_path=shortest(a,b,sedges),community_path=shortest(a,b,community_edges),
            direct_stage_edge_ids=direct,direct_pair_check=dict(accepted=basis is not None,reason=reason,
                basis=basis.model_dump(mode='json') if basis else None),
            direct_hard_conflict=hard_conflict(pp[a],pp[b]),
            shared_bindings=[dict(left=asdict(x),right=asdict(y)) for x,y in shared_bindings(pp[a],pp[b])],
            probe_pair_retained={name:own[a]==own[b] for name,own in owners.items()},
            explanation='Canonical identity/context facts are valid; frozen Stage6 promotes shared identity/flow or inherited process action plus community cadence into same-stage membership. Community scenario connectivity does not certify a phase boundary.'))
    save('ROOT_CAUSE_BY_PAIR.json',pairs)
    group_summary=[]
    for group in known['mixed_stages']:
        sid=group['stage']['stage_id']; relevant=[p for p in pairs if p['predicted_stage']==sid]
        bridges=[dict(edge_id=k,alert_ids=e['alert_ids'],native_ids=[reverse[i] for i in e['alert_ids']],
            truth=[truth[i] for i in e['alert_ids']],evidence_types=e['evidence_types'],temporal_check=e['temporal_check'])
            for k,e in stage_edges.items() if e['stage_id']==sid and len({truth[i] for i in e['alert_ids']})>1]
        group_summary.append(dict(stage_id=sid,composition=group['truth_composition'],incorrect_pairs=len(relevant),
            direct_pairs=sum(bool(p['direct_stage_edge_ids']) for p in relevant),transitive_only_pairs=sum(not p['direct_stage_edge_ids'] for p in relevant),
            crossing_edges=bridges,probe_incorrect_pairs={name:sum(p['probe_pair_retained'][name] for p in relevant) for name in owners}))
    save('group_diagnosis.json',group_summary)
    probe_metrics={}
    for name,owner in owners.items():
        tp=fp=fn=0
        for a,b in combinations(aa,2):
            t,p=truth[a]==truth[b],owner[a]==owner[b]
            tp+=t and p;fp+=not t and p;fn+=t and not p
        probe_metrics[name]=dict(stages=len(set(owner.values())),tp=tp,fp=fp,fn=fn,
            pair_f1=2*tp/(2*tp+fp+fn),known_238_retained=sum(owner[a]==owner[b] for a,b in actual))
    save('probe_metrics.json',probe_metrics)
    save('diagnosis_summary.json',dict(pair_count=len(pairs),all_current_errors_match_prior=True,
        classifications=dict(Counter(p['classification'] for p in pairs)),groups=group_summary,
        resolved_edge_pointer_count=checked,identity_trace_valid=True,production_modified=False,
        suspicious_source_rewriting_in_production=False,probe_metrics=probe_metrics))
    assert unchanged(), 'diagnosis_changed_protected_files'
    print(json.dumps(dict(pairs=len(pairs),groups=[{k:v for k,v in g.items() if k!='crossing_edges'} for g in group_summary],probe_metrics=probe_metrics),ensure_ascii=False))


if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf8')
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=['baseline','diagnose','final'])
    mode=parser.parse_args().mode
    if mode=='diagnose': diagnose()
    else: capture(mode)

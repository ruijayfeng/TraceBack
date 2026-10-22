"""Task acceptance: formal production first, independent truth evaluation second."""
import argparse
from collections import Counter
from itertools import combinations
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'outputs/identity_relation_handoff_20261021'
DATA = Path('D:/Code_WorkSpace/TraceBack-Dataset/data/attack125')
sys.path.insert(0, str(ROOT / 'backend'))
sys.dont_write_bytecode = True
ACTIVE = False
READS = set()
CALLS = Counter()


def save(name, value):
    OUT.mkdir(exist_ok=True)
    (OUT/name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n', encoding='utf8')


def hashes():
    paths = [p for folder in ('backend/app', 'backend/tests', 'configs', 'scripts', 'evaluation')
             for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    paths += [p for p in DATA.rglob('*') if p.is_file()]
    return {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def guard(event, args):
    if not ACTIVE:
        return
    if event == 'socket.connect':
        raise AssertionError('production_network_forbidden')
    if event == 'open' and not isinstance(args[0], int):
        path = Path(os.fsdecode(args[0])).resolve()
        if {'ground_truth', 'evaluation', 'outputs'} & {p.lower() for p in path.parts}:
            raise AssertionError('production_truth_or_snapshot_read:'+str(path))
        if args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError('production_write_forbidden:'+str(path))
        READS.add(str(path))


def profiler(frame, event, arg):
    if event == 'call' and frame.f_globals.get('__name__', '').startswith('app.'):
        if frame.f_code.co_name in {'load_stage_pipeline', 'load_alert_pipeline', 'extract_entities',
                'filter_alerts', 'normalize_behaviors', 'build_communities', 'aggregate_stages',
                'generate_stage_pair_candidates', 'validate_stage_pair_candidates', 'reconstruct_attack_chains'}:
            CALLS[frame.f_globals['__name__']+'.'+frame.f_code.co_name] += 1


def capture(label):
    global ACTIVE
    from app.services.stage_pipeline import load_stage_pipeline
    from app.stage_chains.reconstruction import FrozenStageGraph, reconstruct_attack_chains, validate_reconstruction
    if (OUT/(label+'.json')).exists():
        raise ValueError('capture_exists_do_not_overwrite')
    before = hashes()
    if label == 'before':
        for path in before:
            p = Path(path)
            if p.is_relative_to(ROOT):
                dest = OUT/'source_before'/p.relative_to(ROOT)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(p.read_bytes())
    ACTIVE = True
    sys.setprofile(profiler)
    try:
        run = load_stage_pipeline(DATA/'final/attack125_final.jsonl')
        graph = FrozenStageGraph.from_stage8(run.stages.stages, run.evidence_result, run.community.alerts)
        chains = reconstruct_attack_chains(graph)
        validation = validate_reconstruction(chains, graph)
        deterministic = None
        if label == 'final':
            from app.config import load_config, read_yaml
            from app.adapters.base import AdapterSettings
            from app.adapters.multisource import MultiSourceAdapter
            from app.services.alert_pipeline import ingest_records
            from app.services.stage_pipeline import prepare_stage_pipeline
            config=load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',deployment_override=ROOT/'configs/front-data-sources.yaml')
            routing=read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources']
            adapters={s:MultiSourceAdapter(config,AdapterSettings(**v),s) for s,v in routing.items()}
            rows=[json.loads(l) for l in (DATA/'final/attack125_final.jsonl').read_text(encoding='utf-8-sig').splitlines() if l.strip()]
            repeated=prepare_stage_pipeline(ingest_records(reversed(rows),adapters))
            deterministic=dict(alerts=run.normalized.alerts==repeated.normalized.alerts,
                entities=run.normalized.entities==repeated.normalized.entities,
                projection=run.normalized.identity_projection==repeated.normalized.identity_projection,
                communities=run.community.result==repeated.community.result,
                stages=run.stages==repeated.stages,candidates=run.candidate_result==repeated.candidate_result,
                evidence=run.evidence_result==repeated.evidence_result)
            assert all(deterministic.values()),deterministic
    finally:
        ACTIVE = False
        sys.setprofile(None)
    payload = dict(alerts=[a.model_dump(mode='json') for a in run.community.alerts],
        entities=[e.model_dump(mode='json') for e in run.community.entities],
        communities=run.community.result.model_dump(mode='json'), stages=run.stages.model_dump(mode='json'),
        candidates=run.candidate_result.model_dump(mode='json'), evidence=run.evidence_result.model_dump(mode='json'),
        chains=chains.model_dump(mode='json'), chain_validation=validation,
        identity_projection=run.normalized.identity_projection.model_dump(mode='json'), statistics=run.statistics)
    save(label+'.json', payload)
    save(label+'_hashes.json', before)
    save(label+'_execution.json', dict(reads=sorted(READS), calls=dict(CALLS), validation=validation, reverse_input_determinism=deterministic))
    if label == 'before':
        historical = json.loads((ROOT/'outputs/gt_s02_boundary_audit_20261021/after_runtime.json').read_text(encoding='utf8'))
        equal = {k: v == historical[k] for k, v in payload.items() if k in historical}
        save('stage6_freeze_receipt.json', dict(equal_to_accepted_runtime=equal, all_equal=all(equal.values()),
            frozen_files={p:h for p,h in before.items() if '/app/stages/' in p.replace('\\','/') or
                p.endswith('behavior-stage-v1.yaml') or '/test_stage6_' in p.replace('\\','/')}))
        assert all(equal.values()), equal
    evaluate(label, payload)
    assert hashes() == before


def evaluate(label, payload):
    # This function runs only after all production functions have returned.
    raw = [json.loads(l) for l in (DATA/'final/attack125_final.jsonl').read_text(encoding='utf-8-sig').splitlines() if l.strip()]
    encode = lambda x: json.dumps(x, sort_keys=True)
    aa = {encode(a['raw_alert']):a['alert_id'] for a in payload['alerts']}
    native = {r['event_id']:aa[encode(r['event'])] for r in raw}
    truth = json.loads((DATA/'ground_truth/stages.json').read_text(encoding='utf8'))
    owner = {native[i]:g['stage_id'] for g in truth for i in g['member_alert_ids']}
    pred = {i:s['stage_id'] for s in payload['stages']['stages'] for i in s['alert_ids']}
    community = {i:c['community_id'] for c in payload['communities']['incident_candidates'] for i in c['alert_ids']}
    tp=fp=fn=0
    for a,b in combinations(owner, 2):
        t,p = owner[a]==owner[b], pred[a]==pred[b]
        tp += t and p
        fp += not t and p
        fn += t and not p
    precision, recall = tp/(tp+fp), tp/(tp+fn)
    edges = json.loads((DATA/'ground_truth/edges.json').read_text(encoding='utf8'))
    decisions = {frozenset((d['stage_a_id'],d['stage_b_id'])):d for d in payload['evidence']['decisions']}
    traces = []
    for e in edges:
        witnesses=[]
        for w in e['binding_evidence']:
            a,b=native[w['source_alert_id']],native[w['target_alert_id']]
            witnesses.append(dict(binding=w, source_stage=pred[a],target_stage=pred[b],
                same_community=community[a]==community[b],decision=decisions.get(frozenset((pred[a],pred[b])))))
        traces.append(dict(edge=e,witnesses=witnesses))
    metrics = dict(alerts=len(pred),communities=len(set(community.values())),
        community_sizes=sorted(Counter(community.values()).values()),stages=len(set(pred.values())),
        stage_sizes=sorted(Counter(pred.values()).values()),tp=tp,fp=fp,fn=fn,
        pair_precision=precision,pair_recall=recall,pair_f1=2*precision*recall/(precision+recall),
        fragmentation={g['stage_id']:len({pred[native[i]] for i in g['member_alert_ids']}) for g in truth},
        community_fragmentation={g['stage_id']:dict(Counter(community[native[i]] for i in g['member_alert_ids'])) for g in truth},
        relations=dict(Counter(d['relation_type'] for d in decisions.values())),candidates=len(decisions),
        chains=len(payload['chains']['chains']),chain_validation=payload['chain_validation'])
    save(label+'_metrics.json',metrics)
    save(label+'_gt_traces.json',traces)
    if label == 'final':
        mixed=[]
        for stage in payload['stages']['stages']:
            composition=Counter(owner[i] for i in stage['alert_ids'])
            if len(composition)>1:
                mixed.append(dict(stage=stage,truth_composition=dict(composition),
                    incorrect_pairs=[[a,b] for a,b in combinations(stage['alert_ids'],2) if owner[a]!=owner[b]]))
        save('stage6_new_regressions.json',dict(incorrect_pair_count=fp,mixed_stages=mixed,
            frozen=True,modified=False,locations=['backend/app/stages/evidence.py:pair_evidence',
                'backend/app/stages/evidence.py:same_process_action','backend/app/stages/aggregation.py:community_graph']))
        prior=json.loads((OUT/'stage25_final.json').read_text(encoding='utf8'))
        save('stage8_upstream_freeze.json',{k:prior[k]==payload[k] for k in ('alerts','entities','communities','stages','candidates','identity_projection')})
    print(json.dumps(metrics,ensure_ascii=False))


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf8')
    parser=argparse.ArgumentParser()
    parser.add_argument('label')
    args=parser.parse_args()
    OUT.mkdir(exist_ok=True)
    sys.addaudithook(guard)
    capture(args.label)

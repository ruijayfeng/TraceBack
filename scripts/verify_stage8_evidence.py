"""Offline ⑧ acceptance: official production first; GT and snapshots only afterward.

Use --capture-baseline BEFORE editing upstream code, or supply the baseline
captured for this implementation via --baseline. No baseline supplies facts to
production. All outputs are local review artifacts, not a Stage relation graph.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
sys.dont_write_bytecode = True  # Keep Python's import cache out of the read-only production audit.
DATA = Path('D:/Code_WorkSpace/TraceBack-Dataset/data/attack125')
ACTIVE = False
READS,CALLS,ORDER = set(),Counter(),[]
FILES_CHANGED = ['backend/app/stage_evidence/__init__.py','backend/app/stage_evidence/config.py',
    'backend/app/stage_evidence/models.py','backend/app/stage_evidence/extraction.py',
    'backend/app/stage_evidence/validation.py','backend/app/services/stage_pipeline.py',
    'configs/stage-evidence-v1.yaml','backend/tests/test_stage_evidence.py',
    'backend/tests/test_stage56_repair.py','backend/tests/test_stage_relations.py',
    'scripts/run_stage_pipeline.py','scripts/verify_stage8_evidence.py','docs/STAGE_8_EVIDENCE_VERIFICATION.md']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(folder,name,value):
    (folder/name).write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n',encoding='utf8')


def upstream(run):
    return dict(stages=run.stages.model_dump(mode='json'),communities=run.community.result.model_dump(mode='json'),
        alerts=[a.model_dump(mode='json') for a in run.community.alerts],entities=[e.model_dump(mode='json') for e in run.community.entities],
        candidates=run.candidate_result.model_dump(mode='json'))


def capture(args):
    from app.services.stage_pipeline import load_stage_pipeline
    args.baseline.mkdir(parents=True,exist_ok=True)
    if any((args.baseline/name).exists() for name in ('upstream_before.json','protected_before.json')):
        raise ValueError('baseline_already_exists_do_not_overwrite')
    run = load_stage_pipeline(args.input)
    save(args.baseline,'upstream_before.json',upstream(run))
    files = [p for folder in (ROOT/'backend/app',ROOT/'configs',args.dataset_root) for p in folder.rglob('*')
        if p.is_file() and '__pycache__' not in p.parts]
    save(args.baseline,'protected_before.json',{str(p.resolve()):sha(p) for p in files})


def audit(event,args):
    if not ACTIVE:
        return
    if event == 'socket.connect':
        raise AssertionError('production_network_forbidden')
    if event == 'open' and not isinstance(args[0],int):
        path = Path(os.fsdecode(args[0])).resolve()
        if args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError('production_write_forbidden:'+str(path))
        if {'ground_truth','evaluation','outputs','protected','validated'} & {p.casefold() for p in path.parts}:
            raise AssertionError('production_truth_or_snapshot_read_forbidden:'+str(path))
        if path.suffix not in {'.py','.pyc','.pyd','.dll'}:
            READS.add(str(path))


def profiler(frame,event,arg):
    if event != 'call':
        return
    module,name = frame.f_globals.get('__name__',''),frame.f_code.co_name
    if module.startswith(('app.correlation','app.stage_relations','app.stage_chains','app.chains',
                           'app.api','app.ai','app.services.analysis','evaluation')):
        raise AssertionError('legacy_scorer_or_downstream_execution_forbidden:'+module+'.'+name)
    if module.startswith('app.') and name in {'load_stage_pipeline','load_alert_pipeline','convert_record','extract_entities',
            'filter_alerts','normalize_behaviors','build_communities','aggregate_stages',
            'generate_stage_pair_candidates','validate_stage_pair_candidates'}:
        key = module+'.'+name
        CALLS[key] += 1
        if key not in ORDER:
            ORDER.append(key)


def tests(paths):
    counts = Counter()
    for path in paths:
        doc = ET.parse(path).getroot()
        for suite in (list(doc) if doc.tag == 'testsuites' else [doc]):
            for k in ('tests','failures','errors','skipped'):
                counts[k] += int(suite.attrib.get(k,0))
    return dict(passed=counts['tests']-counts['failures']-counts['errors']-counts['skipped'],
        failed=counts['failures'],errors=counts['errors'],skipped=counts['skipped'])


def verify(args):
    global ACTIVE
    from app.services.stage_pipeline import load_stage_pipeline
    from app.stage_evidence import validate_stage_pair_candidates, load_evidence_config
    from app.community import load_community_config
    from app.utils.stable_id import content_digest
    baseline = json.loads((args.baseline/'protected_before.json').read_text(encoding='utf8'))
    before = json.loads((args.baseline/'upstream_before.json').read_text(encoding='utf8'))
    sys.addaudithook(audit)
    ACTIVE = True
    sys.setprofile(profiler)
    try:
        run = load_stage_pipeline(args.input)
    finally:
        sys.setprofile(None)
        ACTIVE = False
    expected = ['load_stage_pipeline','load_alert_pipeline','convert_record','extract_entities','filter_alerts',
        'normalize_behaviors','build_communities','aggregate_stages','generate_stage_pair_candidates','validate_stage_pair_candidates']
    assert [k.rsplit('.',1)[-1] for k in ORDER] == expected, ORDER
    for name in expected[1:]:
        if name != 'convert_record':
            assert sum(n for k,n in CALLS.items() if k.endswith('.'+name)) == 1, (name,CALLS)
    now = upstream(run)
    unchanged = now == before
    stage7_identical = now['candidates'] == before['candidates']
    result = run.evidence_result
    aa = {a.alert_id:a for a in run.community.alerts}
    ss = {s.stage_id:s for s in run.stages.stages}
    ee = {e.evidence_id:e for e in result.evidence}
    decisions = {(d.stage_a_id,d.stage_b_id):d for d in result.decisions}
    candidates = {(c.stage_a_id,c.stage_b_id):c for c in run.candidates}
    assert decisions.keys() == candidates.keys()
    assert sum(result.statistics[k] for k in ('DIRECTED_EDGE_COUNT','UNDIRECTED_EDGE_COUNT','NO_RELATION_COUNT')) == len(candidates)
    # Independently inspect closure rather than trusting advertised statistics.
    pointers_checked,relations_without,dangling = 0,0,0
    for d in result.decisions:
        ids = ([d.primary_evidence_id] if d.primary_evidence_id else [])+d.supporting_evidence_ids+d.invalid_evidence_ids
        dangling += len(set(ids)-ee.keys())
        if d.relation_type != 'NO_RELATION' and not any(ee[i].valid and ee[i].evidence_strength_class != 'SUPPORTING_ONLY' for i in ids):
            relations_without += 1
        for i in ids:
            e = ee[i]
            assert e.alert_a_id in ss[d.stage_a_id].alert_ids and e.alert_b_id in ss[d.stage_b_id].alert_ids
            for p in e.raw_pointers:
                assert p.alert_id in {e.alert_a_id,e.alert_b_id}
                p.resolve(aa)
                pointers_checked += 1
    assert not relations_without and not dangling
    cp = load_community_config(ROOT/'configs/community-v1.yaml')
    policy = load_evidence_config(ROOT/'configs/stage-evidence-v1.yaml')
    # Reordering member lists is legitimate; all semantic results and IDs must
    # be identical. Existing upstream objects are never repaired or rewritten.
    reordered = run.stages.model_copy(update=dict(stages=list(reversed(run.stages.stages)),behaviors=list(reversed(run.stages.behaviors))))
    ACTIVE = True
    try:
        repeat = validate_stage_pair_candidates(run.candidate_result,reordered,list(reversed(run.community.alerts)),
            list(reversed(run.community.entities)),run.normalized.source_settings,cp,policy)
    finally:
        ACTIVE = False
    deterministic = repeat == result
    assert upstream(run) == now

    def describe(pair):
        a,b = pair
        d = decisions.get(pair)
        c = candidates.get(pair)
        primary = ee.get(d.primary_evidence_id) if d else None
        witness_ids = ([primary.evidence_id] if primary else [])+(d.supporting_evidence_ids if d else [])+(d.invalid_evidence_ids if d else [])
        return dict(stage_a_id=a,stage_b_id=b,community_a_id=ss[a].community_id,community_b_id=ss[b].community_id,
            candidate_recalled=c is not None,candidate_reasons=c.candidate_reasons if c else [],
            relation_result=d.relation_type if d else 'NO_RELATION',relation_type=d.relation_type if d else 'NO_RELATION',
            primary_evidence_type=primary.evidence_type if primary else None,
            witness_alerts=[primary.alert_a_id,primary.alert_b_id] if primary else [],
            direction_basis=primary.metadata['direction_basis'] if d and d.relation_type == 'DIRECTED_EDGE' else 'unresolved',
            direction_claim=d.direction_claim if d else 'NONE',temporal_check=primary.temporal_check if primary else None,
            conflict_status=d.diagnostics if d else ['NOT_RECALLED_BY_STAGE7'],reason=d.reason if d else 'No candidate; ⑧ did not compare this pair.',
            diagnostics=d.diagnostics if d else ['NOT_RECALLED_BY_STAGE7'],
            primary_witness=primary.model_dump(mode='json') if primary else None,
            raw_fields=[dict(alert_id=p.alert_id,pointer=p.pointer,value=p.resolve(aa)) for p in primary.raw_pointers] if primary else [],
            all_evidence_ids=witness_ids)

    # Only now read GT. Mapping uses current native raw digests and the live
    # Stage partition; neither GT Stage labels nor old snapshots enter ⑧.
    by_raw = {content_digest(a.raw_alert):a.alert_id for a in aa.values()}
    native = {row['event_id']:by_raw[content_digest(row['event'])] for row in
        (json.loads(line) for line in args.input.read_text(encoding='utf-8-sig').splitlines() if line.strip())}
    owner = {aid:s.stage_id for s in ss.values() for aid in s.alert_ids}

    def witness_gaps(source_id,target_id):
        """Explain missing formal proof from current facts; never tune production.

        Different namespaces mean an unproven bridge, not a blanket veto on
        cross-host/cross-source attacks. Other valid witnesses remain usable.
        """
        from app.community.evidence import profile
        source,target = aa[source_id],aa[target_id]
        scopes = [dict(kind=l.kind,value=l.value,source_scope=l.scope,target_scope=r.scope,
            source_pointer=l.raw_pointer,target_pointer=r.raw_pointer) for l in source.contexts for r in target.contexts
            if l.kind == r.kind and l.value == r.value and l.scope != r.scope]
        hosts = [{o.entity_id for o in x.entity_occurrences if o.role.value == 'host'} for x in (source,target)]
        profiles = [profile(x,{e.entity_id:e for e in run.community.entities},run.normalized.source_settings[x.source_namespace],cp) for x in (source,target)]
        objects = [[dict(identity=json.loads(b.identity),role=b.role,pointers=list(b.pointers)) for b in p.bindings if b.kind == 'object'] for p in profiles]
        problems = []
        if scopes:
            problems.append('相同原始 context token 落在不同正式 scope；当前没有已声明的可信跨 scope identity 绑定。')
        if source.host and source.host == target.host and all(hosts) and not hosts[0] & hosts[1]:
            problems.append('观测 hostname 相同，但正式 HOST identity 不同（例如 hostname 与 asset_id）；尚无正式 alias 绑定，不能据此证明同一 scoped object。')
        parent_combinations = [(source.process,target.parent_process),(target.process,source.parent_process)]
        if any(p and q and p.pid is not None and p.pid == q.pid and
                not (p.guid or p.instance_id or (p.pid is not None and p.start_time)) for p,q in parent_combinations):
            problems.append('当前进程 PID 与另一端 parent PID 有重合，但至少一端缺少 start_time/GUID；PID 本身不能证明完整进程谱系。')
        source_network = run.normalized.source_settings[source.source_namespace].network_namespace or source.source_namespace
        target_network = run.normalized.source_settings[target.source_namespace].network_namespace or target.source_namespace
        endpoints = lambda x: (x.src_ip,x.src_port,x.dst_ip,x.dst_port)
        if endpoints(source) == endpoints(target) and any(v is not None for v in endpoints(source)) and source_network != target_network:
            problems.append('网络端点/端口有连续性，但正式 network scope 不同；端点或 connection token 同值仅用于候选召回，不能替代可信 flow identity。')
        if (any(c.kind == 'flow' for c in source.contexts) != any(c.kind == 'flow' for c in target.contexts)):
            problems.append('原生 flow ID 未在两端同时出现；不能将单端 native flow 证据投射到另一端。')
        return dict(source_alert_id=source_id,target_alert_id=target_id,explanations=problems,
            equal_tokens_with_different_scopes=scopes,host_entity_ids=[sorted(h) for h in hosts],
            scoped_object_bindings=objects,network_scopes=[source_network,target_network],
            canonical_facts=[dict(alert_id=x.alert_id,source_namespace=x.source_namespace,host=x.host,
                process=x.process.model_dump(mode='json') if x.process else None,
                parent_process=x.parent_process.model_dump(mode='json') if x.parent_process else None,
                contexts=[c.model_dump(mode='json') for c in x.contexts]) for x in (source,target)])

    gt = json.loads((args.dataset_root/'ground_truth/edges.json').read_text(encoding='utf8'))
    details = []
    for edge in gt:
        pairs = {tuple(sorted((owner[native[w['source_alert_id']]],owner[native[w['target_alert_id']]]))) for w in edge['binding_evidence']}
        distinct = sorted(p for p in pairs if p[0] != p[1])
        results = [describe(pair) for pair in distinct]
        order = {'DIRECTED_EDGE':0,'UNDIRECTED_EDGE':1,'NO_RELATION':2}
        best = min(results,key=lambda r:order[r['relation_result']]) if results else None
        direction_matches = None
        if best and best['relation_result'] == 'DIRECTED_EDGE':
            d = decisions[(best['stage_a_id'],best['stage_b_id'])]
            direction_matches = any((owner[native[w['source_alert_id']]],owner[native[w['target_alert_id']]]) == (d.from_stage_id,d.to_stage_id) for w in edge['binding_evidence'])
        witness_pairs = sorted({(native[w['source_alert_id']],native[w['target_alert_id']]) for w in edge['binding_evidence']})
        gaps = [witness_gaps(src,dst) for src,dst in witness_pairs]
        explanations = sorted({message for gap in gaps for message in gap['explanations']}) if not best or best['relation_result'] == 'NO_RELATION' else []
        details.append(dict(edge_id=edge['edge_id'],candidate_recalled=any(r['candidate_recalled'] for r in results),
            relation_result=best['relation_result'] if best else 'NO_RELATION',relation_type=best['relation_type'] if best else 'NO_RELATION',
            primary_evidence_type=best['primary_evidence_type'] if best else None,witness_alerts=best['witness_alerts'] if best else [],
            direction_basis=best['direction_basis'] if best else 'unresolved',temporal_check=best['temporal_check'] if best else None,
            diagnostics=best['diagnostics'] if best else ['GT_BINDING_COLLAPSED_IN_ONE_STAGE'],
            gt_direction_matches=direction_matches,stage_pairs=results,
            evidence_gap_explanations=explanations,gt_binding_evidence=edge['binding_evidence'],witness_fact_checks=gaps))
    gt_counts = Counter(d['relation_result'] for d in details)
    sample_groups = {kind:[describe(pair) for pair,d in sorted(decisions.items()) if d.relation_type == kind][:5]
        for kind in ('DIRECTED_EDGE','UNDIRECTED_EDGE','NO_RELATION')}
    changed = sorted(p for p,h in baseline.items() if not Path(p).exists() or sha(Path(p)) != h)
    allowed = {str((ROOT/'backend/app/services/stage_pipeline.py').resolve())}
    unexpected = [p for p in changed if p not in allowed]
    before_inventory = {p for p in baseline if Path(p).is_relative_to(args.dataset_root.resolve())}
    now_inventory = {str(p.resolve()) for p in args.dataset_root.rglob('*') if p.is_file()}
    dataset_identical = before_inventory == now_inventory and not (set(changed) & before_inventory)
    release = json.loads((args.dataset_root/'manifests/release_manifest.json').read_text(encoding='utf8'))
    mismatches = [p for p,h in release['file_sha256'].items() if sha(args.dataset_root/p) != h]
    test_counts = tests(args.tests)
    blocking = []
    if not unchanged or not stage7_identical or unexpected:
        blocking.append('UPSTREAM_CHANGED')
    if not dataset_identical or mismatches:
        blocking.append('DATASET_OR_GT_CHANGED')
    if not deterministic:
        blocking.append('NONDETERMINISTIC_EVIDENCE')
    if test_counts['failed'] or test_counts['errors'] or not test_counts['passed']:
        blocking.append('TESTS_MISSING_OR_FAILED')
    nonblocking = [d['edge_id']+': '+' '.join(d['evidence_gap_explanations'] or ['No valid strong witness; see per-pair diagnostics.'])
        for d in details if d['relation_result'] == 'NO_RELATION']
    summary = dict(TASK_RESULT='SUCCESS' if not blocking else 'PARTIAL',
        STAGE_8_CROSS_STAGE_EVIDENCE_VERIFICATION='PASS' if not blocking else 'PARTIAL',
        OFFICIAL_PIPELINE_TO_STAGE8_COMPLETE=True,**result.statistics,
        GT_STAGE_RELATION_COUNT=len(details),GT_RELATIONS_WITH_RELATION=len(details)-gt_counts['NO_RELATION'],
        GT_RELATIONS_DIRECTED=gt_counts['DIRECTED_EDGE'],GT_RELATIONS_UNDIRECTED=gt_counts['UNDIRECTED_EDGE'],
        GT_RELATIONS_NO_RELATION=gt_counts['NO_RELATION'],GT_CANDIDATE_RECALL=sum(d['candidate_recalled'] for d in details)/len(details),
        **{d['edge_id'].replace('-','_')+'_RESULT':d['relation_result'] for d in details},
        STAGE_7_OUTPUT_IDENTICAL=stage7_identical,UPSTREAM_STAGE_1_TO_7_LOGIC_MODIFIED=bool(unexpected),
        UPSTREAM_STAGE_1_TO_7_OUTPUT_IDENTICAL=unchanged,DATASET_MODIFIED=not dataset_identical,
        GROUND_TRUTH_MODIFIED=any('ground_truth' in Path(p).parts for p in changed),
        TEST_RESULT=test_counts,FILES_CHANGED=FILES_CHANGED,BLOCKING_ISSUES=blocking,NON_BLOCKING_ISSUES=nonblocking,
        DETERMINISTIC_RESULT=deterministic,RAW_EVIDENCE_POINTERS_CHECKED=pointers_checked,
        RUNTIME_READS=sorted(READS),OFFICIAL_CALL_COUNTS=dict(CALLS),OFFICIAL_PIPELINE=ORDER)
    args.output.mkdir(parents=True,exist_ok=True)
    save(args.output,'evidence_result.json',result.model_dump(mode='json'))
    save(args.output,'gt_relations.json',details)
    save(args.output,'samples.json',sample_groups)
    save(args.output,'integrity.json',dict(unexpected_changed_files=unexpected,allowed_changed_files=sorted(set(changed)&allowed),
        stage7_output_identical=stage7_identical,upstream_output_identical=unchanged,dataset_inventory_identical=dataset_identical,
        release_manifest_mismatches=mismatches,protected_file_count=len(baseline),relations_without_evidence=relations_without,
        dangling_evidence_reference_count=dangling,pointers_checked=pointers_checked))
    save(args.output,'summary.json',summary)
    lines = ['# ⑧ 跨 Stage 证据验证验收','','```text']
    lines += [k+'='+json.dumps(v,ensure_ascii=False) for k,v in summary.items() if k not in {'RUNTIME_READS','OFFICIAL_CALL_COUNTS'}]
    lines += ['```','','## GT 离线结果','','GT 仅在生产返回后读取；有向关系是否吻合 GT 方向单独报告。','',
        '| GT | 候选召回 | 关系结果 | 主证据 | 方向匹配 |','|---|---|---|---|---|']
    lines += ['| '+d['edge_id']+' | '+str(d['candidate_recalled'])+' | '+d['relation_result']+' | '+str(d['primary_evidence_type'])+' | '+str(d['gt_direction_matches'])+' |' for d in details]
    for d in details:
        if d['evidence_gap_explanations']:
            lines += ['',d['edge_id']+'：'+' '.join(d['evidence_gap_explanations'])]
    lines += ['','## 真实样本','','每类按 Stage ID 确定性选取 5 对；完整 Witness、原始字段及全部证据 ID 见 samples.json。','']
    for kind,rows in sample_groups.items():
        lines += ['### '+kind,'']
        for row in rows:
            lines += ['```json',json.dumps(row,ensure_ascii=False,indent=2),'```','']
    (args.output/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in summary.items() if k not in {'RUNTIME_READS','OFFICIAL_CALL_COUNTS'}},ensure_ascii=False,indent=2))


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,default=DATA/'final/attack125_final.jsonl')
    parser.add_argument('--dataset-root',type=Path,default=DATA)
    parser.add_argument('--baseline',type=Path,default=ROOT/'outputs/stage8_evidence_verification/baseline')
    parser.add_argument('--output',type=Path,default=ROOT/'outputs/stage8_evidence_verification')
    parser.add_argument('--tests',type=Path,nargs='*',default=[])
    parser.add_argument('--capture-baseline',action='store_true')
    args = parser.parse_args()
    capture(args) if args.capture_baseline else verify(args)

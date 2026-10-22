"""Offline ⑦ acceptance: run the official entry, THEN read GT for recall only.

No historical snapshot supplies production input. upstream_before.json is used
only to compare the live ①–⑥ output after production has returned.
"""
import argparse
from collections import Counter
import hashlib
from itertools import combinations
import json
import os
from pathlib import Path
import random
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
DATA = Path('D:/Code_WorkSpace/TraceBack-Dataset/data/attack125')
FILES_CHANGED = ['backend/app/stage_candidates/__init__.py', 'backend/app/stage_candidates/models.py',
    'backend/app/stage_candidates/config.py', 'backend/app/stage_candidates/features.py',
    'backend/app/stage_candidates/generator.py', 'backend/app/services/stage_pipeline.py',
    'configs/stage-candidates-v1.yaml', 'backend/tests/test_stage_candidates.py',
    'backend/tests/test_stage56_repair.py', 'backend/tests/test_stage_relations.py', 'scripts/run_stage_pipeline.py',
    'scripts/verify_stage7_candidates.py', 'docs/STAGE_7_CANDIDATE_GENERATION.md']
ACTIVE = False
READS, CALLS, ORDER, TIMES = set(), Counter(), [], []
START = None


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(out, name, value):
    (out/name).write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n',encoding='utf8')


def upstream(run):
    return dict(stages=run.stages.model_dump(mode='json'), communities=run.community.result.model_dump(mode='json'),
        alerts=[a.model_dump(mode='json') for a in run.community.alerts],
        entities=[e.model_dump(mode='json') for e in run.community.entities])


def io_guard(event, args):
    if not ACTIVE:
        return
    if event == 'socket.connect':
        raise AssertionError('production_network_forbidden')
    if event == 'open' and not isinstance(args[0], int):
        path = Path(os.fsdecode(args[0])).resolve()
        if args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError('production_write_forbidden:' + str(path))
        if {'ground_truth', 'evaluation', 'outputs', 'protected', 'validated'} & {p.casefold() for p in path.parts}:
            raise AssertionError('production_truth_or_snapshot_read_forbidden:' + str(path))
        if path.suffix not in {'.py','.pyc','.pyd','.dll'}:
            READS.add(str(path))


def profiler(frame, event, arg):
    global START
    module, name = frame.f_globals.get('__name__', ''), frame.f_code.co_name
    if event != 'call' and not (event == 'return' and module == 'app.stage_candidates.generator' and name == 'generate_stage_pair_candidates'):
        return
    if module.startswith(('app.stage_relations', 'app.stage_chains', 'app.evidence_trace', 'app.chains',
                           'app.correlation', 'app.api', 'app.ai', 'app.services.analysis', 'evaluation')):
        raise AssertionError('downstream_or_legacy_execution_forbidden:' + module + '.' + name)
    if name in {'load_stage_pipeline','load_alert_pipeline','convert_record','extract_entities','filter_alerts',
                'normalize_behaviors','build_communities','aggregate_stages','generate_stage_pair_candidates'} and module.startswith('app.'):
        key = module+'.'+name
        if event == 'call':
            CALLS[key] += 1
            if key not in ORDER:
                ORDER.append(key)
            if module == 'app.stage_candidates.generator' and name == 'generate_stage_pair_candidates':
                START = time.perf_counter()
        elif START is not None:
            TIMES.append(time.perf_counter()-START)


def read_test_counts(paths):
    counts = Counter()
    for path in paths:
        xml = ET.parse(path).getroot()
        for suite in (list(xml) if xml.tag == 'testsuites' else [xml]):
            for key in ('tests','failures','errors','skipped'):
                counts[key] += int(suite.attrib.get(key,0))
    return dict(passed=counts['tests']-counts['failures']-counts['errors']-counts['skipped'],
        failed=counts['failures'], errors=counts['errors'], skipped=counts['skipped'])


def write_report(out, summary, details, samples):
    lines = ['# ⑦ Stage Pair Candidate Generation 验收', '', '```text']
    lines += [key+'='+json.dumps(value,ensure_ascii=False) for key,value in summary.items()]
    lines += ['```','','## 离线 GT 候选召回','',
        '完整可回溯特征和原始字段指针见 gt_candidate_recall.json；此处列出实际端点和召回理由。','']
    for detail in details:
        compact = dict(edge_id=detail['edge_id'],candidate_generated=detail['candidate_generated'],
            collapsed_binding_count=detail['collapsed_binding_count'],stage_pairs=[
                {k:v for k,v in pair.items() if k not in {'stage_a_available_features','stage_b_available_features','missing_retrieval_evidence'}}
                for pair in detail['stage_pairs']])
        lines += ['### '+detail['edge_id'],'', '```json',json.dumps(compact,ensure_ascii=False,indent=2),'```','']
    lines += ['## 候选与未召回对抽样','','随机种子7，各10对。完整字段、作用域、原始指针见 samples.json。','',
        '| 分组 | Stage A | Stage B | 同 Community | 候选理由 |','|---|---|---|---|---|']
    for group,values in samples.items():
        if isinstance(values,list):
            lines += ['| '+group+' | '+v['stage_a']+' | '+v['stage_b']+' | '+str(v['same_community'])+' | '+', '.join(v['candidate_reasons'])+' |' for v in values]
    (out/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf8')


def verify(args):
    global ACTIVE
    from app.services.stage_pipeline import load_stage_pipeline
    from app.stage_candidates import generate_stage_pair_candidates, load_candidate_config
    from app.community import load_community_config
    from app.utils.stable_id import content_digest
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    baseline = json.loads((out/'protected_before.json').read_text(encoding='utf8'))
    sys.addaudithook(io_guard)
    ACTIVE = True
    sys.setprofile(profiler)
    try:
        run = load_stage_pipeline(args.input)
    finally:
        sys.setprofile(None)
        ACTIVE = False
    result = run.candidate_result
    official_calls, official_order, runtime_reads = dict(CALLS), list(ORDER), sorted(READS)
    elapsed = TIMES[0]
    expected = ['load_stage_pipeline','load_alert_pipeline','convert_record','extract_entities','filter_alerts',
                'normalize_behaviors','build_communities','aggregate_stages','generate_stage_pair_candidates']
    assert [name.rsplit('.',1)[-1] for name in official_order] == expected, official_order
    assert official_calls['app.stages.aggregation.aggregate_stages'] == 1
    assert official_calls['app.stage_candidates.generator.generate_stage_pair_candidates'] == 1
    current_upstream = upstream(run)
    unchanged = current_upstream == json.loads((out/'upstream_before.json').read_text(encoding='utf8'))
    cp = load_community_config(ROOT/'configs/community-v1.yaml')
    policy = load_candidate_config(ROOT/'configs/stage-candidates-v1.yaml')
    original = content_digest(current_upstream)
    deterministic, repeat_times = True, []
    rng = random.Random(7)
    for _ in range(3):
        stages, annotations = list(run.stages.stages), list(run.stages.behaviors)
        alerts, entities = list(run.community.alerts), list(run.community.entities)
        for values in (stages,annotations,alerts,entities):
            rng.shuffle(values)
        ACTIVE = True
        started = time.perf_counter()
        try:
            repeat = generate_stage_pair_candidates(run.stages.model_copy(update=dict(stages=stages,behaviors=annotations)),
                alerts,entities,run.normalized.source_settings,cp,policy)
        finally:
            ACTIVE = False
        repeat_times.append(time.perf_counter()-started)
        deterministic &= repeat == result
    unchanged &= original == content_digest(upstream(run))
    ss = {s.stage_id:s for s in run.stages.stages}
    candidates = {(c.stage_a_id,c.stage_b_id):c for c in result.candidates}
    features = {sid:{} for sid in ss}
    for feature in result.features:
        features[feature.stage_id][feature.key] = feature

    def describe(pair):
        a,b = pair
        candidate = candidates.get(pair)
        shared = sorted(features[a].keys() & features[b].keys())
        return dict(stage_a=a,stage_b=b,community_a_id=ss[a].community_id,community_b_id=ss[b].community_id,
            same_community=ss[a].community_id == ss[b].community_id,candidate_generated=candidate is not None,
            candidate_reasons=candidate.candidate_reasons if candidate else [],
            shared_retrieval_keys=candidate.retrieval_keys if candidate else [],
            shared_available_feature_keys=shared,
            stage_a_available_features=[f.model_dump(mode='json') for f in features[a].values()],
            stage_b_available_features=[f.model_dump(mode='json') for f in features[b].values()],
            missing_retrieval_evidence=[] if candidate else [dict(key=key,mode=features[a][key].mode,
                diagnostics=[d for d in result.diagnostics if d['key'] == key]) for key in shared],
            reason='RETRIEVED_FROM_SCOPED_FACTS' if candidate else
                'NO_SHARED_SCOPED_FEATURE' if not shared else 'SHARED_KEYS_RESTRICTED_BY_SELECTIVITY_LOCALITY_OR_ENDPOINT_ROLES')

    # Production is finished. Independent GT is now opened ONLY on this side.
    native_records = [json.loads(line) for line in args.input.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
    by_raw = {content_digest(a.raw_alert):a.alert_id for a in run.community.alerts}
    native = {row['event_id']:by_raw[content_digest(row['event'])] for row in native_records}
    assert len(native) == len(by_raw) == len(run.community.alerts)
    owner = {aid:s.stage_id for s in ss.values() for aid in s.alert_ids}
    edges = json.loads((args.dataset_root/'ground_truth/edges.json').read_text(encoding='utf8'))
    details = []
    for edge in edges:
        witness_pairs = {tuple(sorted((owner[native[e['source_alert_id']]],owner[native[e['target_alert_id']]]))) for e in edge['binding_evidence']}
        distinct = {p for p in witness_pairs if p[0] != p[1]}
        details.append(dict(edge_id=edge['edge_id'],candidate_generated=bool(distinct & candidates.keys()),
            collapsed_binding_count=len(witness_pairs)-len(distinct),stage_pairs=[describe(p) for p in sorted(distinct)]))
    recalled = sum(d['candidate_generated'] for d in details)
    # Full combinations exist ONLY in offline sampling, never in production.
    absent = [pair for pair in combinations(sorted(ss),2) if pair not in candidates]
    samples = dict(random_seed=7,
        generated=[describe(p) for p in random.Random(7).sample(sorted(candidates),min(10,len(candidates)))],
        not_generated=[describe(p) for p in random.Random(7).sample(absent,min(10,len(absent)))])
    current_hashes = {p:sha(Path(p)) for p in baseline}
    changed = sorted(p for p in baseline if baseline[p] != current_hashes[p])
    allowed = {str((ROOT/'backend/app/services/stage_pipeline.py').resolve())}
    protected_changes = [p for p in changed if p not in allowed]
    dataset_before = {p for p in baseline if Path(p).is_relative_to(args.dataset_root.resolve())}
    dataset_now = {str(p.resolve()) for p in args.dataset_root.rglob('*') if p.is_file()}
    dataset_unchanged = dataset_now == dataset_before and not any(p in dataset_before for p in changed)
    release = json.loads((args.dataset_root/'manifests/release_manifest.json').read_text(encoding='utf8'))
    manifest_mismatches = [p for p,h in release['file_sha256'].items() if sha(args.dataset_root/p) != h]
    tests = read_test_counts(args.tests) if args.tests else dict(passed=0,failed=0,errors=0,skipped=0)
    blocking = []
    if protected_changes or not dataset_unchanged or manifest_mismatches or not unchanged:
        blocking.append('PROTECTED_INPUT_OR_UPSTREAM_CHANGED')
    if not deterministic:
        blocking.append('NONDETERMINISTIC_CANDIDATES')
    if tests['failed'] or tests['errors'] or not tests['passed']:
        blocking.append('TESTS_NOT_PASSING_OR_MISSING')
    pairs = list(candidates)
    self_count = sum(a == b for a,b in pairs)
    duplicate_count = len(result.candidates)-len(candidates)
    if self_count or duplicate_count:
        blocking.append('INVALID_CANDIDATE_PAIRS')
    summary = dict(TASK_RESULT='SUCCESS' if not blocking else 'PARTIAL',
        STAGE_7_STAGE_PAIR_CANDIDATE_GENERATION='PASS' if not blocking else 'PARTIAL',
        OFFICIAL_PIPELINE_TO_STAGE7_COMPLETE=True,
        **result.statistics, DETERMINISTIC_RESULT=deterministic,
        GT_STAGE_RELATION_COUNT=len(edges),GT_RELATIONS_RECALLED_BY_CANDIDATES=recalled,
        GT_RELATION_CANDIDATE_RECALL=recalled/len(edges) if edges else 0.0,
        **{d['edge_id'].replace('-','_')+'_CANDIDATE_RECALLED':d['candidate_generated'] for d in details},
        GROUND_TRUTH_USED_BY_PRODUCTION=False, DATASET_MODIFIED=not dataset_unchanged,
        GROUND_TRUTH_MODIFIED=any('ground_truth' in Path(p).parts for p in changed),
        UPSTREAM_STAGE_1_TO_6_LOGIC_MODIFIED=bool(protected_changes),
        UPSTREAM_STAGE_1_TO_6_OUTPUT_IDENTICAL=unchanged,
        CANDIDATE_GENERATION_RUNTIME_SECONDS=sorted(repeat_times)[len(repeat_times)//2],
        AUDITED_CANDIDATE_GENERATION_RUNTIME_SECONDS=elapsed,OFFICIAL_PIPELINE=official_order,
        OFFICIAL_CALL_COUNTS=official_calls,RUNTIME_READS=runtime_reads,
        PROTECTED_FILE_COUNT=len(baseline),RELEASE_MANIFEST_MISMATCHES=manifest_mismatches,
        FILES_CHANGED=FILES_CHANGED,TEST_RESULT=tests,BLOCKING_ISSUES=blocking,
        NON_BLOCKING_ISSUES=[] if recalled == len(edges) else [d['edge_id']+': candidate not recalled; see gt_candidate_recall.json' for d in details if not d['candidate_generated']])
    save(out,'candidate_result.json',result.model_dump(mode='json'))
    save(out,'gt_candidate_recall.json',dict(GT_STAGE_RELATION_COUNT=len(edges),GT_RELATIONS_RECALLED_BY_CANDIDATES=recalled,
        GT_RELATION_CANDIDATE_RECALL=summary['GT_RELATION_CANDIDATE_RECALL'],mapping='Native wrapper event_id -> full raw event digest -> current canonical alert -> current official Stage; GT binding witness pairs only',details=details))
    save(out,'samples.json',samples)
    save(out,'integrity.json',dict(protected_before=baseline,protected_after=current_hashes,
        allowed_changed_files=sorted(allowed & set(changed)),unexpected_changed_files=protected_changes,
        dataset_file_inventory_identical=dataset_unchanged,release_manifest_mismatches=manifest_mismatches,
        upstream_output_identical=unchanged))
    save(out,'summary.json',summary)
    write_report(out,summary,details,samples)
    print(json.dumps({k:v for k,v in summary.items() if k not in {'RUNTIME_READS','FILES_CHANGED','OFFICIAL_CALL_COUNTS'}},ensure_ascii=False,indent=2))


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,default=DATA/'final/attack125_final.jsonl')
    parser.add_argument('--dataset-root',type=Path,default=DATA)
    parser.add_argument('--output',type=Path,default=ROOT/'outputs/stage7_candidate_generation')
    parser.add_argument('--tests',type=Path,nargs='*')
    verify(parser.parse_args())

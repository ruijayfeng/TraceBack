"""Isolated ATTACK125 replay, ending at Stage; integrity files are opaque bytes."""
import argparse
from collections import Counter
from dataclasses import replace
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import builtins

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from verify_community_optimization import protected_hashes, replay, save, sha
from app.adapters.base import AdapterSettings
from app.community import load_community_config
from app.config import read_yaml
from app.stages import aggregate_stages, load_stage_config

OUTPUT = ROOT / 'outputs/stage_optimization'
FILES_CHANGED = ['backend/app/stages/aggregation.py', 'backend/app/stages/models.py',
    'backend/app/stages/evidence.py', 'backend/app/stages/graph.py',
    'backend/tests/test_stage_aggregation.py', 'backend/tests/test_stage_graph.py',
    'scripts/verify_stage_optimization.py', 'scripts/run_stage_aggregation.py', 'docs/STAGE_OPTIMIZATION.md']


def assert_unchanged(before, after):
    if before != after:
        raise ValueError('protected_data_changed_STOP')


def write_acceptance(output, summary):
    from app.community.evidence import seconds
    from app.stages import StageResult
    baseline = json.loads((output / 'baseline/result.json').read_text(encoding='utf8'))
    result = StageResult.model_validate_json((output / 'validation/result.json').read_text(encoding='utf8'))
    StageResult.model_validate(baseline)
    runtime_receipt = json.loads((output / 'validation/implementation.json').read_text(encoding='utf8'))
    assert all(sha(ROOT / name) == digest for name, digest in runtime_receipt.items()), 'runtime_source_changed_since_replay'
    summary['FILES_CHANGED'] = FILES_CHANGED
    summary['LEGACY_STAGE_SCHEMA_READABLE'] = True
    tree = ET.parse(output / 'tests.xml').getroot()
    suites = [tree] if tree.tag == 'testsuite' else list(tree)
    counts = {k: sum(int(s.attrib.get(k, 0)) for s in suites) for k in ('tests', 'failures', 'errors', 'skipped')}
    assert counts['failures'] == counts['errors'] == 0
    summary['TEST_RESULT'].update(counts)
    summary['UNKNOWN_MAX_STAGE_SIZE'] = max((s.alert_count for s in result.stages if s.behavior == 'UNKNOWN'), default=0)
    summary['STAGE_REJECTION_REASONS'] = dict(Counter(d['reason'] for d in result.diagnostics))
    comparisons = []
    for stage in result.stages:
        edges = stage.aggregation_basis
        comparisons.append(dict(stage_id=stage.stage_id, community_id=stage.community_id,
            behavior=stage.behavior, alert_count=stage.alert_count,
            span_seconds=seconds(stage.end_time) - seconds(stage.start_time),
            edge_count=len(edges), evidence_types=dict(Counter(k for e in edges for k in e.evidence_types)),
            edge_strengths=dict(Counter(e.edge_strength for e in edges)),
            shared_binding_count=len({k for e in edges for k in e.binding_evidence}),
            prior_stage_overlaps=[dict(stage_id=s['stage_id'], count=len(set(s['alert_ids']) & set(stage.alert_ids)))
                for s in baseline['stages'] if set(s['alert_ids']) & set(stage.alert_ids)]))
    save(output / 'stage_comparison.json', comparisons)
    save(output / 'final_implementation.json', {name: sha(ROOT / name) for name in FILES_CHANGED})
    save(output / 'summary.json', summary)
    lines = ['# Community → Stage 验收', '', '```text']
    lines += [key + '=' + (value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))
              for key, value in summary.items()]
    lines += ['```', '', '## 实现', '',
        '复用 typed CommunityIndex、Behavior Mapping、Entity/Binding 与 TemporalHistory；'
        '阈值/上下文/冲突 gate → 无向图 → 冲突传播过滤 → Tarjan 弱桥检查 → Connected Components。'
        'aggregation_basis 保留连接边、证据等级、原始指针、实体/Binding、动态时间判定。',
        '', '## 真实对比', '',
        f"旧方法为按时间顺序的 complete-link，固定 120/30 秒；新方法按有证据的连通图聚合。"
        f"Stage 数量 {summary['BEFORE_STAGE_COUNT']} → {summary['AFTER_STAGE_COUNT']}，"
        f"singleton {sum(x == 1 for x in summary['BEFORE_STAGE_SIZES'])} → {summary['SINGLETON_STAGE_COUNT']}，"
        f"最大 Stage {max(summary['BEFORE_STAGE_SIZES'])} → {summary['MAX_STAGE_SIZE']}。",
        '详见 COMMUNITY_DETAILS；同一最新 Community 分区和同一 Behavior 注解已逐条核对。',
        '', '## 问题与限制', '',
        f"Stage 数量变化不代表准确率提升，未读取 GT 评估或调参。UNKNOWN 最大组件 {summary['UNKNOWN_MAX_STAGE_SIZE']} 条。"
        '18 条 Community 的 UNKNOWN Stage 为 14 条，通过明确 Binding 和相邻动态时间连接；'
        '12 条 Community 全部聚成一个 AUTHENTICATION Stage，旧方法同样如此。'
        '新方法未减少最大 Stage，且存在超过旧固定窗口的有证据连续链，需要保留人工语义核查。'
        'UNKNOWN 仍有保守单例。'
        '严格 eligibility 已排除无语义支持的边，因此真实弱桥删除数可为零；合成图测试验证删除条件。'
        '同标签历史节奏、Host+Account/Process 描述组合和候选容量上限仍有局限。'
        '完整说明见 docs/STAGE_OPTIMIZATION.md。',
        '', '本轮已停止在 STAGE_BUILDER_OPTIMIZED，未启动下一阶段。']
    (output / 'ACCEPTANCE.md').write_text('\n'.join(lines) + '\n', encoding='utf8')


def execute(phase, output=OUTPUT):
    output = Path(output).resolve()
    if not output.is_relative_to(ROOT / 'outputs'):
        raise ValueError('isolated_output_required')
    target = output / phase
    target.mkdir(parents=True, exist_ok=False)
    print('Hashing protected data before replay...', flush=True)
    before = protected_hashes()
    save(target / 'protected_before.json', before)
    if phase == 'validation':
        assert_unchanged(before, json.loads((output / 'baseline/protected_before.json').read_text(encoding='utf8')))
    summary = None
    try:
        print('Replaying ATTACK125 through Stage only...', flush=True)
        original_import = builtins.__import__
        def stage_only_import(name, *args, **kwargs):
            if name.startswith(('evaluation', 'app.stage_relations', 'app.stage_chains', 'app.evidence_trace', 'app.api')):
                raise RuntimeError('next_stage_import_forbidden:' + name)
            return original_import(name, *args, **kwargs)
        builtins.__import__ = stage_only_import
        run, community_report = replay()
        assert len(run.alerts) == 125
        assert sorted(c.member_count for c in run.result.incident_candidates) == [12, 18, 21, 27, 47]
        sources = [AdapterSettings(**v) for v in read_yaml(ROOT / 'configs/front-data-profiles.yaml')['sources'].values()]
        settings = {s.source_namespace: s for s in sources}
        community = load_community_config(ROOT / 'configs/community-v1.yaml')
        policy = load_stage_config(ROOT / 'configs/behavior-stage-v1.yaml')
        result = aggregate_stages(run, settings, community, policy)
        save(target / 'community.json', community_report)
        save(target / 'result.json', result.model_dump(mode='json'))
        save(target / 'implementation.json', {str(p.relative_to(ROOT)): sha(p)
             for p in sorted((ROOT / 'backend/app/stages').glob('*.py'))})
        if phase == 'baseline':
            for name in ('aggregation.py', 'models.py'):
                (target / name).write_bytes((ROOT / 'backend/app/stages' / name).read_bytes())
        else:
            # Repeat with all input collections reversed; no later stage imports.
            repeated = aggregate_stages(replace(run, alerts=list(reversed(run.alerts)),
                entities=list(reversed(run.entities))), settings, community, policy)
            assert result == repeated, 'stage_repeat_or_order_instability'
            baseline = json.loads((output / 'baseline/result.json').read_text(encoding='utf8'))
            assert [b.model_dump(mode='json') for b in result.behaviors] == baseline['behaviors'], 'behavior_changed'
            assert community_report['communities'] == json.loads((output / 'baseline/community.json').read_text(encoding='utf8'))['communities']
            sizes = sorted(s.alert_count for s in result.stages)
            tests = ET.parse(output / 'tests.xml').getroot()
            suites = [tests] if tests.tag == 'testsuite' else list(tests)
            counts = {k: sum(int(s.attrib.get(k, 0)) for s in suites) for k in ('tests', 'failures', 'errors', 'skipped')}
            assert counts['failures'] == counts['errors'] == 0
            summary = dict(TASK_RESULT='SUCCESS', INPUT_ALERTS=len(run.alerts),
                COMMUNITY_COUNT=5, COMMUNITY_SIZES=[12, 18, 21, 27, 47], **result.statistics,
                BEFORE_STAGE_COUNT=len(baseline['stages']), AFTER_STAGE_COUNT=len(result.stages),
                BEFORE_STAGE_SIZES=sorted(s['alert_count'] for s in baseline['stages']), AFTER_STAGE_SIZES=sizes,
                GROUND_TRUTH_LEAKAGE=False, DATASET_MODIFIED=False, GROUND_TRUTH_MODIFIED=False,
                PROTECTED_DATA_SHA256_UNCHANGED=True, PROTECTED_FILE_COUNT=len(before),
                FILES_CHANGED=FILES_CHANGED,
                TEST_RESULT=dict(result='PASS', **counts, deterministic_replay=True),
                COMMUNITY_DETAILS=[dict(community_id=c.community_id, alert_count=c.member_count,
                    stage_sizes=sorted(s.alert_count for s in result.stages if s.community_id == c.community_id))
                    for c in run.result.incident_candidates])
        if phase == 'baseline':
            print(json.dumps(dict(stage_count=len(result.stages), stage_sizes=sorted(s.alert_count for s in result.stages))))
    finally:
        builtins.__import__ = original_import
        print('Hashing protected data after replay...', flush=True)
        after = protected_hashes()
        save(target / 'protected_after.json', after)
        assert_unchanged(before, after)
    if summary is not None:
        write_acceptance(output, summary)
        print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['baseline', 'validation'])
    args = parser.parse_args()
    execute(args.phase)

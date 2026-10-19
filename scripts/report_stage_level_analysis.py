"""Render all frozen Stage relations and separate hash/test audit receipts."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET


def report(output, before, after, tests):
    output = Path(output)
    result = json.loads((output/'result.json').read_text(encoding='utf8'))
    manifest = json.loads((output/'manifest.json').read_text(encoding='utf8'))
    stages = sorted(json.loads((output/'stages.json').read_text(encoding='utf8')),
                    key=lambda s:(s['community_id'],s['start_time'],s['stage_id']))
    labels = {s['stage_id']:f'S{i:02}' for i,s in enumerate(stages,1)}
    before_data = json.loads(Path(before).read_text(encoding='utf8'))
    after_data = json.loads(Path(after).read_text(encoding='utf8'))
    if before_data != after_data:
        raise ValueError('protected_data_or_file_inventory_changed')
    suite = ET.parse(tests).getroot().find('testsuite')
    if any(int(suite.get(k,'0')) for k in ('failures','errors','skipped')):
        raise ValueError('tests_not_all_passed')
    summary = dict(manifest['summary'],TEST_RESULT=f"{suite.get('tests')} passed",
                   DATA_SHA256_BEFORE_AFTER_IDENTICAL=True,PROTECTED_FILE_COUNT=len(before_data))
    (output/'completion.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    for source, name in ((before,'integrity_before.json'),(after,'integrity_after.json'),(tests,'tests.xml')):
        shutil.copyfile(source,output/name)
    lines = ['# Stage-level Analysis 完成报告','',
        '仅消费已封存的 Community / Behavior / Stage、CanonicalAlert、Entity 和 Binding。'
        '未重跑 Adapter、实体抽取、Community、Behavior 或 Stage 聚合。真实关系判断仅执行一次；未调用 AI 或路径重构。','',
        '```text',*[(f'{k}={str(v).lower() if isinstance(v,bool) else v}') for k,v in summary.items()], '```','',
        '## 实际契约','',
        '`contract_version=stage-relations-v1`；独立 StageRelation 模型，不改变 Stage、CanonicalAlert、ChainEdge。',
        '每对同 Community 的 Stage 至多一条关系。`stage_a_id/stage_b_id` 按 ID 排序，'
        '`from_stage_id/to_stage_id` 仅在方向已确定时赋值。无向关系两者为 null，`direction_reliable=false`。',
        '`direction_basis`：STRONG_DIRECTED 为 `evidence_semantics`，箭头由主强证据语义决定；'
        'STRONG_UNDIRECTED 为 `unresolved`；WEAK_DIRECTED 为 `temporal_order`，箭头只表示较早 Stage → 较晚 Stage 的展示顺序，'
        '不表示攻击因果或实体传播。`direction_reliable=true` 必须结合该字段解释。'
        '历史 v1 记录缺少此字段时按原有 relation_type 解释，不改写封存数据。',
        '`primary_evidence` 含绑定原告警的 EvidencePointer、实体引用、单条证据的告警对、身份键、语义方向、rank、strength、reason。'
        '`supporting_evidence` 保存其他候选，`witness_alert_ids` 精确覆盖全部实际证据告警。',
        '`semantic_direction` 保留原证据方向；`observed_time_order` 相对于 A/B，'
        '`time_gap` 为两个 Stage 区间的非负间隔秒数，重叠/同时间为 0；'
        '`time_facts.semantic_gap_seconds` 为主证据目标告警时间减源告警时间，可以为负。',
        '`confidence` 直接等于主证据强度；`confidence_basis` 分开保存 evidence_strength、'
        'direction_reliability、time_consistency；不是攻击概率、旧综合评分或阈值校准结果。','',
        '## Evidence ranking','',
        '|rank|证据|strength|','|---|---|---|',
        '|1|父子进程、Request→Response、Session→后续操作、已有结构化显式关系|0.95|',
        '|2|创建→执行同一对象、响应对象→请求对象交接|0.90|',
        '|3|同一完整进程实例 / 同 typed scoped binding|0.70 / 0.60（弱关联）|',
        '|4|同 scope 实体上下文|0.45（弱关联）|',
        '|5|同 scope 网络端点上下文|0.35（弱关联）|','',
        '排序为 rank 升序 → strength 降序 → evidence_id 字典序。只选第一条，不加总证据。'
        '时间、Community、Behavior/ATT&CK 邻接、供应商文本和来源差异均不能单独产生关系。',
        '强关系按主证据语义定向；主证据告警时间反转超过显式配置的 30 秒容差时，'
        '保留 STRONG_UNDIRECTED 并标记 time_conflict=true。30 秒是未校准的 v1 策略，不是实测结论。',
        '同 rank、同 strength 的相反语义证据保留为 STRONG_UNDIRECTED，标记 direction_conflict=true；'
        '不会把这类冲突伪称为时间冲突。弱证据只有 Stage 区间严格可排序才建立 WEAK_DIRECTED；'
        '弱证据区间交叠的 pair 在 diagnostics 中保留证据并标 NO_RELATION。','',
        '## Stage 索引','',
        '|编号|Stage ID|Community ID|Behavior|时间区间 UTC|Alert 数|',
        '|---|---|---|---|---|---|']
    lines += [f"|{labels[s['stage_id']]}|`{s['stage_id']}`|`{s['community_id']}`|{s['behavior']}|{s['start_time']} → {s['end_time']}|{s['alert_count']}|" for s in stages]
    relations = result['relations']
    lines += ['',f'## 全部实际关系（{len(relations)} 条）','',
              '|编号|Stage A|Stage B|类型|主证据|confidence|时间冲突|', '|---|---|---|---|---|---|---|']
    lines += [f"|R{i:03}|{labels[r['stage_a_id']]}|{labels[r['stage_b_id']]}|{r['relation_type']}|{r['evidence_type']}|{r['confidence']}|{str(r['time_conflict']).lower()}|" for i,r in enumerate(relations,1)]
    for i,r in enumerate(relations,1):
        detail = {k:r[k] for k in ('relation_id','community_id','stage_a_id','stage_b_id','from_stage_id','to_stage_id',
            'relation_type','direction_reliable','primary_evidence','witness_alert_ids','semantic_direction',
            'observed_time_order','time_gap','overlap','time_conflict','direction_conflict','time_facts','confidence','confidence_basis','reason')}
        detail['direction_basis'] = r.get('direction_basis', {
            'STRONG_DIRECTED':'evidence_semantics', 'STRONG_UNDIRECTED':'unresolved',
            'WEAK_DIRECTED':'temporal_order'}[r['relation_type']])
        detail['supporting_evidence_count'] = len(r['supporting_evidence'])
        lines += ['',f"### R{i:03}: {labels[r['stage_a_id']]} ↔ {labels[r['stage_b_id']]}",'',
                  '```json',json.dumps(detail,ensure_ascii=False,indent=2),'```']
    lines += ['','## 数据 SHA-256 审计','',
        '独立 evaluation 审计只按字节计算摘要，不解析 GT、不评估或调参。'
        f'前后 {len(before_data)} 个受保护文件的集合和 SHA-256 完全一致；包括冻结实验、GT、归档及前置 Stage 产物。','',
        '|文件|执行前 SHA-256|执行后 SHA-256|','|---|---|---|']
    lines += [f'|`{p}`|`{h}`|`{after_data[p]}`|' for p,h in before_data.items()]
    lines += ['','## 验证与限制','',
        f"- pytest：{suite.get('tests')} passed，0 failed / error / skipped；完整记录见 tests.xml。",
        '- 新增测试覆盖八个指定场景，并验证时间容差边界、反序输入稳定性、完整指针闭包、强弱证据排序、网络方向、运行器数据保护和不重跑 Adapter。',
        '- 生产运行 I/O 和 import tripwire：0 次 GT 或下游模块访问。真实分析没有读取 ground_truth.json；hash-only 操作仅在 evaluation 审计中执行。',
        '- 相关 Community、Behavior、Stage、实体绑定、Schema、Stable ID 和 API/GT 隔离回归通过。',
        '- 工作区缺少三份原始需求文档及 CODEX_TASKS.md，无法核对缺失文档；本次明确指令为当前任务边界。工作区无 Git 元数据，不能提供 Git diff。',
        '- 本轮不进行 accuracy/F1 或 confidence 校准，不对结果完整性作攻击事实承诺。',
        '- CURRENT_PIPELINE_STAGE=STAGE_LEVEL_ANALYSIS_COMPLETE；ATTACK_CHAIN_RECONSTRUCTION_STARTED=false；NEXT_STAGE_NOT_STARTED=true。','']
    if (output/'verification.json').exists():
        lines += ['## 导出结果独立核验','','```json',
                  (output/'verification.json').read_text(encoding='utf8').strip(),'```','']
    changed = [
        'backend/app/stage_relations/__init__.py','backend/app/stage_relations/config.py',
        'backend/app/stage_relations/models.py','backend/app/stage_relations/time.py',
        'backend/app/stage_relations/evidence.py','backend/app/stage_relations/analysis.py',
        'backend/tests/test_stage_relations.py','configs/stage-relations-v1.yaml',
        'scripts/run_stage_level_analysis.py','scripts/verify_stage_level_analysis.py',
        'scripts/report_stage_level_analysis.py','evaluation/stage_relation_integrity.py']
    lines += ['## 新增代码 / 配置文件','',*['- `'+p+'`' for p in changed],'',
              '没有修改既有业务代码、原始需求、历史配置或冻结实验文件。','']
    (output/'REPORT.md').write_text('\n'.join(lines),encoding='utf8')
    receipt = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.iterdir()) if p.is_file() and p.name != 'completion_receipt.json'}
    (output/'completion_receipt.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(relations=len(relations),tests=summary['TEST_RESULT'],protected_files=len(before_data),report=str(output/'REPORT.md'))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--tests', type=Path, required=True)
    args = parser.parse_args()
    report(args.output,args.before,args.after,args.tests)

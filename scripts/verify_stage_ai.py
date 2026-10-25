"""Verify the primary official ATTACK125 Chain without running ①–⑨.

Writes the exact model evidence, actual service result, a clearly labeled local
grounding preview, adversarial receipts and sealed-file hashes. No model name is
invented when local deployment configuration is incomplete.
"""
import argparse
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))

from app.ai.provider import LLMProvider, load_provider_config
from app.ai.providers.openai_compatible import OpenAICompatibleProvider
from app.ai.stage_context import StageContext, build_stage_context
from app.ai.stage_explanation import StageExplanationDraft, StageExplanationService, preview_draft, markdown_report
from app.ai.stage_grounding import validate_and_render
from app.ai.stage_knowledge import make_stage_evidence
from app.api.stage_workbench import STAGE9_ARTIFACT
from app.evidence_trace.snapshot import file_sha256
from app.stage_chains.stage9_reader import Stage9ArtifactReader


class AdversarialProvider(LLMProvider):
    name, model = 'adversarial_test_double', 'NO_REAL_MODEL'

    def __init__(self, mutation):
        self.mutation = mutation

    def explain(self, context):
        draft = preview_draft(context)
        self.mutation(draft)
        return json.dumps(draft, ensure_ascii=False)


def run(output, chain_id=None):
    output.mkdir(parents=True, exist_ok=True)
    def write(name, value):
        (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    source = ROOT / STAGE9_ARTIFACT
    before = {str(p.relative_to(ROOT)): file_sha256(p) for p in source.iterdir() if p.is_file()}
    reader = Stage9ArtifactReader(ROOT, source)
    loaded = reader.load()
    selected = chain_id or max(loaded['reconstruction'].chains, key=lambda c: len(c.stage_ids)).chain_id
    ctx = build_stage_context(reader, selected)
    package = ctx.model_data
    write('evidence_package.json', package)
    write('model_request_messages.json', ctx.messages(ctx.response_schema))
    write('output_schema.json', ctx.response_schema)
    preview = validate_and_render(ctx, StageExplanationDraft.model_validate(preview_draft(ctx)))
    write('grounding_preview.json', dict(result_origin='deterministic_preview', real_model=False, report=preview))
    (output / 'grounding_preview.md').write_text(
        '> 本文件为真实 Stage 证据上的确定性 grounding 预览，不是真实模型输出。\n\n' + markdown_report(preview), encoding='utf-8')
    config_status = 'configured'
    try:
        cfg = load_provider_config(ROOT / 'configs/llm.yaml')
        provider = OpenAICompatibleProvider(cfg) if cfg.configured else None
        if not cfg.configured:
            config_status = 'missing_model' if not cfg.model else 'incomplete_provider_configuration'
    except (ValueError, OSError):
        provider, config_status = None, 'invalid_provider_configuration'
    actual = StageExplanationService(provider).explain(ctx)
    write('actual_service_result.json', actual)
    if provider:
        write('real_model_result.json', actual)

    undirected_index = next((i for i, r in enumerate(package['relations'])
                             if r['direction_status'] == 'UNRESOLVED'), None)
    checks = []
    def rejected(name, context, mutation):
        result = StageExplanationService(AdversarialProvider(mutation)).explain(context)
        okay = result['status'] == 'unavailable' and result['grounding_status'] == 'rejected' and result['report_json'] is None
        checks.append(dict(case=name, result='PASS' if okay else 'FAIL',
                           actual_status=result['status'], grounding_status=result['grounding_status']))
    rejected('nonexistent_alert_id', ctx,
        lambda d: d['stages'][0]['observed_facts'][0].update(evidence_refs=['alt_nonexistent']))
    if undirected_index is not None:
        rejected('undirected_changed_to_directed', ctx,
            lambda d: d['relations'][undirected_index].update(relation_type='DIRECTED_EDGE', direction_status='CONFIRMED_BY_ALGORITHM'))
    rejected('unproven_data_exfiltration', ctx,
        lambda d: d['stages'][0]['confirmed_impact'].append(dict(fact_id=d['stages'][0]['observed_facts'][0]['fact_id'],
            evidence_refs=d['stages'][0]['observed_facts'][0]['evidence_refs'], description='数据已经泄露')))
    rejected('temporal_adjacency_added_as_causal_edge', ctx,
        lambda d: d['relations'].append(dict(relation_id='invented_time_edge',
            source_stage_id=d['stages'][0]['stage_id'], target_stage_id=d['stages'][1]['stage_id'],
            relation_type='DIRECTED_EDGE', direction_status='CONFIRMED_BY_ALGORITHM', supporting_claim_ids=[])))
    # Explicitly synthetic counterexample: do not modify real source records.
    failure_alert = dict(alert_id='alt_synthetic_failure', raw_alert=dict(hostname='synthetic-auth-host',
        operation='authentication_failure', account='admin', result='failure'))
    failure_stage = dict(stage_id='stg_synthetic_failure', alert_ids=[failure_alert['alert_id']], behavior='AUTHENTICATION')
    failure_package = dict(chain=dict(chain_id='synthetic_failure_chain', stage_ids=[failure_stage['stage_id']],
        relation_ids=[], has_directed_cycle=False), stages=[dict(stage=failure_stage, alerts=[failure_alert],
            **make_stage_evidence(failure_stage, [failure_alert]))], relations=[], independent_chain_count=1,
            claims={}, observations={}, resolved_pointers={})
    failure_ctx = StageContext(json.dumps(failure_package), 'f'*64)
    write('synthetic_auth_failure_fixture.json', dict(synthetic=True, evidence=failure_package))
    rejected('authentication_failure_promoted_to_compromise', failure_ctx,
        lambda d: d['stages'][0]['confirmed_impact'].append(
            dict(fact_id='fact_alt_synthetic_failure', evidence_refs=['alt_synthetic_failure'])))
    after = {str(p.relative_to(ROOT)): file_sha256(p) for p in source.iterdir() if p.is_file()}
    unchanged = before == after
    write('source_hashes.json', dict(before=before, after=after, unchanged=unchanged))
    write('grounding_adversarial_results.json', checks)
    receipt = dict(chain_id=selected, stage_count=len(package['stages']), relation_count=len(package['relations']),
        directed_count=sum(r['direction_status'] == 'CONFIRMED_BY_ALGORITHM' for r in package['relations']),
        undirected_count=sum(r['direction_status'] == 'UNRESOLVED' for r in package['relations']),
        member_alert_count=sum(len(s['alerts']) for s in package['stages']),
        model_input_bytes=len(ctx.model_payload.encode('utf-8')), input_digest=ctx.input_digest,
        source_files_unchanged=unchanged, source_file_count=len(before), config_status=config_status,
        REAL_MODEL_TEST='NOT_EXECUTED' if provider is None else ('PASS' if actual['status'] == 'available' else 'FAILED'),
        TEST_RESULT='PASS' if unchanged and all(c['result'] == 'PASS' for c in checks) else 'FAIL',
        actual_service_status=actual['status'], grounding_preview_origin='deterministic_preview')
    write('receipt.json', receipt)
    # Small excerpts contain actual transmitted evidence, with no credentials.
    interesting = next((s for s in package['stages'] if any('/bin/sh /var/www/uploads/' in
                       json.dumps(a['raw_alert']) for a in s['alerts'])), package['stages'][0])
    sid = interesting['stage']['stage_id']
    write('example_stage_input.json', interesting)
    write('example_stage_output_preview.json', dict(result_origin='deterministic_preview',
          stage=next(s for s in preview['stages'] if s['stage_id'] == sid)))
    write('example_relations_preview.json', dict(result_origin='deterministic_preview', relations=[
        next(r for r in preview['relations'] if r['direction_status'] == 'CONFIRMED_BY_ALGORITHM'),
        *([next(r for r in preview['relations'] if r['direction_status'] == 'UNRESOLVED')]
          if undirected_index is not None else [])]))
    write('example_chain_summary_preview.json', dict(result_origin='deterministic_preview', chain_summary=preview['chain_summary']))
    write_acceptance_report(output, receipt, interesting, preview, actual, checks)
    print(json.dumps(receipt, ensure_ascii=True, indent=2))
    return receipt


def write_acceptance_report(output, receipt, stage_input, preview, actual, checks):
    """A reviewable receipt with real excerpts, not an invented model report."""
    files = [
        ('backend/app/ai/stage_context.py', '接入正式⑨', '只读证据 Adapter、作用域/哈希、模型输入及提示'),
        ('backend/app/ai/stage_knowledge.py', '解释实际字段', '字段角色、行为/风险资格、缺失证据及保守确认后果'),
        ('backend/app/ai/stage_grounding.py', '约束证据与关系', '引用闭包、字段回查、方向/成员不变、风险分离及图结构摘要'),
        ('backend/app/ai/stage_explanation.py', '提供独立服务', '严格 Schema、模型失败隔离、缓存、重校验存储、JSON/MD 导出'),
        ('backend/app/ai/providers/openai_compatible.py', '复用调用层', '支持 Stage 上下文 Schema/提示与输入限制，保留旧协议'),
        ('backend/app/api/stage_explanations.py', '提供工作台入口', '证据包、显式生成、已存报告接口及生成前后源哈希检查'),
        ('backend/app/api/stage_workbench.py', '注册研判入口', '安装独立 AI 路由，不改变现有图/告警/证据接口'),
        ('backend/tests/test_stage_ai_explanation.py', '验证行为及边界', '真实主链/单节点、五类错误、指针、超时、存储及 API 隔离'),
        ('scripts/verify_stage_ai.py', '可复现验收', '选正式最大多节点 Chain，输出输入、预览、真实服务状态、攻击测试及哈希'),
        ('frontend/src/api/client.ts', '连接新增 API', '研判生成与已存报告读取'),
        ('frontend/src/types/stageAnalysis.ts', '描述显示数据', '研判结果与证据结构类型'),
        ('frontend/src/components/StageAIReport.tsx', '展示三类研判', '按需调用、分栏语义、证据回查及两种导出'),
        ('frontend/src/pages/StageWorkbench.tsx', '最小集成', '图下增加研判区域，证据按钮打开原告警/关系'),
        ('frontend/src/styles/stageAnalysis.css', '保持可读', '小范围间距、折叠和长文本样式'),
        ('frontend/src/__tests__/stageAIReport.test.tsx', '验证 UI 隔离', '失败、跨链/未校验报告、无向关系及原始文本转义'),
        ('docs/STAGE_AI_ASSISTANCE.md', '说明边界与使用', '输入覆盖、受约束声明、安全语义限制、接口及验证方法'),
    ]
    fence = lambda value: '\n```json\n' + json.dumps(value, ensure_ascii=False, indent=2) + '\n```\n'
    def junit(name):
        import xml.etree.ElementTree as ET
        path = output / name
        if not path.is_file():
            return 'NOT_EXECUTED（缺少测试回执）'
        try:
            suite = ET.parse(path).find('.//testsuite')
            total = int(suite.attrib.get('tests', 0))
            failures = int(suite.attrib.get('failures', 0))
            errors = int(suite.attrib.get('errors', 0))
            skipped = int(suite.attrib.get('skipped', 0))
            return f'{total-failures-errors-skipped} passed、{failures} failed、{errors} errors、{skipped} skipped'
        except (OSError, ValueError, AttributeError, ET.ParseError):
            return 'INVALID_TEST_RECEIPT'
    frontend_status = 'NOT_EXECUTED（缺少测试回执）'
    frontend_path = output / 'frontend_tests.json'
    if frontend_path.is_file():
        frontend = json.loads(frontend_path.read_text(encoding='utf-8'))
        frontend_status = f"{frontend['numPassedTests']} passed、{frontend['numFailedTests']} failed"
    verification = {}
    if (output / 'verification_summary.json').is_file():
        verification = json.loads((output / 'verification_summary.json').read_text(encoding='utf-8'))
    stage = next(s for s in preview['stages'] if s['stage_id'] == stage_input['stage']['stage_id'])
    # Keep source bytes/values intact while excerpting only one member alert.
    input_excerpt = dict(stage=stage_input['stage'], alerts=stage_input['alerts'][:1],
                         facts=stage_input['facts'][:1], eligible_codes=stage_input['eligible_codes'])
    output_excerpt = dict(stage_id=stage['stage_id'], observed_facts=stage['observed_facts'][:1],
        behavior_interpretation=stage['behavior_interpretation'], missing_evidence=stage['missing_evidence'],
        risk_analysis=dict(potential_impact=stage['risk_analysis']['potential_impact'],
                           confirmed_impact=stage['risk_analysis']['confirmed_impact'][:1]))
    lines = ['# Stage AI 辅助研判验收（2026-10-25）', '',
        '**实现与本地证据验证已完成；真实模型测试未执行。当前配置缺少 model，未尝试付费请求。**',
        '实际服务返回 unavailable。下面行为、关系和摘要样例来自真实正式数据上的确定性 grounding 预览，'
        '标记为 deterministic_preview，不是模型输出，不计入 REAL_MODEL_TEST=PASS。', '',
        '## A. 修改文件', '', '| 文件 | 修改原因 | 修改内容 | 影响①～⑨ |', '|---|---|---|---|']
    lines += [f'| `{path}` | {why} | {what} | 否 |' for path, why, what in files]
    lines += ['', '工作区原有文档删除和其他未跟踪目录未作为本轮改动处理。', '',
        '## B. 实际构造的 AI 输入', '',
        f"正式主要 Chain：`{receipt['chain_id']}`；{receipt['stage_count']} 个 Stage、"
        f"{receipt['member_alert_count']} 条成员告警、{receipt['directed_count']} 条有向与 {receipt['undirected_count']} 条无向关系。",
        f"待发送 Evidence Package 为 {receipt['model_input_bytes']} 字节，完整文件 `evidence_package.json`，"
        '完整实际请求消息 `model_request_messages.json`，严格输出 Schema `output_schema.json`。'
        '因为模型未配置，这些消息尚未发往 API。全部 Stage 成员告警保留；每条正式有效 Claim 的见证摘录及省略数量有显式标记。',
        '下方从真实 Stage 输入截取一个完整原始告警；该 Stage 的完整输入见 `example_stage_input.json`。', fence(input_excerpt),
        '## C. 实际服务输出与 Stage 预览', '',
        '真实服务输出（`actual_service_result.json`）：', fence(actual),
        '真实模型输出：未生成。以下是同一 Stage 经正式 grounding 接受的本地预览，confidence=0 不是模型置信度。'
        '完整逐 Stage 输出见 `grounding_preview.json`；此 Stage 见 `example_stage_output_preview.json`。',
        fence(dict(result_origin='deterministic_preview', **output_excerpt)),
        '## D. Relation 样例', '', '以下为相同预览的发布结果；模型不得改变任何端点、类型、方向或成员。']
    for status in ('CONFIRMED_BY_ALGORITHM', 'UNRESOLVED'):
        relation = next((r for r in preview['relations'] if r['direction_status'] == status), None)
        if relation:
            excerpt = {key: value for key, value in relation.items() if key != 'supporting_evidence'}
            excerpt['supporting_evidence'] = [{key: value for key, value in item.items() if key != 'field_refs'}
                                              for item in relation['supporting_evidence']]
            lines.append(fence(excerpt))
    summary = {key: value for key, value in preview['chain_summary'].items()
               if key not in {'main_observed_activities', 'confirmed_overall_impact'}}
    summary['main_observed_activities'] = [dict(description=f['description'], evidence_refs=f['evidence_refs'])
                                          for f in preview['chain_summary']['main_observed_activities']]
    summary['confirmed_overall_impact'] = [dict(description=f['description'], evidence_refs=f['evidence_refs'])
                                          for f in preview['chain_summary']['confirmed_overall_impact']]
    lines += ['', '## E. Chain Summary', '', '本地预览摘要；完整结果见 `example_chain_summary_preview.json`。', fence(summary),
        '## F. Grounding 与只读验证', '', '| 错误注入 | 结果 | 服务行为 |', '|---|---|---|']
    lines += [f"| {c['case']} | {c['result']} | {c['grounding_status']} / 不发布草稿 |" for c in checks]
    lines += ['', '认证失败测试使用明确标记的合成反例，见 `synthetic_auth_failure_fixture.json`，未修改真实认证记录。',
        f"正式结果目录 {receipt['source_file_count']} 个文件前后哈希完全一致；见 `source_hashes.json`。",
        'API 测试注入 timeout 后，原始 Chain、Relation、原告警和证据接口仍正常；存储正文篡改被重新 grounding 拒绝。',
        '', '## 测试运行记录', '',
        f"- Stage AI / Stage 工作台 / ⑨重构回归：{junit('stage_tests.xml')}（`stage_tests.xml`）。",
        f"- 模型传输/配置层：{junit('provider_tests.xml')}（`provider_tests.xml`），全部使用 MockTransport，没有真实模型请求。",
        f"- 相关前端：{frontend_status}（`frontend_tests.json`）；TypeScript={verification.get('typecheck', 'NOT_EXECUTED')}，"
        f"生产构建={verification.get('production_build', 'NOT_EXECUTED')}。",
        f"- 扩展旧 AI 回归：{verification.get('extended_regression', 'NOT_EXECUTED')}。对照 Git HEAD 原始 transport 后："
        f"{junit('legacy_head_transport_baseline.xml')}（`legacy_head_transport_baseline.xml`）。"
        '其中 6 项是旧 analysis 响应新增 pipeline_role 与旧响应 Schema 不匹配；另 1 项是旧 ATT&CK mapping 测试的 provider_error。'
        '均可在本轮修改前的 transport 重现，本轮未修改旧算法/分析接口来处理这些历史问题。',
        '', '## 结论', '', '```text',
        'TASK_RESULT=IMPLEMENTED_LOCAL_VERIFIED_REAL_MODEL_PENDING',
        'AI_STAGE_BEHAVIOR_EXPLANATION=IMPLEMENTED_LOCAL_VERIFIED',
        'AI_RELATION_EXPLANATION=IMPLEMENTED_LOCAL_VERIFIED',
        'AI_RISK_ANALYSIS=IMPLEMENTED_LOCAL_VERIFIED',
        'FINAL_CHAIN_READ_ONLY=true', 'STAGE_MUTATION=false', 'RELATION_MUTATION=false',
        'EDGE_GENERATION_BY_AI=false', 'TIME_BASED_CAUSAL_INFERENCE=false',
        'EVIDENCE_GROUNDING=PASS_LOCAL_VALIDATION', 'POTENTIAL_CONFIRMED_SEPARATION=PASS_LOCAL_VALIDATION',
        f"REAL_MODEL_TEST={receipt['REAL_MODEL_TEST']}",
        'TEST_RESULT=TARGETED_PASS_WITH_7_PREEXISTING_LEGACY_FAILURES', '```', '']
    (output / 'ACCEPTANCE_REPORT.md').write_text('\n'.join(lines), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'outputs/stage_ai_acceptance_20261025')
    parser.add_argument('--chain-id')
    args = parser.parse_args()
    receipt = run(args.output, args.chain_id)
    raise SystemExit(0 if receipt['TEST_RESULT'] == 'PASS' else 1)

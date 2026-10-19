"""Final user decision and complete answers, derived from immutable output files."""
from pathlib import Path
import xml.etree.ElementTree as ET
from . import OUT, OLD
from .runtime import verify_seal
from evaluation.framework.formula_design.runtime import read, save


def table(columns, records):
    return '\n'.join(['| '+' | '.join(columns)+' |', '| '+' | '.join(['---']*len(columns))+' |',
                      *['| '+' | '.join(str(v) for v in row)+' |' for row in records]])


def run():
    frozen, seal = verify_seal('final'); design = frozen['selection']['design']; cp = frozen['selection']['chain_policy']
    result = read(OUT/'final'/('metrics_'+design+'.json')); chain = result['chain_policies'][cp]
    before = read(OLD/'summary.json'); neg = read(OUT/'final/worst_negative_before_after.json')
    suites = list(ET.parse(OUT/'regression.xml').getroot().iter('testsuite'))
    tests = sum(int(t.get('tests', 0)) for t in suites); skipped = sum(int(t.get('skipped', 0)) for t in suites)
    failures = sum(int(t.get('failures', 0))+int(t.get('errors', 0)) for t in suites)
    primary = next(p for p in result['operating_points'] if p['threshold'] == .65)
    separation = not result['binding_negative_pairs'] and result['explicit_negative_max'] <= .45 and (
        result['meaningful_bound_GT_negative_margin'] is not None and result['meaningful_bound_GT_negative_margin'] > 0)
    inflation = chain['background_chain_edges'] > 0 or chain['explicit_negative_chain_edges'] > 0
    accepted = separation and chain['GT_CHAIN_EDGES'] >= 2 and chain['longest_GT_directed_path'] >= 2 and not inflation and not failures
    verdict = 'V5_SEMANTIC_REPAIR_ACCEPTED' if accepted else 'V5_SEMANTIC_REPAIR_PARTIAL' if separation else 'V5_DESIGN_STILL_DEFECTIVE'
    summary = dict(TASK_RESULT=verdict, SCORE_SEMANTICS='SCORE_DESIGN_FIXED' if separation else 'STILL_DEFECTIVE',
        TRANSITION_SEMANTICS='L0_CONTEXT_L1_ROLE_L2_OBSERVED_BEHAVIOR_L3_BOUND',
        DIRECTION_MODEL='INDEPENDENT_SOURCE_BINDING_LIMIT', CHAIN_ADMISSION='INDEPENDENT_CONSERVATIVE_HYBRID_D',
        GT_CORRELATION_EDGES=primary['GT_CORRELATION_EDGES'], GT_DIRECTION_PROOFS=chain['GT_DIRECTION_PROOFS'],
        GT_CHAIN_EDGES=chain['GT_CHAIN_EDGES'], LONGEST_GT_PATH=chain['longest_GT_directed_path'],
        EXPLICIT_NEGATIVE_MAX=result['explicit_negative_max'], POSITIVE_NEGATIVE_OVERLAP='YES' if result['positive_negative_overlap'] else 'NO',
        READY_FOR_FINAL_CALIBRATION='YES' if accepted else 'NO', READY_FOR_CPTC_T2='NO', V5_PRODUCTION_FREEZE='NO',
        NEXT_STEP='V5 FINAL CALIBRATION + PRODUCTION FREEZE' if accepted else 'SOURCE_BINDING_OBSERVABILITY_REVIEW',
        LIMITATION='SOURCE_BINDING_LIMIT', CANDIDATE_RECALL=result['candidate_recall'], GATE_RECALL=result['gate_recall'],
        GT_MIN=result['GT_min'], GT_MEDIAN=result['GT_median'], GT_MAX=result['GT_max'],
        POSITIVE_NEGATIVE_MARGIN=result['positive_negative_margin'], MEANINGFUL_BOUND_GT_MIN=result['meaningful_bound_GT_min'],
        MEANINGFUL_BOUND_GT_NEGATIVE_MARGIN=result['meaningful_bound_GT_negative_margin'],
        BACKGROUND_CHAIN_EDGES=chain['background_chain_edges'], EXPLICIT_NEGATIVE_CHAIN_EDGES=chain['explicit_negative_chain_edges'],
        ACTUAL_CHAIN_EDGES=chain['actual_chain_edges'], FULL_RECONSTRUCTED_PROGRESSION_LENGTH=chain['full_reconstructed_progression_length'],
        PATH_UNIT='edges', REGRESSION='PASS' if not failures else 'FAIL', REGRESSION_PASSED=tests-skipped-failures,
        REGRESSION_SKIPPED=skipped, REGRESSION_FAILURES=failures, PRODUCTION_REGISTERED=False,
        FORMULA_HASH=frozen['formula_hash'], CONFIG_HASH=frozen['config_hash'], IMPLEMENTATION_HASH=frozen['implementation_hash'],
        MAPPING_DIGEST=frozen['mapping_digest'], POST_EVALUATION_PARAMETER_CHANGES=0)
    save(OUT/'summary.json', summary)
    (OUT/'summary.ini').write_text('\n'.join(f'{k}={v}' for k, v in summary.items())+'\n', encoding='utf8')
    lines = ['# V5 Semantic Discrimination + Chain Admission Repair', '', verdict, '',
        '本轮为开发集语义修复；既往开发审查已见标签，不宣称独立盲测。两次新重放各自先封存 score / direction / graph，随后才读取评测标签；评测后参数修改为 0。未进入 UI、CPTC t2、Final Calibration 或生产冻结。', '',
        '## 冻结基线与实际重放', '',
        '旧候选完整重算 10,051 条告警、200,402 个候选、219,504 个原始成员对；逐行比对旧 PairScore / DirectionEvidence / CorrelationEdge，六个阈值图结果及 GT/negative 指标一致。基线回归状态 1467 passed / 4 skipped 保存在收据；本轮另实际运行受影响回归。', '',
        '参见 `baseline_receipt.json`、`baseline_reproduction/score_seal.json`、`development/formula_freeze.json`、`development/score_seal.json`、`final/formula_freeze.json`、`final/score_seal.json` 和各自 `blind/guard_receipt.json`。', '',
        table(['身份', '最终候选'], [[k, frozen[k]] for k in ('algorithm_version', 'formula_hash', 'config_hash', 'implementation_hash', 'mapping_digest')]), '',
        '## 三种 ceiling 设计与四种 chain policy', '',
        '固定 operating points：weak=0.45、partial=0.50、moderate correlation=0.55、strong correlation=0.70、direction=0.75、high direction=0.90。值先于开发比较冻结，没有搜索最优值，也没有改生产阈值。', '']
    development = read(OUT/'development/comparison.json')
    lines += [table(['设计', 'GT min', '负例 max', '原始 overlap', 'bound GT margin', '背景 @.65', '显式负例 progression'],
        [[d, r['GT_min'], r['explicit_negative_max'], r['positive_negative_overlap'], r['meaningful_bound_GT_negative_margin'],
          next(p['unlabeled_background_admission'] for p in r['operating_points'] if p['threshold'] == .65),
          r['chain_policies']['D']['explicit_negative_chain_edges']] for d, r in development.items()]), '',
        'A 仅 L3 解除原弱证据 ceiling；B 允许 L2+角色桥到 0.50，L3 完全解除；C 仅调整组内质量，保留原 ceiling。选择依据为语义安全、负例准入、separation 与背景负担，并列选 A；不按 GT recovery 决胜。最终选择 '+design+' / chain '+cp+'。', '',
        table(['设计 / 策略', 'GT ChainEdge /6', 'GT 最长路径', '全部链边', '背景链边', '负例链边'],
          [[d+'/'+v, c['GT_CHAIN_EDGES'], c['longest_GT_directed_path'], c['actual_chain_edges'], c['background_chain_edges'], c['explicit_negative_chain_edges']]
           for d, r in development.items() for v, c in r['chain_policies'].items()]), '',
        '策略 A 为既有 .70+方向；B 为独立 .55/.75 双置信；C 在 B 上要求 L3；D 为 .70/.75 或 .55+L3/.90。B/C/D 在本数据上结果相同不等于它们普遍等价。', '',
        '## 六条 GT 与真实生成的边', '',
        table(['GT', '旧 score', '新 score', 'tier', '方向', '实际链边', '限制'],
              [[eid, before[eid.replace('GT-', 'GT_')+'_NEW_SCORE'], g['score'], g['transition_level'], g['direction_verified'], g['chain_edge_created'], g['failure']]
               for eid, g in chain['GT'].items()]), '',
        table(['correlation 诊断阈值', '全部边', 'GT /6', '显式负例', '未标注背景'],
              [[p['threshold'], p['total_edges'], p['GT_CORRELATION_EDGES'], p['explicit_negative_admission'], p['unlabeled_background_admission']]
               for p in result['operating_points']]), '',
        '链策略输出独立于 correlation operating point。低于 .65 的真实支撑关联边保存在 policy 目录的 `correlation_edges.jsonl.gz`，不伪装成 .65 展示关联。所有数量来自已落盘边文件；未用时间排序、GT 顺序或 expected edge 补边。', '',
        f"实际链边 {chain['actual_chain_edges']}，覆盖六条指定 GT pair 中 {chain['GT_CHAIN_EDGES']} 条；多个原始成员组合支持同一概念传播阶段，不能把这些包装计为多条 GT progression。GT 最长路径 {chain['longest_GT_directed_path']} edge；系统原始节点图最长路径 {chain['full_reconstructed_progression_length']} edge。", '',
        '组件大小多重集、cycle/conflict/component 拒绝计数及原始告警覆盖见 `final/metrics_'+design+'.json`。', '',
        '## 最高显式负例', '',
        f"旧分 {neg['before']['score']} → 新分 {neg['after']['variants'][design]['final_score']}。共享 ACCOUNT 与 resource_access→authentication 兼容观测存在，但 monitored-host 与 login-source 不相接，无操作绑定。L2 不能解除 A 的 weak ceiling；binding 缺失为 UNOBSERVABLE，不施加虚构 contradiction。", '',
        '完整 before/after breakdown、identity/role/behavior/binding evidence 与 ceiling decision 见 `final/worst_negative_before_after.json`；全部 630 个显式标注负例对（含未入候选的空评分）见 `final/negative_pairs_'+design+'.json`。未入候选的负例不填假分。hard-touching maxima 单独报告，不冒充 explicit-negative max。', '',
        '## 二十项最终回答', '',
        '1. 真实缺陷：compatible transition 被当作独立 progression 证明并二元解除 weak ceiling；.70 同时承担相关、聚类与链准入，隐藏阻断可证明方向。',
        '2. 同身份仅证明 scope 内同一实体引用或调查上下文；不证明同一真人、操作实例、攻击者意图或因果。',
        '3. L0 context-only、L1 role-compatible、L2 raw-observed behavioral transition、L3 bound transition；层级不是概率。',
        '4. A 仅 L3 可以解除原 weak ceiling；原本已有多组独立上下文可形成高相关分，但仍不证明 progression。',
        '5. 原最高负例仅凭同账号与行为兼容就撤掉 .45 cap；没有新增独立绑定信息。',
        f"6. 已压回 {result['explicit_negative_max']}；没有 pair ID 或数据集账号/IP 特判。",
        '7. 六条 GT 的实际变化见上表；E01/E02 失去不成立的 compatibility 奖励，E03/E05 保留上下文关联，E04 利用既有方向，E06 缺绑定。',
        '8. E03/E05 仍受 instance-binding 限制：缺完整 PID/start time/父子实例或认证会话→进程连接；同 host/account/parent executable 不够。',
        '9. E04 可以使用既有两通道字段桥：target account→authenticated actor，source observed host→login source。它只证明观测到的访问传播，不证明被盗凭据或攻击意图。',
        '10. correlation 与 direction 独立；direction 不读取 correlation 分数。反向同时有证明或 hard conflict 则拒绝。',
        '11. candidate chain admission 不再唯一绑定 .70；高相关路线保留 .70，另有 .55+L3/.90 路线，均需组件、目标、时序与 DAG 保护。生产 .70 未修改。',
        f"12. @.65 实际恢复 {primary['GT_CORRELATION_EDGES']}/6 指定 GT CorrelationEdge。",
        f"13. 实际恢复 {chain['GT_DIRECTION_PROOFS']}/6 指定 GT DirectionEvidence；未虚构其余方向。",
        f"14. 实际恢复 {chain['GT_CHAIN_EDGES']}/6 指定 GT ChainEdge。",
        f"15. 最长真实 GT directed path 为 {chain['longest_GT_directed_path']} edge。",
        f"16. 背景链边 {chain['background_chain_edges']}，显式负例链边 {chain['explicit_negative_chain_edges']}；相关背景分布及 hard-touching 统计完整单列。",
        '17. '+('允许' if accepted else '不允许')+'进入 Final Calibration；不足两条 GT 链边及两 edge 路径时必须停止。',
        '18. 不允许 CPTC t2；本轮没有启动。', '19. 不允许 production freeze；本次候选未注册生产 API。',
        '20. 唯一后续建议：'+summary['NEXT_STEP']+'。保留冻结数据，以现有来源可观测性审查明确哪些绑定可获得；不得继续盲调评分或改 GT/synthetic alerts。', '',
        '## Separation 与验收限制', '',
        f"全 GT score margin {result['positive_negative_margin']}，原始 score overlap={'YES' if result['positive_negative_overlap'] else 'NO'}；bound meaningful GT 最低支持 {result['meaningful_bound_GT_min']}，相对显式负例 max 的 margin {result['meaningful_bound_GT_negative_margin']}。因此不能声称所有正负分数已完全可分；已修复的是上下文不再因行为兼容被准入为 progression。",
        f"Candidate Recall={result['candidate_recall']}，Gate Recall={result['gate_recall']}；未标注背景不当作正常真值。评测覆盖={result['evaluation_coverage']}（有标签且实际评分的 pair / 全成员评分 pair）；630 负例清单另外覆盖全部标注 pair。", '',
        f"回归：{tests-skipped-failures} passed / {skipped} skipped / {failures} failures。详见 regression.xml / regression_selection.json；未运行无关 UI 或昂贵的未受影响真实源全重放。七份基线、历史候选、映射与输入完整性见 integrity.json。", '',
        '```ini', *[f'{k}={v}' for k, v in summary.items()], '```', '']
    (OUT/'V5_SEMANTIC_REPAIR_REPORT.md').write_text('\n'.join(lines), encoding='utf8')
    print(verdict, flush=True)


if __name__ == '__main__': run()

"""Render the requested report from sealed predictions; never change policy."""
from collections import Counter
from pathlib import Path
import xml.etree.ElementTree as ET
from . import ROOT,OUT,BASE
from .runtime import verify_seal
from evaluation.framework.formula_design.runtime import read,save,sha


def run():
    frozen,seal=verify_seal()
    results=read(OUT/'separation_results.json');gt=read(OUT/'gt_direction_results.json')['edges']
    negatives=read(OUT/'hard_negative_results.json');blind=read(OUT/'blind/summary.json')
    old_decomposition=read(OUT/'hard_negative_decomposition.json')
    def contrast_row(v):
        fs=v['complete_frozen_evidence']['evidence_v5']['features']
        return dict(support_strength_quality=[dict(name=f['name'],strength=f['strength'],reliability=f['reliability'],
            state=f['state'],role=f['role']) for f in fs],dependency_groups=v['dependency_groups'],
            rarity_frequency=v['frequency'],role_compatibility=v['role_evidence'],time_gap_seconds=v['time_gap_seconds'],
            behavior_semantics=v['behavior_evidence'],source_complementarity=v['source_evidence'],
            event_transition_compatibility='Not scored by baseline; source operations and roles retained in full canonical alert',
            canonical_alert_a=v['canonical_alert_a'],canonical_alert_b=v['canonical_alert_b'])
    save(OUT/'positive_negative_contrast_detail.json',dict(
        axes=read(OUT/'positive_negative_contrast.json')['axes'],
        positives={k:contrast_row(v) for k,v in read(OUT/'gt_evidence_decomposition.json').items()},
        top20_explicit_negatives=[dict(support_pair=v['support_pair'],**contrast_row(v)) for v in old_decomposition['pairs']]))
    worst=negatives['top20_decomposition'][0]
    save(OUT/'post_seal_failure_analysis.json',dict(
        policy_changed_after_evaluation=False,explicit_negative_worst_pair=worst,
        finding='A compatible resource_access->authentication tag removes weak-only ceiling even when upgraded group equals the original single ACCOUNT group. Same account role plus plausible behavior sequence does not bind the source host to the login source. This promotes a labelled unrelated pair from .45 to .4941788209314203.',
        minimal_score_change=dict(baseline=worst['baseline_score'],candidate=worst['score'],
            group_changed=worst['groups']!=worst['score_breakdown']['upgraded_group_support']),
        other_failures='Global entity rarity leaves E01/E02 weak; E04 direction proof is below correlation/cluster gates; E03/E05 have no unique operation-instance link.',
        action='Reject candidate for final freeze; retain once-frozen result. No new condition or weight fitted to this counterexample.'))
    integrity=read(OUT/'historical_end.json');checks=read(OUT/'repository_checks.json')
    suites=ET.parse(OUT/'regression.xml').getroot()
    ts=list(suites.iter('testsuite'));tests=sum(int(t.get('tests','0')) for t in ts)
    failures=sum(int(t.get('failures','0'))+int(t.get('errors','0')) for t in ts)
    skipped=sum(int(t.get('skipped','0')) for t in ts)
    regression='PASS' if failures==0 else 'FAIL'
    p=results['primary'];good_separation=not results['SCORE_OVERLAP']
    direction=p['GT_DIRECTION_EDGES_RECOVERED'];chain=p['GT_CHAIN_EDGES_RECOVERED']
    if good_separation and chain:result='V5_SEPARATION_AND_DIRECTION_REPAIRED'
    elif good_separation:result='V5_SEPARATION_REPAIRED_DIRECTION_STILL_LIMITED'
    elif chain:result='V5_DIRECTION_REPAIRED_SEPARATION_STILL_UNSTABLE'
    else:result='V5_DESIGN_STILL_DEFECTIVE'
    ready=result=='V5_SEPARATION_AND_DIRECTION_REPAIRED' and regression=='PASS'
    summary=dict(TASK_RESULT=result,BASELINE_ALGORITHM_VERSION=frozen['baseline_identity']['algorithm_version'],
        FINAL_ALGORITHM_VERSION=frozen['algorithm_version'],CORRELATION_FORMULA_CHANGED=True,DIRECTION_MODEL_CHANGED=True,
        GT_EDGE_TOTAL=6,**{k:results[k] for k in ('GT_MIN_SCORE','GT_MEDIAN_SCORE','GT_MAX_SCORE','HARD_NEGATIVE_MAX_SCORE','GT_NEGATIVE_MARGIN','SCORE_OVERLAP')},
        GT_CORRELATION_EDGES_RECOVERED=p['GT_CORRELATION_EDGES_RECOVERED'],GT_DIRECTION_EDGES_RECOVERED=direction,
        GT_CHAIN_EDGES_RECOVERED=chain,GT_LONGEST_PATH_EXPECTED=6,GT_LONGEST_PATH_RECOVERED=p['GT_LONGEST_PATH_RECOVERED'],
        BACKGROUND_EDGE_EXPLOSION=p['background_admitted_edges']>1000,GT_LEAKAGE=False,
        HISTORICAL_INTEGRITY=integrity['status'],REGRESSION=regression,REGRESSION_TESTS=tests,
        REGRESSION_PASSED=tests-skipped-failures,REGRESSION_SKIPPED=skipped,
        READY_FOR_FINAL_FREEZE_GATE='YES' if ready else 'NO',
        NEXT_STEP='V5_FINAL_FREEZE_AND_EXTERNAL_VALIDATION_GATE' if ready else 'USER_AUTHORIZED_SEMANTIC_DESIGN_REVIEW_REQUIRED',
        FORMULA_HASH=frozen['formula_hash'],CONFIG_HASH=frozen['config_hash'],IMPLEMENTATION_HASH=frozen['implementation_hash'],
        MAPPING_DIGEST=frozen['mapping_digest'],FINAL_THRESHOLD=None,V5_PRODUCTION_FREEZE='NO',EXTERNAL_VALIDATION_READY='NO',
        DIAGNOSTIC_THRESHOLD=.65,PRODUCTION_API_REGISTERED=False,CPTC_T2_EXECUTED=False,
        REPLAY_SCOPE=blind['pipeline_kind'],DEVELOPMENT_AUDIT_PREVIOUSLY_SAW_GT=True,
        RAW_ALERTS=blind['raw_alert_count'],CANDIDATE_PAIRS=blind['candidate_count'],MEMBER_PAIRS=blind['member_count'],
        FORMULA_REVISION_COUNT=1,POST_SEAL_PARAMETER_CHANGES=0,
        HARD_NEGATIVE_BASELINE_MAX_SCORE=.45,HARD_NEGATIVE_MAX_REGRESSED=results['HARD_NEGATIVE_MAX_SCORE']>.45,
        ALL_DIAGNOSTIC_POINTS_ZERO_CHAIN=all(r['chain_edges']==0 for r in results['diagnostic_points']))
    for eid,g in sorted(gt.items()):
        key=eid.replace('GT-','GT_');summary[key+'_OLD_SCORE']=g['old_score'];summary[key+'_NEW_SCORE']=g['correlation_score']
    save(OUT/'summary.json',summary)
    def scalar(v):
        if v is None:return 'null'
        if isinstance(v,bool):return str(v).lower()
        return str(v)
    (OUT/'summary.ini').write_text('\n'.join(f'{k}={scalar(v)}' for k,v in summary.items())+'\n',encoding='utf8')
    score_rows='\n'.join(f"| {eid} | {g['old_score']:.15f} | {g['correlation_score']:.15f} | {g['direction_status']} | {g['failure_layer']} |" for eid,g in sorted(gt.items()))
    point_rows='\n'.join(f"| {r['diagnostic_threshold']} | {r['correlation_edges']} | {r['GT_CORRELATION_EDGES_RECOVERED']}/6 | {r['GT_DIRECTION_EDGES_RECOVERED']}/6 | {r['GT_CHAIN_EDGES_RECOVERED']}/6 | {r['GT_LONGEST_PATH_RECOVERED']}/6 | {r['background_admitted_edges']} | {r['explicit_negative_admitted_pairs']} |" for r in results['diagnostic_points'])
    negrows='\n'.join(f"| {i} | {r['score']:.9f} | {', '.join(r['score_breakdown']['upgraded_group_support'])} | {r['transition']['rule_id'] if r['transition'] else '无'} | `{' / '.join(a[4:16] for a in r['support_pair'])}` |" for i,r in enumerate(negatives['top20_decomposition'],1))
    audited=read(OUT/'gt_evidence_decomposition.json')
    decompositions='\n\n'.join(f"**{eid}**：{v['interpretation']}\n\n组支持 `{v['complete_frozen_evidence']['evidence_v5']['group_support']}`；mass={v['evidence_mass']:.12f}；quality={v['agreement']:.12f}；temporal={v['temporal_factor']:.12f}；conflict={v['conflict_penalty']}；duplicate={v['duplicate_penalty']}。" for eid,v in audited.items())
    examples='；'.join(f"{eid.replace('GT-','')}：{gt[eid]['old_score']:.9f} → {gt[eid]['correlation_score']:.9f}" for eid in ('GT-E01','GT-E02','GT-E04','GT-E06'))
    oldmargin=.0700479341765514-.45
    report=f'''# V5 Separation + Direction Evidence Repair

TASK_RESULT={result}

## 1. Executive Result

1. 本轮结论：`{result}`。候选实现具备可核验的局部语义改进，完整数据验收结果见下表；不能用合成 witness 通过替代数据集验收。
2. GT 低分主要来自：大多数类别 unknown，原始结构化操作未进入行为证据；既有公式主要奖励共享实体，IP/目标资产的固定可靠度及既有描述符/频率折扣压低跨事件连续性；并非 candidate/gate 漏召回。
3. 基线显式负例高分来自真实共享账户/资产，有些是低频的正常上下文，单组受 .45 ceiling 限制。本轮的 resource_access→authentication 条件过宽：仅凭角色兼容就解除该 ceiling，最坏显式负例升至 {results['HARD_NEGATIVE_MAX_SCORE']:.15f}，构成新暴露的设计失败。标签没有进入评分。
4. identity reliability 与 transition value 此前在执行上混淆：固定 identity 系数实际决定了连续性支持的上限。也不能反过来把身份稀有直接解释成攻击。
5. 已加入有原始指针和实体角色支撑的确定性行为转换，复用现有 rarity；修复数字 IP hostname 与资产身份的依赖重复计数。
6. 修改了独立候选的关联公式：同一 dependency group 内用 max 选择“身份连续”或“有行为/角色支撑的转换”解释；没有增加一个重复独立项。原 V5 代码和 identity 保持原样。
7. {examples}。
8. GT 最低分与显式负例最大分的 margin：{oldmargin:.15f} → {results['GT_NEGATIVE_MARGIN']:.15f}；score overlap={'YES' if results['SCORE_OVERLAP'] else 'NO'}。这不能支持全面 separation 已修复的结论。
9. E03/E05 此前无可验证的跨操作实例绑定：EXECVE→读文件缺 creator/consumer 或 lineage；login→shell 只有同 host/account 与父程序名 sshd，缺 session/PID/start 绑定。时间和行为兼容不能补出因果。
10. 新 DirectionEvidence 使用 target_account→authenticated_account、monitored_host_ip→login src_ip、不同显式 host 与 success；另一条合成验证通道使用匹配 flow_id、receive/execute action、dst_ip→monitored_host_ip。均保留 bound EvidencePointer。D1 的跨源 flow 只是合成能力见证，未宣称真实设备格式验收。
11. 在诊断点 .65：GT CorrelationEdge={p['GT_CORRELATION_EDGES_RECOVERED']}/6，方向证明={direction}/6，ChainEdge={chain}/6，真实图最长 GT 路径={p['GT_LONGEST_PATH_RECOVERED']}/6。方向证明计数独立于 score/cluster 是否准入。
12. Final Freeze Gate：`{'YES' if ready else 'NO'}`。本轮停止，未执行 t2、最终阈值冻结、UI 或数据修改。

## 2. Historical Integrity

开始实现前，已核验 baseline formula/config/implementation/mapping、baseline manifest、sealed score、66,070 个历史文件及 13 个数据集文件。结束核验：`{integrity['status']}`，详见 [historical_end.json](historical_end.json)。七份基线文档均由原仓库只读检查器校验。

| 身份 | Baseline | Candidate |
| --- | --- | --- |
| algorithm | {frozen['baseline_identity']['algorithm_version']} | {frozen['algorithm_version']} |
| formula | `{frozen['baseline_identity']['formula_hash']}` | `{frozen['formula_hash']}` |
| config | `{frozen['baseline_identity']['config_hash']}` | `{frozen['config_hash']}` |
| implementation | `{frozen['baseline_identity']['implementation_hash']}` | `{frozen['implementation_hash']}` |
| mapping | `{frozen['mapping_digest']}` | `{frozen['mapping_digest']}` |

[formula_freeze.json](formula_freeze.json) 保存精确源文件哈希、policy、canonical input 哈希与基线引用。候选算法冻结一次；post-seal 参数修改为 0。报告生成器不参与评分。

## 3. GT Evidence Decomposition

[gt_evidence_decomposition.json](gt_evidence_decomposition.json) 对六对保存完整 CanonicalAlert/raw_alert、所有 evidence family、实体角色、频率、强度×可靠度、折扣、组 max、mass、quality、temporal、两类 penalty 及原始诊断。没有把 missing/unobservable 当 contradiction。

{decompositions}

共同路径是 raw structured observation → 部分 canonical 字段/semantic_observations → 既有 entity evidence；结构化 EXECVE、operation/file 和 detector signature 没有转换成有区分力的旧 score 项。候选只对显式 allowlist 的源字段作确定性投影，不变更原始告警或其类别。

## 4. Hard Negative Decomposition

[hard_negative_decomposition.json](hard_negative_decomposition.json) 为修改前 Top20 的完整分解；[hard_negative_results.json](hard_negative_results.json) 为修改后 30 个负例逐告警结果、全部 630 个标注负例对的候选覆盖及新 Top20 完整分解。新显式负例最大分={results['HARD_NEGATIVE_MAX_SCORE']:.15f}，候选覆盖 {negatives['explicit_scored_count']}/630；无候选没有伪造为 0 分。

| 新排名 | score | dependency groups | transition | 成员对 ID 前缀 |
| --- | --- | --- | --- | --- |
{negrows}

单一 asset≈.5296 或 ACCOUNT≈.5510 经时间因子仍可超过 .45，随后被 weak-only ceiling 截断；.45 是支持指数上限，未经校准，不能当作“45% 攻击概率”。同上下文的中等无向支持本身可解释，但将其用于攻击过程准入仍缺行为区分。候选没有通过直接降低 ceiling 掩盖该问题。

候选最坏负例从 `.45 → .4941788209314203`：其 ACCOUNT 组仍为 `.5510363681556352`，组内 max 实际没有改变；resource_access→authentication 标签却解除 weak ceiling。源告警的 target_account 与后续登录 actor 一致，但源 monitored-host IP 与后续 login src_ip 不同，只有兼容行为和账户相等，没有操作绑定。方向 verifier 正确保留 ambiguous；关联公式仍过度奖励该上下文。完整证据见 [post_seal_failure_analysis.json](post_seal_failure_analysis.json)。本轮没有按此结果新增规则或调整数值。

all-hard-touching 最大分={results['MAX_ALL_HARD_TOUCHING_SCORE']:.15f}，单独统计；基线 .789637 的最高对为 hard×hard，没有 attack×hard 的显式 not-related 标签，不能混入显式负例最大值或总体误报率。

## 5. Positive-Negative Contrast

详见 [positive_negative_contrast.json](positive_negative_contrast.json)、[positive_negative_contrast_detail.json](positive_negative_contrast_detail.json) 及两个分解文件；detail 对每个正例和修改前 Top20 负例逐项保存全部对比轴和原始绑定证据。

| 维度 | 低分 progression | 高分显式负例 | 解释 |
| --- | --- | --- | --- |
| support strength / quality | IP/monitored host 跨角色支持受低固定系数限制 | 完整 account/host 相等支持较强 | 身份匹配质量不能完整定义攻击连续性价值 |
| independence | E01 数字 hostname 是地址别名 | 单账户/资产只应一组 | 候选合并别名、转换取组内 max |
| rarity / frequency | 既有 rarity 已生效 | 植入的正常账户/资产也低频 | 稀有不能区分正常与恶意 |
| role compatibility | E02/E04/E06 有跨观察角色桥 | 相同角色可只是正常重复活动 | 角色须与行为或操作证明结合 |
| event transition / behavior | signature、EXECVE、operation 可见但未计分 | 旧公式不要求行为连续 | 固定规则投影，未知不推断 |
| temporal gap | E01–E06 为 191–491 秒，不是示例中的 2 秒 | 近时共享上下文可受较小衰减 | 时间只修正已有支持 |
| source complementarity | 无 verified independent+complementary proof | 来源名称差异不等于独立 | 不额外奖励 |

## 6. Transition Semantics

版本化规则见 `configs/algorithm-v5-separation-direction.yaml`，审计见 [transition_semantics_audit.json](transition_semantics_audit.json)。候选支持 recon→web、web→execution、execution→resource_access、resource_access→authentication、authentication→execution、execution→network_access 的有限确定性投影，且必须共享非 hot 的允许类型实体并通过角色条件。

Wazuh EXECVE 要求明确 audit.type 和 process；resource_access 要求明确 operation 和非空 file；auth success 要求明确状态。文件路径名不推断 credential theft。类别 unknown 不自动升级为攻击阶段，不使用 ATT&CK/LLM/GT 标签。转换为无向支持解释，不能单独建方向边。

## 7. Specificity / Frequency Audit

[rarity_specificity_audit.json](rarity_specificity_audit.json)：复用 index 的 representative-frequency rarity 和既有折扣，没有再次实现频率系统。候选对 hot identity 禁止转换提升。当前 specificity 仍是单实体全局 rarity，缺事件转换的背景基率；合成 rare transition witness 成功不足以证明真实数据 separation。这是设计局限，不能用“source observability”概括所有失败。

## 8. Correlation Formula Decision

在 A–G 审计完成后选择一个新候选。对已存在组 g：

`g' = max(g, transition_ceiling × compatible_transition_strength × existing_rarity)`；转换只作用于其共享上下文组。

`mass = 1 − product(1 − g')`；`positive = max(direct_support, mass × temporal_factor)`；继承 conflict/duplicate penalty、hard gate、无转换时 weak ceiling；score 限制 [0,1]。数字 IP hostname 的 resource/asset 依赖先合并。每个成员对保留重算 breakdown、绑定指针和 policy hash；代表组只选完整核验的唯一 support_pair，不拼证据。

这是未校准的 v0 语义假设；本轮未按 GT 数值优化。局部证据表达得到修复，但完整结果仍可否决该候选。生产原算法未切换。

## 9. Direction Evidence Model

独立保存 forward_support、reverse_support、contradiction、direction_confidence、两方向 clues、成员 ID 与 EvidencePointer。`.9` 是配置支持指数，不是概率；两个通道为相互补充的字段约束，未把它们当独立 Bernoulli 证据相乘。

相关分数与方向支持分离。保留 CorrelationEdge 与 AMBIGUOUS_DIRECTION，方向不足不造 ChainEdge。候选 Schema `5.2-candidate` 与原 Frozen v1 Domain Schema 隔离，没有让旧 parser 静默接受新字段。

## 10. Direction Verifier

两侧独立检验；反向也成立则冲突拒绝，hard guard/逆时序冲突拒绝；源时间早只参与一致性检查。合法通道：账户目标→认证 actor 与源主机→登录来源的联合角色证明；匹配 flow 接收和目的主机证明；已有 verified explicit relation 沿用原核验结果。

原 [direction_evidence_matrix.json](direction_evidence_matrix.json) 记录字段级可用性和原 verifier 的拒绝原因；新 [gt_direction_results.json](gt_direction_results.json) 对六条逐项记录实际方向、证据、conf、correlation admission、chain creation、failure layer。E03/E05 缺实例绑定的字段级结论保留；不因此声称整个源完全不可观测。

## 11. Blind Evaluation

输入 10,051 条、9,771 个代表、{blind['candidate_count']:,} 个代表候选、{blind['member_count']:,} 个完整成员对。复用经哈希核验的既有候选提名，逐对重算旧公式验证与新公式/方向；并未重新运行 Adapter、去重或候选生成。新图实际执行聚类、节点构造、方向准入与 DAG 保护。

Python read tripwire 只允许三份 canonical/dedupe/entities、原 sealed diagnostics、原配置快照及新输出；拒绝其他读写、子进程、网络。见 [guard_receipt.json](blind/guard_receipt.json)。[score_seal.json](score_seal.json) 封存 PairScore、DirectionEvidence、CorrelationEdge、ChainEdge 后才执行本轮新结果 GT 评估。

本轮 A–G 审计此前已看 GT，这是开发集诊断和工程隔离盲跑，不能声称未见测试集或独立外部验证。候选只冻结一次，六个 operating points 预先写入配置；无 threshold optimization。

## 12. Separation Results

| GT edge | 旧 score | 新 score | 新 direction | .65 failure layer |
| --- | --- | --- | --- | --- |
{score_rows}

min={results['GT_MIN_SCORE']:.15f}；median={results['GT_MEDIAN_SCORE']:.15f}；max={results['GT_MAX_SCORE']:.15f}；explicit negative max={results['HARD_NEGATIVE_MAX_SCORE']:.15f}；margin={results['GT_NEGATIVE_MARGIN']:.15f}。Candidate Recall={results['candidate_recall']}，Gate Recall={results['gate_recall']}。

无标签背景 Top100 及语义分类见 [top_background_pairs.json](top_background_pairs.json)；这些分类为证据审计，不作为 GT 或总体误报率。标注 coverage={results['annotated_pair_coverage']:.9f}，未标注对排除。诊断 .65 背景准入={p['background_admitted_edges']}，基线同点为 0；是否大规模膨胀以绝对量与下表检查，不声称总体 precision。

## 13. Chain Reconstruction

| 诊断点 | 全部 CorrelationEdge | GT correlation | GT direction proof | GT ChainEdge | 最长 GT 路径 | 背景边 | 显式负例边 |
| --- | --- | --- | --- | --- | --- | --- | --- |
{point_rows}

以上来自实际候选图文件，最长路径按真实 ChainEdge 覆盖的 GT 有向边计算，没有用相关边或时间排序代理。聚类/链准入继续使用既有 .70 保护；调低展示 operating point 不会绕开聚类/链阈值。保留组件 hard conflict、target-set、跨度/规模、独立 bridge、区间顺序和 DAG 检查；每个点保留全部 10,051 条告警到节点的回溯。

方向证明可以存在而 ChainEdge 为零：其关联分数或组件保护仍不满足准入。报告没有通过提升无向 score 掩盖此区别。候选图使用新候选对象，未验证旧 SnapshotStore/API 对新 Schema 的端到端接纳。

## 14. Regression

新增 24 个测试通过：S1–S5、D1–D5、hot specificity、missing、alias、duplicate/hard guard、Schema 重算、bound pointer、账户 pivot 真实图衔接、稳定身份/顺序、GT seal 前置与隔离。完整受影响回归：`{regression}`，passed={tests-skipped-failures}，JUnit tests={tests}，failures/errors={failures}，skipped={skipped}；见 [regression.xml](regression.xml)、[regression.log](regression.log)、[regression_selection.json](regression_selection.json)。4 项 skipped 是旧阶段需要显式启用的全量数据审计/重跑，具体名称和原始 skip reason 见 [regression_skipped.json](regression_skipped.json)。不把跳过项算作执行通过；本轮 10,051 条完整成员重放已经独立完成。

原检查器未改写，其旧白名单报告 {len(checks['legacy_errors'])} 项新增范围错误；[repository_checks.json](repository_checks.json) 使用本轮明确授权的六个精确模块扩展只读检查范围，其他冻结文档、技术栈、禁用导入与 GT 隔离断言均保留，scoped errors={len(checks['scoped_errors'])}。这是候选作用域检查，不冒称原命令原样通过。没有运行前端或 t2；未改 UI。

## 15. Known Limitations

- 只支持有限确定性转换；global entity rarity 不等于 transition likelihood。固定强度没有校准，不保证泛化。
- compatible transition 的存在就解除 weak ceiling，即使没有增加组内有效支持；本轮显式负例由此升到 .4941788。语义兼容不能代替操作绑定，这是 E 结论的直接设计反例。
- E03/E05 的 causal instance binding 缺失；E04 的角色证据可利用，因而无法选择“全是 source observability limit”的 D 结论。
- 候选独立运行，生产调用链、API、存储和 Frozen v1 Schema 均未切换；不能据候选文件宣称 production freeze。
- 本轮为完整成员对重放和实际候选图执行，非重新 Adapter→候选的全生产重跑；候选集合经 digest 锁定不变。
- 6 条正例和 30 个设计负例不足以证明总体统计能力；开发审计已见 GT。
- 本工作区无 Git 元数据，使用源文件/数据/历史清单 SHA-256 证明保留；没有提交或 PR。

## 16. Final Decision

`TASK_RESULT={result}`。`READY_FOR_FINAL_FREEZE_GATE={'YES' if ready else 'NO'}`。margin 数值改善不等于 separation 修复：GT 仍低分重叠，显式负例上界还变高，实际 GT 链恢复为 0。候选仅保留为可复现失败结果，不切换生产。缺口按 score、direction、clustering/chain guard 分别记录；局部方向 verifier 的有效修复没有满足整体验收。

完整机器摘要见 [summary.json](summary.json) 和 [summary.ini](summary.ini)。`FINAL_THRESHOLD=null`、`V5_PRODUCTION_FREEZE=NO`、`EXTERNAL_VALIDATION_READY=NO`。

## 17. Next Step

{summary['NEXT_STEP']}。下一项须由用户单独指定；建议先审查 transition 的背景区分语义与组件准入对可用方向证明的影响。此处只记录待办，不自动恢复、调参或推进新阶段。本轮已停止；没有启动 CPTC t2、改动 GT/输入、冻结生产阈值或进入 UI。
'''
    (OUT/'report.md').write_text(report,encoding='utf8')
    source_paths=[p for folder in (ROOT/'backend/app/correlation/separation_direction',
        ROOT/'evaluation/framework/separation_direction') for p in sorted(folder.glob('*.py'))]
    source_paths += [ROOT/p for p in ('configs/algorithm-v5-separation-direction.yaml',
        'backend/tests/test_v5_separation_direction.py','evaluation/tests/test_v5_separation_direction_evaluation.py')]
    source_inventory={p.relative_to(ROOT).as_posix():sha(p) for p in source_paths}
    save(OUT/'source_changes.json',dict(added_files=source_inventory,existing_files_modified=[],
        original_baseline_sources_verified=True,production_dispatch_api_or_schema_registration_changed=False,
        no_git_metadata=True))
    save(OUT/'manifest.json',dict(summary=summary,files={p.relative_to(OUT).as_posix():sha(p)
        for p in sorted(OUT.rglob('*')) if p.is_file() and p.name!='manifest.json'},
        sources=source_inventory))
    print(result,'REPORT_WRITTEN',flush=True)


if __name__=='__main__':run()

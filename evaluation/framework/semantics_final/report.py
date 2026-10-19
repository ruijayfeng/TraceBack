"""Deliver measured results and a fail-closed freeze decision, without rescoring."""
from collections import Counter
from pathlib import Path
import json,xml.etree.ElementTree as ET
from . import ROOT,OUT
from .runtime import verify_freeze,verify_seal,verify_history
from evaluation.framework.formula_design.runtime import read,save,sha

def junit(path):
    root=ET.parse(path).getroot()
    suites=[root] if root.tag=='testsuite' else list(root.iter('testsuite'))
    return {k:sum(int(s.attrib.get(k,0)) for s in suites) for k in ('tests','failures','errors','skipped')}

def run():
    frozen=verify_freeze();seal=verify_seal()
    cal=read(OUT/'calibration.json');chain=read(OUT/'chain_validation.json')
    gt=read(OUT/'ground_truth_edge_scores.json');neg=read(OUT/'hard_negative_scores.json')
    bg=read(OUT/'top_background_pairs_review.json');dist=read(OUT/'blind_score_distribution.json')
    checks={name:junit(OUT/(name+'.xml')) for name in ('regression','postseal_tests','repository')}
    regression=all(r['failures']==r['errors']==0 for r in checks.values())
    repo=read(OUT/'repository_check.json')
    ui=read(OUT/'frontend_checks.json')
    regression=regression and repo['status']=='passed' and all(v['exit_code']==0 for v in ui['commands'])
    receipt=OUT/'historical_end_verification.json'
    if not receipt.exists():
        from .runtime import history_end
        history_end()
    history=read(receipt)
    if history['inventory_sha256']!=sha(OUT/'historical_before.json'):raise ValueError('history_inventory_changed')
    stable=cal['selected_threshold'] is not None
    selected=cal['selected_threshold']
    operating=chain['operating_threshold']
    def sweep(t):return min(cal['threshold_sweep'],key=lambda r:abs(r['threshold']-t))
    row=sweep(selected if stable else operating);allgt=sweep(cal['all_GT_threshold'])
    admitted=chain['CorrelationEdges_recovered']
    ready=bool(stable and admitted==6 and chain['ChainEdges_recovered']==6 and
               chain['Longest_GT_path_recovered']==6 and regression and history['status']=='PASS')
    result=('V5_READY_FOR_EXTERNAL_VALIDATION' if ready else
            'V5_FORMULA_VALID_THRESHOLD_UNSTABLE' if not stable else
            'V5_CHAIN_RECONSTRUCTION_STILL_BROKEN' if admitted==6 and chain['ChainEdges_recovered']<6 else
            'V5_CALIBRATION_FAILED')
    final_threshold=selected if ready else None
    summary=dict(TASK_RESULT=result,V5_PRODUCTION_FREEZE='YES' if ready else 'NO',
        EXTERNAL_VALIDATION_READY='YES' if ready else 'NO',ALGORITHM_VERSION=frozen['algorithm_version'],
        FORMULA_HASH=frozen['formula_hash'],CONFIG_HASH=frozen['config_hash'],
        FINAL_THRESHOLD=final_threshold,GT_EDGE_TOTAL=6,GT_EDGE_CANDIDATE=sum(r['candidate_present'] for r in gt['edges'].values()),
        GT_EDGE_GATE_PASS=sum(r['gate_pass'] for r in gt['edges'].values()),GT_EDGE_ADMITTED=admitted,
        GT_MIN_SCORE=gt['min'],GT_MAX_SCORE=gt['max'],GT_MEDIAN_SCORE=gt['median'],HARD_NEGATIVE_TOTAL=30,
        HARD_NEGATIVE_FP=row['Hard_Negative_FP'],HARD_NEGATIVE_MAX_SCORE=cal['MAX_HARD_NEGATIVE_SCORE'],
        HARD_NEGATIVE_ALL_TOUCHING_MAX_SCORE=cal['MAX_ALL_HARD_TOUCHING_SCORE'],
        GT_NEGATIVE_MARGIN=cal['GT_NEGATIVE_MARGIN'],BACKGROUND_ADMITTED_EDGES=row['background_admitted_edges'],
        TOTAL_CORRELATION_EDGES=row['total_admitted_edges'],GT_CHAIN_EDGES_RECOVERED=chain['ChainEdges_recovered'],
        GT_LONGEST_PATH_EXPECTED=6,GT_LONGEST_PATH_RECOVERED=chain['Longest_GT_path_recovered'],
        OVER_CORRELATION='YES' if allgt['background_admitted_edges']>=1000 else 'NO',
        OVER_CORRELATION_THRESHOLD=cal['all_GT_threshold'],DIAGNOSTIC_THRESHOLD=operating,
        SCORE_OVERLAP='YES' if cal['SCORE_OVERLAP'] else 'NO',HISTORICAL_INTEGRITY=history['status'],
        REGRESSION='PASS' if regression else 'FAIL',
        NEXT_STEP='CPTC_T2_EXTERNAL_VALIDATION' if ready else 'V5_DEVELOPMENT_REVIEW_SEPARATION_AND_DIRECTION_EVIDENCE')
    save(OUT/'summary.json',dict(**summary,diagnostic_only=not ready,diagnostic_threshold=operating,
        operating_counts_scope='Measured actual diagnostic replay; FINAL_THRESHOLD null means no production operating point',
        full_recall_point=allgt,regression_detail=checks,frontend=ui,repository_check=repo,
        implementation_hash=frozen['implementation_hash'],mapping_digest=frozen['mapping_digest']))
    old=read(ROOT/'outputs/v5_formula_repair_integration/gate_analysis.json')
    f3=read(ROOT/'outputs/v5_formula_repair_integration/ground_truth_edge_scores.json')['edges']
    e01=gt['edges']['GT-E01']
    gate=dict(E01_BEFORE_GATE=old['GT_E01']['gates'],E01_F3_BEFORE_THIS_TASK=f3['GT-E01']['breakdown']['gate'],
        E01_AFTER_GATE=e01['breakdown']['gate'],WHY_CHANGED='F2 role whitelist was already removed by the preceding F3 integration. This candidate preserves that repair and adds explicit five-state semantics and dependency grouping; no new GT-specific gate exception.',
        GENERAL_RULE='Affirmative non-temporal contextual support may reach scoring without strong-role evidence; hard isolation, explicit reversed propagation and duplicate-observation rejection remain mandatory.',
        admitted_at_diagnostic=e01['score']>=operating,score=e01['score'])
    save(OUT/'gate_repair.json',gate)
    def val(v):return 'null' if v is None else str(v)
    edge_table='\n'.join('| '+k+' | '+format(r['score'],'.15g')+' | '+str(r['gate_pass'])+' | '+str(r['independent_support_count'])+' | '+str(r['verified_relation_count'])+' | '+chain['failures'][k]+' |' for k,r in sorted(gt['edges'].items()))
    explicit_keys={':'.join(sorted(r['max_explicit_pair'])) for r in neg['alerts'] if r['max_explicit_pair']}
    highest=sorted((r for k,r in neg['highest_pair_explanations'].items() if k in explicit_keys),
                   key=lambda r:(-r['score'],r['support_pair']))[:5]
    hard_table='\n'.join('| '+format(r['score'],'.15g')+' | '+json.dumps(r['groups'],ensure_ascii=False)+' | '+str(r['temporal_factor'])+' | '+str(r['duplicate_penalty'])+' | '+str(r['conflict_penalty'])+' |' for r in highest)
    grid='\n'.join('| '+str(r['threshold'])+' | '+str(r['GT_TP'])+' | '+str(r['Hard_Negative_FP'])+' | '+str(r['total_admitted_edges'])+' | '+str(r['background_admitted_edges'])+' | '+str(r['multi_alert_incidents'])+' | '+str(r['chain_edges'])+' | '+str(r['GT_longest_path'])+' |' for r in cal['threshold_sweep'] if round(r['threshold'],2)==r['threshold'] and .4<=r['threshold']<=.8)
    ini='\n'.join(k+'='+val(v) for k,v in summary.items())
    text=f'''# V5 Evidence Semantics Repair + Final Calibration

TASK_RESULT={result}

V5_PRODUCTION_FREEZE={summary['V5_PRODUCTION_FREEZE']}
EXTERNAL_VALIDATION_READY={summary['EXTERNAL_VALIDATION_READY']}

## 1. Executive Result

1. 本轮结果为 `{result}`。
2. 五状态明确分离缺失、不可比较、中性零支持、正支持与显式反证；asset/resource/execution 等依赖组取最大值，多个独立上下文可累积并解除单线索 ceiling。F3 既有“无全家族分母惩罚”与弱上下文准入保留。
3. MISSING=字段/关系缺失；UNOBSERVABLE=已知抑制、未声明比较 scope 或不适用；OBSERVED_NEUTRAL=可比较但不支持且无排他冲突；OBSERVED_SUPPORT=strength>0；OBSERVED_CONTRADICTION=明确冲突证明。前三者均不进入支持分母或负项。
4. E01 gate={e01['gate_pass']}。F2 原 gate=false；历史 F3 已经 gate=true，本轮仍 true。不能把前一阶段已有修复宣称为本轮新修复。E01 的弱分数与 gate 拒绝是两个不同问题。
5. 公式 `{frozen['algorithm_version']}`；formula_hash=`{frozen['formula_hash']}`。
6. 六条 GT 分数见下表，范围 [{gt['min']}, {gt['max']}]。
7. 30 个 hard-negative 告警对 21 个 attack 告警的显式负链接最高分={cal['MAX_HARD_NEGATIVE_SCORE']}；所有 hard-touching 候选（含未标注 hard-hard/background）最高分={cal['MAX_ALL_HARD_TOUCHING_SCORE']}，两种口径均披露。
8. GT_NEGATIVE_MARGIN={cal['GT_NEGATIVE_MARGIN']}；SCORE_OVERLAP={summary['SCORE_OVERLAP']}。
9. 正式 threshold={val(final_threshold)}。{'提名阈值通过完整验收。' if ready else '没有通过全部验收的 production threshold；0.65 仅为明确标注的诊断重放点，不是冻结结果。'}
10. 诊断点恢复 GT CorrelationEdge={admitted}/6，GT ChainEdge={chain['ChainEdges_recovered']}/6，GT longest path={chain['Longest_GT_path_recovered']}/6；总正式无向边={row['total_admitted_edges']}。
11. 诊断点 background admission={row['background_admitted_edges']}；全 GT 召回分数边界 background admission={allgt['background_admitted_edges']}。背景未标注，admitted 不等于已证误报；Top100 仅语义审计。
12. production freeze={summary['V5_PRODUCTION_FREEZE']}，external validation ready={summary['EXTERNAL_VALIDATION_READY']}。本轮未启动 t2，完成后停止。

## 2. Historical Integrity

起始和结束均核验历史文件与冻结数据。结尾状态={history['status']}；历史 {history['historical_count']} 文件、数据 {history['dataset_count']} 文件。包含 V4 预测、preformula baseline、前次 blind predictions、mapping、manifest 与原始半合成数据；测试临时目录不作为历史 artifact。基线既有声明哈希也在开始时比对，不能只依赖新采集哈希掩盖旧损坏。

本轮新产物仅在本目录；历史目录没有重写。评分从 byte-sealed CanonicalAlert/DedupeGroup/Entity 起点重放，而不是重做 adapter/projection。数据 fingerprint、原始输入、场景和 GT 的哈希均保持，10051=10000 background+21 attack+30 hard negatives。没有用 synthetic 冒充真实厂商能力验收。

## 3. Evidence Semantics Repair

完整 21-family 审计见 evidence_semantics_matrix.json。不存在产品名推断的完整 source-capability 矩阵：无法证明“不具备采集能力”时只记字段 MISSING，跨源身份无法比较或已知抑制则记 UNOBSERVABLE。可比较但不相同通常是 NEUTRAL，不能自动变为排他身份冲突。

所有 positive family 保留原角色、频率、descriptor 质量折扣。metadata/category、transport、source 名称和时间不单独创建 semantic context。共享 IP/主机/端点/flow 合并 asset，DOMAIN/URL 合并 resource，PROCESS/FILE/COMMAND 合并 execution；实体 ID 重叠再作依赖连通合并。组内 max 防止同一事实重复包装。

本次接续时五状态实现与配置已经存在但没有最终目录；先审计，再运行无 GT 单元见证，随后冻结一次。没有新数值搜索，也未针对某条 GT 改权重。明确反证才产生 conflict penalty；different-target/no-context 等不能证明排他冲突的 soft 启发式不充当本公式反证，既有 hard guard、Target Set 与显式方向要求继续执行。

## 4. Gate Repair

E01_BEFORE_GATE（历史 F2）=false；E01_F3_BEFORE_THIS_TASK=true；E01_AFTER_GATE={str(e01['gate_pass']).lower()}。

GENERAL_RULE：有实际非时间上下文即允许评分，缺 host/account/monitored endpoint 不是拒绝理由。WHY_CHANGED：角色白名单移除已在前次 F3 完成，本轮保留并验证通用规则。namespace 隔离、字段证明的反向传播与 duplicate observation 仍可直接拒绝；普通单线索/hot-only 受可靠度与 ceiling 控制，不会因通过 gate 就自动成为正式边。gate_repair.json 保留原始前后字段。

## 5. Formula

设依赖组 g 的最强正支持为 v_g=max(strength_i × reliability_i)，仅选 OBSERVED_SUPPORT 的 entity/relation（direct 另作备择路径）。

```text
agreement = Σ(s_g r_g) / Σ(r_g)       # 仅正支持；诊断语义一致度
mass = 1 - Π(1-v_g)
temporal = 0.8 + 0.2 × exp(-ln(2) × gap / half_life)
direct = max(verified_direct_strength × reliability)
positive = max(direct, mass × temporal)
raw = positive - 0.45 × explicit_conflict - 0.40 × duplicate
score = clamp(raw, 0, 1)
```

若无 direct/具体 SESSION或PROCESS 且不足两个非 hot 正支持依赖组，则 score≤0.45。hard contradiction、显式反向传播、duplicate observation 或无非时间支持则 score=0。agreement 为上下文诊断，不是概率；缺失不影响 agreement，evidence mass 仍体现现有证据不足。direct 与其他视图取 max，避免重复加分。role consistency 通过原字段角色 factor，source capability 只决定状态，source complement 不重复增加基础事实质量。

理论范围 [0,1]；3 个独立 s=.7,r=.7 的中等线索：无时间正支持仍可达 0.6938792，有 time=1 达 0.867349；3 个 .8×.8 线索/time=1 达 0.953344；真实可核验 direct=1 达 1；单一普通 IP≤0.15。hot-only 不能绕 ceiling。反证扣分和 hard 拒绝在无 GT 单元见证中验证。

全部 reliability 未改，配置见 formula_freeze.json/effective；IP=.15、DOMAIN=.10 等低可靠线索仍可能得低分，解除 ceiling 不承诺其必然达正式阈值。实际弱证据质量与“证据项数量”不能混淆。

formula_hash=`{frozen['formula_hash']}`
config_hash=`{frozen['config_hash']}`
implementation_hash=`{frozen['implementation_hash']}`
mapping_digest=`{frozen['mapping_digest']}`

公式/状态/gate/生产 Python/候选/投影在盲算前封存；所有后续读取均复核 freeze 和 score seal。没有 score→改公式→再评分循环。旧 F3 的执行身份继续仅用于历史兼容，本轮唯一候选为 evidence-semantics-v1。

## 6. Blind Score Distribution

候选={dist['candidate_count']}；完整原始成员评分={dist['scored_count']}；gate rejected={dist['gate_rejected_count']}。candidate digest 相同={seal['candidate_identity_equal']}；无 resource truncation 的完整状态见 blind/record.json。量化分布与 histogram 在 blind_score_distribution.json、score_histogram.json。候选与成员数量口径不同，不把组内成员核验当新独立候选。

```json
{json.dumps(dist['score_quantiles'],ensure_ascii=False,indent=2)}
```

评分 Python audit guard 的 non_code_reads/rejected_events 见 blind/guard_receipt.json。它是进程内可核验 read tripwire，不宣称 OS 级 sandbox。评分期间未读取 GT、未联网、未访问 t2；所有分数先 sealed 才加载 evaluation labels。

## 7. GT Results

| Edge | 未舍入 score | Gate | 独立组数 | Verified relations | 诊断重放失败点 |
|---|---:|---|---:|---:|---|
{edge_table}

Candidate Recall={gt['candidate_recall']}；Gate Recall={gt['gate_recall']}；GT median={gt['median']}。逐边排名、support/contradiction families、mass、agreement 和完整 breakdown 见 ground_truth_edge_scores.json。这里只用封存结果，不重新算分；未入选/漏候选不从分母消失。

## 8. Hard Negative Results

30 个设计 hard-negative 告警，显式负链接=30×21=630。已评分负链接={neg['scored_explicit_negative_pairs']}；不在候选中的链接不伪造零分，正阈值下按无预测 TN 计数。每个 hard alert 用其显式负链接的最大分统计 FP；pair FP 单独保留，不能混用两个统计单位。

```json
{json.dumps(neg['per_alert_max_distribution'],ensure_ascii=False,indent=2)}
```

hard_negative_scores.json 对每个 hard alert 保存 max/pair、显式负链接分布、所有 touching 分布和最高分解释。最高分 hard pair 共享的 account/asset/session 等真实上下文仍可产生高分，而 GT 的 src/domain 或描述性执行证据可靠度较低，形成重叠；缺失证据不是反证也不保证可判别。unknown background touching 不自动作为已标注 negative。

30 个告警中有 {neg['per_alert_max_distribution']['count']} 个的显式负链接进入候选，其余没有可报告分数，保留 null；不能把这些缺失分数混入 median/p95。所有 hard-touching 候选最高分={cal['MAX_ALL_HARD_TOUCHING_SCORE']}；诊断点有 {row['hard_touching_admitted_edges']} 条 hard-touching admission，即使显式负链接 FP={row['Hard_Negative_FP']}，也不能宣称所有涉及 hard alert 的关联都正确。

最高的显式负链接具体分解如下；每组数值为 max(strength×reliability)，不是实体出现次数，完整 pointer/字段依据在 JSON 中。

| Score | Dependency group support | Temporal factor | Duplicate penalty | Conflict penalty |
|---:|---|---:|---:|---:|
{hard_table}

## 9. Background Top-Pair Audit

审计真实 background 双端 Top {len(bg['pairs'])}，另附非 GT 总体 Top100（含 hard/attack）；类别计数={json.dumps(bg['counts'],ensure_ascii=False)}。检查 hot、duplicate observation、相同 detector/signature、单源地址复现、网络/transport/time 巧合和派生事实重复。每对保留实际证据，见 top_background_pairs_review.json。

分类是确定性语义诊断，不是人工已核真值，未回灌公式。MAX_BACKGROUND_SUSPICIOUS_SCORE={val(cal['MAX_BACKGROUND_SUSPICIOUS_SCORE'])}；只代表 Top100 中 LIKELY_FALSE/DUPLICATE_OBSERVATION/HOT_ENTITY_ARTIFACT 的最大值，不宣称覆盖所有未知背景误报。

Top100 中同 detector={sum(r['same_detector'] for r in bg['pairs'])}、同 signature={sum(r['same_signature'] for r in bg['pairs'])}。最高背景分={max((r['score'] for r in bg['pairs']),default=None)}：常见模式为相同扫描源/目标及 URL 的短时间重复告警，asset+resource 两组足以形成无向合理性，但不证明不同攻击步骤或同一底层 observation。既有 observation verifier 没有证明重复时不擅自标成已确认 DUPLICATE_OBSERVATION。PLAUSIBLE 不是安全负例或已确认相关；全召回点的 112k 量级首先是运行负担/过度连边问题，不能借未标注背景宣称已测得真实世界 FPR。

## 10. Threshold Calibration

先冻结公式再扫 .40–.80（步长 .02），另加 GT/negative 分数边界和 nextafter。精确表见 threshold_sweep.csv/calibration.json。TP/FN=6，Hard FP/TN=30；pair precision/F1 限已标注的 6+630，不代表总体性能。原聚类/chain score floor=.70、direction=.75 与所有方向/目标保护保持，表中图指标来自实际 production reconstruction，低 admission 差异没有资格改变≥.70 的图。

| Threshold | GT TP | Hard-alert FP | Total edges | Background edges | Multi-alert incidents | Chain edges | GT longest path |
|---:|---:|---:|---:|---:|---:|---:|---:|
{grid}

MIN_GT_SCORE={gt['min']}
MAX_HARD_NEGATIVE_SCORE={cal['MAX_HARD_NEGATIVE_SCORE']}
MAX_BACKGROUND_SUSPICIOUS_SCORE={val(cal['MAX_BACKGROUND_SUSPICIOUS_SCORE'])}
GT_NEGATIVE_MARGIN={cal['GT_NEGATIVE_MARGIN']}
SCORE_OVERLAP={summary['SCORE_OVERLAP']}

全 GT correlation 召回边界={cal['all_GT_threshold']}，该点 hard-alert FP={allgt['Hard_Negative_FP']}/30、background={allgt['background_admitted_edges']}、total={allgt['total_admitted_edges']}。没有以数千背景边换取漂亮的 6/6，也没有因失败再修改公式。预先声明的安全区间标准是全 GT/0 hard-alert FP/background≤1000/宽度≥.02，不能视为经现实业务校准的 SLA。选定正式阈值={val(final_threshold)}；提名 stable interval={cal['stable_interval']}。

## 11. End-to-End Reconstruction

使用封存 PairScore 运行实际 correlation edge→controlled incident→node→direction→ChainEdge→grounding/storage；没有以连通分量或时间排序代替生产实现。诊断 admission={operating}，总 CorrelationEdges={row['total_admitted_edges']}；GT 恢复={admitted}/6；总 ChainEdges={chain['summary']['chain_edge_count']}，GT 有向边={chain['ChainEdges_recovered']}/6；GT longest path={chain['Longest_GT_path_recovered']}/6。所有实际领域表持久化往返={chain['all_tables_roundtrip']}，grounding={chain['grounding_valid']}。

实际 Incident={chain['summary']['incident_count']}，其中 multi-alert Incident={chain['summary']['multi_alert_incident_count']}、singleton={chain['summary']['singleton_incident_count']}；ChainNode={chain['summary']['chain_node_count']}。节点可回溯率={chain['summary']['grounding']['node_traceability']}；零条正式 ChainEdge 的边可回溯率为 null（不适用），不能以 100% 表示。所有 {row['total_admitted_edges']} 条关联边均保留在 unresolved 诊断中，方向拒绝见实际 replay diagnostics。

7 个 GT 节点的告警证据保留数={chain['GT_NODES_RETAINED']}，跨预测节点的稳定一对一 alert-overlap 支撑匹配={chain['GT_NODES_SUPPORT_MATCHED']}，完全相同 category/GT stage 的诊断匹配={chain['GT_NODES_EXACT_STAGE_MATCHED']}。GT_NODES_RECOVERED={val(chain['GT_NODES_RECOVERED'])}；GT 无冻结 Category 翻译及 gold Incident 匹配契约，正式 RQ3 节点恢复不可计算，不能以告警保留冒充完整节点恢复。每条 GT 的失败分层见 chain_validation.json。若无 verified explicit relation，分数再高也不能发布方向边。

Explain/ATT&CK 对实际图检查证据闭包；没有 GT 有向路径时不生成虚构路径说明。真实外部 AI provider 调用没有执行；Fake provider 的 grounded summary/ATT&CK、API故障降级与引用闭包由回归测试验证，不声称真实 provider 的全数据端到端已验收。

## 12. Regression

```json
{json.dumps(checks,ensure_ascii=False,indent=2)}
```

覆盖历史 v0/v2/v3/v4/F3、候选、证据、评分、incremental、API、Incident、Chain、Stable ID、Schema、Grounding、LLM/Explain 和 GT isolation。预运行 32 个 F3/语义测试通过，新增两个真实 scorer 控制后语义套件 22/22 通过。正式 regression 的 post-seal artifact 用例在初次盲算期间尚未生成而 skip，完成产物后单独执行并通过，不隐藏 skip。既有数据条件 skip 数见 XML。

前端既有 tests=35/35、typecheck/build 已通过；旧 UI 的 ObjectDetail 假定旧七项 breakdown，V5 需 legacy_audit 显示兼容，现有 tests 未覆盖 V5，因此不能把这些通过宣称为 V5 UI 验收。按本任务不重做前端，记录为继承限制。仓库检查仅补登记三个本次已授权 V5 源文件，未放宽 GT/需求哈希/未知文件检查；repository_check={repo['status']}。

## 13. Known Limitations

- 单一 development fixture 仅六条正例边和三十个设计负例，不能证明现实总体性能；没有独立测试集、没有 t2。
- 稀疏上下文虽通过 gate，但支持可靠度仍不足以和某些共享高质量上下文的负例分离；这属于当前候选的实测能力边界，不再追逐单边调权重。
- 不能从 entity equality/category/time 自动推断因果；现有 verifier 未接受的传播不能为了验收强行构造。
- 未有完整声明的 source-capability/exclusivity 证据接口；未证明的 session 冲突不伪造。具体状态与 gate 限制见审计。
- score 是证据支持指数，不是校准概率；evidence_mass/quality 也不表示攻击已确认。
- 真实 provider 的全量解释与 V5 UI 展示兼容不属于本轮已通过的能力。

## 14. Freeze Decision

公式候选已冻结，production algorithm/threshold 未因一次小样本校准自动冻结。最终 V5_PRODUCTION_FREEZE={summary['V5_PRODUCTION_FREEZE']}。{'全项通过，可进入外部验证。' if ready else '未满足稳定分离与完整有向攻击链验收，保留失败结果和全部 artifacts；不发布正式阈值。'}

## 15. Next Step

NEXT_STEP={summary['NEXT_STEP']}

本轮到此停止。后续工作需用户另行指定，不自动启动 CPTC t2、改数据或继续调公式。

```ini
{ini}
```
'''
    (OUT/'V5_EVIDENCE_SEMANTICS_FINAL_REPORT.md').write_text(text,encoding='utf8')
    delivered=[p for p in OUT.iterdir() if p.is_file() and p.name!='manifest.json']
    for directory in ('blind','downstream','evaluation'):
        delivered.extend(p for p in (OUT/directory).rglob('*') if p.is_file())
    save(OUT/'manifest.json',dict(algorithm_version=frozen['algorithm_version'],formula_hash=frozen['formula_hash'],
        config_hash=frozen['config_hash'],implementation_hash=frozen['implementation_hash'],mapping_digest=frozen['mapping_digest'],
        result=result,ground_truth_used_only_after_seal=True,formula_revision_count=1,weights_changed=False,
        historical_integrity=history,production_freeze=ready,t2_executed=False,
        files={p.relative_to(OUT).as_posix():sha(p) for p in sorted(delivered)}))
    print(ini,flush=True)

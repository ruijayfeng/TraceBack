"""Assemble the review package from measured artifacts; never tune or score."""
from pathlib import Path
import json
import xml.etree.ElementTree as ET
from . import ROOT,OUT
from .runtime import verify_seal
from evaluation.framework.formula_design.runtime import read,save,sha


def test_result(name):
    suites=ET.parse(OUT/name).getroot().findall('testsuite')
    def identity(test):
        classname=test.get('classname','')
        if not classname:
            matches=[p.split('::')[0] for p in read(OUT/'regression_selection.json')['targets']
                if p.endswith('::'+test.get('name'))]
            if len(matches)==1:classname=Path(matches[0]).stem
        parts=classname.split('.')
        start=next((i for i,p in enumerate(parts) if p.startswith('test_')),0)
        return '.'.join(parts[start:])+'.'+test.get('name')
    counts={k:sum(int(s.get(k,0)) for s in suites) for k in ('tests','failures','errors','skipped')}
    failures=[dict(test=identity(t),message=f.get('message'),text=f.text)
        for s in suites for t in s.findall('testcase') for f in list(t) if f.tag in {'failure','error'}]
    skipped=[dict(test=identity(t),message=f.get('message'),text=f.text)
        for s in suites for t in s.findall('testcase') for f in t.findall('skipped')]
    return dict(**counts,passed=counts['tests']-counts['failures']-counts['errors']-counts['skipped'],
        cases=[identity(t) for s in suites for t in s.findall('testcase')],
        failure_details=failures,skipped_details=skipped,junit=name)


def run():
    seal=verify_seal();frozen=read(OUT/'formula_freeze.json');before=read(OUT/'before.json')
    ev=read(OUT/'evaluation_summary.json');dist=read(OUT/'score_distribution.json')
    chain=read(OUT/'chain_validation.json');gt=read(OUT/'ground_truth_edge_scores.json')
    tests=test_result('regression.xml');contract=test_result('contract_final.xml');current_receipt=test_result('current_receipt.xml')
    # The full run may have collected the 11-test module before its API case
    # was added. Count unique identities; preserve both complete JUnit reports.
    passed_cases=set(tests['cases'])|set(contract['cases'])|set(current_receipt['cases'])
    failures={r['test']:r for r in tests['failure_details']+contract['failure_details']}
    resolved=[]
    if not current_receipt['failures'] and not current_receipt['errors']:
        for name in current_receipt['cases']:
            if name in failures:resolved.append(failures.pop(name))
    protected={name:dict(expected=h,actual=sha(ROOT/name)) for name,h in before['protected_files'].items()}
    changed={n:r for n,r in protected.items() if r['expected']!=r['actual']}
    dataset_root=Path(r'D:\Code_WorkSpace\TraceBack-Dataset')
    data={name:dict(expected=h,actual=sha(dataset_root/name)) for name,h in before['dataset_files'].items()}
    data_changed={n:r for n,r in data.items() if r['expected']!=r['actual']}
    current={p.relative_to(ROOT).as_posix():sha(p) for p in (ROOT/'backend/app').rglob('*.py')}
    source_changes={n:dict(before=before['production_files'].get(n),after=current.get(n))
        for n in sorted(set(before['production_files'])|set(current)) if before['production_files'].get(n)!=current.get(n)}
    regression=dict(affected_suite=tests,contract_suite=contract,current_receipt_suite=current_receipt,
        selection=read(OUT/'regression_selection.json'),
        superseded_source_pin_failures=resolved,unique_test_cases=len(passed_cases),
        unique_tests_failed=len(failures),unique_tests_passed=len(passed_cases)-len(failures)-tests['skipped'],
        historical_v4_integrity='PASS' if not changed else 'FAIL',protected_file_count=len(protected),
        changed_protected_files=changed,original_configs_unchanged=not any(n.startswith('configs/') for n in changed),
        v4_serializer_source_unchanged='backend/app/models/scoring.py' not in source_changes,
        candidate_generator_source_unchanged='backend/app/correlation/candidates.py' not in source_changes,
        test_note='Affected suite plus final API-contract and active-receipt supplements; repeated identities counted once. Interrupted whole-repository attempts are not counted. Earlier fixture failure retained in contract.xml.',
        modified_production_sources=source_changes,frontend_changed=False)
    save(OUT/'regression_summary.json',regression)
    from app.models.correlation_v5 import ScoreBreakdownV5
    schema=ScoreBreakdownV5.model_json_schema()
    save(OUT/'score_breakdown_v5.schema.json',schema)
    save(OUT/'schema_contract.json',dict(schema_version='5.0',algorithm_version=frozen['algorithm_version'],
        implementation_version=frozen['implementation_version'],config_hash=frozen['config_hash'],mapping_digest=frozen['mapping_digest'],
        formal_contract='backend/app/models/correlation_v5.py:ScoreBreakdownV5',schema_ref='score_breakdown_v5.schema.json',
        feature_families=['time','entity','relation','behavior','source','conflict'],
        states=['SUPPORTED','UNOBSERVABLE','OBSERVED_ZERO','CONTRADICTED'],
        arithmetic='group maxima -> bounded semantic union; direct proof alternative; temporal modulation; explicit penalties; weak cap; hard guards',
        provenance='EvidencePointer(alert_id,pointer,side), restricted to support_pair; reasons and raw canonical evidence retained',
        precision='full-precision feature strengths and sealed member scores; six-decimal public score/raw_total; unrounded selection and thresholds',
        replay_semantics='No original CorrelationScorer.score_pair evidence extraction after labels; sealed PairScore lookup only. Schema re-evaluates arithmetic on the same sealed feature values as a consistency check.',
        identity=frozen,serialization=True,deserialization=True,artifact_persistence=True,dispatch=True,
        reconstruction_pipeline=True,api_compatibility=not contract['failures'] and not contract['errors'],
        tests=contract['cases'],
        historical_contract='Original ScoreBreakdown retained as independent union branch; v4 config and serializer unchanged.',
        feature_profile='algorithm.version=v4 retains the exact canonical extractor/candidate profile. implementation_version and formal ScoreBreakdown are explicitly V5. No v4 score is relabelled.',
        diagnostic_caveat='blind/summary.json correlation_v2 and alert_correlation_diagnostics retain historical extractor gate counters. Authoritative V5 gate results are blind/members.jsonl.gz and ground_truth_edge_scores.json.',
        end_to_end_definition='Synthetic attested multistep and real frozen nonempty pipeline executed; dataset chain recovery is reported separately.'))
    blind_receipt=read(OUT/'blind/guard_receipt.json');down_receipt=read(OUT/'downstream/guard_receipt.json')
    save(OUT/'anti_leakage.json',dict(status='PASS' if not data_changed and not changed and not blind_receipt['rejected_events'] and not down_receipt['rejected_events'] else 'FAIL',
        prospective_design_ref='before.json',failure_decomposition_ref='failure_decomposition.json',
        freeze_sha256=sha(OUT/'formula_freeze.json'),sealed_scores_sha256=sha(OUT/'score_seal.json'),
        order=['old F2 failure decomposition','prospective F3 rule','formula freeze','GT-denied scoring','score seal','post-hoc labels','calibration','sealed-score actual downstream'],
        blind_guard=blind_receipt,downstream_guard=down_receipt,
        dataset_file_count=len(data),dataset_unchanged=not data_changed,dataset_hash_checks=data,
        historical_artifacts_unchanged=not changed,historical_protected_file_count=len(protected),historical_mismatches=changed,
        candidate_digest_equal=seal['candidate_identity_equal'],candidate_digest=seal['candidate_digest'],
        t2_read=False,t2_validation_started=False,external_dataset_inventory_not_performed=True,
        historical_test_write_incident=read(OUT/'historical_restoration.json'),
        historical_integrity_definition='Final byte hashes match before.json. Six test-generated capacity receipts were accidentally rewritten by the first unredirected run, then restored byte-for-byte using pre-task SHA-256 identities. No prediction/dataset artifact was altered.',
        new_GT_evaluation_count=1,formula_revisions=1,parameter_search=False,
        scope='Development dataset already inspected in F2. Blind here means a new isolated scoring worker before the new label evaluation, not an independent holdout.',
        first_attempt='blind_attempt1_import_guard retained; guard rejected a late Python module read. No score seal or label evaluation existed. Module preloaded before retry; data whitelist unchanged.',
        downstream_attempts='Two unsealed downstream attempts rejected late module imports (formula_v5, capacity); both directories/logs retained. Preloading fixed execution; the data whitelist stayed unchanged.'))
    save(OUT/'formula_revision_history.json',dict(revisions=[dict(formula_version='F3-independent-support-v1',
        algorithm_version=frozen['algorithm_version'],implementation_version=frozen['implementation_version'],
        config_hash=frozen['config_hash'],mapping_digest=frozen['mapping_digest'],change_rationale=before['rationale'],
        GT_distribution=dist['distributions'].get('GT'),annotated_negative_distribution=dist['annotated_negative'],
        hard_negative_distribution=dist['hard_negative'],PR_AUC=ev['ranking']['PR_AUC'],
        Average_Precision=ev['ranking']['Average_Precision'],GT_gate_pass=ev['GT_gate_pass'],
        GT_correlation_recovery_065=chain['primary']['CorrelationEdges_recovered'],
        GT_chain_recovery=chain['primary']['ChainEdges_recovered'],FP_at_065=ev['historical']['FP'],
        F2_ranking=ev['F2_ranking'],one_prospective_structural_revision=True)],
        calibration_uses_same_sealed_scores=True,production_threshold_freeze=False))
    improved=ev['ranking']['PR_AUC']>ev['F2_ranking']['PR_AUC'] and ev['ranking']['Average_Precision']>ev['F2_ranking']['Average_Precision']
    verdict='V5_FORMULA_PROMISING_BUT_NOT_READY' if improved and not failures and not changed else 'V5_FORMULA_REPAIR_FAILED'
    final=dict(TASK_RESULT=verdict,V5_FORMULA_FREEZE='EXPERIMENTAL_F3_ONLY',V5_THRESHOLD_FREEZE='NO',
        V5_END_TO_END_READY='NO',READY_FOR_EXTERNAL_VALIDATION='NO',actual_reconstruction_executed=True,
        contract_integration_passed=not failures,formula_artifacts_sealed=True,
        blockers=['No stable safe all-six-witness operating region' if not ev['safe_region'] else 'Operating region requires downstream acceptance',
            'Frozen GT witness pairs lack verified explicit propagation; do not invent ChainEdges',
            'Dataset directed multistep recovery acceptance unmet'],
        recommended_admission_threshold=None,recommended_clustering_threshold=None,recommended_chain_threshold=None)
    save(OUT/'summary.json',final)
    rows_gt='\n'.join('| '+e+' | '+f"{r['score']:.12f}"+' | '+str(r['valid'])+' | '+str(r['relation_count'])+' |'
        for e,r in sorted(gt['edges'].items()))
    s=chain['primary']['summary'];p=chain['background_pollution'];ranking=ev['ranking']
    report=f'''# V5 Formula Repair + End-to-End Integration

TASK_RESULT={verdict}

本轮完成 F3 正式后端 contract、生产 dispatch、封存盲评分与实际下游执行。冻结数据的完整攻击链恢复未达标；不冻结生产阈值，不启动 CPTC t2。

## A. F2 为什么失败

- Gate：hybrid 把角色白名单当作不可替代的硬条件。E01 有普通 src IP 与 DOMAIN 共享，但没有 host/account/monitored endpoint/direct/flow，因此 contextual=false、strong=false 被拒。这个充分性门槛属 OVER_RESTRICTIVE_GATE；普通上下文弱不等于矛盾。显式传播方向 gate 仍属 VALID_SAFETY_GATE。
- Separation：全 observed 分母含 URL、detector identity、network 等替代路径的零值，压低独立支持；稀疏证据再受 weak ceiling 压缩。缺失与零值已区分，但零值处理仍形成分母惩罚。
- Threshold：F2 全部 GT 分数低于 0.70，旧下游分数门槛形成零恢复上限。
- Downstream：六个 GT witness 均无生产 verifier 接受的显式传播。分数提高也不能替代方向证据。
- Contract：旧 F2 仅在 evaluation 执行，无正式 schema、序列化与 dispatch，不能导出非空正式图。

六条边的 channels、gates、逐维 numerator/denominator、family contributions、正/零/缺失/矛盾、quality、最终分和下游资格见 failure_decomposition.json。该文件的原始分解在修改生产代码前完成，逐维算术表为同一旧结果的展开。

## B. 结构修复与风险

1. flat observed average → 每个语义组取最大可靠支持，再用 `1-∏(1-support)` 聚合。HOST 与 monitored IP 共用 asset 组；重复包装不加分。缺失与无关替代路径零值保留审计，不稀释已有支持。风险：多类共享上下文仍可能误相关。
2. contextual-role hard gate → 仅保留 hard contradiction、same-observation 与没有非时间语义支持。弱证据由分数/0.45 cap 控制。风险：低阈值会暴露更多背景候选，必须查看负控。
3. direct proof 与所有维度平均 → verified direct propagation 作为充分的独立支持路径，与 contextual mass 取 max，不重复强化。风险：上游错误 attestation；原关系 verifier 未改。
4. 正式 ScoreBreakdownV5(schema_version=5.0) → 独立版本、配置身份、四状态、可靠度、gate、分数组件、EvidencePointer 和重算校验。V4 serializer/config 保持原样。

只进行一个预先声明的 F3 revision，无参数搜索。四状态为 SUPPORTED / UNOBSERVABLE / OBSERVED_ZERO / CONTRADICTED；字段不可观测不构成反证。不同操作的对象不相同不自动证明排他矛盾。

## C. 新公式身份与分数语义

```text
algorithm_version={frozen['algorithm_version']}
implementation_version={frozen['implementation_version']}
config_hash={frozen['config_hash']}
mapping_digest={frozen['mapping_digest']}
```

`algorithm.version=v4` 仅保留既有 canonical extractor/candidate profile；执行分派、算法身份、公开 breakdown 均独立为 V5。旧七项 components 放在 legacy_audit，不冒充 F3 贡献。

0.0：没有肯定语义支持或受硬约束拒绝；0.3：弱/稀疏上下文；0.5：中等佐证；0.7：较充分的独立上下文或可核验传播；1.0：完整字段支持指数。它们均非攻击概率或经实验校准的置信度。

预先固定 admission=0.65（允许展示），clustering=0.70（允许保护合并），chain=0.70 加显式传播与 direction>=0.75。三者使用同一 relatedness 支持尺度，合并/方向各有额外不可替代约束。没有为了恢复 GT 降低门槛。F3 已能在 attested synthetic control 达到下游分数门槛，证明旧数学零上限已消除；这不保证数据集有相应证据。

## D. GT Evaluation

```text
GT candidates={ev['GT_candidates']}/6
GT gate pass={ev['GT_gate_pass']}/6
GT score range={ev['GT_score_range']}
PR_AUC={ranking['PR_AUC']}
Average_Precision={ranking['Average_Precision']}
ROC_AUC={ranking['ROC_AUC']}
```

| Witness | F3 score (unrounded) | valid | verified relations |
|---|---:|---|---:|
{rows_gt}

F2 PR_AUC={ev['F2_ranking']['PR_AUC']}，AP={ev['F2_ranking']['Average_Precision']}。GT/hard-touching overlap：{dist['F2_GT_hard_overlap_count']} → {dist['GT_hard_overlap_count']} /6。Ranking 改善，但 hard tail 更差、overlap 验收失败，不以 ROC 或平均指标掩盖该问题。

主 ranking 仅比较 6 positive 与实际计算到的 {ranking['negative_count']} annotated negatives。其余未标注 pair 排除，不能当作 FP；evaluation_coverage={dist['evaluation_coverage']}。hard-touching 是含已标注 hard-negative 告警的候选，不代表每个 pair 都有显式负标签。

## E. Hard Negative

```text
hard_negative_max={ev['hard_negative']['max']}
hard_negative_p95={ev['hard_negative']['p95']}
hard_negative_admitted_at_065={ev['historical']['hard_touching_admitted']}
annotated_FP_at_065={ev['historical']['FP']}
```

完整分位数见 score_distribution.json，annotated negative 与 hard-touching 分开统计。

## F. Threshold Calibration

```text
recommended admission threshold=NONE
recommended clustering threshold=NONE
recommended chain threshold=NONE
```

公式 freeze → 独立生产盲评分 → score seal → GT → 阈值扫描 → actual downstream。扫描 0..1 步长0.005及 GT 精确边界/nextafter，同一份未舍入 sealed scores，不重算。预声明保守条件为所有6 witness恢复、annotated FP=0、hard-touching admission=0，并要求邻域；满足扫描点数={len(ev['safe_region'])}。阈值及 ±0.01/0.02/0.05 的诊断见 threshold_metrics.csv / threshold_stability.json；诊断点不是推荐点。

最大全 witness 诊断阈值={ev['diagnostic']['threshold']}，接纳 {ev['diagnostic']['total_edges']} 条关联、annotated FP={ev['diagnostic']['FP']}、hard-touching={ev['diagnostic']['hard_touching_admitted']}。这一低阈值不作为正式配置，也没有把低阈值图的路径 proxy 当作实际重建。0.65/0.70 邻域统计同样来自封存 CSV。

## G. Actual End-to-End Chain

```text
CorrelationEdges recovered={chain['primary']['CorrelationEdges_recovered']}/6 (admission 0.65)
ChainEdges recovered={chain['primary']['ChainEdges_recovered']}/6
Longest GT path={chain['primary']['Longest_GT_path_recovered']}/6
Actual reconstruction executed=true
```

完整 frozen CanonicalAlert/Entity/Dedupe 输入与封存正式 V5 edges 进入原生产 clustering、direction、DAG、grounding。仅用 sealed PairScore lookup 完成支撑核验；生产公式重算次数=0。0.65 与0.70分别执行，实际图、诊断、DuckDB/Parquet/JSONL、落盘重读在 downstream/。六个 witness 无 verified relation，不能用时间、GT阶段或分类补造方向边。

上述0指原 `CorrelationScorer.score_pair` 重新抽取/评分成对证据的次数；Schema 仍对同一组封存 features 重算算术以校验一致性，不引入新证据或 GT。

独立 synthetic integration control 已实际生成至少两条 CorrelationEdges、两条 directed ChainEdges 和多步链，且经 API 与持久化测试。它只证明 contract/pipeline 可执行，不能算冻结数据 GT 恢复。

## H. Background Pollution

```text
total edges={p['total_edges']}
multi-alert incidents={p['multi_alert_incidents']} (representative facts)
largest incident={p['largest_incident']} representatives / {p['largest_incident_original_alerts']} original alerts
chain edges={p['chain_edges']}
largest chain={p['largest_chain']} edges
pollution={p['status']}
```

完整合并拒绝原因与 exact sizes 见 chain_validation.json。无标签背景不推定为已确认良性，也不宣称所有未标注关联正确。

## I. Regression / Historical Isolation

```text
unique tests passed={regression['unique_tests_passed']}
unique tests failed={regression['unique_tests_failed']}
existing optional tests skipped={tests['skipped']}
historical v4 integrity={regression['historical_v4_integrity']}
protected historical/config/doc files={len(protected)}
frozen dataset files checked={len(data)}
```

命令：`.venv/Scripts/python.exe -u -B -m evaluation.framework.formula_repair.regression_run`。精确 pytest 文件清单/参数在 regression_selection.json，覆盖上一阶段核心回归及新增配置、正式 V4/V5、dispatch/service、AI grounding；未改动的实数据 AI 三源和 AIT capacity 大型重放不在最终受影响回归范围内。两次未完成的全仓尝试保留日志，不计入通过数。插件仅复用既有 legacy 输出重定向，不删除测试或改变断言。最终12项 contract补测见 contract_final.xml（含 V5 全输入顺序置换/Stable ID 和越界 provenance 拒绝）；回归与补测按唯一测试身份计数。初次 API fixture 缺 severity 映射的失败保留在 contract.xml，补齐部署配置后通过。

首次未使用重定向插件的回归重写了6份容量测试凭据；已中止并凭 before.json 的原 SHA-256 从未变的汇总记录恢复原字节，historical_restoration.json 保留审计。最终完整性重新核验。Task06.6 的“当前源码”校验迁移到 F3 独立 freeze，旧 supersession chain 和严格旧 executor 拒绝测试保留；current_receipt.xml 单测与最终受影响回归均验证新当前代码，未修改旧 receipt，也不声称旧 receipt 可授权新源码。

V4 config/hash、原 serializer 源文件、历史 artifacts 按 before.json 校验；候选代码未变，重新生成候选 digest 与旧 run 精确相等，candidate_count={seal['candidate_count']} / member_count={seal['member_count']}。无 t2 读取。新旧 artifacts 分目录。

说明：blind/summary.json 中 correlation_v2 / alert_correlation_diagnostics 是保留的旧 feature extractor gate 诊断；V5 gate 以封存 member 记录与本报告 GT 表为准。该兼容性诊断标签尚可后续单独整理。

## J. Final Verdict / Stop

```text
TASK_RESULT={verdict}
V5_FORMULA_FREEZE=EXPERIMENTAL_F3_ONLY
V5_THRESHOLD_FREEZE=NO
V5_END_TO_END_READY=NO
READY_FOR_EXTERNAL_VALIDATION=NO
```

保留实验公式与封存证据供人工审查。没有安全全 witness 阈值区域/有效方向证据时不选阈值、不补造步骤。本阶段停止，不启动 CPTC t2、UI、论文或 demo 工作。
'''
    (OUT/'V5_FORMULA_REPAIR_INTEGRATION_REPORT.md').write_text(report,encoding='utf8')
    included=[]
    for path in OUT.rglob('*'):
        if not path.is_file():continue
        relative=path.relative_to(OUT)
        if any(part.startswith(('regression_tmp','regression_safe_tmp','regression_isolated','affected_regression_tmp','contract_tmp','contract_final_tmp','unit_tmp','current_receipt_tmp','blind_attempt','downstream_attempt')) for part in relative.parts):continue
        if path.name=='manifest.json' and path.parent==OUT:continue
        included.append(path)
    save(OUT/'manifest.json',dict(summary=final,files={p.relative_to(OUT).as_posix():sha(p) for p in sorted(included)},
        excluded='temporary pytest workspaces and preserved unsealed import-guard attempt; final sealed worker and all required deliverables included',
        production_sources=current,
        task_sources={p.relative_to(ROOT).as_posix():sha(p) for p in [
            *sorted(p for p in (ROOT/'evaluation/framework/formula_repair').glob('*') if p.suffix in {'.py','.md'}),
            ROOT/'backend/tests/test_formula_v5.py',ROOT/'evaluation/tests/test_task_06_6.py',ROOT/'configs/algorithm-v5.yaml']},
        formula_freeze_sha256=sha(OUT/'formula_freeze.json'),
        dataset_unchanged=not data_changed,protected_files_unchanged=not changed,t2_read=False))
    print(json.dumps(final),flush=True)


if __name__=='__main__':run()

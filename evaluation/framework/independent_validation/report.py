"""Render sealed validation evidence; no scorer or prediction mutation."""
import collections
import json
import xml.etree.ElementTree as ET
from . import ROOT, OUT, DATA
from .evaluate import verify_predictions
from .seal import verify
from evaluation.framework.scoring_calibration.snapshot import read, save, sha


def table(headers, rows):
    return ['| '+' | '.join(headers)+' |','| '+' | '.join('---' for _ in headers)+' |']+['| '+' | '.join(str(x) for x in row)+' |' for row in rows]


def run():
    verify_predictions()
    result=read(OUT/'result.json');m=read(OUT/'metrics.json');primary=m['primary']
    anchors=read(OUT/'anchor_metrics.json');sources=read(OUT/'source_metrics.json')
    sensitivity=read(OUT/'parameter_robustness.json')['experiments']
    thresholds=read(OUT/'threshold_robustness.json')['experiments']
    background=read(OUT/'background_statistics.json');audit=read(OUT/'background_audit.json')
    negatives=read(OUT/'exact_anchor_failures.json');independence=read(OUT/'independence_audit.json')
    regression=read(OUT/'regression_summary.json')
    unit=ET.parse(OUT/'unit.xml').getroot()
    suites=list(unit) if unit.tag=='testsuites' else [unit]
    unit_counts={k:sum(int(s.attrib.get(k,0)) for s in suites) for k in ('tests','failures','errors','skipped')}
    unit_counts['passed']=unit_counts['tests']-unit_counts['failures']-unit_counts['errors']-unit_counts['skipped']
    result['PARAMETER_ROBUSTNESS']='NUMERICALLY_STABLE_BUT_SEPARATION_FAILED'
    result['THRESHOLD_ROBUSTNESS']='SEPARATION_FAILED_ACROSS_0.60_TO_0.70'
    result['validation_scope']='LIMITED_VALIDATION_SYNTHETIC_STRESS_SLICE'
    result['regression']=regression
    result['new_tests']=unit_counts
    save(OUT/'result.json',result)
    near=[s for s in audit['samples'] if s['stratum']=='near_threshold']
    archived=DATA.with_name(DATA.name+'_schema_attempt1')
    label_unchanged=sha(DATA/'evaluation/answers.json')==sha(archived/'evaluation/answers.json')
    original={r['event_id']:r for r in (json.loads(line) for line in (archived/'input/alerts.jsonl').open(encoding='utf8'))}
    corrected=[json.loads(line) for line in (DATA/'input/alerts.jsonl').open(encoding='utf8')]
    corrected_count=0
    for row in corrected:
        if row['source_type']=='edr':
            assert row['event'].pop('executable')=='/usr/local/bin/'+row['event']['process_name']
            corrected_count+=1
        assert row==original[row['event_id']]
    assert len(original)==len(corrected)
    schema_correction=dict(first_attempt_input_sha256='16ebb58c5865564b0c322711f61d921fd39d907b60caf21d2eebef9deddd3e15',
        corrected_input_sha256=sha(DATA/'input/alerts.jsonl'),answers_byte_identical=label_unchanged,
        only_added_native_executable=True,corrected_records=corrected_count,correction_before_scoring=True,production_modified=False,
        retained_logs='preprocessing_schema_attempt1.log')
    save(OUT/'schema_correction_receipt.json',schema_correction)
    lines=['# V5 Independent Validation + Exact-Anchor Stress Test','',
        '**结论：V5_EXACT_ANCHOR_OVER_CORRELATED。不得进入 production integration，不得冻结 V5。**','',
        '72/72 GT 被召回且接纳，但 180 对困难负例中 150 对被接纳（全部携带 exact anchor）；HN rejection 仅 16.67%，最差裕度为负。保留封存参数与 0.65，未调参、未添加规则、未部署 Candidate C。','',
        '## 验证数据与独立性','',
        f"数据：`{DATA}`。4,134 条全合成告警：3,600 background、84 attack observations、360 HNX01–06 observations、90 HNX07 repeated-observation controls。新 seed={independence['seed']}，与 development v2 共享 observation ID=0、原生 body=0；12 个独立实例，每实例 7 observations / 6 条分支边，共 72 GT edges / 6 binding families。不同于开发集线性七边。",'',
        '六类 GT binding：flow、application session、request/worker、process lineage、authentication session、network session；涵盖 IDS↔WAF、WAF↔WAF、WAF↔EDR、Host/Audit↔EDR、EDR/Host↔Authentication、Firewall↔Host。后两类为 Host/Audit 上的登录/连接上下文；没有机械复制开发集 EDR↔Authentication / Firewall↔EDR 七边。','',
        '独立性限定：未参与 Candidate C 开发/校准的新记录、身份、时间与场景实例；生成器不导入 production 或 scorer，生成后没有依据评分调整。仍由同一操作者编写，复用已知 native schemas，并非第三方盲标或真实厂商告警验收。**LIMITED_VALIDATION**；可用于证伪 exact-anchor 充分性，不能据此估计真实环境误接纳率。','',
        '首次预处理在评分前遇到 name-only EDR 的既有 Adapter provenance 错误；原数据和失败日志均保留。只补原生 executable 后重新开始，答案文件逐字节相同；没有修改 Adapter。见 schema_correction_receipt.json。','',
        '## 封存与盲预测','',
        '读取新标签前生成 validation_formula_seal.json / validation_parameter_seal.json，含 implementation_hash、config_hash、formula_hash、parameter_hash、source_hashes（2,394 个既有文件）。原 Candidate C、源映射、候选策略、hard/duplicate guard、rarity/hot、时间、family grouping 全部保持。','',
        'Worker 1 仅从 input/alerts.jsonl 执行原 Adapter→Dedupe→Entity→Candidate/production diagnostics，输出 preprocessing；Worker 2 仅允许 canonical、entities、diagnostics、candidate_pairs 四个文件，执行 Candidate C 与预定的十个单参数扰动。全部成员完整评分并分别选唯一 winning member，14,976 candidates，未遗漏或资源截断。','',
        'validation_predictions/ 与 prediction_seal.json 先封存；随后 Phase B 才打开 evaluation/answers.json。Phase B 不导入、不调用 scorer；禁止在 evaluation_started 后重新盲算。Python audit tripwire 阻止未列入白名单的文件、子进程、网络访问；这是可信 Python 进程审计，不是 OS 沙箱。','',
        '每 candidate 的 frozen prediction 包含 winning member、全部 observable features、decomposition、anchor selected/type/strength/reliability/scope/hot/context、time factor、penalties、gate、rejection codes 与 final admission；members 文件保留每个成员的完整分解。','',
        '## Primary metrics','']
    lines+=table(['Metric','Result'],[
        ('GT Candidate Recall','72/72 = 100%'),('GT Admission Recall','72/72 = 100%'),
        ('HN total / candidates / admitted','180 / 180 / 150'),('HN rejection rate','30/180 = 16.67%'),
        ('min GT score',f"{primary['min_gt_score']:.12f}"),('max HN score',f"{primary['max_hn_score']:.12f}"),
        ('worst margin',f"{primary['worst_margin']:+.12f}"),
        ('GT > HN pairwise ordering',f"{primary['pairwise_ordering_numerator']}/{primary['pairwise_ordering_denominator']} = {primary['pairwise_ordering_rate']:.6%}"),
        ('Total admitted / candidates',f"{result['TOTAL_ADMITTED']} / {result['CANDIDATES']}"),
        ('Evaluation coverage',f"252/14976 labelled candidate pairs = {m['evaluation_coverage']:.6%}; HNX07 separate")])
    lines+=['','所有 GT/HN 均入候选，故本轮没有用未提名来提高拒绝率。其他未列 pair 不算 FP；没有定义整体 precision/F1。','',
        '## Exact-anchor failures','']
    labels={'HNX01':'Reused session/request token','HNX02':'Long-lived network session','HNX03':'Proxy / sensor-local flow ambiguity',
        'HNX04':'Shared authenticated login context','HNX05':'PID reuse / same parent, distinct start','HNX06':'Worker pool handles unrelated actions'}
    lines+=table(['Class','Description','Candidates','Admitted','Diagnosis'],[(f,labels[f],v['hn_candidates'],v['hn_admitted'],
        'PASS distinct child instance / parent-only suppression' if f=='HNX05' else ', '.join(next(x['classification'] for x in negatives['failures'] if x['family']==f)))
        for f,v in m['hard_negative_families'].items()])
    lines+=['','SESSION 不可靠：typed scope 可以区分类型/主机/namespace，但没有解决 token 生命周期、持久连接中的不同任务、代理后 sensor-local ID 复用或长期登录态。PROCESS 的 host+PID+start_time 避免了 HNX05；但 HNX06 显示完整 worker instance 仍不足以证明同一任务或攻击 progression。','',
        'HNX07 是正向 correlation 对照、负向 progression 对照：90/90 pair 允许同事件关联，0 对有 verified direct relation anchor。它们没有计入 HN correlation 分母。本轮按要求不运行 Incident/Chain reconstruction，因此不报告实际链推进准确率；不能把 90 条无向关联解释成 90 个攻击推进步骤。','',
        '每个接纳 HNX 的完整 pair / winning member / why_anchor_qualified / which_context_supported / score_before_time / time_factor / penalties / final_score / why_current_guard_did_not_reject / taxonomy 均见 exact_anchor_failures.json（150 条）。以下是每类一个封存例子：','']
    for family in ('HNX01','HNX02','HNX03','HNX04','HNX06'):
        f=next(x for x in negatives['failures'] if x['family']==family)
        lines += [f"- {family}: `{f['winning_member'][0]}` ↔ `{f['winning_member'][1]}`；anchor={f['anchor']['anchor_type']}，before_time={f['score_before_time']:.9f}，T={f['time_factor']:.9f}，final={f['final_score']:.9f}。context={json.dumps(f['which_context_supported'],sort_keys=True)}。"]
    lines+=['','## Anchor-specific audit','']
    lines+=table(['Selected anchor','Candidate','Admitted','GT','HN','Background'],[(k,*[v.get(f,0) for f in ('candidate_count','admitted_count','GT_count','HN_count','background_count')]) for k,v in anchors['selected_classes'].items()])
    lines+=['','GT/HN/background 数是该类 candidate 中的计数；选定主 anchor 为互斥类别。额外 any-qualified-types 可重叠，详见 anchor_metrics.json。direct relation 在独立负例中没有覆盖，不能宣称其误接纳风险已被排除。','',
        '本 slice 的 9,324 个带 anchor candidates 全部接纳；5,652 个 no-anchor candidates 全部拒绝。数学上仍有 hard/duplicate guard、penalty 与 time，因此不是所有可能输入均“无条件接纳”。但当前 context_floor=0.90，即使缺少 context 仍保留 90% anchor 支撑；强 anchor 路径显著压过弱证据 cap，而现有 guard 不检查任务/生命周期兼容。这解释了五类负例的系统性高分。','',
        '## Frozen parameter sensitivity','']
    lines+=table(['Perturbation','GT admitted','Δrecall','HN admitted','ΔHN','Worst margin','Δmargin'],[
        (x['variant'],x['gt_admitted'],f"{x['gt_recall_change']:+.3f}",x['hn_admitted'],f"{x['hn_admitted_change']:+d}",f"{x['worst_margin']:+.9f}",f"{x['worst_margin_change']:+.9f}") for x in sensitivity])
    lines+=['','±10% 没有使 GT recall 灾难性塌陷，但 HN 仍为 140–150，所有 worst margin 为负。数值稳定不等于正确；这组实验稳定复现结构性失败。minimum_anchor_strength/parent_only_factor 的局部扰动无效，不代表所有参数范围可靠。没有选新最佳参数。','',
        '## Threshold neighborhood','']
    lines+=table(['Threshold','GT admitted','HN admitted','HN rejection'],[(x['threshold'],x['gt_admitted'],x['hn_admitted'],f"{x['hn_rejection_rate']:.2%}") for x in thresholds])
    lines+=['','0.60–0.70 都保留 72/72 GT；HN 接纳 140–150，最高拒绝率仅 22.22%。0.65 并非唯一窄点，也不是可用 operating point。没有重新选择 threshold。','',
        '## Background / same-source audit','',
        f"Background admitted={background['background_admitted']}；同一 slice 的旧 production formula 也是 {background['production_background_admitted']}（ratio={background['ratio_vs_same_slice_production']:.1f}）。平均 degree={background['mean_degree']:.1f}，最大 degree={background['max_degree']}；600 个六传感器上下文各形成 15 条边。当前 slice 未发现跨背景上下文的边爆炸，但持久共享上下文本身已在 HNX02/04/06 失败，不能据此解除风险。",'',
        f"背景抽样三个互斥 strata 各 50：{audit['classifications']}。这只是可观测语义分诊，没有人工独立裁决，不把 background 自动当 FP。最近阈值组距离范围 [{min(s['near_threshold_distance'] for s in near):.6f}, {max(s['near_threshold_distance'] for s in near):.6f}]，本 slice 缺乏真正贴近 .65 的 background 样本。",'']
    lines+=table(['Source scope','Candidates','Admitted'],[('same-source',sources['same_source_candidates'],sources['same_source_admitted']),('cross-source',sources['cross_source_candidates'],sources['cross_source_admitted'])])
    lines+=['','同源正常关联允许；其中 WAF↔WAF GT=12/12，同时 HNX01 同源负例=30/30 被接纳。Candidate C 没有 cross_source prerequisite；跨源标签不能修复 scope/lifecycle 语义。','',
        '## 回归、完整性与文件范围','',
        f"既有选择回归：{regression['passed']} passed / {regression['failures']} failed / {regression['skipped']} skipped；新增验证测试：{unit_counts['passed']} passed / {unit_counts['failures']} failed。合计 {regression['passed']+unit_counts['passed']} passed / 5 failed / 4 skipped。",'',
        '历史 5 个失败保持原解释：一个旧 formula freeze 检测此前授权的 backend/app/entities/extraction.py 改动；四个 repository-contract 断言报告此前 11 个 semantic_repair/separation_direction 模块未登记 whitelist。没有修改/删除断言或重写旧 seal。4 skipped 的具体原因保留在 regression.xml。选择覆盖 Adapter、Projection、Entity、Candidate、Dedupe、V2–V5、Stable ID、Schema、API、Grounding、Chain synthetic、source-bound、semantic-repair、separation-direction（具体 target 清单见 regression_selection.json）。','',
        '新增文件：TraceBack-Dataset/scripts/build_independent_validation_v1.py、新 validation data；evaluation/framework/independent_validation/{__init__,seal,predict,evaluate,regression,report}.py；evaluation/tests/test_independent_validation.py；outputs/v5_independent_validation/**。三份需求、四份工程文档、development dataset/GT/HN、原生成器、Adapter/Projection/Entity/Candidate、production scorer/admission、UI、Chain 实现均未改。2394 个既有保护文件及所有 prediction/seal 再次逐字节核验。','',
        '## Required final answers','']
    answers=[
        ('独立 validation 真正未参与开发？','是：新生成且无旧 observation/body 重叠；同操作者、同 schema 的独立合成实例，非第三方/真实 validation。'),
        ('多少 GT edge？','72，12 episodes × 6，六类 binding。'),('Candidate Recall？','72/72，100%。'),('Admission Recall？','72/72，100%。'),
        ('HN admitted？','150/180。'),('exact-anchor HN admitted？','150。'),('min GT？',f"{primary['min_gt_score']:.12f}"),
        ('max HN？',f"{primary['max_hn_score']:.12f}"),('worst margin？',f"{primary['worst_margin']:+.12f}"),
        ('SESSION anchor 可靠？','作为跨独立任务关联的充分证据不可靠；HNX01–04 共 120/120 接纳。'),
        ('PROCESS anchor 可靠？','完整实例区分 PID reuse 有效；shared worker 30/30 误接纳，不能单独证明任务关联。'),
        ('identifier reuse 问题？','有：request/session/flow 复用；完整 PID+start_time 能排除本轮 PID reuse。'),
        ('long-lived session over-correlation？','有：HNX02 30/30；HNX04 30/30。'),
        ('background admitted 异常增长？','本 slice 无：9000，与旧公式相同，max degree=5；不能推及其他分布。'),
        ('0.65 稳定？','GT 稳定，但 separation 失败；整个 0.60–0.70 都不合格。'),
        ('参数 ±10% 稳定？','召回未塌陷；140–150 HN、裕度始终为负，稳定地失败。'),
        ('development overfit？','表现出负例覆盖外的泛化失败与高 overfit 风险；不能仅凭压力 slice 区分参数过拟合和分布迁移。'),
        ('允许 production integration？','否。'),('允许冻结 V5？','否。'),
        ('最大剩余风险？','把 exact-looking session/完整进程实例当作关联充分证据，缺少生命周期与独立任务边界。')]
    for i,(q,a) in enumerate(answers,1): lines += [f'{i}. **{q}** {a}']
    lines+=['','## Final block','','```text']
    fields=['TASK_RESULT','VALIDATION_DATASET','VALIDATION_INDEPENDENT','SCORING_FORMULA','THRESHOLD','GT_EDGES','GT_CANDIDATE_RECALL','GT_ADMISSION_RECALL','HN_TOTAL','HN_ADMITTED','EXACT_ANCHOR_HN_ADMITTED','MIN_GT_SCORE','MAX_HN_SCORE','WORST_MARGIN','BACKGROUND_ADMITTED','SAME_SOURCE_ADMITTED','CROSS_SOURCE_ADMITTED','PARAMETER_ROBUSTNESS','THRESHOLD_ROBUSTNESS','DEVELOPMENT_OVERFIT_RISK','V5_PRODUCTION_INTEGRATION_READY','V5_FREEZE_READY','PRIMARY_REMAINING_BLOCKER']
    for k in fields:
        v=result[k];lines.append(k+'='+str(v).lower() if isinstance(v,bool) else k+'='+str(v))
    lines+=['```','','本轮停止。即使未来修订，也必须使用另行预注册的新独立集；不得在本验证集反复调到通过。']
    (OUT/'V5_INDEPENDENT_VALIDATION_REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    verify_predictions();verify()
    sources_now={str(p):sha(p) for p in (ROOT/'evaluation/framework/independent_validation').glob('*.py')}
    sources_now[str(ROOT/'evaluation/tests/test_independent_validation.py')]=sha(ROOT/'evaluation/tests/test_independent_validation.py')
    sources_now[str(ROOT.parent/'TraceBack-Dataset/scripts/build_independent_validation_v1.py')]=sha(ROOT.parent/'TraceBack-Dataset/scripts/build_independent_validation_v1.py')
    save(OUT/'immutability_check.json',dict(protected_files=2394,changed=[],production_unchanged=True,development_unchanged=True,
        predictions_unchanged=True,formula_and_parameters_unchanged=True,original_requirements_and_engineering_docs_unchanged=True,
        candidate_c_deployed=False,post_label_scorer_runs=0))
    files={str(p.relative_to(OUT)):sha(p) for p in OUT.rglob('*') if p.is_file() and p.name!='manifest.json'
        and p.name!='report.log' and not any(x.endswith('_tmp') or x=='__pycache__' for x in p.parts)}
    save(OUT/'manifest.json',dict(files=files,new_sources=sources_now,result={k:result[k] for k in fields},
        formula_seal_sha256=sha(OUT/'validation_formula_seal.json'),parameter_seal_sha256=sha(OUT/'validation_parameter_seal.json'),
        prediction_seal_sha256=sha(OUT/'prediction_seal.json'),LIMITED_VALIDATION=True,no_production_integration=True))
    print('REPORT_AND_MANIFEST_COMPLETE',flush=True)


if __name__=='__main__': run()

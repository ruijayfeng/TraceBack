"""Deliver the development result, limitations, and immutable artifact manifest."""
import collections
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from . import ROOT, BASE, OUT, POLICY
from .snapshot import read, save, sha, verify
from .evaluate import verify_seal


def table(headers, rows):
    return '\n'.join(['|'+'|'.join(headers)+'|', '|'+'|'.join(['---']*len(headers))+'|',
                      *['|'+'|'.join(str(v).replace('|', '/').replace('\n', ' ') for v in row)+'|' for row in rows]])


def test_counts(path):
    tree = ET.parse(path).getroot()
    suites = list(tree) if tree.tag == 'testsuites' else [tree]
    result = {k: sum(int(s.attrib.get(k, 0)) for s in suites) for k in ('tests', 'failures', 'errors', 'skipped')}
    result['passed'] = result['tests']-result['failures']-result['errors']-result['skipped']
    return result


def main():
    verify_seal()
    integrity = verify()
    baseline_hashes = read(BASE / 'before_hashes.json')
    # Also detect newly added files in protected input/generator trees, not only edits.
    for key in ('dataset', 'generators'):
        paths = [Path(p) for p in baseline_hashes[key]]
        base = Path(__import__('os').path.commonpath([str(p) for p in paths]))
        if base.is_file():
            base = base.parent
        current = {str(p): sha(p) for p in sorted(base.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
        if current != baseline_hashes[key]:
            raise ValueError('protected_tree_membership_changed:' + key)
    actual_production = {str(p.relative_to(ROOT)): sha(p) for p in sorted((ROOT / 'backend/app').rglob('*.py'))}
    if actual_production != read(OUT / 'baseline/seal.json')['implementation_files']:
        raise ValueError('production_tree_changed')
    save(OUT / 'immutability_check.json', dict(**integrity, protected_tree_membership_unchanged=True))
    summary = read(OUT / 'evaluation_summary.json')
    baseline, selected = summary['baseline'], summary['selected']
    sweep = read(OUT / 'threshold_search.json')
    distributions = read(OUT / 'score_distributions.json')
    margins = read(OUT / 'separation_margins.json')
    folds = read(OUT / 'group_calibration.json')
    sensitivity = read(OUT / 'parameter_sensitivity.json')
    changes = read(OUT / 'admission_changes.json')
    background = read(OUT / 'background_semantic_review.json')
    families = read(OUT / 'hard_negative_family_diagnosis.json')
    witnesses = read(OUT / 'complete_witness_decomposition.json')
    regression = read(OUT / 'regression_summary.json')
    new_tests = test_counts(OUT / 'verification.xml')
    if new_tests['failures'] or new_tests['errors']:
        raise ValueError('current_task_tests_failed')
    old_failures = {r['name'] for s in read(BASE / 'regression_summary.json')['suites'].values()
                    for r in s.get('failed_tests', [])}
    new_failures = {r['name'] for r in regression['failed_tests']} - old_failures
    if new_failures:
        raise ValueError({'new_regression_failures': sorted(new_failures)})
    stable = [r['threshold'] for r in sweep['rows'] if r['variant'] == selected['variant']
              and r['gt_admitted'] == 7 and r['hn_admitted'] == 0]
    result = dict(TASK_RESULT='V5_SCORING_PROMISING_BUT_NOT_READY',
        SCORING_FORMULA='C_STRONG_ANCHOR_CONTEXT_V1_RESEARCH', ADMISSION_POLICY='global threshold + frozen hard/duplicate guard',
        RECOMMENDED_THRESHOLD=selected['threshold'], GT_CANDIDATE_RECALL='7/7', GT_ADMISSION_RECALL='7/7',
        HN_ADMITTED=selected['hn_admitted'], HN_REJECTION_RATE=selected['hn_rejection_rate'],
        TOTAL_ADMITTED=selected['total_admitted'], BACKGROUND_BACKGROUND_ADMITTED=selected['background_background_admitted'],
        SAME_SOURCE_ADMITTED=selected['same_source_admitted'], CROSS_SOURCE_ADMITTED=selected['cross_source_admitted'],
        V5_FREEZE_READY=False, PRIMARY_REMAINING_BLOCKER='INDEPENDENT_VALIDATION_AND_ANCHOR_CALIBRATION',
        metric_scope='Sealed experimental C development predictions; production behavior remains baseline 4/7, HN48, total14788.',
        production_deployed=False, new_tests=new_tests,
        regression=dict(passed=regression['passed'], failures=regression['failures'], errors=regression['errors'], skipped=regression['skipped']),
        combined_passed=regression['passed']+new_tests['passed'], combined_failed=regression['failures'],
        limitations=['Only one semisynthetic development dataset and one attack sequence; no untouched independent test.',
                     '10% anchor reliability decrease or anchor-strength eligibility increase causes GT6/7.',
                     'Known HN failures share a parent-only template; no negative coverage for genuinely shared benign exact sessions.',
                     'Background triage is provisional observable semantics, not independent human adjudication.',
                     'Five inherited regression failures remain; no production Schema/API integration of experimental formula.'])
    save(OUT / 'result.json', result)
    metric_keys = ['gt_admitted', 'hn_admitted', 'total_admitted', 'background_background_admitted', 'same_source_admitted', 'cross_source_admitted']
    gtrows = [r for r in witnesses if not r['scenario_id']]
    paragraphs = [
        '# V5 Scoring Semantics + Admission Calibration',
        '## 结论与边界',
        '`TASK_RESULT=V5_SCORING_PROMISING_BUT_NOT_READY`，`V5_FREEZE_READY=false`。推荐继续验证 Candidate C，开发阈值保留 **0.65**。实验指标改善，但不能凭这一份开发数据冻结生产 V5。没有部署生产公式、没有执行 Final Dataset 的 Incident/有向攻击链重构。',
        '```text\n'+'\n'.join(f'{k}={str(v).lower() if isinstance(v, bool) else v}' for k, v in result.items()
            if k in ('TASK_RESULT', 'SCORING_FORMULA', 'ADMISSION_POLICY', 'RECOMMENDED_THRESHOLD', 'GT_CANDIDATE_RECALL', 'GT_ADMISSION_RECALL',
                     'HN_ADMITTED', 'HN_REJECTION_RATE', 'TOTAL_ADMITTED', 'BACKGROUND_BACKGROUND_ADMITTED', 'V5_FREEZE_READY', 'PRIMARY_REMAINING_BLOCKER'))+'\n```',
        '**以上数字属于已封存的离线 Candidate C 预测。生产仍保持原公式、0.65 和 14,788 条关联的行为。**',
        table(['指标', '基线', 'C / global / 0.65'], [[k, baseline[k], selected[k]] for k in metric_keys]),
        '## 1. 封存与复现',
        '新边界先封存当前 backend/app 全部 Python 源码与有效配置，再运行候选公式。旧 source-recovery seal 完全保留。baseline/seal.json 保存 config hash、implementation hash、mapping digest、candidate/score/admission digest 和全部保护文件哈希；baseline/source/ 保存可复核的当前源码副本。',
        f"候选 digest `{read(OUT/'baseline/seal.json')['candidate_digest']}`；成员评分 digest `{read(OUT/'baseline/seal.json')['score_digest']}`；原接纳 digest `{read(OUT/'baseline/seal.json')['admission_digest']}`。",
        '完整评分输入来自冻结的 9,985 条 CanonicalAlert 和既有实体/候选/诊断，240,621 个候选全部核验 G1×G2 的 241,464 个成员。逐成员原公式重算误差 **0**，原始 score digest 与边数准确复现。唯一 support pair 按完整分和原 timestamp/ID 决胜；不同成员的分项不会拼合。',
        'predictions/member_features.jsonl.gz 保存全部成员的观察维度、原值、reliability、指针、typed bindings、共享实体、原 breakdown；predictions/members.jsonl.gz 保存三公式完整分解；predictions/candidates.jsonl.gz 保存每个策略的独立合法成员胜出结果。完整 187 个 GT/HN 对见 complete_witness_decomposition.json；12 个无候选 HN 明确无评分，不填零冒充已评分。',
        '实验 worker 的四个允许读取文件只有 canonical/entities/diagnostics/candidate_pairs，未读取 GT、HN、trace_map、source_capabilities。可信 Python audit tripwire 拒绝额外文件/网络/子进程；它不是 OS 沙箱。人工已经知道开发集问题，因此不宣称人工盲审或独立测试。预测及评分实现先封存，之后 evaluation 才解封标签对齐；后续审计只分析封存预测，未改公式或重新调参。',
        '## 2. 分布与可分性',
        'GT witness 是明确指定对；attack-support observation pairs 定义为两端都在 125 条攻击观察中的候选，**不宣称这些对全是正例**。background-background 是两端都不在 GT/HN 观察中的候选。Known HN 的总分母固定180，其中168已评分、12未提名；分位数只统计实际评分。跨源/同源按原生六源统计，OTHER 枚举不会把 Auth/Firewall/Audit 合并成同源。',
        table(['Model', 'Group', 'Count', 'Scored', 'min', 'p05', 'p25', 'median', 'p75', 'p90', 'p95', 'p99', 'max', 'Admitted', 'Rate'],
            [[m, g, d['count'], d['scored_count'], *[None if d[k] is None else round(d[k], 6) for k in
                ('min', 'p05', 'p25', 'median', 'p75', 'p90', 'p95', 'p99', 'max')], d['admitted_count'], round(d['admission_rate'], 6)]
             for m in ('baseline', 'C:global') for g, d in distributions[m].items()]),
        table(['Model/group']+[f'{i/10:.2f}–{(i+1)/10:.2f}' for i in range(10)],
             [[m+'/'+g, *d['buckets'].values()] for m in ('baseline', 'C:global') for g, d in distributions[m].items()]),
        '完整 A/B/C 与基线分布、十个桶见 score_distributions.json。全局策略未通过 guard 的已评分候选依照实验公式为0；这与无候选 HN 的 null 不同。',
        table(['Model', 'min GT', 'max HN', 'worst margin', 'GT>HN order rate'],
             [[m, *[round(d[k], 9) for k in ('gt_min', 'hn_max', 'worst_case_margin', 'positive_negative_order_rate')]] for m, d in margins.items()]),
        '基线 GT 最低分0.589681941，HN最高分0.806864364，最差 margin=-0.217182423，明显交叠；平均数不能证明分离。C 的开发集最差 margin=+0.273687671；这是已知样本上的排序分离，不是概率校准或泛化证明。',
        '## 3. 三条漏接 GT 的根因',
        table(['Witness', 'Baseline', 'C', '原 evidence mass', '时间因子'],
             [[w['pair_id'], f"{w['baseline_score']:.9f}", f"{w['member_predictions']['experiments']['C']['score']:.9f}",
               round(w['features']['baseline']['evidence_mass'], 9), round(w['features']['baseline']['temporal_factor'], 9)] for w in gtrows]),
        '**E01 IDS/WAF：** 共享 flow SESSION 的 strength=0.697859626，再乘0.8得到0.558287701；asset=0.092937889、resource=0.039234491；noisy-OR mass=0.615059220，再乘0.958740105得到0.589681941。不存在 host/account/process 缺失分母，但弱的附属上下文很难补足质量；原始五元组并未作为额外独立特征消费。这里是“已调整的会话强度再乘固定可靠性”的复合折扣，不是多次时间衰减。',
        '**E02 WAF/WAF：** application-session support=0.728987548×0.8=0.583190038；asset=0.234788499，resource=0.039234491；mass=0.693565977，再乘0.934723358=0.648292319。差0.001707681只是阈值表现；ticket/操作上下文没有独立专用消费路径。与E01/E05相同的会话质量模型被系统性压低，不做 epsilon 放行，也不把同源视作不能关联。',
        '**E05 EDR/Auth：** SSH connection SESSION=0.677841570×0.8=0.542273256，受监控endpoint=0.200484855；mass=0.634040536，时间因子0.939474367，最终0.595664831。account 没有支持便不加分；源差异/未确认独立性不加 source bonus。缺失不被额外惩罚，问题仍是 exact scoped connection 被当作一般低质量会话线索。不能为了提高分数把五元组和同一connection包装为两份独立观察。',
        '三者均 valid、gate passed、weak_only=false、无 conflict/duplicate penalty；没有额外弱证据 ceiling 命中。存在 sparse evidence 的实际 mass 上界，和 reliability/rarity 的连乘，不能笼统归因为缺失惩罚。',
        '## 4. 全部 HN 家族',
        table(['Family', 'Pairs', 'Scored', 'Baseline admitted', 'C admitted', 'Parent-only pairs'],
              [[s, d['count'], d['scored'], d['baseline_admitted'], d['recommended_admitted'], d['parent_only_feature_pairs']] for s, d in families.items()]),
        'HN07/08/10/13 每类12对均显示：entity.PROCESS 的指针是双方 parent_process_id，strength=0.892613857×0.8=0.714091085；它是共同祖先进程，不能证明同一子进程、PID重用后的同一实例、同一认证会话或网络动作属于同一进程。加上 host≈0.2348、account≈0.152 和接近1的时间因子，得分约0.8068。不是 time-only，也不是 source-name 奖励。',
        'HN07：不同进程却共享父进程；HN08：PID/启动时间不同，共同父进程掩盖区别；HN10：sshd 父守护进程不能绑定不同登录会话；HN13：执行/网络动作不同子进程，共同祖先不足。类别名只在 evaluation 使用，数值模型不读取 scenario ID。其余11类保留完整12对审查；HN11无非时间提名保持未候选，其余共享账号/host/URI/tuple/proxy等不足以突破既有门槛或分数。',
        '逐家族 dominant_false_support_features / missing_disambiguating_features / double-counting / gate / score / admission 结论见 hard_negative_family_diagnosis.json。更合适的修复是角色语义与强锚点资格，父父共享降为上下文；不把不同session值直接当互斥冲突，不禁止正常兄弟进程运维关联。48指 undirected correlation 暴露，不是48条错误攻击链。',
        '## 5. 独立性与五态',
        '当前公式已对IP/HOST、URL/DOMAIN、PROCESS/FILE/COMMAND分别取max；没有把src_ip/dst_ip/port/protocol/tuple/flow机械累加成六份证据。剩余问题是 SESSION 与 asset/resource 的依赖未全部合并、一个共同父实例被提升为强身份，并与同一操作中的host/account上下文一起做 noisy-OR；不同family名称不证明独立观察。',
        '实验依赖组：context={IP,HOST,URL,DOMAIN,endpoint/flow view}，execution={PROCESS,FILE,COMMAND}，identity={ACCOUNT}，session={既有typed scoped SESSION}。B将network/session/context合为同组取max；C把强锚点作为替代证明通路，与mass取max，绝不再做一次noisy-OR。相同字段/重复包装不会刷分。',
        table(['状态', '当前/实验语义'], [
            ['SUPPORTED','仅真实共享/关系事实可产生支持'], ['OBSERVED_ZERO / NO_SUPPORT','原公式最终分忽略；A用有限零支持权重降低可见一致性'],
            ['MISSING','不产生负分，不进入正负分母'], ['UNOBSERVABLE','不进入正负分母；source capability本身不产正分'],
            ['CONTRADICTORY','仅已核验矛盾沿用显式负分/hard guard；不同值不自动等于互斥']]),
        'source capability metadata未传入worker。source reliability不是产品类型先验；沿用原feature reliability，C仅对已存在且合格的exact typed identity应用显式可配置可靠性假设。没有因“此源能看到”奖励得分。',
        '## 6. 三个明确候选公式',
        '共同定义：x_f=strength_f×reliability_f；双方仅parent_process的PROCESS再乘p=0.20且不能成为anchor。g_k=max(该依赖组x_f)；M=1−∏(1−g_k)；T=0.8+0.2×原TimeScore；P=原conflict_penalty+原duplicate_penalty。',
        '```text\nA: Q=Σg_k / (Σobserved-supported group reliability + 0.15×n_observed_zero)\n   S_A=clamp(Q×M×T − P,0,1)\nB: M_B=1−∏(1−max_in_dependency_group(x_f))\n   session/context合并后 S_B=clamp(M_B×T − P,0,1)\nC: a=max_exact_anchor[0.90×(0.80+0.20×strength)]\n   已核验direct relation使用原strength×reliability作为另一anchor\n   c=max(g_context,g_identity)\n   S_C=clamp(max(min(M,0.45), a×(0.90+0.10×c))×T − P,0,1)\n```',
        'anchor必须是既有typed scoped SESSION，或含host/pid/start_time且不是父父共享的PROCESS，或原已核验direct relation；还须not hot且strength≥0.60。一个裸PID、短token、同名进程或同source不能生成anchor。所有模型保留原member validity、hard/duplicate gate；弱单项上限0.45，gate不通过则0。没有score floor，anchor中的0.80是确切身份的可靠性假设，不能解释为缺字段补分。',
        '时间仅乘子；role来自existing occurrence；频率沿用已有rarity/strength与hot限制；冲突/duplicate沿用原惩罚；缺失和不可观察均排除。源差异无独立奖励，behavior/detector identity不单独计入mass。B更保守但仍压低稀疏连接；A出现明显under-correlation；C把exact binding的质量与数量分开。所有数值为开发假设，非最优权重或校准概率。',
        table(['Variant@.65','GT/7','HN/180','Total','Background'],
              [[r['variant'],r['gt_admitted'],r['hn_admitted'],r['total_admitted'],r['background_background_admitted']]
               for r in sweep['rows'] if r['threshold']==.65 and r['policy']=='global']),
        '## 7. 阈值、接纳与整组校准',
        '先封存三公式，再搜索0.40–0.85、步长0.01，共46点×16个baseline/实验组合=736行。完整表含同源/跨源/背景/GT/HN见 threshold_search.csv；Pareto frontier保存在threshold_search.json。Pareto按GT越高、HN暴露越低、总边越少定义，不把背景当FP。',
        table(['Pareto variant','threshold','GT','HN','total','background'],
             [[r['variant'],r['threshold'],r['gt_admitted'],r['hn_admitted'],r['total_admitted'],r['background_background_admitted']] for r in sweep['pareto_frontier']]),
        '基线降到0.58虽可7/7，但HN仍48；提高到0.81才拒绝这48个，却只留1/7 GT。因此threshold-only无法消除交叠。推荐修复属于 **formula + role-aware evidence normalization/anchor eligibility**，不是全局降阈值。',
        f"C在本开发网格的GT7/7、HN0稳定区间是[{min(stable):.2f},{max(stable):.2f}]；保留0.65是预先声明的简单性/距既有阈值最近决胜，并非用最低阈值追求7/7。",
        '已比较global、evidence-class threshold(无anchor提高0.10)、strong-anchor、score+contradiction gate、score+mass≥0.50。0.65处C的五策略指标相同，因此优先global；其他阈值的差异全部保留，未按scenario/source label定class。',
        f"按5个完整binding family、15个HN family做20折leave-one-family-out：每折只用其余标签选择既定公式/策略/阈值；20折均选C/global/.65，留出GT全接纳、留出HN全拒绝。选型不重新拟合公式。binding整组仍可能只有1或2条GT，单条attack序列无法提供独立泛化。",
        table(['Sensitivity','×','value','GT/7','HN/180','margin'],
             [[r['parameter'],r['multiplier'],round(r['value'],3),r['gt_admitted'],r['hn_admitted'],round(r['margin'],6)]
              for r in sensitivity['rows'] if r['multiplier'] != 1.0]),
        '这项敏感性只重算7个GT和168个已评分HN的冻结特征，不冒充全体边数实验。anchor_reliability降10%导致最弱GT=0.647482582、6/7；anchor minimum从0.60升到0.66也导致6/7且最差margin变负。没有针对这两次失败继续调参。',
        '## 8. 未标注背景与新增边',
        table(['Stratum','Semantic class','Count'], [[s,c,n] for s,counts in background['counts'].items() for c,n in counts.items()]),
        '三组各100且本次恰好300个唯一pair；random按seed=42的hash排名并排除前两组。background_semantic_review.json保存每对字段依据与provisional标记；这属于可复核的规则语义初审，不是独立人工裁决/新真值。所有七种分类均定义，未出现的类别计0。',
        f"全体变更：保留{changes['counts']['retained']}，移除{changes['counts']['removed']}，新增{changes['counts']['added']}。背景移除{changes['counts']['removed_background_background']}，新增{changes['counts']['added_background_background']}，净增103；总边净增643（4.35%），背景净增0.78%。新增背景105对均为同具体session、同category的运维关系线索。新方案另保存high/near/random各100背景样本。",
        '没有证据把13,324背景关联全部判FP，也不能因语义初审就证明没有新over-correlation。特别是合法共享的长会话、良性同实例重复观察、错误或重用typed标识仍可能过强；当前HN集缺这些exact-anchor困难负例。C故意不以“有anchor”直接宣布攻击进展，相关性也没有变成有向边。',
        '## 9. 回归、完整性与停止',
        f"既有受影响回归 **{regression['passed']} passed / {regression['failures']} failed / {regression['skipped']} skipped**；新增合成+产物集成 **{new_tests['passed']} passed**。合计{result['combined_passed']} passed / 5 failed / 4 skipped。没有删除失败测试、跳过这5项或改旧seal。第一次新增合成测试有一处测试预期错误（把shared-parent当正式typed binding），已修正为仅保留context并重跑；首次失败日志保留。",
        '5个失败与开始登记一致：旧historical source-freeze检测上轮授权extraction.py变化1项；semantic_repair/separation_direction的11个既有模块未登记whitelist导致4项。未把它们拆成额外任务，也没有宣称全绿。',
        '运行范围包含Adapter/projection/entity/candidate/dedupe、V2/V3/V4/V5、Stable ID/Schema/API/隔离、chain/grounding、source-bound、semantic-repair、separation-direction。chain仅运行既有合成回归，不执行Final Dataset的Incident/攻击链重建。未改UI，未运行无关高成本capacity/真实AI provider实验；完整命令在regression_selection.json。',
        f"{integrity['protected_file_count']}个保护文件逐字节核验通过；Dataset/GT/generator/Adapter/projection/candidate policy/生产score/admission与上一阶段seal均不变，并核对输入、generator、production文件集合未增删。无Git元数据，本轮以SHA-256清单核验，不伪称git diff。",
        '## 10. 十五问直接回答',
        table(['问题','结论'], [
            ['1 E01/E02/E05为何低分','稀疏的exact会话被既有调整strength×0.8再乘时间；mass上界低，不是缺host/account的显式分母惩罚。'],
            ['2 四HN为何接纳','双方共同父实例当强PROCESS，加host/account上下文稳定过线；每类12对一致。'],
            ['3 是否double count','基本字段已max去重；仍有session/context依赖及parent语义升级风险，不能视不同family为独立观察。'],
            ['4 Missing/Unobservable是否隐式压分','原final不使用可见分母；两者不罚分。少观察导致mass少，需区分质量与数量。'],
            ['5 分布能否分离','基线交叠，C已知开发对分离；独立集未知。'],
            ['6 修复属于哪里','公式、role-aware normalization及强anchor资格；全局threshold保留。'],
            ['7 新公式','第6节C明确公式；全部可配置，研究实现不进生产。'],
            ['8 推荐threshold','开发0.65；整网格与简单性决胜，独立验证前不称生产最优。'],
            ['9 GT Admission','实验C7/7；生产基线仍4/7。'],['10 HN admitted','实验C0/180；12未候选计拒绝但无评分；生产基线48。'],
            ['11 Background变化','13221→13324；不等于FP变化。'],['12 同/跨源变化','4938→5166；9850→10265。'],
            ['13 新over-correlation','新增105背景为session运维关联线索；未证明恶性新增，也无法排除exact-anchor误接纳。'],
            ['14 过拟合迹象','20折选型稳定，但单数据/单攻击且anchor参数±10%可掉召回；存在开发集与模板偏差风险。'],
            ['15 能冻结吗','不能。需要未触碰独立输入/困难exact-anchor负例、参数稳健性验证，并处理遗留回归和生产契约接入验收。']]),
        '## 复现',
        '```powershell\n# 新目录单次执行snapshot与replay，不覆盖已有seal\n.venv/Scripts/python.exe -B -m evaluation.framework.scoring_calibration.snapshot\n.venv/Scripts/python.exe -B -m evaluation.framework.scoring_calibration.replay\n# 之后仅评测封存预测，可复核统计\n.venv/Scripts/python.exe -B -m evaluation.framework.scoring_calibration.evaluate\n.venv/Scripts/python.exe -B -m evaluation.framework.scoring_calibration.audit\n.venv/Scripts/python.exe -B -m evaluation.framework.scoring_calibration.regression\n.venv/Scripts/python.exe -B -m pytest evaluation/tests/test_scoring_calibration.py evaluation/tests/test_scoring_calibration_artifacts.py -q -p no:cacheprovider --basetemp=outputs/v5_scoring_calibration/verification_tmp --junitxml=outputs/v5_scoring_calibration/verification.xml\n.venv/Scripts/python.exe -B -m evaluation.framework.scoring_calibration.report\n```',
        '已结束于scoring/admission研究交付。`V5_FREEZE_READY=false`，停止，不自动重构攻击链、改UI/数据、写论文或启动新数据集。']
    (OUT / 'V5_SCORING_CALIBRATION_REPORT.md').write_text('\n\n'.join(paragraphs)+'\n', encoding='utf8')
    artifacts = {}
    for path in sorted(OUT.rglob('*')):
        # stdout may still append to report.log after the manifest is written.
        if path.is_file() and not any(p.endswith('_tmp') or p == '__pycache__' for p in path.parts) and path.name not in {'manifest.json', 'report.log'}:
            artifacts[path.relative_to(OUT).as_posix()] = sha(path)
    changed_files = sorted([str(p.relative_to(ROOT)) for p in (ROOT / 'evaluation/framework/scoring_calibration').glob('*.py')] +
        [str(POLICY.relative_to(ROOT)), 'evaluation/tests/test_scoring_calibration.py', 'evaluation/tests/test_scoring_calibration_artifacts.py'])
    save(OUT / 'manifest.json', dict(result=result, artifacts=artifacts,
        baseline_seal_sha256=sha(OUT / 'baseline/seal.json'), prediction_seal_sha256=sha(OUT / 'prediction_seal.json'),
        changed_files={p: sha(ROOT / p) for p in changed_files}, integrity=integrity,
        formula_deployed=False, final_dataset_chain_reconstruction=False))
    print('FINALIZED', result['TASK_RESULT'], result['combined_passed'], result['combined_failed'], flush=True)


if __name__ == '__main__':
    main()

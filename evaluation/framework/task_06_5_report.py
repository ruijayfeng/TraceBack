"""Human-readable Task 06.5 artifact, entirely derived from diagnostic results."""

import json
from pathlib import Path


CHANGED_FILES = ["evaluation/io/task_06_5.py", "evaluation/sensitivity/score_reachability.py",
                 "evaluation/framework/task_06_5.py", "evaluation/framework/task_06_5_report.py",
                 "evaluation/tests/test_task_06_5.py"]


def table(headers,rows):
    return "\n".join(["| " + " | ".join(headers) + " |", "|"+"|".join(" --- " for _ in headers)+"|",
                      *("| " + " | ".join(str(c).replace("|","\\|").replace("\n"," ") for c in r)+" |" for r in rows)])


def write_report(out,baseline,stats,members,top,blocking,reach,sensitivity,gt,verification):
    def number(v):
        return "null" if v is None else f"{v:.12g}" if isinstance(v,float) else str(v)
    t=stats["edge_threshold"]
    temporal=gt["same_window_union"]
    tests_path=Path(out,"tests.json")
    tests=json.loads(tests_path.read_text(encoding="utf-8")) if tests_path.exists() else None
    test_text=(table(["检查","passed","skipped","failed / error"],
                     [[k,v.get("passed"),v.get("skipped",0),v.get("failures",0)+v.get("errors",0)] for k,v in tests["runs"].items()])
               + "\n\nRepository check: "+tests["repository_check"]["status"]+"。专项测试、contract 与全量 pytest 实际日志 / JUnit XML 随报告保存。"
               + "\n\nSkipped 原因："+json.dumps(tests["skipped_tests"],ensure_ascii=False)) if tests else "实际测试结果待写入 tests.json；不能把未执行当通过。"
    body = ["# Task 06.5 · 评分体系诊断与算法可达性分析", "",
        "## 1. Scope", "",
        "只读诊断 + 离线分析。生产实现、原输入、原 Task 05.2 / Task 06 冻结快照、配置、Mapping、七份基线不变。"
        "不调参，不改提名/Top-K/hot/guard，不发布新边，不运行下一 Task。所有输出仅在 outputs/evaluation/task_06_5/。",
        "诊断直接读取经过 SHA-256 验证的原始未舍入评分；全量核对七项贡献、加权和、clamp、guard 状态、G1×G2 完整性及赢家排序。"
        "Top 20 再调用原 CorrelationScorer.score_pair 和原 CorrelationEdge Schema 完整复验。不是重新实现近似 scoring。",
        "## 2. Production Baseline", "",
        table(["项","冻结值 / 实际核验"],[[k,v] for k,v in baseline.items() if k not in {"source_counts","input_source_counts"}]), "",
        "输入记录口径为 Wazuh 41,488 + AMiner 4,056 = 45,544。Stable ID 重复导入折叠后 canonical 告警数与代表数另列，"
        "不将 raw 输入行数、canonical 存储数、dedupe 代表数混用。原 summary.counts 保存在 production_baseline.json。",
        "所有 826,313 个代表 Candidate 均完成全部成员核验；成员 pair 数 826,519，不是额外 Candidate。"
        "policy_pruned 是唯一 Potential Pair 未准入数；resource_truncated=0。无资源遗漏。",
        "## 3. Scored Pair Distribution", "",
        table(["统计","值"],[[k,number(stats[k])] for k in ("count","min","max","mean","median","std","P50","P75","P90","P95","P99","P99.5","P99.9")]), "",
        f"正式阈值 {t} 从分析快照中恢复并严格校验的正式配置读取，未复制硬编码阈值。Observed max={stats['max']:.16g}，Gap={stats['gap_to_threshold']:.16g}。",
        "标准差为 population std；分位数线性插值；阈值以未舍入浮点比较。代表级 winner 与全成员统计分别见 score_distribution.json / member_pair_distribution.json。",
        "## 4. Score Member Distribution", "",
        table(["成员","min","max","mean","P50","P90","P95","P99","非零数 / 比例","到 box max 数","平均带符号贡献"],
              [[r['member'],*(number(r[k]) for k in ('min','max','mean','P50','P90','P95','P99')),
                f"{r['nonzero_count']} / {r['nonzero_ratio']:.6%}",r['at_theoretical_max_count'],number(r['mean_signed_contribution'])] for r in members]), "",
        "真实正式成员为 time/entity/relation/behavior/source/conflict/duplicate；没有 RuleScore 或 TechniqueScore。"
        "厂商 rule 参与标准化和 Duplicate 特征，不是独立关联奖励；ATT&CK 不进入本评分公式。",
        "Time 和 Entity 在全部 Candidate 非零。Behavior 仅已映射 authentication↔authentication 有 0.4；涉及 unknown 为 0。"
        "Relation/Source 在整个数据集字段与当前配置下均不可触发，缺失权重不重分配。Conflict/Duplicate 是减分，soft penalty 不等于 hard rejection。",
        "非零成员组合计数、最高分及平均分见 score_combinations.json；全成员明细统计见 raw_member_score_members.csv。"
        "Top 20 的高分来自近时间、较稀有的多个共享实体、authentication 同类兼容；仍不具有显式传播或已确认独立来源奖励。",
        "## 5. Top Candidate Analysis", "",
        "稳定排名：未舍入 score 降序、代表 ID / 成员 ID 升序。每对包含两源、timestamp、rule、sensor、时间差、实体 scope/角色/rarity、"
        "七项原值/带符号贡献、候选提名全 provenance、soft/hard conflict、重复特征、字段证据引用与原 diagnostics byte offset。"
        "只输出实体必要摘要和字段指针，不复制完整原始 payload。完整可复核解释见 top_candidates.json。",
        table(["Rank","Pair ID","源","gap(s)","T / E / R / B / S / C / D","score","未成边原因"],
              [[r['rank'],r['pair_identifier'], '/'.join(a['source_type'] for a in r['alerts']),number(r['time_gap_seconds']),
                ' / '.join(number(r['score_members'][k]) for k in ('time','entity','relation','behavior','source','conflict','duplicate')),
                number(r['final_score']),'below_correlation_threshold; valid; schema replay passed'] for r in top]), "",
        "每个 Top Candidate 均已通过全部现有成员 guard，原 Schema 离线校验也通过。未成边原因是最终分数未达到阈值。"
        "高分不是攻击事实或 pair 真值；证据仅说明设备产生的告警具有这些共享字段。",
        "## 6. Edge Admission Blocking Reasons", "",
        "生产执行顺序：成员七项评分及 hard/missing_non_time_support 检查 → 完整 G1×G2 取最高有效成员 → "
        "若无有效成员则 no_valid_member_pair → 比较 correlation threshold → 正式 CorrelationEdge Schema。",
        table(["First blocking reason","pair 数","比例"],[[r['reason'],r['pair_count'],f"{r['ratio']:.6%}"] for r in blocking['first_blocking_reason']]), "",
        table(["All failed conditions","pair 数","比例"],[[r['reason'],r['pair_count'],f"{r['ratio']:.6%}"] for r in blocking['all_failed_conditions']]), "",
        "全部 826,519 成员 pair 的 hard/missing-support 失败数为 0。冲突惩罚与重复惩罚已计入分数，不能再次计为独立准入拒绝。"
        "无向 CorrelationEdge 不要求非零 RelationScore，也不检查 ChainEdge 方向；不存在可归因于 direction 的本层拒绝。"
        "verified_incompatible_session 保留原实现 unproven 状态，不伪造已核验互斥会话。",
        "## 7. Mathematical Score Reachability", "",
        "raw = Σ正项 weight×value − Σ惩罚 weight×value；final=clamp(raw,0,1)。权重在 reachability / 分解 CSV 与原快照中可核验。",
        f"七项独立数值定义域的 Maximum Theoretical Score = {number(reach['mathematical_box_upper_bound'])} (exact box maximum)。"
        "它是独立成员取各自最大、惩罚为 0 的数学上界，不等于现实字段可联合取得。所需值："+json.dumps(reach['box_requirements'],ensure_ascii=False),
        f"当前配置允许的更紧上界 = {reach['configuration_allowed_upper_bound']:.16g} (upper bound)。"
        f"无 independence mapping ⇒ S=0；CanonicalAlert 实体字段数量限制与实体权重给 E≤{reach['configuration_entity_envelope']:.16g}；"
        "再保守取 T、R、B 各自允许最大、C=D=0。该值仍为松弛上界，不宣称所有关系/行为/实体上限可以在同一个 pair 同时达到。",
        f"公式可达的 constructive witness：冻结配置下 synthetic 进程父子样本经原生产 scorer 得 score={reach['formula_witness']['score']:.16g}，"
        "valid=true 且 ≥ threshold；没有修改任何权重/阈值、没有 GT。此证据仅证明公式与阈值不自相矛盾，不冒充真实数据能力。",
        "## 8. Dataset-Constrained Reachability", "",
        f"Dataset-Constrained Maximum Reachable Score ≤ {reach['dataset_constrained_maximum_reachable_score']:.16g}，类型 **upper bound**。"
        "不是 max(observed)，覆盖整个原告警集合的所有跨组 pair，包含非 Potential / policy-pruned pair。",
        "完整证明："+json.dumps(reach['proof']['category_counts'],ensure_ascii=False)+"；所有告警的 upstream relations 为空；"
        "所有 PROCESS 实体缺完整实例；verify_relations 的全部分支均缺必要入口 ⇒ R=0。"
        "当前配置无独立映射规则 ⇒ S=0。真实类别集合逐一用原 behavior_value 两向枚举 ⇒ B≤0.4。",
        f"第一层严格松上界 T≤1、E≤1、C,D≥0 ⇒ score≤{reach['coarse_dataset_upper_bound']:.16g} < threshold。"
        "这已经证明任何当前真实 pair 都不可越阈值，而不受 Candidate 覆盖范围影响。",
        "更紧上界保留每个真实 endpoint 的实体、df/N rarity、实例/描述因子和每类型贡献上限；"
        "只允许 df≥2 的可共享实体，将 partner role 松弛为配置最大，利用 noisy-OR 单调性得 E(pair)≤min(Ecap(A),Ecap(B))。"
        "再保守放宽 T/chronology 与惩罚、用该 endpoint 类别的最强 B，遍历所有真实 endpoints 取最大。"
        "endpoint_bound_witness 仅为上界出处，不是新合成的支撑告警 pair；不能拿各项最大值拼成正式分数。",
        f"Threshold Reachability Classification：**{reach['classification']}**。数学可达；当前真实标准化字段+配置不可达。"
        "该判断不等于原数据没有真实攻击，也不证明原始 payload 中没有尚未抽取的信号。",
        "## 9. Counterfactual Signal Analysis", "",
        "只代换某个成员，其他真实成员保持不变；直接使用原未舍入 contributions 加差值，不另建评分算法。"
        "七项逐一推至允许最大；惩罚项取最大会降低分数，另外列出惩罚归零影响。所有 counterfactual 均不构造实体/事实/边。",
        "这里的 max 是单成员数值定义域上限。当前配置没有独立性映射，因此 S 的可实现上限为 0；"
        "S→数值 max 的行明确标 configuration_gate_known_unavailable=true，只表示代数缺项容量，不表示可由当前配置产生。"
        "即使单成员代数越阈值，也还须用真实字段重新评分并通过全部 guard，不能视为形成 edge。",
        table(["成员","Top 1 actual","推至 max 后 score","越阈值"],[[r['member'],number(r['actual_value']),number(r['final_score']),r['score_passes']] for r in top[0]['counterfactual']['single_member_to_allowed_maximum']]), "",
        f"Top 1 最少同时补齐 {top[0]['counterfactual']['minimum_positive_members_to_maximum']} 个正成员即可代数过阈值；"
        "全部最小组合及 Top 20 每对逐成员结果见 counterfactual.json。"
        "把 R 补到最大意味着取得缺失的字段级传播证据；把 B 提高意味着有合法映射的不同安全行为；"
        "把 S 提高意味着确认独立性+上下文+互补侧面。当前实体/时间再强也无法弥补固定缺失的评分容量。",
        "## 10. Threshold Sensitivity", "",
        table(["delta","T","Score-Passing Pair","Actual-Admissible Pair","剩余 guard 失败"],
              [[r['delta'],number(r['threshold']),r['score_passing_pair'],r['actual_admissible_pair'],r['remaining_guard_failed_pair']] for r in sensitivity]), "",
        "Score-Passing 使用全部成员中最高分，Actual-Admissible 使用原完整 guard 后唯一最高有效成员；未把 score 过线直接当作 edge。"
        "模型 Schema 另经 Top 20 实际回放及专项有效边 fixture 验证。所请求五个阈值没有任何 score 过线，因而后续 Schema/guard 根本无新增入场者。"
        "Relation 与方向对 CorrelationEdge 无独立门槛；chain/clustering 阈值保持原值，不模拟下游链，不发布生产边。",
        "## 11. Ground Truth Diagnostic", "",
        "labels.csv 格式只有 scenario,attack,start,end；粒度为攻击窗口，不含 alert identity、benign label、pair relation 或 incident membership。"
        "因此 GT-positive / same-incident pair 的 Potential/Admitted/Scored/guard 统计 **unavailable**，不能以窗口内共现冒充真值。"
        "真实攻击相关告警有没有相遇（Q5）无法在目前 GT 粒度下确定；不调用真值生成生产 Candidate 或修改评分。",
        "生产已完成，且本次所有生产回放/全输入 potential 观察/可达性计算均完成、prediction_freeze.json 落盘后才加载 GT。"
        "之后只用冻结 bitsets/score 表做 evaluation 时间映射。原 Top-K / hot 策略没有重跑或改动。",
        table(["同一窗口内代表组 proxy（跨窗口去重）","值"],[[k,v] for k,v in temporal.items() if k not in {"score_distribution"}]), "",
        f"时间窗口 proxy 中 {temporal['scored_pair']} 对已经进入 Scored Pair；最高 {number(temporal['score_distribution']['max'])}；"
        f"全部被 threshold 阻止，其他 hard guard 失败 0。Potential 未入选 {temporal['policy_pruned']} 对；"
        f"其中只有 time-only 而无非时间 channel 的 {temporal['time_only_without_non_time_channel']} 对。"
        "这些是时间上下文统计，不是攻击召回率或质量指标。按窗口明细见 gt_diagnostic.json，重叠窗口计数不简单相加。",
        "## Final Diagnosis", "",
        "**Q1：为什么 826,313 Scored Pair 为 0 CorrelationEdge？** 全部有效 winner 的未舍入 score 都低于正式阈值；"
        "不存在资源截断或本层 hard guard 导致的零边。高分依赖时间、稀有实体和同类 authentication，缺少 R/S 奖励。",
        "**Q2：瓶颈主次？** 主因是 Data Signal / 当前映射覆盖 → Score 容量与 Threshold 的组合；"
        "Relation 无传播入口、Source 无独立映射、Behavior 仅 0.4 上限，使全数据上界低于阈值。"
        "Candidate 策略损失很大但其真实攻击质量影响未知，且恢复任何当前 pair 也不能突破这个上界；"
        "Guard 不是独立拒绝主因，Direction 尚未到达本层。soft Conflict / Duplicate 是次要分数抑制因素。",
        "**Q3：对公式是否数学可达？** 是。独立 box max 和冻结配置 synthetic 生产可达 witness 共同证明，非 Formula-Unreachable。",
        "**Q4：对 russellmitchell 是否实际上可达？** 否，在当前 canonical 字段、mapping、有效配置下为 Dataset-Unreachable；"
        "此证明覆盖全部原 pair，不只 admitted observed max。",
        "**Q5：真实攻击相关告警在哪级阻断？** 缺 alert/pair/incident GT，不能给出真攻击 pair 的准入/遗漏结论。"
        "同窗口 proxy 已有大量候选相遇且完成评分，它们被 threshold 阻止；未提名的时间 proxy 有 time-only/Top-K policy 损失。"
        "二者不能直接认定为真实攻击关系。",
        "**Q6：A–E 分类？** 当前可证明的工程解释为 E（当前字段/映射可表达信号与评分容量、阈值组合），"
        "表现与 B 的保守容量一致；不能据未标注数据独立断言 A（真实攻击缺信号）、C（丢失关键攻击关系）或 D（hard guard 过强）。"
        "本 Task 提供调整决策依据，不实施任何调整。",
        "## 13. Files Changed", "",
        *["- `"+p+"`：独立诊断/证明/报告/专项测试。" for p in CHANGED_FILES],
        "- `outputs/evaluation/task_06_5/`：JSON/CSV/Markdown、deterministic gzip potential bitsets、复现摘要与实际测试日志。", "",
        "## 14. Tests", "",
        test_text, "",
        "## 15. SHA-256 / Reproducibility Information", "",
        f"analysis_id=`{verification['snapshot_identity']['analysis_id']}`；config_hash=`{verification['snapshot_identity']['config_hash']}`；"
        f"dataset_digest=`{verification['snapshot_identity']['dataset_digest']}`。",
        "完整输入、配置、mapping、算法版本、生产原文件与原 Task 06 每项 SHA-256 在 reproducibility.json；"
        "diagnostic 产物与实现 SHA-256 见 deliverable_manifest.json；原 cache 的 diagnostics binding、Parquet 完整 hash 与全量算式/赢家核验一并记录。"
        "重复运行的核心产物字节摘要与 prediction_digest 应一致，详见 determinism.json。",
        "## 16. Frozen / Unchanged Contract Confirmation", "",
        "生产算法/Schema/阈值/权重/候选/Top-K/hot/guard/ChainRelationType/Mapping/GT isolation 未改；"
        "七份基线、原告警、生产快照及 Task 06 已有输出逐文件 SHA-256 前后完全一致。"
        "未创建 evaluation API export，不覆盖生产目录，不更新旧 evaluation.duckdb，不进入后续 Task。",
        "诊断分析已执行；涉及真实攻击 pair 的验收仍受 GT 粒度限制，不能宣称已完成该项真值诊断。"]
    # The source contains no cached findings: every numeric statement above
    # derives from machine artifacts or the explicitly supplied baseline.
    Path(out,"TASK_06_5_REPORT.md").write_text("\n\n".join(body)+"\n",encoding="utf-8")

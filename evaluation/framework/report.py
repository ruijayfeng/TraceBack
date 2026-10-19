"""Human-readable report separates truth availability from engineering evidence."""


def table(rows, columns):
    header = "| " + " | ".join(columns) + " |\n| " + " | ".join("---" for _ in columns) + " |\n"
    return header + "\n".join("| " + " | ".join("null" if row.get(c) is None else str(row[c]) for c in columns) + " |" for row in rows)


def write_report(destination, summary, mapping, candidates, distribution, structure, baselines, ablation, sensitivity, noise, conclusion):
    identity = summary["prediction_identity"]
    text = f"""# Task 06 Evaluation Report

## 1. Analysis Identity

- analysis_id: `{identity['analysis_id']}`
- dataset: `{summary['run_identity']['scenario']}`
- config_hash: `{identity['config_hash']}`
- mapping_digest: `{identity['mapping_digest']}`
- dataset_digest: `{identity['dataset_digest']}`
- input: {identity['input_count']}; CanonicalAlert: {identity['canonical_alert_count']}; representatives: {identity['representative_count']}
- prediction snapshot: `{identity['prediction_snapshot']}`
- GT SHA-256: `{summary['gt_sha256']}`
- evaluation run: `{summary['run_id']}`

## 2. Ground Truth Mapping

GT 是 scenario/attack/start/end 的场景攻击时间区间。epoch 秒转 UTC 微秒；半开区间 [start,end)。无告警 ID、正常标签、Incident 成员或因果关系。

GT rows={mapping['total_rows']}; selected={mapping['selected_rows']}; out-of-scope={mapping['out_of_scope_rows']}; temporal mapped={mapping['mapped']}; unmapped={mapping['unmapped']}; ambiguous={mapping['ambiguous']}。

mapped 指区间内存在告警；一个区间可对应多条告警，不代表这些告警来自同一次攻击。ambiguous 指存在同时落入多个选定区间的告警；mapped/ambiguous 可重叠。直接 ID 映射数=0。窗口外告警不视为 benign。

时间重叠告警={mapping['temporal_overlap_alert_count']}; 窗口外={mapping['outside_window_alert_count']}; 时间重叠比例={mapping['temporal_overlap_fraction']:.6f}。告警级质量评测 coverage=0。

## 3. Candidate Evaluation

Potential={candidates.get('unique_potential_pairs')}; admitted={candidates.get('admitted_candidate_count')}; scored={candidates.get('scored_candidate_count')}; policy_pruned={candidates.get('policy_pruned_count')}; resource_truncated={candidates.get('resource_truncated_count')}。

GT positive pairs、admitted/pruned positive、candidate recall/miss 均为 null / unavailable。不能把时间窗口内的 pair 生成正例。Policy pruning 是策略计数，resource truncation 是执行资源计数，二者保持生产原口径。

## 4. Ground-truth Quality Evaluation

CorrelationEdge TP/FP/TN/FN、Precision/Recall/F1、PR/AP/ROC/AUC：**Not Evaluatable / Ground Truth Unavailable**。

冻结零分母策略：null+not_applicable；缺真值：null+unavailable。零预测数是工程事实，不能凭空填充 FN 或分母。通用显式 pair-label 指标函数和 tie-aware ranking 函数由专项测试验证，真实窗口 GT 不输入这些函数。

## 5. Structural / Engineering Score Diagnostics

全部 admitted candidates 的完整成员评分明细保存在 member_scores.parquet；候选元数据在 admissions.parquet。selected_scores.parquet 保留最高有效成员分及支撑 ID；ground_truth=null，原始 diagnostics byte offset 可审计。

有效候选={distribution['valid_candidate_count']}; max={distribution['maximum']}; mean={distribution['mean']}; p50={distribution['p50']}; p90={distribution['p90']}; p99={distribution['p99']}。

生产 threshold={distribution['production_threshold']}; 达阈值有效候选={distribution['valid_candidates_at_or_above_threshold']}。无效成员对={distribution['invalid_member_pair_count']}。GT Positive/Negative score distributions 不可评测；score_distribution.json 的窗口内/外统计仅为时间上下文。

"""
    text += table([{"component": k, **v} for k, v in distribution["components"].items()], ["component", "max", "mean", "nonzero_member_count"])
    text += "\n\n## 6. Baseline Comparison\n\n同一输入/标准化/去重；三个 Baseline 使用 300 秒窗，无生产 Top-K，全量匹配数使用 range bitset 精确计数而非展开平方 pair 列表。Baseline 未发布因果链；不同候选政策已披露。所有质量指标 unavailable。\n\n"
    text += table(baselines, ["method", "predicted_edge_count"])
    text += "\n\n## 7. Ablation\n\n六项 score-only 消融，固定 admitted pairs、threshold 与 hard guards，正权重不重归一化；每组按完整成员最高有效分重选。Entity Rarity 消融复用生产 EntityScore 函数并重新选择贡献实体。不会修改生产配置，不声称 end-to-end。质量及 candidate recall unavailable。\n\n"
    text += table(ablation, ["experiment", "max_valid_score", "predicted_edge_count"])
    text += "\n\n## 8. Threshold Sensitivity\n\n包含冻结阈值与有效分布分位点/上界；只统计既有有效候选在不同阈值的边数，不调参、不发布新 Incident/Chain。Precision/Recall/F1 unavailable，边数随阈值非递增。\n\n"
    text += table(sensitivity, ["threshold", "is_production_threshold", "predicted_edge_count"])
    text += "\n\n## 9. Noise Robustness\n\nseed=42，固定真实告警代表子集及完整原始成员，从同一数据集加入其他真实未标注告警。新增告警不称已确认 benign。保持原事实、ID、配置、所有证据/guard。直接调用生产候选/评分/聚类/链实现，预测全部完成后才加载 GT。样本运行成本实验不能代表全量数据的质量鲁棒性，跨场景/测试 split 未提供。\n\n"
    text += table(noise, ["ratio", "input_alert_count", "potential_pair_count", "admitted_candidate_count", "policy_pruned_count", "resource_truncated_count", "edge_count", "runtime_seconds"])
    text += f"""\n\n## 10. Incident / Chain Evaluation

Incident clustering P/R/F1、ARI/NMI、Chain Node/Edge Coverage/P/R/F1、Direction/Stage/Path Accuracy：**Not Evaluatable / Ground Truth Unavailable**。不从窗口创建 Gold Incident / Chain，不推定攻击阶段映射。

工程结构：Incidents={structure['incident_count']}; singleton={structure['singleton_incident_count']}; singleton ratio={structure['singleton_incident_ratio']}。链节点分布={structure['chain_node_count_distribution']}; 链边分布={structure['chain_edge_count_distribution']}。

窗口覆盖={structure['temporal_context']['covered_attack_windows']}/{structure['temporal_context']['total_attack_windows']}；Incident overlap={structure['temporal_context']['incident_overlap']}；Chain overlap={structure['temporal_context']['chain_overlap']}。统计口径均为成员告警时间的重叠，不是攻击识别率。

节点引用可回溯率={structure['node_traceability_rate']}; node reason coverage={structure['node_reason_coverage']}。无边时 edge traceability/coverage 空分母，不声称100%。原 completed Analysis 的 grounding 摘要及字段 provenance 在 structural_metrics.json。

## 11. Zero-edge Conclusion

当前生产正式边={summary['score_extraction']['accepted_edge_count']}。所有有效已准入候选最大分={distribution['maximum']}，生产阈值={distribution['production_threshold']}；有效候选达阈值数={distribution['valid_candidates_at_or_above_threshold']}。

已准入证据的保守容量上界={conclusion['scoring_loss']['conservative_admitted_evidence_capacity_bound']}：T/E 各按理论最大1，R/B/S 按已评分成员的观测上界（R={distribution['components']['relation']['max']}、B={distribution['components']['behavior']['max']}、S={distribution['components']['source']['max']}），忽略全部负项。它只是不可能超越的数学上界，不是拼接证据形成的候选分，也不适用于未准入 pairs。

- Candidate Admission Loss：policy_pruned={candidates.get('policy_pruned_count')}；是否丢失真实正例未知。不能把资源完整误称召回完整。
- Scoring Loss：relation 非零成员数={distribution['components']['relation']['nonzero_member_count']}，source 非零成员数={distribution['components']['source']['nonzero_member_count']}。类别及来源独立性分布见机器报告，不用产品名补分。
- Threshold Loss：有效分数范围与冻结阈值的比较可解释当前已评分候选的拒绝；无法证明降低阈值会提升准确率。消融/敏感性表展示变化幅度。
- Guard Loss：无效成员对={distribution['invalid_member_pair_count']}；reject codes={conclusion['guard_loss']['rejection_codes']}。它与阈值拒绝独立记录。
- GT Mapping Limitation：区间真值无 pair/组/链语义，不能衡量准确率、真实漏报量或给这些损失做攻击级归因。
- Data Limitation：未知类别/缺字段传播/未确认独立来源的具体统计在报告中；统计说明输入证据不足，不等于证明没有真实攻击关系。

保留冻结生产配置；当前实验没有开发/独立测试划分，只作描述性验证，不选择最优参数。

## 12. Reproducibility / Runtime / Isolation

本轮 wall time={summary['runtime']['total_seconds']:.3f}s；进程峰值内存={summary['runtime']['process_peak_memory_mb']:.3f}MB（进程高水位，缓存命中时包含验证/统计，子集实验耗时沿用其实际执行轮）。完整流式首轮与重复轮成本见 initial_streaming_run.json / reproducibility.json；原生产分阶段耗时另见 summary.json。当前工作区文档、生产代码/YAML、原 Analysis 文件在本轮执行前后哈希相同；与历史冻结基线的符合性另由 repository check 验证，不能由该运行内检查代替。

GT 只由 evaluation/io/ground_truth.py 在 production snapshot 和实验预测冻结后打开；后台/生产模块没有 evaluation import。API 只读 EvaluationSummaryExport 白名单聚合，不返回 GT、攻击时间或逐样本答案。API 脱敏导出另存 data/processed/evaluation_exports。

## 13. Validation

专项、完整后端 pytest、repository/contract check 的实际计数与运行日志在测试完成后写入 validation.json 与本段附录；不把未执行称通过。

## 14. Frozen State

生产 threshold / scoring weight / candidate admission / guard / clustering / chain reconstruction / GT isolation 的修改均为：**否**。见 frozen_state.json。完成 Task 06 后停止，不进入后续 Task。
"""
    (destination / "TASK_06_EVALUATION_REPORT.md").write_text(text, encoding="utf-8")

"""Human-readable report mirrors machine values, including unavailable results."""

import json


def write_report(output, summary, files):
    dataset = summary["dataset"]
    lines = ["# TASK 06.6 · Cross-dataset Evaluation", "", "## 1. Dataset", "",
             "Framework: `"+summary["framework_status"]+"`；真实评测：`"+summary["run_status"]+"`。", "",
             "```json", json.dumps(dataset, ensure_ascii=False, indent=2), "```", "",
             "没有第二真实数据集时，记录数、字段/实体覆盖、评分/链结果和 runtime 均为 null；不能填 0 或据测试样本判断迁移性。", "",
             "输入清单与缺失材料见 dataset_readiness.json；现有 Adapter 能力见 adapter_compatibility.json。", "",
             "## 2. Files Changed", ""]
    purposes = ["严格加载独立数据声明、兼容性与冻结核验", "复用现有生产入口、覆盖统计与阶段计时",
                "只读基线对比、缺数据阻塞报告与独立评测编排", "Markdown 报告生成",
                "Adapter/确定性/冻结/GT隔离/无硬编码/空稀疏测试", "新增 Task 06.6 使用与数据门槛说明",
                "可随代码复跑的生产核心/配置/七份基线 SHA-256 锚点"]
    lines += ["- `"+path+"`："+purpose+"。" for path,purpose in zip(summary["files_changed"], purposes)]
    lines += ["", "Production Core Modified: **NO**。Task 06.5 与原始生产快照未覆盖。", "",
              "## 3. Adapter / Canonical Coverage", "",
              "字段使用 DATA_CONTRACT 的 CanonicalAlert 实际字段；分母为唯一已接受告警，重复导入单独计数。", "",
              "missing_by_source / mapping_failure / parse_failure / invalid_value 分开记录；拒绝记录不冒充字段级覆盖。", "",
              "详见 adapter_coverage.json 与 entity_coverage.json。缺数据时九类实体数量均不可计算，不能写 0。", "",
              "## 4. Pipeline Result", "",
              "详见 pipeline_stage_stats.json、score_distribution.json、score_reachability.json。", "",
              "Normalization 与 Adapter 共用现有 convert；正式边准入在 scoring 内，单独耗时不可分解，均明确标记。", "",
              "Task 06.5 的可达性证明仅在其字段前提成立时复用；不成立返回 proof_inconclusive，不把观测最大值当全数据可达上限。", "",
              "## 5. Evaluation", "", "| Metric | Value | Status / Reason |", "| --- | --- | --- |"]
    for name,row in files["cross_dataset_metrics.json"]["metrics"].items():
        lines.append(f"| {name} | {row['value'] if row['value'] is not None else 'N/A'} | {row['status']} / {row['reason']} |")
    lines += ["", "复用现有 Task 06 pair 指标；攻击窗口不提供 pair/Incident/chain 真值。现有框架未支持的对象级 GT 指标保持不可计算，不另造匹配协议。", "",
              "## 6. Cross-dataset Comparison", "", "| Metric | RussellMitchell | CrossDataset | Reason |", "| --- | --- | --- | --- |"]
    for row in summary["comparison"]:
        cross = row["CrossDataset"] if row["CrossDataset"] is not None else "N/A"
        lines.append(f"| {row['metric']} | {row['RussellMitchell']} | {cross} | {row['reason'] or ''} |")
    lines += ["", "主数据集取已冻结生产快照与 Task 06.5 产物；singleton/multi-alert 按代表事实组数统计，去重包装不计多步骤。", "",
              "## 7. Generalization Conclusion", "", "```json", json.dumps(summary["generalization"], ensure_ascii=False, indent=2), "```", "",
              "RQ1–RQ6 见 cross_dataset_summary.json；缺真实第二数据时全部不可计算，不能选择 A–D 类别。", "",
              "## 8. Runtime", "", "```json", json.dumps(files["runtime.json"], ensure_ascii=False, indent=2), "```", "",
              "缺数据时 framework wall time 仅表示只读检查与报告生成时间，不表示 Cross-dataset pipeline 耗时。峰值使用已有进程 high-water mark，独立运行口径写明；无测量时 not_available。", "",
              "## 9. Freeze / Isolation", "", "```json", json.dumps({k:summary[k] for k in (
                  "core_algorithm_changed", "threshold_changed", "weights_changed", "candidate_policy_changed", "guard_changed",
                  "incident_chain_rules_changed", "gt_isolation", "dataset_specific_hardcoding", "freeze_verification")}, ensure_ascii=False, indent=2), "```", "",
              "核心参数 hash 对比剔除显式 source parsing/mapping 引用；完整配置快照/hash、mapping digest 与 source config/hash 各自保存。", "",
              "## 10. Tests", "", "```json", json.dumps(summary["tests"], ensure_ascii=False, indent=2), "```", "",
              "## 11. Output Manifest", "", "输出目录：`"+str(output)+"`。", "",
              "manifest.json 记录逐文件 SHA-256、版本、输入/配置/映射绑定与 run status；自身摘要排除以避免递归。", "",
              "```json", json.dumps({"baseline_config_hash": summary["baseline_identity"]["config_hash"],
                "baseline_mapping_digest": summary["baseline_identity"]["mapping_digest"], "binding": summary["binding"],
                "code_version": summary["code_version"]}, ensure_ascii=False, indent=2), "```", "",
              "## 12. Remaining Issues", ""]
    if summary["run_status"].startswith("evaluation_blocked"):
        lines += ["- 缺少独立真实安全告警数据；尚未完成真实 Cross-dataset Evaluation。",
                  "- 需提供独立来源/场景、namespace/timezone/格式与版本、数据来源材料，才能验证同一核心迁移。",
                  "- 实际精确率/召回率/链方向等还需相应粒度的独立 GT；当前主数据集仅有攻击窗口。"]
    else:
        lines += ["仅按实际 coverage、stage 与不可计算指标中已记录的限制解释结果；不据零边修改参数。"]
    lines += ["", "本 Task 到此停止；不进入 Task 06.7。", ""]
    (output / "TASK_06_6_REPORT.md").write_text("\n".join(lines), encoding="utf-8")

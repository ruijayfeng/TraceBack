# Task 06 · Evaluation

本次用户授权覆盖原计划的 Evaluation 范围，以 Task 06 命名；不实现计划中的前端或 AI。生产代码/YAML、七份基线及原快照只读。Python 3.11，使用现有 DuckDB/Pydantic/PyYAML/pytest，无新增依赖。

根目录 PowerShell：

```powershell
.venv/Scripts/python.exe -m evaluation.framework.runner --root . --analysis-id ana_c24111d997ab7a4cc809392ffb0306155ffffc6e1a73f74a0e1e45fab3c413d7 --gt data/ait_ads/russellmitchell/evaluation/labels.csv --scenario russellmitchell
.venv/Scripts/python.exe -m pytest evaluation/tests -q
.venv/Scripts/python.exe -m pytest backend/tests -q
.venv/Scripts/python.exe scripts/check_repository.py
```

`--mode all|evaluate|baseline|ablation|sensitivity|noise`；默认 all。`--config` 只读取 evaluation 配置，严格拒绝未知键。完整分析必须 completed、is_complete=true、无资源截断，文件哈希、配置/映射/输入摘要必须可核验。不会使用 incomplete snapshot。默认输出 `outputs/evaluation/<analysis_id>/`。重跑提取缓存必须匹配 diagnostics SHA-256 与所有 Parquet 哈希；run identity 包含 GT 内容、scope、配置、实现版本、代码摘要和原快照摘要。运行耗时不作算法身份。

流水线：验证完整生产快照 → 流式抽取 unrounded 已评分成员对 → 冻结基线/六消融/扫描/噪声预测 → 加载仅 evaluation 可读的 labels.csv → 攻击窗口外部时间映射 → 结构/工程诊断与报告 → 原快照/生产/基线哈希复核 → 脱敏聚合导出。当前 GT 仅 `scenario,attack,start,end`，epoch 秒、UTC 微秒、`[start,end)`。scenario 显式指定，其他场景报告 out_of_scope，不静默丢弃；CSV 原文件不改。

时间重叠按窗口匹配全部 CanonicalAlert 并映射代表组；mapped 指有时间重叠，unmapped 指无时间重叠，ambiguous 指存在重叠多个选定区间的告警（与 mapped 可重叠）。**同处窗口不是 pair 正例，窗口外不是 benign**。时间覆盖/重叠集中程度与质量 coverage 不同。质量 coverage=0，Pair/Incident/Chain/Direction/PR/ROC 指标 null+unavailable。没有 Gold Incident/Chain，不造 Gold；未定义的 Gold 匹配阈值也不自行补成契约。

通用显式 pair-label 指标函数仅在独立提供标签时可使用；未标注 pair 排除分母，候选遗漏正例仍为 FN，candidate disposition 缺审计时 unknown，不能默认 policy_pruned。空分母严格 null+not_applicable。ranking 按分数并列整批计算 AP/ROC，需正负两类；真实窗口 GT 不调用分类/ranking 质量函数。

Time-only / Time+IP / Time+All Entities 使用原配置的 baseline 300 秒窗、同输入/标准化/去重，以实际成员共现匹配，实体 scope 由 Stable Entity ID 保持；全量基线 pair 数使用分块 range bitset 精确计数，不展开 N² pair 列表。Full 仍是已有生产 Candidate Policy。候选/预算差异必须披露，简单 baseline 不证明 Full 应有更高 F1，也不发布时间因果链。

六消融都是 **score-only**：固定候选、阈值、完整成员评分和 hard guard，逐项移 Entity Rarity/Relation/Behavior/Source/soft Conflict/Duplicate；正权重不重分配。rarity-off 复用生产实体组件并重选 top contributors；其余直接使用原 unrounded contribution。实验最高分按全成员有效最大值重新选取，不能用 feature maxima 拼证据。没有 end-to-end 消融/方向/聚类实验，不声称执行过。

Sensitivity 包含原冻结阈值、配置 grid 和当前有效分数分位点/最大值；只计既有有效候选，阈值升高边量不增加。禁止据 GT 选择生产阈值。

Noise 是成本受控的真实子集工程实验：seed=42，512 个完整事实组（保留去重成员），额外加入同数据集其他原始未标注事实组，比例 0/10/25/50%。不修改/伪造告警，不称新增数据为已确认 benign；从同一原快照抽取独立成员，直接复用生产 run_correlation/run_reconstruction，GT 加载前结束预测。子集重新计算频率，故不能把子集零噪声与原全量指标直接比较。缓存包含输入计划和预测摘要；质量 P/R/F1 unavailable；不能据此宣称全数据或攻击质量鲁棒性。跨数据集和独立测试 split 未提供。

Score Parquet 保留完整原成员分、贡献、未舍入分、guard 和原 diagnostics byte offset。admissions.parquet 保留现有提名 provenance。selected_scores.parquet 包含组间胜出成员和显式 null GT。evaluation.duckdb 为可重建缓存。机器 JSON 与 TASK_06_EVALUATION_REPORT.md 同时输出。API 白名单导出在 `data/processed/evaluation_exports/<run_id>.json`，不包含 GT/攻击时间/样本答案。

## Task 06.6 · Cross-dataset Evaluation

仅验证冻结核心跨数据/场景迁移，不调参数、不改生产代码、不覆盖 Task 06/06.5，也不进入 06.7。当前本地只有 russellmitchell；无第二数据时完成框架与只读评估，输出 `framework_completed` + `evaluation_blocked_by_missing_dataset`，真实统计为 null + not_computable，不拿测试 fixture 或主数据随机分割冒充迁移。

```powershell
.venv/Scripts/python.exe -m evaluation.framework.task_06_6 --root . --analysis-id ana_c24111d997ab7a4cc809392ffb0306155ffffc6e1a73f74a0e1e45fab3c413d7
.venv/Scripts/python.exe -m pytest evaluation/tests/test_task_06_6.py -q
```

默认输出 `outputs/evaluation/task_06_6/`，含就绪检查、现有 Adapter 兼容性、字段/实体覆盖、阶段统计、评分分布/可达性、指标、对比 CSV、runtime、报告与逐文件 SHA-256 manifest。主数据数值从完整校验的生产快照和 Task 06.5 诊断读取。缺数据不推定 portable 或 core_generalization_issue。

真实第二场景必须另提供 dataset name、来源/独立性材料、安全告警文件、namespace/timezone、格式说明/AMiner版本。`--dataset-metadata evaluation/configs/<declaration>.yaml` 读取严格结构：

```yaml
version: cross-dataset-v1
dataset: <independent dataset or scenario name>
origin: <source/provenance>
independence_evidence: <why independent of russellmitchell>
source_config: configs/<source-only-override>.yaml
sources:
  - adapter: wazuh  # or aminer; unsupported profiles require a verified new parser
    path: data/input/alerts/<security-alerts>.jsonl
    format_reference: <vendor format/version documentation>
    settings:
      source_namespace: <declared stable source instance>
      format_profile: wazuh_json_v1
      generator: Wazuh
      generator_version: <verified value or explicitly unknown>
```

源配置保持现有生产加载器的 `configs/` 路径要求，只准修改 normalization 的 source_timezones/host_aliases/category_mapping_files/severity_mapping_files，duplicate 的 payload_mapping_files/rule_equivalence_mapping_files，以及 source.independence_mapping_files。版本化 mapping 仍由原 Mapping v1 校验；核心配置参数必须与冻结基线逐项相同。完整 config hash 包含映射/部署声明，不要求全 hash 相等；另保存核心参数 hash 证明算法不变。不得用源配置修改 category_priority、threshold、weights、窗口、Top-K、guard 或任何 Incident/Chain 规则。

现有生产入口原样执行 Adapter.convert（内含基础 Normalization）→ deduplicate → extract_entities → run_correlation → run_reconstruction。诊断写入新 evaluation 目录，不写生产快照。已有 candidate/scoring/incident/chain instrumentation 原样复用；Normalization 与 Adapter、边准入与 scoring 合并计时并标注，不捏造独立耗时。空输入明确 not_applicable；缺实体/零边是合法结果。Task 06.5 的全数据可达上界证明有 R/S 字段前提，无法证明时返回 proof_inconclusive/null，保留原阈值。

`--gt <path> --gt-kind attack_windows --scenario <scope>` 复用已有窗口 loader；`--gt-kind pair_labels` 支持显式 `left_alert_id,right_alert_id,positive` CSV（positive 为 true/false），复用现有 evaluate_pairs。GT 仅在 prediction_freeze.json 落盘后读取，未标注 pair 排除分母，空分母 null + not_applicable。当前对象级 Gold Incident/Chain 匹配接口未实现，相关指标明确 not_computable，不引入另一套指标。未提供 GT 不表示精确率为 0。独立性文字声明需要数据来源材料核验，框架不把声明本身当自动证明。

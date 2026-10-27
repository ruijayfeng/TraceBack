# Stage 1–4 正式输入流水线

唯一主入口：`app.services.alert_pipeline.load_alert_pipeline()`。

```powershell
.\.venv\Scripts\python.exe -B scripts/run_alert_pipeline.py --input D:/Code_WorkSpace/TraceBack-Dataset/data/attack125/final/attack125_final.jsonl
```

该命令只读原生 JSONL，向 stdout 输出统计；默认不启用 AI，不写数据或快照，
在 `BEHAVIOR_NORMALIZATION_COMPLETE` 停止，不执行 ⑤ Community 或更后续算法。
编号遵守最终流程：① 告警统一标准化、② 实体提取与绑定、③ 告警噪声抑制、④ 行为语义标准化。

实际调用链：

```text
load_alert_pipeline
→ ingest_records
→ MultiSourceAdapter.convert_record → AlertAdapter.convert → CanonicalAlert
→ extract_entities(contract="front-data-v1") → Entity / Binding
→ prepare_alerts → filter_alerts → NoiseFilterResult.kept_alerts
→ normalize_behaviors → normalize_behavior → semantic_input
→ NormalizedAlerts(alerts, entities, behaviors, source_settings, behavior_config_hash)
```

`NormalizedAlerts` 是 CanonicalAlert 与 alert 级 BehaviorAnnotation 的一一对应交接结构。
`alerts` 只暴露 kept_alerts；完整输入仍留在 `noise_filter.original_alerts` 供审计。
合法但无法识别的告警保留为 UNKNOWN，不以 UNKNOWN 数量或剔除率作为验收目标。

后续调用方可将该结果传给 `prepare_communities(result, result.source_settings, policy)`。
该函数直接消费已完成的实体、保留告警与 Behavior，不重复 Adapter、Entity、Noise 或 Behavior。
② 为全部 CanonicalAlert 提取实体；③ 后的实体清单仅保留 kept_alerts 及其成员引用。
历史 CanonicalAlert 调用方仍由兼容分支适配，不代表正式完整流水线。
Stage 输入适配只附加 community_id 上下文，
不重新计算标签、不调用 AI。Behavior 的核心计算不依赖 community_id。

## 证据与来源

- 六源使用 `configs/front-data-profiles.yaml` 声明的原生格式。
  Firewall/Auth/Host 的枚举虽为 `other`，namespace、产品信息及 source_settings 仍分别保留。
- 六源 IDS 原生 priority 复用 `cptc-suricata-severity.yaml`；2 映射为 medium。
  历史 Wazuh 包装告警的等级映射不作为原生 Suricata 契约。
- 新提取的 ProcessRef 子字段使用 `process.pid`、`process.name`、
  `process.executable`、`parent_process.*` 各自的 raw pointer。
  历史 aggregate-only provenance 仍可读取，但不能借 PID 指针伪证进程名。
- 从 raw 提取的产品名使用 field_provenance；部署 generator 回填的产品名使用
  `metadata_provenance.source_product=adapter_settings.generator`，不伪造 raw pointer。
- semantic_input 附带 namespace/product 元数据，明确与 raw evidence refs 区分；
  只传白名单事实，不传整条 raw。规则、标签词表、AI 阈值保持原有值。

## 真值隔离

`app.adapters.truth.GROUND_TRUTH_FORBIDDEN_FIELDS` 是共享的单一契约。
Adapter、Noise、Behavior、历史 AnalysisService 复用同一递归检查。
含评测字段的记录 fail closed，不剥掉字段后偷偷继续计算；原始文件不修改。
精确识别 ground_truth、attack_flag、is_attack、expected_behavior 等评测字段，
不会按字符串包含 label 就拒绝普通 rule/product/UI label。
GT 文件只允许独立完整性检查按字节哈希，不解析给运行算法。

## 历史入口

| 入口 | 角色 |
|---|---|
| run_alert_pipeline.py | 唯一正式 Stage 1–4 CLI；止于 Behavior |
| run_stage_pipeline.py | 正式 ①–⑥ CLI；复用上述前置输出，止于 Stage |
| run_community_builder.py / run_stage_aggregation.py | 后续兼容消费方；共享 Noise→Behavior 边界 |
| evaluation/attack125_runtime.py / attack125_baseline.py | LEGACY 历史 correlation 比较；重构分支也只能接收 kept_alerts |
| services/front_data.py / validate_front_data.py | NOT_OFFICIAL_ANALYSIS_PIPELINE；保留所有输入的离线索引诊断 |
| services/analysis.py / normalization.py | LEGACY 历史回放与快照兼容；不是正式 Stage 1–4 入口 |
| 已封存快照读取器 | 历史快照兼容，不代表按新流水线重新运行 |

新入口及字段修复不改写旧快照。⑤⑥ 的实现与调用链位于 `backend/app/services/stage_pipeline.py`；
本节描述的 Stage 1–4 入口不进入 ⑦ Stage Pair Candidate Generation 或后续阶段。

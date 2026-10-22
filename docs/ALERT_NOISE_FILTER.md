# 告警噪声剔除

本阶段实现确定性逻辑剔除：`CanonicalAlert → Noise Filter → kept_alerts → Behavior Normalization → Entity Binding → Community → Stage → Stage Relation → Attack Chain`。没有训练、概率评分、告警降权或后验成链判断。原始输入及 Ground Truth 均不改写。正式输入边界见 [Stage 1–4 流水线](STAGE_1_4_PIPELINE.md)。

## 真实代码审计与插入位置

| 环节 | 当前实现与本阶段处理 |
| --- | --- |
| CanonicalAlert | `backend/app/models/alerts.py`。包含 timestamp、source_type/source_namespace、可选告警标识/实体描述、raw_alert/raw_fingerprint、field_provenance；raw_evidence 属性引用 raw_alert。类型、ATT&CK、Process/Session 等不是必填事实。 |
| Canonical 生成 | `AlertAdapter.convert()`；当前六类来源通过 `MultiSourceAdapter.convert_record()` 路由到原有 Adapter，不使用封装层实验 ID 构造告警身份。 |
| 主入口 | `backend/app/community/builder.py::prepare_communities()`。保留冲突身份和真值污染检查；紧接着调用 `filter_alerts()`，其 kept_alerts 才进入 context projection 与 extract_entities。 |
| Entity Binding | `extract_entities(..., contract='front-data-v1') → entities/front_data.py`；Community profile 建立 typed bindings，接收的都是保留告警。 |
| Community | `build_communities()` 继续消费抽取结果；不改变已有 create/join/merge 算法。低层 builder 仍是已抽取数据的算法入口，过滤由 prepare 统一完成。 |
| Stage | `scripts/run_stage_aggregation.py → prepare_communities() → aggregate_stages()`；真实脚本已接入过滤策略快照及完整审计归档。 |
| Stage Relation / Chain | `run_stage_level_analysis.py` 读取封存 Stage 和 source alerts；`run_attack_chain_reconstruction.py` 消费封存图。过滤发生在这些快照形成之前，不修改关系或成链算法。 |
| ATTACK125 | 现有 `evaluation/attack125_baseline.py` 保护正式输入、真值和 release manifest，`attack125_runtime.py` 还包含历史 correlation 路径。本次新增独立验证入口，调用当前 Community/Stage/Relation/Chain 的真实函数；不改写历史实验脚本或已封存结果。 |
| Raw Evidence | CanonicalAlert 保存完整 raw_alert、指纹和 RFC6901 字段来源指针；既有 EvidenceTraceIndex 继续追溯保留告警。新增完整输入档案为被过滤记录提供回溯。 |
| 配置 | 沿用 configs YAML、Pydantic 严格校验和 content_digest；Noise 配置使用已有 read_yaml，拒绝重复键、未知字段和未经声明的选项。 |
| 测试 | Python 3.11 / pytest；既有 Canonical、Entity、Community、Stage、Relation、Evidence Trace、Chain 测试及新增 synthetic 测试，无需前端。 |

接入范围是当前阶段重构主入口及两个实际导出脚本。历史 normalization / correlation / incremental 实验入口保持原有回放语义；本次不改动 API、前端、算法参数或保护数据。

## 三类规则

1. `DUPLICATE_NOISE`：默认窗口为 2 秒。保留最早告警；同时间以 alert_id 排序。非完全相同的导入记录还必须具备告警标识（rule_id/signature/alert_type）、核心对象（host、完整 src/dst、process、file 或 URL），且 source/namespace/sensor、规则、对象和除已证实时间字段以外的完整原始内容一致。原生事件 ID、请求、进程、命令、目标、未知原始字段均参与严格比较；不同 ID 的相似动作默认保留。窗口以代表告警为锚，不允许相邻时间无限串联。完全重复导入按相同 canonical identity 折叠，逐输入记录计数。代表和其余成员都带 duplicate_group_id、representative_alert_id、整个簇的 duplicate_count。
2. `KNOWN_BACKGROUND_NOISE`：仅 configs/noise-filter.yaml 中显式声明的规则可剔除；默认规则列表为空。规则内全部条件 AND 匹配，规则之间任一命中即剔除，审计记录首次命中的 rule_id。至少声明一个来源条件及另一事实条件，禁止来源条件单独过滤整个来源。字符串为精确匹配，不进行正则、通配、子串或风险推断。
3. `INVALID_FOR_RECONSTRUCTION`：仅重新校验真实 CanonicalAlert 契约失败，包括无有效时间/来源、结构损坏、指纹或证据引用错误等。正常 Adapter 已会隔离大部分这类输入；测试使用绕过校验的损坏模型验证防御边界。UNKNOWN 类型/类别、稀疏字段、只有 IP 的合法 CanonicalAlert 仍可进入现有单例及 UNKNOWN 流程，不作为无效输入剔除。

顺序为 Invalid → Known Background → Duplicate。每个输入恰有一条决策，未命中剔除条件即 `keep=true / reason_code=KEEP`。不按 severity、缺少边/跨源关系/强绑定、没有 ATT&CK 或 AI 语义、时间距离或 single_stage 结果删除记录。

原生 ID 不同而其他字段相似时保留，意味着当前方案会有意漏过一部分潜在重复告警；这是保护不同真实动作的保守选择，不用模糊相似度扩大剔除。

## 配置示例

以下仅是独立 synthetic 示例，不在默认部署配置中启用：

```yaml
version: noise-filter-v1
duplicate_window_seconds: 2
background_rules:
  - rule_id: declared-monitor-probe
    match:
      source_namespace: sensor.edr
      alert_type: CommandExecution
      host: monitor-host
      process: probe
      path: /opt/probe
    time_pattern:
      timezone: UTC
      weekdays: [0, 1, 2, 3, 4]
      start: '01:00:00'
      end: '02:00:00'
```

可用 match 字段：source_type、source_namespace、alert_type、signature、rule_id、src_ip、dst_ip、host、process、path。字段全部可选，但每条规则须满足上述来源约束。process 精确匹配 Canonical ProcessRef 的 name/executable/GUID；path 精确匹配 canonical file 或完整 URL；普通字段缺失视为不匹配。配置值应使用标准化后的值。

source_type 是真实 Canonical 枚举：例如原生 ids 映射为 suricata，firewall/authentication/host_audit 目前映射为 other；这些来源可用 source_namespace 精确区分。不会根据配置为 CanonicalAlert 增加猜测字段。

time_pattern 使用 UTC、周一=0、端点包含；跨午夜区间以开始日确定 weekday。仅时间窗口不能独立剔除任何记录。

两个已有 CLI 均新增 `--noise-policy <yaml>`；不传则读取 configs/noise-filter.yaml。策略内容进入现有 manifest.config_snapshot/config_hash；Analysis ID 使用全部输入 ID，避免不同被剔除告警集合共享同一个空/保留输入身份。

## 审计、统计与 Raw Evidence

`CommunityRun.noise_filter` 返回 NoiseFilterResult，包括 original_alerts、kept_alerts、audit_records、statistics、config_snapshot 和 config_hash。每条 NoiseAuditRecord 包含 alert_id、input_index、keep、枚举 reason_code、rule_id、evidence、representative_alert_id、重复簇信息、raw_fingerprint、raw_evidence_ref。

两个真实导出入口在 `data/processed/<analysis_id>/` 保存：

- `noise_source_alerts.jsonl.gz`：按输入顺序保存全部原始 CanonicalAlert，包括被剔除记录；raw_alert 不做修改。
- `noise_audit.jsonl.gz`：逐输入记录的过滤决定。
- 原有 community_alerts / stage_source_alerts：仅下游实际使用的保留告警。

`outputs/analyses/<analysis_id>/noise_summary.json` 保存真实统计。所有新增档案由现有 manifest.artifacts 的 SHA-256 封存。

`raw_evidence_ref` 的 `noise_source_alerts.jsonl.gz#/records/N/raw_alert` 表示 gzip JSONL 中从 0 开始的第 N 条记录，并非 RFC6901 文档内数组。可使用：

```python
from app.noise_filter import resolve_raw_evidence
raw = resolve_raw_evidence(domain / 'noise_source_alerts.jsonl.gz', audit_record)
```

解析器检查输入索引、alert_id、保存的指纹，并重新计算 raw_alert 指纹；即使原 CanonicalAlert 结构不合法，也能按 JSON 取回 raw payload。内存结果也提供 `result.raw_evidence(audit_record)`。重复告警的审计可以进一步找到保留代表。

统计为 INPUT_ALERTS、KEPT_ALERTS、REMOVED_ALERTS、NOISE_REDUCTION_RATE、DUPLICATE_NOISE_COUNT、KNOWN_BACKGROUND_NOISE_COUNT、INVALID_NOISE_COUNT。剔除率是 0–1 的真实比例，满足 INPUT=KEPT+REMOVED。完全重复导入共享 alert_id，剔除的是输入出现次数，其代表 ID 合法保留在下游；逐次审计用 input_index 区分。

## 验证

新增测试覆盖 10 条明确重复 → 1 保留 / 9 剔除、相似非重复、配置全字段命中与不命中、UTC 日内/跨日时段、缺普通字段保留、损坏契约剔除、默认空背景规则、两个脚本实际归档、原始证据重新解析与篡改检测。通过真实 Entity extraction spy、Community membership、Stage、StageRelation witness 和非空 AttackChain/EvidenceTrace 检查验证隔离。

独立 ATTACK125 验证：

```powershell
.\.venv\Scripts\python.exe -B scripts/verify_noise_filter.py --input D:/Code_WorkSpace/TraceBack-Dataset/data/attack125/final/attack125_final.jsonl --protected-root D:/Code_WorkSpace/TraceBack-Dataset/data/attack125 --output outputs/noise_filter_NEW
```

输出目录必须不存在。验证器只对保护目录文件做字节哈希，算法仅接收 native alerts；不会将 Ground Truth 解析给过滤器。它保存完整噪声审计、实际下游结果、前后哈希和验收指标，并在无噪声时独立重放原始无过滤 handoff，检查结果一致。

本阶段停止在 NOISE_FILTER_INTEGRATED。后续算法优化、阈值校准、AI Explain、前端与 API 页面改造均未启动。

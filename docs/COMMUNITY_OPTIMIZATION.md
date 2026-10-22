# Alert → Community 构建优化

本次只修改 Community 构建、其配置、测试和独立验证工具。保留已有噪声过滤入口、Entity/Binding extraction、typed postings 和 IncidentCandidate 正式 schema。没有修改 Stage、Stage Relation、Attack Chain、API 或前端；运行这些模块的已有测试仅用于回归。

## 关联规则

| Evidence Tier | 身份/证据 | Alert admission | 已有 Community merge |
| --- | --- | --- | --- |
| A | Request、完整 Flow 五元组、Session（含原有子类型）、Task；保留已有显式 record-reference | 保留原有身份窗口及总成员/生命周期上限 | 每个被并入区域都必须有 A 类证明 |
| B | Host+Process instance、Process+Behavior、Host+Account、Host+Behavior、Account+Behavior；保留已有明确 object handoff | 组合证据、动态时间、上下文冲突检查及原有非强关联成员上限全部通过 | 不以 B 类证明合并多个已有社区 |
| C | IP overlap+Behavior | 动态时间兼容后可加入一个社区；公共 IP 还需共享 Host/Account/Process | 禁止 |

历史 `match_level` 1–5 保持正式模型兼容；新的 A/B/C 按 `identity_kind` 判断，不能用 `match_level <= 2` 判断强 Binding。Process instance 是 B 类，不再仅靠相同 GUID 关联。只有 Host 的 Process descriptor 仍需 Account/Behavior/已绑定上下文佐证，避免把同名程序视为明确实例。仅 Port/Protocol、仅 IP、仅 Host/Account/Process 均不能聚合。

完整 Flow 的既有语义是完整五元组；partial flow/native flow ID 的审计、typed recall 规则没有改变。Request/Session/Task 的字段身份和部署 scope 没有改变。显式来源共享 scope 仍是跨来源短 ID 互通的前提。

Behavior 优先来自配置声明的既有 scalar 字段：`behavior`、`behavior_label`、`normalized_behavior`、`attack_type`；缺失时使用已有非 unknown Canonical category 与 signature 组合。保留原始字段指针，不调用行为阶段归一化器、ATT&CK mapping 或 AI。

## 时间与公共实体

非强关联使用候选社区**已经接受的成员**的时间序列。相邻间隔采用总体标准差，`T = mean(interval) + std(interval)`；新候选间隔不参与自己的阈值训练。

`configs/community-v1.yaml` 声明全部新默认值：

```yaml
temporal:
  min_seconds: 5
  fallback_seconds: 30
  max_seconds: 300
  min_intervals: 3
common_entities:
  min_count: 10
  ratio: 0.1
```

不足 3 个间隔使用 fallback，阈值始终夹在 min/max 内。Binding 继续使用已有身份窗口和生命周期上限。索引对非 Binding 保留到动态 max cap，避免历史固定 tier 窗口提前丢掉可接受的慢速上下文。实际 admission 同时检查 witness 时间差与候选社区节律。

按噪声过滤后 distinct alerts 统计 typed Host、Account 和有 network scope 的 IP；同时达到绝对频次和比例阈值才是公共实体，原 hot-host 配置也保留。公共 Host/Account 的语义关联需要额外共享 Process 或 Account/Host；公共 Host+Account 还需 Process/Behavior/明确上下文。实体及原始证据不删除。

每个 incoming alert 仍通过原 `CommunityIndex.query` 的 bounded postings 找候选，优先 A 类。`max_witnesses_per_key`、`max_candidates_per_alert`、总成员、生命周期和非强关联成员 cap 保留。不建立全量 Alert×Alert 表，也没有统一评分公式或通用聚类。

## 诊断口径

`CommunityResult.diagnostics` 中每个 Community 有 `COMMUNITY_SUMMARY`，包含 ID、members、association evidence summary、三类证明边数、time range、bridge suppression、rejected weak links、high-degree hits 和当前节律统计。正式 IncidentCandidate/CanonicalAlert schema 没有扩展。

`ADMISSION` 记录实际采用的非强关联阈值、mean/std 与 fallback；`REJECT` 保留原因、次数及一个 witness 样本；`HIGH_DEGREE_EVIDENCE` 保留公共身份 key。证明边保留两端原始指针和实际使用的 Behavior/实体/时间证据。

`STRONG_RELATION_COUNT` 等是**最终接受的证明边数**，不是所有可行关系数或不同 Binding identity 数。`REJECTED_WEAK_LINK_COUNT` 是 B/C 候选 posting witness 的拒绝次数，排除纯 recall postings；同一 Alert 对可能有多个 posting。`BRIDGE_SUPPRESSION_COUNT` 只计已经通过 admission 但在跨社区合并时被拒绝的区域数，时间/实体冲突拒绝单独计数。`HIGH_DEGREE_ENTITY_HIT_COUNT` 是每条告警命中的不同公共身份数之和。

## ATTACK125 真实验证

从 `TraceBack-Dataset/data/attack125/final/attack125_final.jsonl` 经真实 Adapter → CanonicalAlert → Noise Filter → extraction → index → Community 重放。125 条全部保留，未载入 GT 语义。

| 指标 | 优化前 | 优化后 |
| --- | --- | --- |
| Community count | 4 | 5 |
| Community sizes | [12, 21, 27, 65] | [12, 18, 21, 27, 47] |
| 最大 Community | 65 | 47 |

优化后接受 A/B/C 证明边分别为 119 / 1 / 0；拒绝 B/C posting witness 4239 次；公共身份命中 210 次。真实数据的 merge-guard 拒绝计数为 0：本轮在 admission 的时间/冲突/成员上限处已排除了多余候选。专门 synthetic 测试另行验证了跨社区 bridge suppression 确实触发，不能用真实数据上的 0 冒充它触发过。

历史 65 条的证明为 Session 23、Connection 12、Application Session 9、Request 9、Flow 9、Process instance 2，即 62 条 A 类身份边和 2 条 Process 上下文边。没有仅依赖 Host/IP 的已接受边。相关公共身份包括 Host `asset-c2b3b05a72`（全输入 51 条）和 Account `www-data`（37 条）；公共 IP 的身份按 source/network scope 区分，不能仅凭相同显示值累计。

65 条分为 18 和 47，具体原因如下，详见验证输出 `validation/historical_65_edges.json`：

| 原 Process 关联 | prior 成员数 | 间隔 | prior mean | prior std | T | 结果 |
| --- | --- | --- | --- | --- | --- | --- |
| Host + PID 1820 + 明确 start time | 18 | 15 s | 3.823529 s | 2.120913 s | 5.944442 s | 时间不兼容，未关联 |
| Host + PID 2800 + 明确 start time | 11 | 10 s | 28 s | 48 s | 76 s | 保留 |

新的 47 条社区由 45 条 A 类边（Session 23、Connection 12、Request 9、Flow 1）和 1 条 Host+Process 上下文边支持，无 C 类弱网络边。结果不证明原 65 条属于不同攻击：同一真实 Process 的稀疏活动可能被保守时间门控切开。此次未读取 GT、未以 Community 数量调参，也未把拆小本身当作优化成功证据。

## 测试与保护

必需上游/本阶段测试 718 passed；已有 Stage/Relation/Chain 回归 133 passed，共 851 passed、0 failed。前一轮本阶段组合测试另有 121 passed，与最终结果重叠，不重复累计。

全量 backend pytest 已尝试，两个旧 Demo 模块收集时缺少 `data/ait_ads/dataset.yaml`。忽略这两个模块后的扩大尝试在旧 `test_ai_explanation` 的 API service fixture 停滞，已中断；不宣称全量通过，不修改外部数据来修复这些环境前提。

保护范围包括外部 ATTACK125 全目录（含 GT、release manifest、native/final 输入）、本仓库全部 `data`（含 Canonical snapshots）、`evaluation/outputs` 历史实验以及 `outputs/analyses` 已有分析。对所有文件做 SHA256，并检测新增/删除文件；GT 只作为字节哈希。所有新增输出位于独立 `outputs/community_optimization`，不向历史分析或数据目录写入。

保护前后清单、逐社区证据、公共实体频次和验收字段分别见：

- `outputs/community_optimization/baseline/protected_before.json`
- `outputs/community_optimization/baseline/replay.json`
- `outputs/community_optimization/validation/protected_after.json`
- `outputs/community_optimization/validation/replay.json`
- `outputs/community_optimization/validation/historical_65_edges.json`
- `outputs/community_optimization/summary.json`
- `outputs/community_optimization/test_results.json`

Baseline 必须在修改实现前生成。验证工具拒绝覆盖已有 baseline/validation 目录，且只调用 Community 上游函数：

```powershell
.\.venv\Scripts\python.exe -B scripts/verify_community_optimization.py baseline --output outputs/community_optimization_NEW
# 实现前完成上述 baseline；实现后，先运行文中回归并保存 required.xml/downstream.xml，再执行：
.\.venv\Scripts\python.exe -B scripts/verify_community_optimization.py validation --output outputs/community_optimization_NEW
.\.venv\Scripts\python.exe -B scripts/verify_community_optimization.py diagnostics --output outputs/community_optimization_NEW
```

本次停止在 `COMMUNITY_BUILDER_OPTIMIZED`。

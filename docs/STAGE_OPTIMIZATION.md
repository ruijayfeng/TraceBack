# Community → Stage 图连通聚合

本轮运行入口是 `scripts/verify_stage_optimization.py`，实验输出仅写入
`outputs/stage_optimization/`。正式 ATTACK125 回放在 Stage 构建后停止，
通过 import guard 禁止加载 Stage Relation、Stage Chain、Evidence Trace、API 和 evaluation。

## 现有实现审计

旧 `aggregation.py` 按 timestamp、alert_id 排序，逐条选择第一个满足条件的已有组。
组内 Behavior 必须完全一致，每个新成员必须与全部已有成员通过 `pair_basis`。
已知行为固定限制为 120 秒，UNKNOWN 为 30 秒；时间不能单独建立成员证明。
共享 Request/Flow/Session/Task 或完整 Process instance + Host 提供上下文。
不同 Host、Account、Process 实例、Command/File/URL、同 scope 的 Session/Request 和完整 Flow 阻止合并。
UNKNOWN 可以凭强 Binding 合并，否则单例。

Stage ID 使用 Community ID、Behavior 和排序去重的 alert_ids 的内容摘要。
下游 Stage Relation 读取 Stage 成员、时间、实体、Binding 字段，并从原 Alert 重建 typed postings；
没有依赖 complete-link 的证明数量。既有 Evidence Trace 消费 aggregation_basis 的原始指针。
本轮保留这些字段及 Stage ID 算法，只将证明约束由完整图改为连通图。

## 实际算法

1. 每个 Community 建立独立图，全部 Alert 是节点，孤立节点保留。
2. 复用 `CommunityIndex` 的 typed key、时间有序 postings 和容量上限生成候选 pair，去重后只判定一次。
3. 使用现有 `normalize_behavior`。当前 Mapping 未定义不同标签之间的兼容关系，因此仅接受完全相同标签；
   不增加 Behavior 规则，不按 signature/alert_type 相似度合并。
4. STRONG：共享完整 scoped Request、Session（含 Auth Session 及既有子类型）、Flow、Task、
   Process instance/明确父子实例、Object。仅共享 parent process 不成立。
   NORMAL：同 Behavior + scoped Host/Account 组合。
   WEAK：同 Behavior + scoped Host/不完整 Process 描述组合，不能冒充完整实例。
   单一 Host、IP、时间、来源或 Community 都不能通过上下文 gate。
5. UNKNOWN 仅允许明确 typed Binding；已知 Behavior 与 UNKNOWN 不连接。
6. 复用 `TemporalHistory.snapshot` 和既有 Community temporal policy：
   `mean(interval) + population_std(interval)`，包含既有 fallback、min/max 约束。
   计算范围是本 Community 内同 normalized Behavior 的**先前**观察；当前较晚端点不训练自己的阈值。
   原 StageConfig 的两个固定 span 字段保留用于旧配置读取，图算法不再使用它们切 Stage。
7. 已知实体、实例、强上下文及观察对象冲突先阻止建边；动态时间不通过亦拒绝。
   再按证据等级、排序 pair 稳定过滤边：若连边会通过缺字段的中间节点引入已知实体/上下文冲突，
   在合并之前拒绝该边。不会先形成 Stage 再按目标数量拆分。
8. 迭代 Tarjan 检测所有无向 bridge；仅删除同时满足 WEAK、无 typed binding、无足够语义兼容证据的 bridge。
   强 bridge 保留。当前严格 eligibility 已排除语义不兼容边，因此真实回放可能没有可删除弱桥；
   合成图测试单独覆盖删除条件，不能把图论 bridge 数量当成错误边数量。
9. 在过滤后的图上计算 Connected Components，每个分量生成一个 Stage。

`aggregation_basis` 就是 connectivity edges：双端 `alert_ids`、`edge_strength`、`evidence_types`、
`behavior_compatible`、`binding_evidence`、`entity_evidence`、`temporal_check` 及原始 EvidencePointer。
语义和 timestamp 的原始指针也保留。拒绝和删除记录位于 result.diagnostics。
新增证明字段有默认值，旧封存 complete-link Stage 可继续读取；新 Stage 必须有唯一且连通的成员证明。
既有运行入口的 config snapshot 新增图算法版本，使新算法获得独立 Analysis ID，避免复用旧实现的发布身份。
该入口本轮未执行，正式实验只使用独立 verifier。

## 验证与数据保护

baseline 在算法修改前执行旧实现；同一最新 Community 分区上的新结果与其逐条对照。
两个阶段分别对 ATTACK125 全目录（含 GT 的不透明字节）、项目 data、evaluation/outputs、
outputs/analyses 的文件做运行前后 SHA256，且 validation 再对比 baseline 初始清单。
数据内容不回写，GT 不进入候选、连边、时间估计、Behavior、阈值或 Stage 判定。
任一 hash/文件集变化会抛出 `protected_data_changed_STOP`，不会发布成功 summary。

正式验证还比较旧、新 Behavior 注解完全一致，Community 分区完全一致；反转 Alert/Entity 输入后
重复运行并比较完整结果，覆盖 membership、ID、ordering、证据与 diagnostics。

最终统计见 `outputs/stage_optimization/summary.json`，完整成员与边证据见
`outputs/stage_optimization/validation/result.json`，测试明细见 `tests.xml`。

## ATTACK125 真实对比

Behavior 注解保持一致：86 条 Mapping，39 条 UNKNOWN；本轮未调用 AI。
旧方法 47 个 Stage，新方法 42 个；singleton 25 → 27，最大 Stage 12 → 15。
候选 pair 1301 个，拒绝 1150 个，保留 151 个；全部为 STRONG，NORMAL/WEAK 均为 0。
拒绝原因是语义不同 562、动态时间不通过 373、URL 不同 154、Command 不同 55、强上下文不同 6。
真实输入没有触发额外的跨分量冲突拒绝。50 条 bridge 全部有强 Binding，未删除。
候选裁剪数为 0。

| Community Alert 数 | 旧 Stage 数 | 新 Stage 数 | 新 Stage 大小 |
| --- | --- | --- | --- |
| 12 | 1 | 1 | 12 |
| 18 | 3 | 2 | 4, 14 |
| 21 | 18 | 18 | 1×15, 2×3 |
| 27 | 14 | 14 | 1×11, 2, 4, 10 |
| 47 | 11 | 7 | 1, 4, 4, 5, 8, 10, 15 |

不能宣称“减少错误大 Stage”：最大值实际增加，且不使用 GT 无法判定准确率。
UNKNOWN 最大组件为 14 条，来自旧的两个 7 条 Stage，跨度 65 秒；13 条相邻边都有
Request、完整 Flow、Application Session、Object、Process instance 证据，没有 Host/IP/时间单独连边。
该 UNKNOWN 连通区域仍需语义消歧，不能把强 Binding 等同于已确认的相同攻击行为。
另有 13 条 UNKNOWN singleton，UNKNOWN Stage 总数为 19。

12 条 Community 整体成为一个 AUTHENTICATION Stage，旧方法同样如此；14 条边具有 Session/Connection 证据。
最大 FILE_ACTIVITY Stage 为 15 条，跨度 262 秒，48 条边有 Process instance 证据，部分同时有 Session。
一个 NETWORK_ACTIVITY Stage 的 10 条 Alert 形成跨度 378 秒的连续链，9 条相邻边都具有 Connection/Flow/Session。
这些说明连通分量允许超过旧固定总跨度，不能把链式时间传递说成已被全部消除。
未发现不同标准化 Behavior 被串入同一 Stage；已知硬冲突传递由合成测试覆盖。

## 当前限制

- 不提供跨 Behavior 标签的兼容矩阵；未知语义保持 UNKNOWN。本轮未开启新的 AI 调用。
- 动态时间基于 Community 内的同标签历史，仍可能受该标签中的多种活动节奏影响。
  连续、有证据的长链可以形成跨度大于旧 120 秒的 Stage，这是连通聚合的含义；不等于全成员两两可连接。
- Host+Account 和 Host+Process 描述仍弱于实例 Binding，同一账号的重复行为可能混合；需要检查实际边证据。
- 候选继承 CommunityIndex 容量限制；大输入可能裁剪候选，统计显式报告 pruned 数。
  冲突过滤在候选分量之间检查已有成员，最坏情况下成本较高；本轮目标规模为 125 条。
- 冲突边竞争采用稳定证据优先顺序，具有确定性；它不声称求得唯一、全局最优语义划分。
- 数据未用于 GT 调参；不把 Stage 数量减少或增加当作准确率改善。

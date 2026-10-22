# ⑤ Alert → Community / ⑥ Community → Stage

正式完整入口为 `app.services.stage_pipeline.load_stage_pipeline()`；
`load_alert_pipeline()` 继续独立提供 ①～④ 输出。

```powershell
.\.venv\Scripts\python.exe -B scripts/run_stage_pipeline.py --input <native.jsonl>
```

调用顺序：

```text
① MultiSourceAdapter.convert_record / AlertAdapter.convert → CanonicalAlert
② entities.extraction.extract_entities(front-data-v1) → Entity / Binding
③ services.alert_pipeline.prepare_alerts / filter_alerts → kept_alerts
④ normalize_behaviors / normalize_behavior → BehaviorAnnotation
⑤ prepare_communities / build_communities → IncidentCandidate
⑥ aggregate_stages / community_graph → Hard Conflict → weak_bridge_check
   → connected_components → Stage
STOP
```

② 使用现有实体与上下文提取算法。③ 后裁去实体上的已剔除成员引用，原始输入及噪声审计仍完整保留。
⑤ 直接使用 `NormalizedAlerts.entities / alerts / behaviors`，不重跑前置步骤；⑥ 只消费既有 Behavior。
历史裸 CanonicalAlert 调用者保留兼容适配分支。正式完整入口拒绝缺少实体交接的前置结果。
CLI 只输出统计，service 返回 Community 与 Stage 对象，不发布快照、不自动启用 AI、不调用 ⑦～⑭。

## ⑤ 公共实体与弱上下文

保留时间排序、候选索引、CREATE/JOIN/MERGE，不强制改为 Connected Components。
公共 Host/Account/IP 继续按既有 typed identity 和 scope 计数，但改用既有绝对频次阈值。
`common_entities.ratio`、`hot_host_ratio` 仅为旧配置兼容保留，不参与准入；阈值数值不变。
添加不共享实体/上下文的样本不再稀释原实体的公共属性。

Host/Account/IP 加 Behavior、Time 仍不足以单独准入，必须额外共享独立的实体或已绑定上下文。
不同 GUID/instance ID 阻断普通弱上下文匹配。明确 A 类 Binding 保持原有优先级及规则；
B/C 只能 JOIN 一个已有区域，MERGE 多个既有 Community 仍要求每侧有 A 类证明。

## ⑥ 组件弱桥

保留既有 pair eligibility、Hard Conflict 和跨组件冲突过滤，之后执行弱桥检查，最后提取连通分量。
只检查没有强 Binding 的 WEAK 图论桥。临时移除桥，取两侧当前连通区域，对每个跨侧 Alert pair
重新执行既有 `pair_evidence`，复用较晚端点当时记录的动态时间快照。
存在不支持的跨侧成员对时删除桥，并记录成员、原因、两侧大小与完整生产 `AggregationBasis`。
按稳定边顺序处理，先前删除的桥不再参与后续区域遍历。

这不新增边、不覆盖 Hard Conflict、不改 Behavior 或时间阈值。
STRONG/NORMAL 边保持；两条告警具有合法弱上下文和时间兼容时仍保留。
0/20/40 秒的 Host+进程名称弱链会拆成 1+2；0/20 秒的合法弱 pair 保持一个 Stage。
候选空间受 Community 约束，跨侧一致性检查在大弱组件上存在额外计算成本。

## Guard 与验证

统一真值污染 guard 增补 `stage_id / attack_stage / expected_community / attack_path`，
沿用大小写、camelCase、连字符、空格别名归一化。此为防御增强，不表示先前存在已证实 GT 泄漏。

新增回归位于 `backend/tests/test_stage56_repair.py`，覆盖公共实体稀释、不同进程实例、强绑定、
生产模型弱桥删除、保留合法弱 pair、Hard Conflict、①→⑥ 顺序、噪声后的交接和 GT guard。
ATTACK125 数量不作为断言条件。正式运行的分区覆盖、重复成员、跨 Community、空 Stage、
悬空引用与原始证据指针由 `StagePipelineRun.statistics` 校验。

修复后的 ATTACK125 仍为 125 kept、5 Community（12/18/21/27/47）、42 Stage。
这批数据的 Stage 图全部为 STRONG 边，因此不会被新弱桥删除规则拆分。
数据、GT、Raw Evidence、Behavior Mapping、词表与阈值均未修改。

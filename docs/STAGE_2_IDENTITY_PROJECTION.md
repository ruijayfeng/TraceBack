# ② Cross-Source Identity Projection

2026-10-21。正式入口仍为 `load_stage_pipeline` → `load_alert_pipeline` → `ingest_records` → `extract_entities(front-data-v1)`，随后执行③～⑧。本轮没有调用⑨、旧告警对评分器、API 或解释服务。

## 根因与正式交接
559
此前 HOST 按原生 asset ID 优先、hostname 回退生成身份，同一受信主机的两种观测被拆开，继而拆开 host-scoped Object 和 ContextRef。认证 ContextRef 还将 source namespace 作为硬边界，Auth/EDR 的同一认证 token 无法共享身份。

新增能力在现有 `extract_front_data` 内执行：先收集原生 Host Alias 共现证据，再生成 HOST/ACCOUNT/PROCESS 和原有关系，最后基于 canonical HOST 投影 AuthSession。`EntityResult.identity_projection` 经 `NormalizedAlerts` 正式交接，`CanonicalAlert.identity_binding_ids` 连接实体观测与绑定证据。未声明 authority 的来源不启用跨源投影。

## Host Alias

`HostAuthority` 明确 authority_domain、deployment_scope、network_scope、原生附加 scope pointers 和最大别名观测年龄。当前部署在 source profiles 中声明 native asset inventory 的共同语义；它不声明连接、流或进程 namespace 权威。

仅原生记录同时观测 hostname 与 asset_id/host_id/server_host_id 时建立证据。hostname 保守规范化后按 authority/deployment/network/原生附加 scope 分组。hostname-only 观测必须落入某条原生共现证据前后 900 秒内；窗口取并集，禁止跨越没有证据覆盖的空档。不同 scope、过期或同 scope 多资产冲突均不投影。单条事件中资产字段互相矛盾也标记 AMBIGUOUS_ALIAS。

`HostAliasBinding` 保留 canonical HOST、alias、作用域、真实 first/last seen、有效窗口、源 namespace、证据告警、原始字段指针及实际应用的告警列表。CanonicalAlert.host 和 raw_alert 均不改写。不存在 IP-only 匹配、字符串相似度匹配或永久全局 alias。

## AuthSession

`AuthSessionAuthority` 明确认证 token 字段及其等价字段、authority domain、deployment、session type、start/close 操作及生命周期语义。当前 Auth 与 EDR 显式声明共享 host-scoped logon token authority；Auth 的 session_id 只有与 logon_id 值相等时才作为已声明别名。connection_id/flow_id 禁止配置为认证会话别名。

SESSION identity 结合 canonical HOST、兼容 authority、类型、token、已知 account/realm/boot/session epoch 和显式生命周期边界。不同 HOST、authority、已知账户或 epoch 冲突保持独立；缺失值只有在该组唯一已知值无冲突时才按声明语义投影。close 后的观测不回到已关闭生命周期；显式再次 start 形成新生命周期。同一时刻无法区分的边界保守隔离。没有 start 证明的生命周期保持 LIFECYCLE_UNKNOWN，不能把 first_seen 当成 session birth。

原始来源 ContextRef 完整保存在 `AuthSessionBinding.observations.source_contexts`，包括原 scope、namespace、token、raw pointer。活动 contexts 使用正式 canonical scope；不同时保留可绕过生命周期隔离的旧共享 token 引用。其他 request、connection、application_session、flow、task ContextRef 沿用原规则。

绑定的 source observation → alert → raw pointer 均验证闭合。③过滤后的 kept entities 只包含活动告警；别名证据仍能从 pre-noise 原始告警归档及 identity_archive_entities 回溯。覆盖了唯一别名证据被③过滤的测试。

## Process 安全边界

没有实现 Process Continuity Projection。Auth 的 PID 缺少 process start/GUID、共享 boot、可信时钟及连续 lifetime 权威，结论为 PROCESS_IDENTITY_PROJECTION_NOT_PROVABLE。

不完整 PID 观测改为 observation-local 弱实体，防止 host+PID 被当成共同进程；它们不会成为 complete process_instance binding。原来 12 条 Auth 的 current/parent PID-only 观测从 2 个弱实体拆成 24 个，PROCESS 总数因此从 8 到 30。具有原生 GUID 或 host+PID+start 的既有实例规则保持原样，未向 Auth 复制 EDR 的 parent start_time。

## 正式运行结果

| 指标 | Before | After |
|---|---:|---:|
| 输入告警 | 125 | 125 |
| Entity / HOST / PROCESS / SESSION | 14 / 3 / 8 / 0 | 41 / 2 / 30 / 6 |
| Community sizes | 12,18,21,27,47 | 39,39,47 |
| Stage / Candidate | 42 / 165 | 42 / 165 |
| Directed / Undirected / No relation | 12 / 1 / 152 | 22 / 1 / 142 |

Host Alias 2 条，歧义 0 条；AuthSession 投影 6 条，其中 1 条跨源；Process 投影 0 条。CROSS_SOURCE_ENTITY_MERGE_COUNT=3 表示被投影绑定覆盖且包含多个来源的 canonical identity 数（Host 2 + AuthSession 1），不等于实体净减少量。

前端主机相关 Community 从 18+21 合并为 39，数据库主机的认证/EDR Community 从 12+27 合并为 39，另一组 47 条保持独立。42 个 Stage 的告警成员集合完全不变，因所属 Community 变化部分 Stage ID 自然变化。候选数量仍为 165，增加的正式 session/object 特征进入已有召回规则。新增 10 条有向关系分别是 1 OBJECT_HANDOFF 与 9 AUTH_ESTABLISH_USE；原有 12 条 PARENT_CHILD_PROCESS 未增加。

GT 仅在两次 live run 及顺序反转复跑结束后读取。E02 的 hostname-only 与 asset-bearing WAF 观测通过正式原生 alias 统一，Object/应用会话 scope 自然一致，最终 OBJECT_HANDOFF。E06 同一 HOST 的 Auth/EDR logon_id 共享 canonical AuthSession，最终 AUTH_ESTABLISH_USE；Auth PID 仍未绑定到 EDR parent process。E05/E07 均仍 NO_RELATION，无新共享 connection identity，也没有补造 protocol/native flow ID。

## 审计与验证

每个 canonical HOST 最多吸收 1 个 hostname alias，观测到的不同 hostname 数均为 1；最大 AuthSession 为 22 条来源观测；最大已有 Process 为 47 条观测。没有主机坍缩。Stage 成员集合未变化，Community 合并有明确身份绑定，未靠公共主机/账户弱上下文吸收。

945 项相关测试通过，包含 25 项投影专项用例；最终增强的噪声归档用例又经专项复跑通过。覆盖 alias 正向、歧义、scope/有效期/证据空档、同 IP 不同主机、不同 host/authority/epoch/account 的 token、close/restart 复用、同时边界、PID reuse、非法配置及原始证据追溯。原⑤公共实体稀释/弱上下文/硬冲突和⑧Context/Relation、Claim 去重、时间及方向回归均通过。输入逆序后实体、绑定、上下文、Stage、Candidate 和全部⑧结果一致。

全 backend suite 在收集阶段仍被缺失 `data/ait_ads/dataset.yaml` 阻断（2 个既有 demo 模块）。历史 repository checker 仍限制 Task 01–05，并报告已有下游目录及缺失冻结文档；没有扩大其白名单。它们是环境/历史检查限制，不声称全库通过。

数据目录全部文件及⑤～⑧代码/配置执行前后 SHA-256 不变；原始告警、指纹及 ProcessRef 字段逐条相同。Stage8 未进行接口适配，STAGE8_LOGIC_MODIFIED=false。⑧语义不变、无 weak-directed 或 time-only relation；⑨没有启动。本轮身份及证据前置条件已具备，完整仓库健康仍受上述既有环境限制。

可复验命令（仓库根目录）：

```powershell
.venv\Scripts\python.exe -B scripts/verify_stage2_identity_projection.py after
.venv\Scripts\python.exe -B scripts/verify_stage2_identity_projection.py compare
```

`before` 仅用于修改前捕获，已有 baseline 时拒绝覆盖。验收资料在 `outputs/stage2_identity_projection/`：before/after、protected hashes、acceptance、gt_traces、overmerge_audit、downstream_attribution、relation_changes 与测试 XML。所有输出仅供离线审核，生产禁止读取这些快照或 GT。

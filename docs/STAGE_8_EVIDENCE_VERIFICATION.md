# ⑧ Cross-Stage Evidence Verification

> 本文记录历史 `stage-evidence-v1` 验收语义及原始 Witness 格式。当前正式⑧已迁移为 Claim / Context / Trace 三层结构，见 [Stage ⑧ Relation Semantics Repair](STAGE_8_RELATION_SEMANTICS_REPAIR.md)。原始 v1 结果与审核报告保留，不作为当前生产输入。

正式入口 `app.services.stage_pipeline.load_stage_pipeline()` 现在依次执行①～⑧，返回后停止。`candidate_result` 保留⑦的完整原始输出，`evidence_result` 提供⑧的 `CrossStageEvidenceResult`。没有调用旧 Stage relation analyzer、Alert pair correlation scorer、关系图、攻击链、API、前端或 AI。

```text
⑥ StageResult
  → ⑦ StagePairCandidateResult（原对象）
  → ⑧ validate_stage_pair_candidates()
       → scoped typed witness postings
       → witness identity / scope / semantic / temporal checks
       → all-valid-witness semantic aggregation
       → DIRECTED_EDGE | UNDIRECTED_EDGE | NO_RELATION
  → RETURN
```

⑧仅遍历传入的 Candidate；不会枚举全部 Stage 对，也不使用 Candidate reason、检索强度或时间来证明关系。⑦检索特征不直接升级成关系证据；⑧从当前 Stage 成员回查正式 Alert、Entity、ContextRef、Binding 和原始指针，复用 `community.evidence.profile` 的事实投影。行为注解用于确认正式 handoff 完整，不根据行为类别相似度创造关系。所有执行只读，GT 只在离线验收器中读取。

## 证据与决策

`CrossStageEvidence` 包含 Stage/Alert 双端点、证据类型、语义强度、方向主张、全部原始指针、时间检查、冲突原因、有效性和身份/角色元数据。证据 ID 对完整规范化内容取摘要，模型检查原始指针分别绑定两个 Witness，生产时解析指针并验证 Stage 成员身份。

| 强度 | 证据 | 方向来源 |
|---|---|---|
| DIRECTIONAL_STRONG | PARENT_CHILD_PROCESS | 同一完整进程实例分别作为当前进程和另一事件父进程；校验子进程完整且不同 |
| DIRECTIONAL_STRONG | REQUEST_RESPONSE | 相同 scoped request，显式互补 REQUEST/RESPONSE 操作 |
| DIRECTIONAL_STRONG | OBJECT_CREATE_EXECUTE | 同一 scoped host 和绝对对象路径，显式创建及执行/消费操作 |
| DIRECTIONAL_STRONG | OBJECT_HANDOFF | 显式 response_object_id → request_object_id |
| DIRECTIONAL_STRONG | AUTH_ESTABLISH_USE | 同一 scoped session/connection，显式成功建立与已配置的使用操作 |
| DIRECTIONAL_STRONG | EXPLICIT_ATTESTED_RELATION | scoped 原生 predecessor 引用或已绑定端点且通过类型校验的 Adapter attestation |
| ASSOCIATIVE_STRONG | 同一完整 process、native flow + 完整 tuple、scoped session/request/object/connection/task、明确 related_event | 只证明强关联，不证明传播方向 |
| SUPPORTING_ONLY | host/account/URL/command/IP、进程描述、路径或只有 tuple 的 flow | 永远不能单独建边 |

文件路径必须为绝对路径且绑定同一 scoped HOST；同名文件不支持创建执行关系。路径相同本身仅为 supporting context，不证明同一对象生命周期。无法校验完整 flow tuple 时，裸 flow ID 不能成为强证据。session 的未知行为、失败登录和两个普通使用操作不能形成 establishment → use 方向。结构化 session_continuity 仍为无向关联，不能因端点按 src/dst 排列就断言传播。

先验证全部 Witness，再按有效证据的语义集合决策：

1. 有合法方向证据且全部方向一致：`DIRECTED_EDGE`。
2. 两个方向均存在：记录 `DIRECTION_CONFLICT`；合法方向证据仍证明强关联，因此输出 `UNDIRECTED_EDGE`。
3. 无合法方向证据但存在强关联证据：`UNDIRECTED_EDGE`。
4. 只有 supporting evidence 或无有效证据：`NO_RELATION`，附具体 diagnostics。

不会比较证据 score、rank，不会按数量加分或设建边阈值。primary 仅按稳定证据 ID 选取一个符合最终决策的展示 Witness；方向决策先于 primary 选择，全部有效和无效 Witness 都被保留。决策包含 primary/supporting/invalid evidence IDs、各类型计数、各强度有效计数及冲突数。模型拒绝悬空引用、遗漏证据、伪造方向和不一致的 Witness 汇总。

## Witness 级冲突和时间

⑧拥有独立的 conflict contract，不导入⑥的 hard conflict。不同 URL、command、request、account、session 不会 veto 整个 Stage 对。

只有具体 claim 的身份、scope、语义或时序事实不成立时，才拒绝该 Witness：例如 GUID 碰撞但已知 PID/start_time 矛盾、匹配桶中出现不同身份/scope、错误 explicit relation 端点、子进程出生早于父进程，或 REQUEST 实际晚于 RESPONSE。一个无效 Witness 不影响同一对其他合法 Witness。

时间永远不提出边或方向。进程谱系检查父/子出生时间，父进程晚被观测不构成因果冲突；其他方向类型检查已由语义提出的 predecessor 时间。缺少出生时间时明确标记 `UNKNOWN`，不会用观测时间补造出生事实。每种方向类型的 reversal tolerance 独立配置于 `stage-evidence-v1.yaml`；没有统一最大时间窗口，长期强关联和谱系不因时间跨度大而被删除。

时间冲突会让该方向 Witness 无效；若仍有合法共享身份，则最终可以无向。无其他强证据则 `NO_RELATION`。不会把时序相反的无效方向反转成另一方向。

`stage_relations` 的 v1 enum、旧测试和既有消费者保留为历史兼容。正式⑧使用独立的三值 enum，不执行旧模块，不生成 `WEAK_DIRECTED`。

## 运行与验收

```powershell
.venv\Scripts\python.exe scripts/run_stage_pipeline.py --input D:/Code_WorkSpace/TraceBack-Dataset/data/attack125/final/attack125_final.jsonl
.venv\Scripts\python.exe -m pytest backend/tests/test_stage_evidence.py backend/tests/test_stage_candidates.py backend/tests/test_stage56_repair.py backend/tests/test_stage_relations.py backend/tests/test_evidence_trace.py -q --junitxml=.tmp/stage8/tests.xml
.venv\Scripts\python.exe scripts/verify_stage8_evidence.py --tests .tmp/stage8/tests.xml
```

实现前保存的 `upstream_before.json` 和 `protected_before.json` 已迁移至 `outputs/stage8_evidence_verification/baseline/`，该目录也是验收器默认的基线路径。两份文件保留原始内容，包含当时实时运行的①～⑦输出、全部已有生产源码/配置哈希及 ATTACK125 文件清单/哈希。验收器只在生产执行返回后将这些文件与本次输出比较；不会从快照加载生产事实。重新建立未来修改前的基线可用 `--capture-baseline --baseline <新目录>`，不允许覆盖已有基线。

`.tmp/stage8/` 仅存放可清理的临时测试报告；测试结束后可删除，运行上面的验收命令前需重新生成 `tests.xml`。历史基线应保留在 `outputs/stage8_evidence_verification/baseline/`，清理输出目录时也不要删除该子目录。基线属于本地产物，由现有 `outputs/` 忽略规则排除在 Git 之外。

验收器用运行时文件审计禁止生产读取 GT/evaluation/outputs、写文件或联网，用 profiler 禁止旧 scorer/旧 relation analyzer/下游图链/API/AI 执行，并确认编号步骤各执行一次。它独立重算 Witness 追溯闭包、比较①～⑦完整输出、打乱输入验证确定性、检查数据发布清单，最后才读取 GT。

输出目录为 `outputs/stage8_evidence_verification/`：

- `summary.json`：固定验收字段、执行统计和检查结果。
- `evidence_result.json`：完整 165 对 Decision 及全部 Witness。
- `gt_relations.json`：7 条 GT 的所有实际 Stage 对、召回、关系和原始字段；有向关系另外报告 GT 方向是否一致。
- `samples.json`：每类确定性抽样至多 5 对，包含 Community、Candidate reasons、Witness、raw values、direction basis、时间和冲突。
- `integrity.json`：源码/数据保护结果和独立追溯计数。
- `REPORT.md`：可直接审阅的统计、GT 表和 15 个完整真实样本。

GT 将 native wrapper event_id 经原始事件摘要映射到当前 Alert 和 Stage，仅用于离线评估关系是否找到。多组 binding 映射至多个 Stage 对时保留全部明细；汇总报告最强已找到关系，同时单列 GT 方向是否匹配，避免把关系召回等同于方向正确。允许 GT 为 `NO_RELATION`，不为 GT 调整证据、候选或 Stage。

⑥现有的 Stage 内部 Alert 连通性图仍属于上游聚合；⑧没有构建⑨ Stage Relation Graph，没有计算 Stage relation connected components、入口/出口或攻击链。

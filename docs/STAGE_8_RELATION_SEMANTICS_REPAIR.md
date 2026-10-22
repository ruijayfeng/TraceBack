# ⑧ Relation Semantics / Evidence Claim Deduplication

正式入口仍为 `load_stage_pipeline()`：①～⑦原样运行，⑦输出的 Candidate 对象直接交给⑧，返回后停止。当前正式输出契约为 `stage-evidence-v2`。本轮未修改任何实体、scope、mapping、Community、Stage 或 Candidate 生成规则，也未实现⑨。

## Context Membership 与直接关系

三类事实分开保存：

| Claim semantic_class | 含义 | 可否独立建边 |
|---|---|---|
| DIRECTIONAL_RELATION | 父子进程、请求响应、对象创建执行/交付、认证建立使用、显式因果引用 | 合法方向一致时 DIRECTED_EDGE |
| DIRECT_ASSOCIATIVE_RELATION | 显式原生 pair reference；或符合独占身份契约的双 Stage 身份 | UNDIRECTED_EDGE |
| CONTEXT | 同一 scoped Flow / Process / Session / Request / Object / Connection / Task 的成员身份 | 不单独建边 |
| SUPPORTING | Host / Account / URL / Command / IP / Path / descriptor 等辅助上下文 | 不单独建边 |

已有可靠方向证据优先，Context 大小不 veto 方向。相反方向的合法直接关系 Claim 保持独立，记录 DIRECTION_CONFLICT，保留直接关联、降为无向；不会按时间或列表顺序选方向。

没有关系 Claim、只有合法 Context 时输出 `NO_RELATION + SHARED_CONTEXT_ONLY`；Context 与其原始字段保留。没有合法 Claim 或 Context 才使用 `NO_VALID_EVIDENCE`。Decision 的 `context_identity_ids` 也保留只以全局 membership 表达的事实，例如共享显式父进程上下文。

## 全局 Context Posting 与独占例外

`ContextIdentityPosting` 保存 type、完整 scoped identity、全局 Stage/Alert/source 集合、时间范围、Claim IDs，以及每条原始 membership 的 Stage、Alert、角色和 pointer refs。

所有当前 Stage 的正式 typed postings 扫描一次，覆盖未出现在某个 Candidate 子集中的 Stage。Process 足迹包含当前进程和显式 parent_process 角色；不能遗漏第三个 Stage 的 parent 引用后，错误声明一个进程为双 Stage 独占。

按 `stage-evidence-v1.yaml` 的 `exclusive_context_policy`，一个共享身份只有在恰好两个 Stage、身份完整、原始双端有效且未发现身份污染时，才允许赋予 `DIRECT_ASSOCIATIVE_RELATION`。该例外是完整身份的局部独占契约，不是“共享人数超过阈值就 veto 整个 Pair”。

Process GUID/key 碰撞但已知 PID/start/GUID/instance ID 矛盾时标记 identity_polluted，禁止独占晋升。更多 Stage 共享同一身份时默认 Context；另有独立 native pair reference 或方向关系仍可建边。显式原生 related_event 不因其所在 session 覆盖多个 Stage 而丢失直接关联语义。

Context Posting 不枚举新的 Stage Pair；⑧仍只验证⑦产生的 Candidate。

## Claim 与 Observation 索引

Claim key：

```text
Stage A/B + Evidence Type + 完整 Scoped Identity
+ Semantic Direction + Endpoint Roles
```

`claim_id` 只由逻辑事实决定，不含 observation 数量、列表顺序或时序评分。ParentChild identity 同时绑定父和子实例；同父不同子不会合并成一条 Claim。

`EvidenceClaim` 保存分类、方向、身份、有效性、时间检查汇总、冲突、理由，以及 `observation_ids` / `observation_count`。重复 Alert Pair 不会增加 strength 或产生独立 Claim。一个 Claim 的部分观测无效时，只使用其余有效观测，完整拒绝原因仍在 trace validation 中。

正式结果只在顶层保存一次 Trace Index：

```text
Decision.primary_claim_id / relation_claim_ids
  → EvidenceClaim.observation_ids
  → SupportingObservation(alert_a_id, alert_b_id,
                          raw_pointer_ids, validation_id)
  → RawEvidenceReference / ObservationValidation
  → CanonicalAlert.raw_alert 原始字段

ContextIdentityPosting
  → evidence_claim_ids / memberships.raw_pointer_ids
  → 同一个 Trace Index
```

每个 Decision 明确分列 relation/context/supporting/invalid Claim IDs 和计数；`primary_claim_id` 仅出现在真正的 Edge 上。不会把850条 Observation 全部内嵌到单条 Relation。

Raw Pointer、Validation 和 Observation 使用稳定内容 ID，重复内容只存一次。所有原始 Alert Pair 与 raw pointers 仍可通过 Claim 展开。模型验证无悬空引用、无孤立表项、双端绑定正确、Claim 语义和最终决策一致。

`app.stage_evidence.models` 保留历史 v1 读取结构；正式入口导出的 Decision/Result 来自 `contracts.py`，不会调用 v1 决策。没有 API 或前端迁移代码。

## 验证与复审

```powershell
.venv\Scripts\python.exe -B -m pytest backend/tests/test_stage_evidence.py backend/tests/test_stage_evidence_claims.py backend/tests/test_stage_candidates.py backend/tests/test_stage56_repair.py backend/tests/test_entity_binding_index.py backend/tests/test_stage_relations.py backend/tests/test_evidence_trace.py -q -p no:cacheprovider --basetemp=outputs/stage8_semantics_repair/repair_tmp --junitxml=outputs/stage8_semantics_repair/repair_tests.xml
.venv\Scripts\python.exe -B scripts/verify_stage8_semantics_repair.py --tests outputs/stage8_semantics_repair/repair_tests.xml
```

验收器先在只读审计下运行当前①～⑧，再读取实现前快照与 GT 作离线比较。检查①～⑦完整输出、⑦逐字段一致、数据发布哈希、原始 Witness 多重集合、完整 trace、Claim 唯一性、输入排列确定性以及有向边端点变化。

Before/After 体积采用相同 UTF-8、sort_keys、indent=2 和结尾换行格式；After 包含所有 trace 表，不通过遗漏明细减体积。原始4898 Witness逐字段重建比较包含类型、身份、方向、角色、Alert Pair、指针、时间、有效性及理由。

`outputs/stage8_semantics_repair/REPORT.md` 包含两类10-Stage Flow案例、15×14谱系压缩案例、合理有向/无向关系、Context-only样本、全部GT回归及离线 skeleton 统计。小型真实关系 clique 可以保留；它必须由每一对自己的合法关系 Claim 支撑，不能靠共享 Context 自动生成。

全量后端测试尝试的既有 AIT-ADS manifest 缺失属于环境限制，单列于报告；不补造或修改数据。旧 `verify_stage8_evidence.py` 和 `audit_stage8_relation_quality.py` 对应修复前 v1 验收/审核，现有报告作为历史基线保留。

本轮完成后停在⑧。后续若实现⑨，应消费明确区分的直接关系与 Context membership，保持两层语义，不补边、不把上下文展开为攻击关系。

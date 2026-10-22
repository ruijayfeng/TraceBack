# Attack Step 真实输入映射 v1.1

审计日期：2026-10-22。配套 [主契约](ATTACK_STEP_SEMANTIC_CONTRACT.md)。下表字段名来自实际代码和已封存 JSON，不把审计派生字段当生产字段。

状态：D=真实直接读取；R=真实但须引用解析；O=可选/可能为空；M=当前无可靠来源；F=未来新增接口。required 指本契约要求，不暗示上游已经实现。下表每行均包含要求的六项，另列 availability。

路径约定：S8=`outputs/stage9_formal_acceptance_20261022/run1/stage8.json`；S9=同目录 `stage9.json`；RC=同目录 `receipt.json`。这些与 `outputs/stage6_oversegmentation_audit_20261022/formal_run/` 同名产物一致。未来必须选择同次封存配对输入，不能混用运行。

## A. Stage、观测与身份

| LOGICAL_FIELD | ACTUAL_FIELD | SOURCE_MODEL_OR_FILE | RESOLUTION_METHOD | OPTIONAL_OR_REQUIRED | MISSING_DATA_BEHAVIOR | availability |
|---|---|---|---|---|---|---|
| Stage ID | `stages.stages[].stage_id` | S8；`backend/app/stages/models.py:Stage` | 建 `stg_` ID 索引，禁止按数组位置认身份 | required | 缺失/重复 intake 失败 | D |
| Stage 告警成员 | `stages.stages[].alert_ids`、`alert_count` | 同上 | 每项解析 S8.alerts[].alert_id；数量一致 | required | 悬空、重复归属、计数不符失败；不得丢困难告警 | R |
| Community ID | `stages.stages[].community_id` | 同上 | 解析 S8.communities.incident_candidates[].community_id | required | 缺失/越界失败；不同社区不自动否定高层关联 | R |
| Community 依据 | `matching_evidence`、`membership_decisions`、`alert_ids` | `backend/app/community/models.py:IncidentCandidate` | 依据 alert_ids、supporting_evidence 回溯；仅候选上下文 | required snapshot / optional semantic support | 不可把社区匹配证明升级成攻击步骤证明 | D/R |
| Stage 代表行为 | `stages.stages[].behavior` | `stages/models.py` | 原值读取；不能替代逐告警注释 | required | 缺失失败；UNKNOWN 合法且保留 | D |
| 行为注释 | `stages.behaviors[]` 的 alert_id, behavior, resolver, matched_rule, confidence, reason, evidence, input_digest | `BehaviorAnnotation` | 依 alert_id 回查全体注释，不按 Stage 代表标签推造 | required annotation；community_id 可选 | 缺关键注释阻止基于它确认；UNKNOWN 不自动拒绝 | R/O |
| 时间范围 | `stages.stages[].start_time/end_time` | `Stage` | 原值及成员 timestamp 核对；不产生方向 | required | 不一致 intake 失败；不添加新时间阈值 | D |
| 证据摘要 | `evidence_summary` | `Stage` | 描述用途，不能替代原始证据路径 | required snapshot | 摘要不支持因果或目的确认 | D |
| Stage 聚合证据 | `aggregation_basis[]` 的 alert_ids/rule/keys/evidence/strength/evidence_types/temporal_check | `AggregationBasis` | 原始告警 pair 与 EvidencePointer 逐项解析 | optional for singleton | 空列表可合法；不得伪造 Stage 内证据 | D/R/O |
| Host | `host_entities[]` | `Stage`；S8.entities[] | ent_ ID → entity.type/scope/value/alert_ids，再回成员 entity_occurrences | optional | 空不以 IP/主机名猜 host；目的依赖它时无法确认 | R/O |
| Account | `account_entities[]` | 同上 | 保留主体及作用域；不可只比较显示值 | optional | 不推断同名账号同一主体 | R/O |
| Process | `process_entities[]` | 同上 | 回查实体与成员 process/parent_process 及其 provenance | optional | PID 单独不足；不把同父进程的全部子进程视为同一实例 | R/O |
| Entity 总索引 | `entities[].entity_id/type/scope/value/display_value/alert_ids` | S8；实体提取依赖 `backend/app/entities/extraction.py` 与 `backend/app/models/` | 按 ID 解析；display_value 仅显示 | required table；成员列表可空 | 引用悬空失败；不能按显示同名 join | R |
| 观测实体角色 | `alerts[].entity_ids/entity_occurrences[]`；occurrence 的 entity_id/role/raw_pointer | `backend/app/models/alerts.py:CanonicalAlert/EntityOccurrence` | 保留 src/dst/shared 及证据 pointer | optional semantic binding | 缺少角色不得假设互补动作 | R/O |
| Identity binding | `alerts[].identity_binding_ids[]` | `CanonicalAlert`；`entities/identity_projection.py` | 分别按 alias_binding_id 或 projection_id 在相应 typed 表查找 | optional，默认空 | 不按名字拼接 ID；缺失阻止依赖该绑定的确认 | R/O |
| Host alias | `identity_projection.host_alias_bindings[]` | `HostAliasBinding` | alias_binding_id → canonical_host_entity_id/status/authority_scope/observations | optional | AMBIGUOUS_ALIAS 或 null host 不当作 BOUND | R/O |
| Auth session | `identity_projection.auth_session_bindings[]` | `AuthSessionBinding` | projection_id → canonical_session_entity_id、host、authority_scope、lifecycle_status、observations | optional | 同 token 不跨 authority/lifecycle 拼接 | R/O |
| Request / connection projection | `identity_projection.context_bindings[]` | `ContextIdentityBinding` | projection_id → kind/scope/value/observations；kind 为 request/connection | optional | 不把 request 与 connection 的相同 token 视为同种身份 | R/O |
| Process projection | `identity_projection.process_bindings[]` | `IdentityProjectionResult` | 当前只是未定义条目模型的 list 占位，本次为空；不假定与其他 projection 表共享 ID 格式 | optional placeholder | 本版不作为确认输入；使用已定义的 process entity/occurrence/provenance，新增投影结构需另行适配 | D/O/M |
| Request / Flow / Session / Task | `request_bindings/flow_bindings/session_bindings/task_bindings` | `Stage` | **哈希绑定键**，回查成员 contexts、原始网络 tuple 及 provenance、候选 features、claim identity、typed projection 及 raw pointers | optional | 不逆推键、不拼补缺字段；相同键只表上下文，须验证作用域/角色 | R/O |
| 原生上下文 | `alerts[].contexts[]` 的 kind/scope/value/raw_pointer | `ContextRef` | 根据 kind 和 scope 解释，保留源 namespace | optional | 裸 token 无权威作用域不能升级直接绑定 | R/O |
| 原始值及溯源 | `alerts[].raw_alert`、`field_provenance` | `CanonicalAlert/FieldProvenance` | field_provenance.raw_pointer/transform 及 EvidencePointer.resolve | required raw；可选字段可缺 | 区分缺失、null、冲突；不从 GT 补齐 | D/R/O |
| 原始证据指针 | `{alert_id,pointer,side}` | `backend/app/models/alerts.py:EvidencePointer` | alert_id → CanonicalAlert.raw_alert，RFC 6901 JSON Pointer；保留 side | required whenever cited | 无效路径标 INVALID；不存在标 MISSING；确认禁止未解析 | R |

## B. Candidate 与正式 Stage Relation

| LOGICAL_FIELD | ACTUAL_FIELD | SOURCE_MODEL_OR_FILE | RESOLUTION_METHOD | OPTIONAL_OR_REQUIRED | MISSING_DATA_BEHAVIOR | availability |
|---|---|---|---|---|---|---|
| 检索候选 | `candidates.candidates[].candidate_id/stage_a_id/stage_b_id` | `backend/app/stage_candidates/models.py` | scp_ pair 只是召回；以⑧ decision 判断接受 | required snapshot | 无候选不是拒绝关系，也不是无关联证明 | D |
| 候选特征 | `candidates.features[]` 及 witnesses | 同上 | witness 的 alert_id/namespace/scope/role/pointers 解析 | optional semantic support | retrieval hint 不升级 E1/E2 | R/O |
| Relation ID | `evidence.decisions[].candidate_id` | S8；`backend/app/stage_evidence/contracts.py:StageRelationDecision` | 正式 `scp_`；没有独立 relation_id 字段 | required | 缺/重复失败；不得使用旧 str_ 输出混接 | D |
| 无序身份端点 | `stage_a_id/stage_b_id` | 同上 | a < b 为 canonical pair，不是时间或因果排序 | required | 悬空或自配对失败 | D/R |
| 因果起终点 | `from_stage_id/to_stage_id` | 同上 | 仅 DIRECTED_EDGE 非 null；原值复制 | conditional | 无向/null 不猜方向；方向冲突失败 | D/O |
| 类型 | `relation_type` | 同上 | DIRECTED_EDGE / UNDIRECTED_EDGE / NO_RELATION | required | 未知值不映射成旧强/弱边 | D |
| 方向依据 | `direction_claim` | 同上 | A_TO_B/B_TO_A/UNDIRECTED/NONE；核对原端点 | required | 不从时间或 ID 顺序推导 | D |
| 接受/拒绝 | 无 accepted 字段；由 relation_type 导出 | 同上 | != NO_RELATION 为接受 | required derived | 未出现在 decision 表的 pair 是未评估，不伪造拒绝 | R |
| 决策原因 | `reason/diagnostics` | 同上 | 原文保留，语义理由单独记录 | required reason | 不重写原决策来迎合语义组 | D |
| Claim 引用 | `primary_claim_id/relation_claim_ids/context_claim_ids/supporting_claim_ids/invalid_claim_ids` | 同上 | → evidence.claims[].claim_id；primary 仅接受关系有效 | conditional | 不把 context/invalid claim 充作直接关系 | R/O |
| Claim 内容 | `claims[].evidence_type/semantic_class/identity/direction_claim/role_a/role_b/valid/temporal_check/conflict_status/reason/observation_ids/metadata` | `EvidenceClaim`（contracts.py） | 保留完整真实身份与角色；通过 observation_ids 追溯 | required when used | invalid 或缺失 witness 不支持确认 | D/R |
| Witness Alert | decision 无 witness_alert_ids；`trace.observations[].alert_a_id/alert_b_id` | `contracts.py` | decision → claim.observation_ids → observations → alerts | required for E1/E2 | 无路径即缺证据，不从 Stage 全成员笛卡尔积补造 | R |
| Evidence refs | `trace.observations[].raw_pointer_ids/validation_id`；`trace.raw_pointers[].pointer_id/raw_pointer` | `contracts.py` | obs_ → erp_ → EvidencePointer；evc_ → trace.validations | required when used | 每跳检查，不把 audit summary 当证据替代品 | R |
| 上下文 posting | `evidence.context_postings[]` | `contracts.py` | 按 context_identity_id 及 memberships 的 stage/alert/role/raw_pointer_ids 解析 | optional | 共享上下文不构成 pair 边；exclusive_direct_eligible 必须真实成立 | R/O |

正式结果版本是 `stage-evidence-v2`；证据 policy 的配置版本 `stage-evidence-v1` 是另一概念。`config.py` 中的 REQUEST_RESPONSE 依赖已有 scoped request 和互补操作角色；PARENT_CHILD_PROCESS、AUTH_ESTABLISH_USE 等不能互换为请求/响应目的。

## C. Attack Chain

| LOGICAL_FIELD | ACTUAL_FIELD | SOURCE_MODEL_OR_FILE | RESOLUTION_METHOD | OPTIONAL_OR_REQUIRED | MISSING_DATA_BEHAVIOR | availability |
|---|---|---|---|---|---|---|
| Chain ID | `chains[].chain_id` | S9；`backend/app/stage_chains/reconstruction.py:AttackChainMembership` | sch_ 原值索引 | required | 重复/缺失失败 | D |
| 成员 Stage | `chains[].stage_ids` | 同上 | → S8.stages.stages；全体 Stage 恰归一链 | required | 悬空、漏项、重归属失败 | R |
| 原关系归属 | `chains[].relation_ids` | 同上 | → S8.evidence.decisions[].candidate_id；只含接受关系 | required；singleton 可空 | 拒绝/悬空/归属不一致失败 | R |
| 连通分量 | 无 component_id；chain 本身为接受混合图分量；`single_stage` | reconstruction.py | chain_id 表示上游分量；组内诱导分量是未来派生，不冒充既有字段 | required original；F group partition | 不按同 Chain 假设所选子集连通 | R/F |
| Entry / Exit | `entry_stage_ids/exit_stage_ids/entry_exit_basis` | 同上 | existing_directed_relations_only；纯无向多节点可为空；singleton 为自身 | required arrays | 空不是缺失；不能补时间最早/最晚节点 | D/R |
| 环及弱方向 | `has_directed_cycle/weak_direction_is_causal` | 同上 | 保留；后者 false | required | 不拓扑化去环，不提升无向关系 | D |
| 链时间 | `start_time/end_time` | 同上 | 原值保留 | required | 不把时间顺序当路径 | D |
| 链证据 | 无嵌入 evidence_refs | S9 → S8 | stage_ids/relation_ids → 原 Stage/decision/claim/trace | required resolvability | 不使用旧模型 source_analysis_id/community_id/relations 字段填补 | R/M |
| 图摘要与保护 | 顶层 `input_digest/guard` | AttackChainReconstruction | 与 receipt.graph_input_digest 及⑧复核 | required | 不符停止 intake | D |

## D. 运行元数据和未来字段

| LOGICAL_FIELD | ACTUAL_FIELD | SOURCE_MODEL_OR_FILE | RESOLUTION_METHOD | OPTIONAL_OR_REQUIRED | MISSING_DATA_BEHAVIOR | availability |
|---|---|---|---|---|---|---|
| 上游 Run ID | 无可靠统一字段 | RC 无 run_id | 不采用审计目录名/source_run 字符串伪装 | unavailable | 明确 absent；不阻塞只读审查 | M |
| 语义 Run ID | 未来 envelope.run_id | 主契约 §2 | 按冻结输入/配置/策略内容寻址 | required future | 缺输入不生成成功产物 | F |
| dataset_version | RC 没有；数据发布方有 release 信息，但不在正式 envelope 中 | 数据集 CURRENT_RELEASE / manifests/release_manifest.json（仅本次审计来源） | 未来生产者输出不含 GT 的 provenance receipt，版本与输入 SHA 绑定 | required future | 当前接口缺失；禁止路径猜测或运行时读取 GT manifest 字段 | M/F |
| 数据 SHA256 | RC.input_sha256 | receipt.json | 对原始文件字节复算；S8 raw_fingerprint 不能替代整文件 SHA | required | 不符失败 | D/R |
| 上游配置摘要 | S8.communities/stages/candidates/evidence.config_hash | 对应 Result | 四项原值保存；不冒充配置文件字节 SHA | required | 缺失失败 | D |
| S8/S9 文件摘要 | RC.stage8_sha256/stage9_sha256 | receipt.json | 对两文件字节 SHA256 复算 | required | 不符失败 | D/R |
| 图输入摘要 | S9.input_digest、RC.graph_input_digest；S8.evidence.input_digest 语义不同 | reconstruction / receipt | 分字段保存、按定义核对，不能互换 | required | 不一致停止；不以重新序列化哈希替代文件哈希 | D |
| 上游契约版本 | S8.communities/stages/candidates/evidence.contract_version；S9.contract_version | 各模型 | 分别 community-v1 / behavior-stage-v1 / stage-candidates-v1 / stage-evidence-v2 / attack-chain-reconstruction-v1 | required | 未知版本需显式适配，不静默猜测 | D |
| 本语义契约 | 未来 contract_version=`attack-step-semantic-v1.1` | 本次文档/Schema | 固定版本，升版复审 | required future | 不冒充已存在上游输出 | F |
| 语义词表版本 | 未来 taxonomy_version=`attack-step-taxonomy-v1.1` | 主契约 §4（仅文档目录） | 与 label/purpose_rule_id 联合核对 | required future | 现有 behavior 标签不是语义词表 | M/F |
| 策略摘要 | 未来 policy_digest | 本主契约文件（含 P1/标签目录） | 原始文件字节 SHA256，核对本轮 documentation_manifest.json | required future | 不接受未知/修改后的规则或用 config_hash 替代；新规则必须升版 | F |
| semantic groups / ledger / membership / projection / summaries | 当前无接口 | 本次 Schema | 未来只读原型生成；V01–V12 校验 | required future | 本次只定义，不声称现成能力 | F |

`backend/app/entities/models.py`、`backend/app/models/entities.py`、`backend/app/stages/pipeline.py` 在当前仓库不存在；采用实际 `entities/identity_projection.py`、`models/alerts.py:Entity`、实体提取模块以及 `stage_chains/pipeline.py` → `services/stage_pipeline.py` 的依赖链。所有未来字段都有明确缺失处理；“映射完成”不等于“未来接口已实现”。

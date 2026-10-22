# TraceBack — Attack Step Semantic Contract v1.1

状态：**FROZEN_FOR_OFFLINE_PROTOTYPE**；冻结日期：2026-10-22。

本契约定义下一轮离线原型的输入、判据、输出和验收。当前项目没有实现本契约的分组器、序列化器或评估器。本轮只修改文档和 Schema。唯一设计基线是本文件原 v1.0，原文保存在 `outputs/attack_step_contract_freeze_20261022/ATTACK_STEP_SEMANTIC_CONTRACT.before.md`。

## 1. 不变量与概念

Alert 是真实观测；Action Stage 是⑥产出的不可拆分动作单元；Stage Relation 是⑧的原始决策；Attack Chain 是⑨依据接受关系构造的混合图连通分量。Attack Step 是只读语义归属，不是新的 Stage、Chain、路径或因果边。

1. 保留全部原始 Alert / Stage / Relation / Chain 的身份、内容及归属。不修改①～⑨、Behavior Mapping、生产词表、阈值、配置、数据及 Ground Truth。
2. 不重判⑧的接受/拒绝结果，不新增、删除、反转、合并或隐式制造关系。无向关系始终无向，时间先后不产生方向。
3. 不同动作可以属于同一高层活动；URL、Command、Behavior 不同不是本层自动拒绝理由，也不是确认理由。⑥的动作级拒绝不能直接充当高层目的冲突。
4. 确认必须证明共同且边界明确的观测活动；有关联、连通、同社区或同标签不能代替证明。
5. 每个 Stage 最多一个 CONFIRMED 主归属；候选允许重叠；全部未分配 Stage 必须保留。
6. 跨 Chain 语义候选必须如实记录断连。分组永远不能作为补边、合并 Chain 或连续路径的依据。
7. GT 仅在语义输出封存后供独立评估。不得为了凑成 8 组而合并 15 个 Stage。AI 不决定成员归属。

## 2. 权威输入与元数据

正式入口是 `scripts/run_stage_pipeline.py` → `stage_chains.pipeline.load_attack_chain_pipeline`。输入白名单为同次封存的 `stage8.json`、`stage9.json`、`receipt.json` 及 SHA256 核对后的原始告警文件。逐字段来源见 [映射表](attack_step_input_mapping.md)。

⑧正式关系身份是 `stage8.evidence.decisions[].candidate_id`（`scp_…`），类型为 `DIRECTED_EDGE / UNDIRECTED_EDGE / NO_RELATION`。旧 `stage_evidence.models`、`stage_chains.assembly` 接口不能代替正式接口。⑨只持有成员/关系引用，证据须回查同次⑧。

历史 `stage6_input_snapshot.json`、`algorithm_stages.json`、GT 映射与案例报告只供设计审阅，不进入分组输入白名单。`evidence_trace_paths.json` 也是审计工具生成的报告，不是假定存在的生产接口。

原型还需要未来新增的 provenance receipt：生产者提供非空 `dataset_version` 及其非 GT 来源说明。当前正式 receipt 没有可靠统一 Run ID 或 dataset_version。缺少版本凭据、文件摘要不符、未知上游契约、重复 ID、核心 Stage/Chain 引用无法闭合时，intake 失败，另存错误报告，不发布符合本 Schema 的成功产物。不从路径名猜测数据版本，不读取 GT 补齐。

未来语义 `run_id=asrun_` + SHA256(JCS({contract_version, taxonomy_version, dataset_version, input_artifact_digests, upstream_config_digests, policy_digest}))。JCS 为 RFC 8785 JSON Canonicalization Scheme；值均取自输出 envelope。它不是上游 Run ID。v1.1 的 `policy_digest` 固定为本主契约文件原始字节 SHA256（含 P1 和标签目录），须与本轮 `documentation_manifest.json` 核对；不能用源码或上游 config_hash 代替。运行时间、机器路径等放独立执行 receipt，不参与语义 ID。

未来 provenance receipt 的最小字段固定为：`contract_version="attack-step-provenance-v1.1"`、非空 `dataset_version`、64 位小写十六进制 `dataset_sha256`、非空 `producer`、`version_source`（对象，kind 为 `PRODUCER_RELEASE` 或 `IMMUTABLE_DATASET_MANIFEST`，reference 为非空发布凭据定位字符串）。该 receipt 仅提供来源，不携带 GT 标签/路径或规则；dataset_sha256 必须等于实际输入文件及 RC.input_sha256。reference 的凭据由生产者在 intake 前提供，不由分组器自行搜索 GT/审计目录取得。receipt 文件字节摘要写入 input_artifact_digests.provenance_receipt_sha256。

文件 SHA256、上游 `input_digest` 和配置 `config_hash` 不可混用。新 ID、输入封装、规则目录加载和输出字段均为未来接口，本轮未实现。

## 3. 证据分级

| 等级 | 可核实依据 | 限制 |
|---|---|---|
| E1 | 既有权威作用域下的直接跨动作绑定，身份、角色、witness 完整且符合冻结目的规则 | 相同 token、哈希键或字段名不够 |
| E2 | ⑧接受的有效强直接关系，claim → observation → pointer 可解析 | 只证明关联；父子、对象交接、认证建立使用均可能跨步骤 |
| E3 | Host、Account、Session、Flow、Community、时间等上下文 | 可支持有限候选，不能独自确认 |
| E4 | 标签、文本或名称相似 | 仅提示，不分配主归属 |
| NONE | 没有可核实支持证据 | 候选 ID 不构成证据 |

等级不是置信分数。invalid claim、NO_RELATION 或缺失 witness 不构成 E1/E2。关键引用缺失时保留失败原因，按剩余证据降级。组等级取最高可核实等级，但确认须逐成员全覆盖；一个 E1 pair 不能掩盖其余成员只有 E3。

## 4. 冻结的确认档案与标签

v1.0 的“共同目的明确”不能成为任意解释入口。v1.1 定义最小确认档案 **P1_REQUEST_RESPONSE_TRANSACTION**。它描述观测到的请求/响应活动，不声称攻击成功、凭据窃取、横向移动或攻击者意图。其他目的暂为候选/无法判断；扩展确认能力须升版本。

P1 须全部满足：

1. 使用⑧已接受决策中的 valid `REQUEST_RESPONSE` claim；既有方向、REQUEST/RESPONSE 角色、temporal_check、conflict_status 有效，语义层不得新造 claim。
2. 所有采用 claim 解析到同一个完整、权威、兼容的 scoped request identity。引用真实 identity/metadata 比较，不只比较 request token，不逆推哈希。
3. 每个成员 Stage 的全部告警，都由该活动已有 typed witness/身份绑定证明覆盖。未覆盖告警阻止整 Stage 确认，不能拆 Stage。缺作用域、生命周期不明、多活动污染均阻止确认。
4. 组内接受关系的诱导混合图连通；不能靠组外 Stage 路径补足。连通只是一项必要条件。
5. 无关键矛盾或未答问题；证据全解析；保留动作差异及原关系；主归属没有重叠。

P1 依赖跨 Stage 的既有 REQUEST_RESPONSE 关系，因此单 Stage 不适用。不能继承 Action Stage 的合法性就确认高层目的。当前档案也不支持跨 Chain 确认；它们的候选表达保留。新增单 Stage 证明、其他目的或跨 Chain 确认档案须升版并定义完整覆盖证明。这是原型能力限制，不否认其语义可能性。

输出文档目录 `attack-step-taxonomy-v1.1` 包含 `REQUEST_RESPONSE_TRANSACTION`、`WEB_ACTIVITY_CANDIDATE`、`REQUEST_EXECUTION_CANDIDATE`、`CREDENTIAL_ACTIVITY_CANDIDATE`、`HOST_ACTIVITY_CANDIDATE`、`UNCLASSIFIED_ACTIVITY`。这是新契约定义，未修改现有生产词表。仅首项可被 P1 确认；其余是有限候选描述。`label_source=FROZEN_RULE` 仅配 P1；其他用 `EVIDENCE_BOUNDED_DESCRIPTION` 或 `UNCLASSIFIED`。禁止 GT/AI/审计文件名充当标签来源。

## 5. 状态、优先级与重叠

见 [决策表](attack_step_decision_table.md)。按以下顺序处理，每组保留最终 ledger：

1. 先检查输入完整性；失败则不发布有效产物。
2. 有证据证明提案中的同一活动身份互斥、作用域冲突、角色/生命周期不兼容：REJECTED，至少一项具体 contradiction。拒绝语义提案不推翻⑧。
3. 关键绑定/witness 缺失、主归属冲突未决，或不能形成可核实的具体活动假设：UNRESOLVED，记录 unresolved_questions。
4. 有可核实的具体有限假设，但缺少完整 P1 证明：CANDIDATE，记录 unresolved_questions，不主分配。
5. 全部 P1 条件通过：暂为 CONFIRMED。多个暂确认组共享 Stage 时，所有冲突组降为 UNRESOLVED，记 PRIMARY_MEMBERSHIP_CONFLICT，不按 ID、分数、遍历顺序选胜者。

E4/NONE 不能成为 CANDIDATE。CANDIDATE 可为 E1/E2/E3；E1/E2 也可 UNRESOLVED/REJECTED。CONFIRMED 必须 E1，contradictions 和 unresolved_questions 均为空。缺证据不是反证，不能单凭缺失给 REJECTED。

跨 Chain 本版本最多 CANDIDATE，并须 `disconnected_members=true`、真实分量分区及限制说明。没有连接不是语义无关的反证。所有未确认 Stage 的主归属均为 null。

## 6. 输出及 Schema 外的强制校验

正式结构见 [Schema](attack_step_output.schema.json)，Draft 2020-12。新 semantic ID、membership index、ledger、projection、trace summary 均是未来输出，不是假定现成接口。

`semantic_step_id=asp_` + SHA256(JCS({run_id, member_stage_ids, semantic_label, purpose_rule_id}))。数组排序去重；同组同标签最多一条。成员仍为原 Stage ID。所有集合和对象数组按稳定 ID 或完整对象 JCS 字节排序；不能使用时间、随机数、机器路径、线程完成顺序决定结果。

Schema 检查类型、枚举、必填和状态条件；跨文件存在性及语义真实性必须另行验证。本轮只定义以下检查，不实现未来校验器：

| ID | 强制条件 |
|---|---|
| V01 | 逐文件摘要一致；上游契约受支持；两种新 ID 复算一致；规则目录版本/摘要匹配 |
| V02 | 原 Stage ID 唯一；membership index 恰好覆盖全部 Stage；原 chain_id 按⑨解析 |
| V03 | 组成员存在、无重复；member_chain_ids 等于成员的⑨归属集合；candidate_group_ids 列全所有未确认提案（含 UNRESOLVED/REJECTED） |
| V04 | primary_semantic_step_id 仅指 CONFIRMED；正反成员一致；确认组无重叠；未确认主归属 null |
| V05 | source_relation_ids 只含两端在组内的⑧接受决策；拒绝关系仅在 ledger/source_decision_ids 或反证引用保留 |
| V06 | evidence_refs 按 kind 解析；supporting_alert_ids 来自成员 Stage；组外反证可引用但不混入 supporting_alert_ids；raw pointer 按原始 JSON 解析 |
| V07 | P1 全部满足；purpose_covered_alert_ids 精确等于全部成员告警，且每项有目的证明；列表齐全不能代替证明 |
| V08 | connected_components 是接受关系的精确诱导分量；分区不漏不重；disconnected_members 当且仅当分量数 > 1；无向边只用于连通 |
| V09 | projection 对每条接受关系恰一条，保留原 candidate_id、stage_a/b、类型和 from/to；NO_RELATION 不得投影；保留内部及未分配端点关系 |
| V10 | 投影端点 primary group 可 null，且与 membership index 一致；同组也保留两个原 Stage 端点，不制造新 group 因果边 |
| V11 | 每组恰一条最终 ledger，status/reason/证据一致；REJECTED 有反证；缺引用标 MISSING/INVALID，不能伪标 RESOLVED |
| V12 | 汇总计数按真实引用重算；输入字节、Stage/Relation/Chain 内容及归属不变；自报 true 不代替证明 |

可选语义证据无法解析，可在未确认组中记录；核心输入损坏须 intake 失败。uniqueItems 不能保证对象按 ID 唯一，必须执行 V02–V04。`projected_relation_view` 是原关系注释表，不是新图；不重算⑨ entry/exit、时间或环。

## 7. 评估隔离与推广

相同冻结输入/策略的语义 JSON 按 JCS 应逐字节一致。执行 receipt 单独存放。先用白名单输入运行并封存语义 JSON、输入/策略摘要和软件版本，独立评估进程之后才读 GT，不能写回产物/策略。ATTACK125 四案已用于设计审查，属于已见审计集，不能宣称未见测试集。

指标、空分母、缺失映射和推广阈值冻结于 [评审文档](attack_step_contract_review.md)。GT 恢复与原 Chain 正确性分别报告。组数接近 8 不是指标；通过契约不代表通过语义质量门槛。

## 8. v1.0 → v1.1 变更记录

| 变更 | 理由与影响 |
|---|---|
| 校准正式入口、candidate_id、trace 引用 | 目录有旧同名模型；正式⑨无嵌入证据 |
| 声明缺失 Run ID、dataset_version、新目录和未来 intake | 避免把设计字段伪装成已有运行能力 |
| P1 最小确认档案，其他目的暂不确认 | “共同目的”需闭合判据；父子/连接存在跨步骤反例；不对四案定制确认 |
| 单 Stage、跨 Chain 确认暂不支持 | 当前档案无对应完整证明；保留候选，扩展须升版 |
| 明确 overlap、unassigned、诱导分量、一对一关系投影 | 避免顺序依赖、丢 Stage、借组外路径或隐式补边 |
| Schema 与 V01–V12 分工 | 标准 Schema 无法独自证明跨文件引用及语义正确 |
| 固定指标、门槛、已见集限制 | 防止 GT 泄漏、删除困难样本、空分母美化和按组数优化 |
| 清理 Markdown 转义与空行 | 提高可读性；只读原则不变 |

下一轮须在独立授权后实现离线只读原型。确认能力、标签含义、输入来源、指标或阈值变化均须升版本并在新实验前复审。

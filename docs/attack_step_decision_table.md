# Attack Step 分组决策表 v1.1

配套 [主契约](ATTACK_STEP_SEMANTIC_CONTRACT.md) 和 [Schema](attack_step_output.schema.json)。本表是未来原型测试规格，不是已执行的分组算法。状态按主契约 §5 优先级判定；任何行均不能绕过完整性、全组目的证明或重叠检查。

通用 TRACE 要求 T：保留 member_stage_ids/member_chain_ids、原关系身份及方向；记录 witness/claim/observation/raw pointer 路径、原拒绝决策和最终 ledger；原 Stage 全量进入 membership index，未确认主归属 null；候选之间不造边。证据等级描述可核实证据，不自动决定状态。

| # | INPUT_CONDITIONS | REQUIRED_EVIDENCE | DECISION | OUTPUT_STATUS | REJECTION_OR_UNCERTAINTY_REASON | TRACEABILITY_REQUIREMENTS |
|---|---|---|---|---|---|---|
| D01 | 单 Stage，无独立高层目的证明 | 现有 Stage 与其完整成员；代表 behavior 不是目的证明 | 保留 singleton 未分配；有具体有限假设可改走 D03，否则无法判断 | UNRESOLVED | PURPOSE_NOT_PROVEN；本版本 P1 不覆盖 singleton | T；原 singleton Chain、空关系均合法 |
| D02 | 多 Stage 动作不同，但满足全部 P1 请求/响应条件 | 同完整 scoped request、有效 REQUEST_RESPONSE、全部成员告警覆盖、诱导图连通、无冲突 | 确认同一观测请求/响应活动；不声明攻击成功 | CONFIRMED | P1_COMPLETE | T；E1；source_relation_ids、purpose_covered_alert_ids 非空且精确；V07 |
| D03 | 不同动作有直接关系，能提出有限具体假设，但非完整 P1 | 有效已接受 claim + 全路径；保留角色差异 | 保存有限候选，不主分配 | CANDIDATE | PURPOSE_NOT_PROVEN | T；E2；明确尚缺何种共同目的/全成员覆盖证明 |
| D04 | 只有共享 Host/Account，无跨动作证据或具体活动假设 | typed 主体和作用域可核实 | 无法判断；不得将主体相同当活动相同 | UNRESOLVED | CONTEXT_ONLY | T；E3；不合成 source_relation_ids |
| D05 | 同 Session，但 Connection 或 Action 不同；没有具体活动证明 | session authority/lifecycle、connection identity、动作原值 | 保留差异；上下文不足确认 | UNRESOLVED | CONTEXT_ONLY | T；有有限活动假设才可按 D03/D16 为候选；同 token 不跨生命周期 |
| D06 | URL/Request/Command 不同，只有差异，没有活动身份反证 | 原始值、scope、角色、引用 | 差异不足直接拒绝，也不足确认 | UNRESOLVED | PURPOSE_NOT_PROVEN | T；不能忽略 query/命令参数，不能套用⑥动作级 hard conflict |
| D07 | 提案声称同一 request/connection，但同权威、同身份域下记录证明为互斥实例 | 至少一项可解析身份/生命周期反证；明确冲突的是提案所依赖的同一身份 | 拒绝此具体同活动提案；原关系保持 | REJECTED | INCOMPATIBLE_ACTIVITY_IDENTITY | T；contradictions 非空；不能把不同 URL 本身当身份互斥 |
| D08 | Behavior 不同，但有完整 P1 | 与 D02 同等，不以 behavior 相同为必要条件 | 保留不同注释并确认 | CONFIRMED | P1_COMPLETE | T；逐 alert 注释，不改 mapping |
| D09 | 两 Stage 有接受的有向关系，只有方向本身 | 有效 claim、真实 from/to；可解析 witness | 无具体假设则无法判断；已有具体假设但未满足 P1 按 D03 | UNRESOLVED | RELATION_NOT_PURPOSE | T；不把 parent-child/auth 等同于一步；不扩展因果 |
| D10 | 只有接受的无向关系，存在有限活动假设 | 原 UNDIRECTED_EDGE 和有效 claim/witness | 可记候选；不确认 P1、不猜方向 | CANDIDATE | PURPOSE_NOT_PROVEN | T；from/to 为 null；source_relation_ids 可含原无向关系 |
| D11 | 成员跨 Chain，存在有限具体假设及上下文/直接证据 | 独立于 Chain 的实际支持、原 chain_id、诱导分量 | 保存断连候选；本版本不支持跨 Chain 确认 | CANDIDATE | CROSS_CHAIN_CONFIRMATION_UNSUPPORTED | T；disconnected_members=true；至少两分量和限制说明 |
| D12 | 无接受连接，也无具体可核实假设 | 原 decision/候选检索状态；区分不存在与 NO_RELATION | 无法判断；不能当作已证实无语义关联 | UNRESOLVED | NO_ACCEPTED_CONNECTION | T；source_relation_ids=[]；不补边 |
| D13 | 组内出现作用域/身份/生命周期关键冲突 | 可解析证据证明冲突，须说明它否定的目的条件 | 拒绝整个具体提案；不靠传递闭包忽略冲突 | REJECTED | GROUP_CONTRADICTION | T；逐成员 contradiction；不能只检查相邻 pair |
| D14 | 确认所必需的实体绑定或 Witness Alert 缺失 | 当前已有 refs 及每条 resolution；不得补造 witness | 无法判断，并按剩余可核实证据降级 | UNRESOLVED | MISSING_REQUIRED_EVIDENCE | T；MISSING/INVALID 保留；核心输入损坏应 intake 失败 |
| D15 | 存在 NO_RELATION；只有这条拒绝决策被提出作支持 | 原 reason、invalid/context/supporting refs | 不能把拒绝关系作接受边；无其他假设则无法判断 | UNRESOLVED | REJECTED_RELATION_NOT_SUPPORT | T；拒绝 ID 进 source_decision_ids，不进 source_relation_ids/projection |
| D16 | 存在 NO_RELATION，但另有独立有限活动假设和可核实 E3 | 上下文及具体假设；原拒绝原因未被改写 | 可保存候选；不重判拒绝，不满足 P1 | CANDIDATE | PURPOSE_NOT_PROVEN | T；source_relation_ids 只列真正接受关系；拒绝留 ledger |
| D17 | 一个 Stage 被两个暂确认提案覆盖 | 两份证明与完整 overlap 清单 | 所有冲突提案均降级；不按顺序择一 | UNRESOLVED | PRIMARY_MEMBERSHIP_CONFLICT | T；该 Stage.primary=null；所有候选反向索引齐全 |
| D18 | 多候选共享 Stage，但没有确认组 | 各候选独立依据 | 保留重叠候选，每组仍分别满足候选门槛 | CANDIDATE | PURPOSE_NOT_PROVEN | T；candidate_group_ids 多值；主归属 null |
| D19 | 只有时间接近、文本或标签相似 | 原值可追溯；无具体跨动作活动证明 | 无法判断 | UNRESOLVED | SIMILARITY_ONLY | T；时间仅 E3，标签/文本仅 E4；不创建边 |
| D20 | 不知道是否同一步骤，或多个解释无法排除 | 已有证据、未答问题完整列出 | 明确保留未知 | UNRESOLVED | AMBIGUOUS_PURPOSE | T；不得用较高证据等级或自报置信度升级 |
| D21 | 同 Chain 的所选子集，只能经组外 Stage 连通 | 原接受关系及精确诱导分量 | 有有限假设时为断连候选，否则 D12 | CANDIDATE | DISCONNECTED_INDUCED_SUBGRAPH | T；disconnected_members=true，不能因 chain_id 相同设 false |
| D22 | 多成员部分有 E1，其他成员只有 E3 | 逐成员目的覆盖及未覆盖告警清单 | 不能传递确认；依缺失严重性按 D14 或保存候选 | CANDIDATE | INCOMPLETE_MEMBER_COVERAGE | T；E1 等级可保留但不赋 CONFIRMED；不可拆 Stage 逃避 |
| D23 | P1 目的成立但存在未解决关键问题 | 完整记录问题/可能反证 | 未解决前不确认；缺关键证明按 D14 | UNRESOLVED | AMBIGUOUS_PURPOSE | T；contradictions 不能通过改名为 limitation 绕开 |
| D24 | 输入摘要不符、核心引用损坏或缺数据版本凭据 | 字节摘要、元数据 receipt、原始 ID 索引 | 停止 intake，不生成成功语义 JSON | 无分组状态（run invalid） | INPUT_CONTRACT_INVALID | 单独错误报告；不能输出空组伪装成功 |

`grouping_basis`、ledger 的 reason_code 使用上述冻结原因枚举。自由文本只能解释已有事实，不能创造新确认条件。P1_COMPLETE 只适用于最终 CONFIRMED；REJECTED 必须有 contradiction；CANDIDATE/UNRESOLVED 必须有 unresolved_questions。

四案具体预期与跨 GT 反例见 [评审](attack_step_contract_review.md)。Schema 结构示例见 `attack_step_schema_examples.json`；这些是明确标注的合成测试文档，不能当正式运行结果。

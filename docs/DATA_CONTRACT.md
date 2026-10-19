# TraceBack 数据契约 v1

Frozen v1 Schema（schema_version="1.0"）与 v0 工程契约，依据需求 §8–20、§21–22、§25–26、§35、§39–42及用户确认要求；差异按 AGENTS §3，数值仍为未验证假设。Task 01实现全部字段、枚举、校验及身份语义。

本文件定义字段与身份；算法见 ALGORITHM_CONFIG，最低测试见 CODEX_TASKS。Mapping v1按 ALGORITHM_CONFIG §2.0，拒绝旧 version / priority、裸字符串跨告警指针及 offset/limit。

## 1. 基础类型与校验约定

| 记号 | 冻结含义 |
| --- | --- |
| R | required，输入 / 持久化必须提供，无隐式默认 |
| O | optional，可省略；省略后使用表中默认值 |
| — | 无默认值 |
| string | 非空 UTF-8 字符串；除明确允许外，空串不能代替 null |
| Json | JSON 值，禁止 NaN / Infinity，不能包含运行时对象 |
| ID | 下述带对象前缀的完整 SHA-256 ID |
| UTCDateTime | RFC 3339 字符串，UTC、固定微秒精度：`2026-10-04T02:31:04.000000Z` |
| Score | 有限 number，范围 [0,1]，最多保留 6 位小数 |
| ID[] | 无重复；持久化按字典序排序；不能包含 null |

模型严格校验类型并拒绝未声明字段；厂商扩展仅放 raw_alert。共同字段 `schema_version:string`（O，默认且仅允许非 null 的 `"1.0"`）适用于 CanonicalAlert、Entity、DedupeGroup、CorrelationEdge、Incident、ChainNode、ChainEdge、AttackChain、AIClaim、AIExplanation、AnalysisRecord；这些领域对象嵌入其他对象时仍携带版本。

内嵌 ProcessRef、FieldProvenance、EntityOccurrence、EvidencePointer、SupportPair、AlertRelation、Reason、ScoreBreakdown、ScoreWeights、ScoreContributions、GroundedProposition、AttackMapping、AnalysisMetrics 随所属对象版本，不另带 schema_version（Reason 有 ID 也不例外）。EvaluationSummaryExport 独立使用 §13 白名单。仅标记 `T \| null` 的字段允许 null；数组默认空值不豁免最小长度；引用须在同一 analysis 快照解析。

时间统一 UTC：接受带时区输入；epoch 单位须由 Adapter 配置声明；无时区输入须有显式 source timezone，并保留原值与解析策略。缺失、非法、无策略或 DST 歧义则隔离，不以导入/当前/零点时间补齐。超过微秒向下截断；API/Parquet/DuckDB 往返保持带时区 UTC 微秒，API 固定 `Z`，前端本地显示须标时区。

### 1.1 枚举

| 名称 | v1 枚举值 | 默认 / 说明 |
| --- | --- | --- |
| SourceType | `wazuh, aminer, suricata, waf, edr, ids, siem, windows_security, cloud_security, other` | 无默认，未知产品明确映射 other；不是 sensor ID |
| SourceIndependence | `confirmed_independent, confirmed_same_origin, unknown` | pair 级状态；无确认依据必须为 unknown，不由产品名差异推定独立 |
| Severity | `unknown, informational, low, medium, high, critical` | unknown；有序等级为 0,1,2,3,4,5，仅供比较 |
| EntityType | `IP, HOST, ACCOUNT, SESSION, PROCESS, URL, DOMAIN, FILE, COMMAND` | 无默认 |
| Category | `unknown, reconnaissance, initial_access, web_attack, authentication, process_execution, command_execution, persistence, privilege_escalation, defense_evasion, credential_access, discovery, lateral_movement, command_and_control, collection, exfiltration, impact` | unknown；是告警语义类别，不声称 ATT&CK 技术已确认 |
| IncidentStatus | `new, investigating, resolved, false_positive` | new；false_positive 是人工工作流状态，不能反向训练 / 调整生产评分 |
| EntityRole | `src_ip, dst_ip, host, account, session, process, parent_process, url, domain, file, command` | 无默认；用于保留告警字段角色 |
| AlertRelationType | `target_to_process, parent_child_process, account_host_pivot, network_pivot, session_continuity` | 无默认；描述告警字段可回溯的实体关系，用于 AlertRelation 与 explicit_relation Reason |
| ChainRelationType | `PROCESS_CAUSAL, REQUEST_TO_PROCESS, ACCOUNT_PIVOT, NETWORK_PIVOT, SESSION_FLOW` | v0 Frozen；无默认、非空；与 AlertRelationType 为独立枚举，映射与证据准入见 ALGORITHM_CONFIG §6 |
| ClaimKind | `fact, inference, recommendation, attack_mapping` | 无默认 |
| ClaimSection | `summary, attack_path, risk, recommendations, attack_mapping` | 无默认 |
| GroundingStatus | `pending, validated, rejected` | pending；由 Validator 写入，模型无权自行批准 |
| AnalysisStatus | `queued, running, completed, failed, incomplete` | queued；v1.1 incomplete 包括资源截断 / 执行遗漏；policy_pruned 不包括在内，旧快照保留旧语义 |

category 由版本化源映射读取 `rule_id / alert_type / signature / vendor category`；主类别按 normalization.category_priority 选择，保留全部命中 provenance（ALGORITHM_CONFIG §2.0），未知为 unknown；不用 LLM。枚举存在不表示来源已支持。

### 1.2 severity 统一

原 severity 保留于 raw_alert/provenance，统一为 Severity 字符串，映射放 YAML。Wazuh rule.level：0–2→informational、3–5→low、6–9→medium、10–12→high、13–15→critical；缺失/未识别→unknown，非法越界隔离。AMiner 仅明确同名文本等级可映射，其余 unknown，待真实格式配置；其他来源按自身量纲配置，不直接比较厂商数字。

Incident/ChainNode 取支撑告警最高已知 severity，全 unknown 则 unknown；算法置信分与 AI 风险文本不回写事实等级。

## 2. Stable ID 与不可变身份

ID=`<prefix>_<sha256_hex_64>`；完整 SHA-256 输入为 UTF-8 规范 JSON：递归键排序、无多余空白、不转义 Unicode、保留 null、字符串 NFC；声明的集合去重排序，多重集排序保留重复，普通数组保留原序。非整数身份数值先转为类型标记对象 `{ "$decimal": "0.5" }`（去末尾零，负零归零），覆盖 Reason.params/AIClaim.propositions，不直接序列化二进制浮点。外层固定 `{id_version:"v1", kind:<kind>, identity:<下表输入>}`。禁用随机 UUID、进程 hash、生成时间、行号、绝对路径或算法分值作身份（Reason/Claim 内容身份除外）；同 ID 不同 identity 报错，不能覆盖。

| 模型 / prefix | Stable ID 的 identity 输入 |
| --- | --- |
| CanonicalAlert / alt | source_namespace、origin_namespace（可 null）、source_record_id（可 null）、timestamp、raw_fingerprint |
| Entity / ent | type、scope、normalized value |
| DedupeGroup / dup | 排序后的成员 alert_ids |
| CorrelationEdge / cor | 两端 alert ID 按字典序排序 |
| Incident / inc | 完整排序成员 alert_ids（包含去重组原始成员） |
| ChainNode / nod | incident_id、category、排序支撑 alert_ids |
| ChainEdge / che | incident_id、有方向的 source_node_id、target_node_id、relation_type |
| AttackChain / chn | incident_id、排序 node_ids、排序 edge_ids |
| Reason / rsn | code、排序 alert_ids、排序 entity_ids、按上述数值预处理规范化的 params |
| AIClaim / clm | kind、section、text、排序 node_ids / edge_ids / alert_ids、propositions、attack_mapping |
| AIExplanation / aix | analysis_id、incident_id、chain_id、input_digest、provider、model、prompt_version、排序 claim_ids |
| AnalysisRecord / ana | 排序输入 alert_ids、config_hash、algorithm_version、schema_version |

下表声明的语义集合递归规范成员、去重、排序；持久化与 ID 使用同一结果，不对任意 JSON 数组排序：

| 字段 | 数组语义与规范顺序 |
| --- | --- |
| shared_entity.roles | 集合；按 EntityRole 字符串字典序去重排序 |
| explicit_relation.raw_pointers | EvidencePointer 集合；按 `(alert_id, pointer, side)` 去重并字典序排序 |
| source_complement.source_types | 集合；按 SourceType 字符串字典序去重排序 |
| source_complement.sensor_names | 集合；按规范字符串字典序去重排序 |
| source_complement.raw_pointers | EvidencePointer 集合；按 `(alert_id, pointer, side)` 去重并字典序排序 |
| source_complement.independence_rule_ids | 字符串集合；按规范字符串字典序去重排序 |
| clustering_guard.component_sizes | 无端点顺序的大小多重集；按整数升序排序，保留重复值（两个大小均为 2 的分量必须保留为 [2,2]） |
| AIClaim.propositions | 命题集合；以 `(subject_type, subject_id, field, canonical(value))` 规范键去重并按该键字典序排序后参与 claim_id |

`canonical(value)` 按本节键排序/NFC/十进制类型标记处理；引用集合字段用其规范顺序，普通数组保留原序，不改写事实。AlertRelation.raw_pointers 也是集合。集合重排/重复不改变 reason_id/claim_id；component_sizes 重排稳定，成员数量仍参与身份。

`raw_fingerprint` 为原告警规范 JSON SHA-256（文本为精确保留的原文本 UTF-8 摘要），排除路径/导入批次。raw 数值输出规范十进制数字，不用身份类型标记，拒绝非有限值；序列化策略跨语言固定。键重排不改 ID，内容改变产生新告警 ID。Adapter 先解析 UTC 并计算身份，后续 severity/category/实体处理不改 alert_id；可格式化 JSON，但不能删改原告警字段，不要求保留原始字节。

source_namespace 为部署声明的稳定源实例，sensor 为展示名，不用临时路径替代。origin_namespace+origin_record_id 仅从真实血缘字段抽取。缺 source_record_id 用 raw_fingerprint 等既定输入；完全相同且无记录标识的告警为同一存储记录，另统计重复导入，不以行号造身份。

Stable ID 标识逻辑对象，配置改变可使同 ID 的分数/reasons 改变；存储键为 `(analysis_id,object_id)`，禁止跨分析覆盖。成员改变生成新 Incident/Node/Chain ID，人工 status 另按逻辑 ID 保存。相同算法输入/版本/配置结果确定；LLM 文本进入其 ID，缓存按 input_digest+provider+model+prompt_version。

## 3. CanonicalAlert

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| alert_id | ID(alt) | R | — | 内部稳定告警身份，非 null |
| timestamp | UTCDateTime | R | — | 告警发生时间，非 null，禁止导入时间替代 |
| source_type | SourceType | R | — | 告警产品 / 来源类型，非 null |
| source_namespace | string | R | — | 源实例身份，非 null |
| sensor | string \| null | O | null | 设备 / 检测器名称，缺失可空 |
| source_record_id | string \| null | O | null | 本源原生告警 ID，缺失可空 |
| origin_namespace | string \| null | O | null | 转发前原始告警源身份，与 origin_record_id 同时有值或同时 null |
| origin_record_id | string \| null | O | null | 原始告警记录 ID，不把裸数字跨源比较 |
| rule_id | string \| null | O | null | 原触发规则编号，数值源转文本 |
| alert_type | string \| null | O | null | 厂商告警类型，不强加公共枚举 |
| category | Category | O | unknown | 标准化主类别，非 null |
| signature | string \| null | O | null | 厂商特征 / 规则名称 |
| severity | Severity | O | unknown | 统一等级，非 null |
| src_ip / dst_ip | string \| null（各字段） | O | null | 合法 IPv4 / IPv6，规范文本；缺失可空，非法隔离 |
| src_port / dst_port | integer \| null（各字段） | O | null | [0,65535]，非整数 / 越界隔离 |
| host / account / session | string \| null（各字段） | O | null | Adapter 提取值，范围由 Entity scope 明确 |
| process / parent_process | ProcessRef \| null（各字段） | O | null | 结构化进程引用，无进程数据可空 |
| url / domain / file / command | string \| null（各字段） | O | null | 告警内已有资源 / 对象值；不得推断缺失值 |
| entity_ids | ID(ent)[] | O | [] | 抽取后填充，抽取前允许空 |
| entity_occurrences | EntityOccurrence[] | O | [] | entity_ids 的角色与字段回溯，抽取前允许空 |
| relations | AlertRelation[] | O | [] | 告警字段中可直接支撑的关系，无依据为空 |
| raw_alert | object<string, Json> \| string | R | — | 完整原始安全告警，非空、非 null；不是普通运行日志 |
| raw_fingerprint | string | R | — | 小写 hex SHA-256，非 null，校验与 raw_alert 一致 |
| field_provenance | object<string, FieldProvenance> | R | — | 非空，至少覆盖 timestamp、source_type 及所有已提取非空事实字段 |

衍生 entity_ids 可分阶段填充，正式结果须匹配 occurrences，relations 引用已有实体。厂商可选空串转 null 并留记录，解析错误不当缺失忽略。混入评测标注时整条隔离，不以 raw_alert 保留要求绕过生产真值隔离。

### 3.1 配套结构

| 结构 | 字段定义（同样严格类型） |
| --- | --- |
| ProcessRef | `name, executable, pid, start_time` 均 O 默认 null；name / executable 为 string\|null，pid 为非负 integer\|null，start_time 为 UTCDateTime\|null；至少 name / executable / pid 一项非空；pid 不能单独作为跨告警进程实例身份 |
| FieldProvenance | `raw_pointer:string` R（JSON Pointer；文本原告警可用 `""` 指整个记录）、`transform:string` R（版本化映射 / 解析规则 ID）；不能引用外部原始日志 |
| EntityOccurrence | `entity_id:ID(ent)` R、`role:EntityRole` R、`raw_pointer:string` R；三者非 null；指向该告警真实字段 |
| EvidencePointer | `alert_id:ID(alt)` R、`pointer:string` R（允许 `""` 表示记录根）、`side:enum(src,dst,shared)` R；全部非 null；只按 JSON Pointer 解析指定 alert_id 的 raw_alert，不能引用另一告警或外部日志 |
| SupportPair | `alert_id_src:ID(alt)` R、`alert_id_dst:ID(alt)` R；非 null、不同且分别属于边的两端事实组；是完整评分的原始成员对，不是合成告警 |
| AlertRelation | `relation_type:AlertRelationType` R、`source_entity_id:ID(ent)` R、`target_entity_id:ID(ent)` R、`raw_pointers:EvidencePointer[]` R（非空集合，按 §2 规范化）；均非 null；由结构化字段关系生成，不依赖 LLM |

EvidencePointer 仅解析指定 alert_id 的 raw_alert，拒绝裸字符串；Reason 指针须属于其 alert_ids，关系证据限定 support_pair。src/dst 为关系端点角色；shared 仍绑定单条告警，双方共享字段分别绑定。告警内 FieldProvenance/EntityOccurrence 保持单数 raw_pointer，跨告警聚合须转 EvidencePointer。文本仅根指针可解析，不因此视为有结构化关系字段。

target_to_process 须有请求/操作触发进程实例或明确 lineage，目标与实例同 scope、可解析，EvidencePointer 覆盖连接关键字段。同 host、时间、类别或 request/session 相同不足；缺依据不填 relations/不奖励传播。其他关系各按自身字段门槛，不要求都含 process；见 ALGORITHM_CONFIG §4.3。

## 4. Entity

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| entity_id | ID(ent) | R | — | 按 type + scope + value 生成，非 null |
| type | EntityType | R | — | 九种实体之一，非 null |
| value | string | R | — | 规范化值，非 null |
| scope | string | R | — | 关联身份范围，非 null；无充分作用域时使用源实例限定范围 |
| display_value | string | R | — | 展示值，由同实体最小 alert_id 的原始字段确定，非 null |
| alert_ids | ID(alt)[] | R | — | 出现记录，至少 1 条；分析范围内的引用 |

scope / normalize 的 v1 规则：

- IP：IPv6 压缩、小写；scope 为部署 network_namespace，防止不同网络复用私网 IP；无映射时回退 source_namespace。不同 network_namespace 不强行合并。
- HOST / DOMAIN：小写并移除 DNS 末尾点；HOST 的短名与 FQDN 不自动等同，只有有据可查的 alias 配置才统一；HOST scope 为资产命名空间，DOMAIN 为 `global`。
- ACCOUNT：保留用户名大小写，scope 为 realm / tenant；只有明确的源大小写策略才折叠。缺 realm 用 source_namespace，不假定 `admin` 全球同一人。
- SESSION：scope 为应用 / 主机会话范围，缺范围用 source_namespace；不能跨源凭同一个短会话号认定同一会话。
- PROCESS：有 host + pid + start_time 才标识进程实例，value 为这些值的规范 JSON；否则仅是进程描述实体（executable 优先、name 其次、pid-only 则绑定 alert_id），scope 绑定主机或源。描述匹配不能当作父子实例关系。
- URL：scheme / host 小写，去默认端口与 fragment，保留 path 大小写、query 及编码差异，不删除查询串来合并请求；相对 URL 的 scope 必须为已知目标 host / domain，否则 source_namespace。
- FILE：scope 绑定 host；按已声明操作系统规则处理分隔符 / 大小写，未知系统保留原值，禁止跨主机按路径直接合并。
- COMMAND：保留大小写、引号和参数，不做 shell 语义重写，scope 绑定 host；无 host 用 source_namespace。

EntityOccurrence 必须回溯 raw_alert；通用进程名/文件名相同不构成强实体继承。

## 5. DedupeGroup（补充契约）

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| group_id | ID(dup) | R | — | 成员集合稳定身份 |
| representative_alert_id | ID(alt) | R | — | 成员中最小 alert_id，非 null |
| alert_ids | ID(alt)[] | R | — | 至少 2 条真实记录，不丢证据 |
| duplicate_score | Score | R | — | 多成员组为全部组内 pair 的 min(dup)，单成员逻辑组为 1.0；精确重复 pair 为 1.0；非校准概率 |
| reasons | Reason[] | R | — | 非空，依据源血缘 / payload / 时间等 |

去重是保留全部 CanonicalAlert 的视图，组成员互斥。单成员逻辑组 duplicate_score=1.0，可不持久化（DedupeGroup 模型至少两成员）；多成员取全部 i<j 的 min(dup(ai,aj))，精确重复 pair=1.0，部分字段相同不算精确。候选用代表身份，实体保留全组证据，组间评分按 ALGORITHM_CONFIG §4.0，不跨成员拼接或传递误合并。

Duplicate Candidate Generation 输入 Adapter 基础规范化事实，输出排序唯一原始 alert pair/来源键桶及理由；不生成 CorrelationEdge、不依赖后续 Entity/相关性索引。索引与 complete-link 按 ALGORITHM_CONFIG §2.1/§4.7；证据不足/核验未完成不能当已去重，资源不足须 Analysis incomplete。

## 6. Reason 与 ScoreBreakdown

### 6.1 reasons[] 是结构化 Reason[]，不采用自由字符串作为机器契约

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| reason_id | ID(rsn) | R | — | 内容稳定身份 |
| code | ReasonCode | R | — | 下述枚举，非 null |
| message | string | R | — | 由确定性模板生成的人可读中文描述，非 null |
| alert_ids | ID(alt)[] | R | — | 至少 1 条；边理由必须覆盖参与告警 |
| entity_ids | ID(ent)[] | O | [] | 有实体依据必须引用，无实体时间理由可空 |
| params | object<string, Json> | R | — | 按 code 严格校验的结构，不接受任意未声明键 |

| ReasonCode | params 的必需字段（非 null），除说明外不允许其他字段 |
| --- | --- |
| `time_gap` | `gap_seconds:number>=0, half_life_seconds:number>0` |
| `shared_entity` | `entity_type:EntityType, roles:EntityRole[], rarity:Score, contribution:Score`；roles 非空 |
| `explicit_relation` | `relation_type:AlertRelationType, raw_pointers:EvidencePointer[]`；非空，绑定实际支撑告警 |
| `behavior_transition` | `from_category:Category, to_category:Category, compatibility:Score` |
| `source_complement` | `source_types:SourceType[], sensor_names:string[], rule_id:string, source_independence:SourceIndependence, raw_pointers:EvidencePointer[], independence_rule_ids:string[]`；source_types 非空，sensor_names 可空；后两个依据集合可为空仅当确无确认依据，confirmed 状态至少有一种可核验依据 |
| `conflict` | `rule_id:string, penalty:Score` |
| `duplicate` | `rule_id:string, similarity:Score` |
| `direction` | `rule_id:string, source_node_id:ID(nod), target_node_id:ID(nod), direction_score:Score` |
| `clustering_guard` | `rule_id:string, decision:enum(accept,reject), component_sizes:integer[]`；正整数非空 |
| `node_basis` | `rule_id:string, category:Category, confidence:Score` |

message 必须由 params 支持，rule_id 可追溯配置快照；同 code/引用/params 合并，按 reason_id 排序。拒绝理由只进诊断，不作正式边肯定依据。

source_complement 也记录 S=0 判定；unknown 不称“独立来源”。independence_rule_ids 须引用真实血缘/检测拓扑规则，不以不同 source_type 证明独立。每个指针仅解析绑定告警，不在其他支撑告警搜索同名字段。已确认同 origin 优先，冲突记诊断且不给奖励。

### 6.2 ScoreBreakdown

正式 CorrelationEdge/ChainEdge 均携带完整 ScoreBreakdown；无依据项填 0 并留理由/无匹配诊断。

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| time_score | Score | R | — | 时间衰减原值 |
| entity_score | Score | R | — | 共享实体原值 |
| relation_score | Score | R | — | 显式实体传播原值 |
| behavior_score | Score | R | — | 行为兼容原值 |
| source_score | Score | R | — | 独立来源互补原值 |
| source_independence | SourceIndependence | R | — | 该支撑告警 pair 的来源血缘判定，与 source_complement 理由一致；ChainEdge 原样继承所选关联边的状态 |
| conflict_penalty | Score | R | — | 冲突强度原值 |
| duplicate_penalty | Score | R | — | 疑似重复原值 |
| weights | ScoreWeights | R | — | 与配置快照一致的实际权重 |
| contributions | ScoreContributions | R | — | 正项为 weight×value，惩罚项为 -weight×value |
| raw_total | number | R | — | 有限加权和，允许负值 |
| final_score | Score | R | — | clamp(raw_total,0,1) 后的总分 |
| config_hash | string | R | — | 配置快照 SHA-256 |
| selected_correlation_edge_id | ID(cor) \| null | O | null | ChainEdge 采用的支撑关联边；CorrelationEdge 本身为 null |

ScoreWeights 的 `time,entity,relation,behavior,source,conflict,duplicate` 均 R、number≥0、非 null、无默认；五项正权重和=1，两项惩罚权重各≤1。ScoreContributions 同名七项均 R、有限 number、非 null、无默认；前五≥0，后两≤0。内部计算/阈值比较用未舍入值，输出6位小数，重算误差≤0.00001；方向分另存，不改关联分。

source_independence 为 pair 派生状态，不加单告警标签；confirmed_same_origin/unknown 的 source_score=0，confirmed_independent 仍须上下文及不同侧面，同 sensor=0；不同产品类别不自动独立（ALGORITHM_CONFIG §4.5）。

## 7. CorrelationEdge（无向关联）

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| edge_id | ID(cor) | R | — | 无向端点排序产生 ID |
| source_alert_id | ID(alt) | R | — | 字典序较小端点，非因果方向 |
| target_alert_id | ID(alt) | R | — | 字典序较大端点，不能等于 source |
| score | Score | R | — | 必须等于 score_breakdown.final_score |
| reasons | Reason[] | R | — | 非空；至少时间理由和实际非时间关联依据 |
| entity_ids | ID(ent)[] | O | [] | 实体支撑，可为空但需有其他非时间显式依据 |
| score_breakdown | ScoreBreakdown | R | — | 七项完整，非 null |
| support_pair | SupportPair | R | — | 产生最高有效完整分的实际原始告警成员对 |

仅保存达阈值且通过 hard guard 的正式边。代表 ID 字典序固定 G1/G2，G1×G2 全成员独立计算七项分/guard，取有效最高未舍入分；并列按 `(src.timestamp,dst.timestamp,src.alert_id,dst.alert_id)` 升序确定唯一 support_pair。全部肯定理由与分解来自该 pair；其他成员仅进诊断。端点仍为代表，support_key 每代表 pair 只计一条，src/dst 无因果含义；event_time 即 timestamp，不增事件模型。完整算法见 ALGORITHM_CONFIG §4.0。

## 8. Incident

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| incident_id | ID(inc) | R | — | 完整成员集合身份 |
| start_time / end_time | UTCDateTime（各字段） | R | — | 成员最早 / 最晚时间，start≤end |
| severity | Severity | R | — | 成员最大已知等级，非 null |
| alert_ids | ID(alt)[] | R | — | 至少 1 条；包括去重组全部原始成员 |
| entity_ids | ID(ent)[] | O | [] | 成员实体并集 |
| correlation_edge_ids | ID(cor)[] | O | [] | 该快照中两端均在本 Incident 的正式关联边；单点允许空 |
| status | IncidentStatus | O | new | 人工工作流状态，非 null |
| summary | string \| null | O | null | v1 为确定性摘要；AI 摘要通过 AIExplanation 引用呈现 |

同一 analysis 每条原告警恰属一个 Incident（含单点），去重组不拆。无方向依据允许无链边；status/summary 不作关联、聚类或评分输入。

配置阈值控制展示 `0.65 <= score < 0.70`、聚类 `score >= 0.70`。聚类支撑数/目标保护按 ALGORITHM_CONFIG §5：两单点可一边起步，单点加入非单点与两个非单点默认两条，仅字段证明的传播可单桥；计代表数，不计重复成员。

## 9. ChainNode

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| node_id | ID(nod) | R | — | incident + category + 支撑成员身份 |
| incident_id | ID(inc) | R | — | 所属事件，非 null |
| alert_ids | ID(alt)[] | R | — | 至少 1 条，全部在 Incident 内 |
| start_time / end_time | UTCDateTime（各字段） | R | — | time_range，取支撑告警极值，start≤end |
| category | Category | R | — | 告警映射出的步骤主类别，非 null |
| severity | Severity | R | — | 支撑告警最大已知等级 |
| entity_ids | ID(ent)[] | O | [] | 支撑实体并集 |
| confidence | Score | R | — | 确定性步骤置信分，不是攻击真实概率 |
| reasons | Reason[] | R | — | 非空 node_basis，解释合并 / 单告警构造与置信分 |

统一 start_time/end_time，不另存 timestamp/time_range；单告警两者相等。v0 每去重组/单告警一节点；额外同义合并仅允许明确同请求/会话/进程实例。类别冲突选配置最高优先级，同级最小 alert_id，并留原类别及冲突理由；unknown 不推断新行为，全部成员均有节点引用。

## 10. ChainEdge（有向步骤关系）

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| edge_id | ID(che) | R | — | 包含有序端点与 relation_type 的身份 |
| incident_id | ID(inc) | R | — | 所属事件，非 null |
| source_node_id / target_node_id | ID(nod)（各字段） | R | — | 有方向端点；必须不同且同 Incident |
| relation_type | ChainRelationType | R | — | 确定性重构的步骤关系，非 null；v0 五值与映射 Frozen，不借用 AlertRelationType |
| confidence | Score | R | — | min(支撑关联分, direction_score)，非校准概率 |
| direction_score | Score | R | — | 确定性方向置信分，非 null |
| alert_ids | ID(alt)[] | R | — | 至少 2 条，覆盖两端节点的实际支撑告警 |
| entity_ids | ID(ent)[] | O | [] | 方向关系涉及实体；显式关系引用的实体必须存在 |
| correlation_edge_ids | ID(cor)[] | R | — | 非空；跨端点的关联依据 |
| reasons | Reason[] | R | — | 非空且含 direction、非时间关系理由 |
| score_breakdown | ScoreBreakdown | R | — | 拷贝最强支撑 CorrelationEdge 的分解，selected ID 必填非 null |

最强支撑边按 score 最大、edge_id 最小选择，分解原样引用、不累加，完整 correlation_edge_ids 保留。方向准入/DAG 按 ALGORITHM_CONFIG §6；不能仅时间排序补边。未决关联保留 Incident/CorrelationEdge及诊断，允许孤立/分支，去环保存拒绝边与原因。

AlertRelationType 与 ChainRelationType 独立；五值映射、优先级及字段门槛 Frozen，统一按 ALGORITHM_CONFIG §4.3/§6。无合法显式关系不生成 ChainEdge，不降级为 behavior_transition/entity_propagation/source_complement/mixed_evidence；扩展须显式版本变更。

require_explicit_propagation=true 不可绕过：字段语义及最低关系分同时成立，任意指针或高时间/行为/来源分不能替代。方向证据仅来自选定 CorrelationEdge.support_pair，不能借其他成员；仍须通过所有阈值、margin、节点区间 chronology/skew、hard guard、时间与 DAG 检查。

## 11. AttackChain

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| chain_id | ID(chn) | R | — | 节点 / 边集合身份 |
| incident_id | ID(inc) | R | — | 一个 Incident 一份当前链快照 |
| nodes | ChainNode[] | R | — | 至少 1 个，按 node_id 排序 |
| edges | ChainEdge[] | O | [] | 按 edge_id 排序，允许无边 |
| status | enum(`complete, partial`) | R | — | partial 表示方向未决 / 拒边；complete 仅表示重构流程完整，不表示真实攻击完整恢复 |
| unresolved_correlation_edge_ids | ID(cor)[] | O | [] | 不能转为方向边的关联，允许空 |

节点/边 ID 唯一且引用闭合，同属 Incident，边端点在 nodes 内；允许孤立，不为连通补事实。

## 12. AIClaim / AIExplanation

### 12.1 AIClaim

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| claim_id | ID(clm) | R | — | 内容与引用稳定身份 |
| kind | ClaimKind | R | — | fact / inference / recommendation / attack_mapping |
| section | ClaimSection | R | — | 报告所属部分 |
| text | string | R | — | 单个陈述；不能藏有未引用的额外事实 |
| node_ids | ID(nod)[] | O | [] | 所属链的节点依据 |
| edge_ids | ID(che)[] | O | [] | 所属链的方向边依据；cor 边通过 che 回溯 |
| alert_ids | ID(alt)[] | O | [] | 必须在所属 Incident 内 |
| propositions | GroundedProposition[] | O | [] | fact 必须非空，包含陈述对应的字段 / 算法结论 |
| attack_mapping | AttackMapping \| null | O | null | 仅 attack_mapping kind 允许非空，其余必须 null |
| grounding_status | GroundingStatus | O | pending | Validator 写入，禁止采用 LLM 自报 validated |
| validation_errors | string[] | O | [] | 模板化错误码，rejected 必须非空 |

GroundedProposition 字段均 R、无默认：`subject_type:enum(alert,node,chain_edge,correlation_edge)`、`subject_id:ID`、`field:string`、`value:Json`；前三非 null。field 限 §12.2 模型投影，value 精确等于快照值（仅原值 null 才可 null），禁任意 JSONPath/外部文件/标签。alert 命题需 alert_ids；node 需 node_ids及支撑 alert_ids；边需 edge_ids、两端 node_ids及支撑 alert_ids；correlation_edge 经引用 ChainEdge.correlation_edge_ids 闭包解析。

AttackMapping：`technique_id:string` R（T+四位数字，可附三位子技术）、`technique_name:string` R、`tactic:string\|null` O 默认 null、`catalog_version:string` R、`rationale:string` R；仅 tactic 可 null。node_ids/alert_ids 非空，引用已有节点并经本地版本化 ATT&CK catalog 校验；语义映射不改 category、不增节点/边。

fact 的 alert_ids 非空，涉及节点/边须满足对应闭包；inference 引用已有依据且标“可能/疑似”，不能换 kind 绕过事实检查；recommendation 可无引用，但仅建议未执行的动作。所有 kind 均检查事实边界。

ID 存在不证明陈述正确。正式 fact 由已校验 propositions 经受控模板渲染；AI 待审文本不一致则拒绝或替换模板、重算 claim_id。自由风险/建议分区，新增行为断言拒绝。0% 无依据事实依靠受控发布，不宣称通用自然语言蕴涵判断已完美解决。

### 12.2 AI 输入白名单与正式结论（v0 Frozen）

AI 白名单：已确认告警 ID/时间/source/category/severity、已抽取 Entity、Incident/ChainNode、已接受 CorrelationEdge/ChainEdge 的类型/分数、ATT&CK 候选、确定性 Reason及绑定 EvidencePointer。event ID仅 alert_id，不建 CanonicalEvent；指针不授权解引用传送全文。

禁止事实输入包含原始日志/完整 raw_alert、未抽取 payload、拒绝候选/诊断证据或 AI 新实体；原告警仍完整供 Evidence UI。仅通过 Grounding 的已接受结构化事实进入投影；ATT&CK 候选标候选，不当观测事实。

命题语义为事实描述、关系解释、ATT&CK/风险解释，沿用 ClaimKind/Section。fact 精确核对白名单值，关系仅解释已有正式方向；inference 标推测，v0 正式结论禁止未观测身份、地理、意图、步骤推断。recommendation 仅纯处置建议，不称已执行或增加事实。

input_digest=SHA-256(canonical_json(白名单事实+evidence refs+grounding/template version))，复用 §2；facts 按稳定 ID，refs 按 EvidencePointer 键规范化。投影/实际 Grounding及模板版本在调用前固定，不含模型文本；provider/model/prompt_version 独立参与缓存和解释身份。

### 12.3 AIExplanation

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| explanation_id | ID(aix) | R | — | 内容与分析快照身份 |
| analysis_id | ID(ana) | R | — | 对应固定算法结果 |
| incident_id | ID(inc) | R | — | 对应 Incident |
| chain_id | ID(chn) | R | — | 对应链快照 |
| input_digest | string | R | — | SHA-256(canonical_json(白名单事实 + evidence refs + grounding/template version)) |
| provider / model / prompt_version | string（各字段） | R | — | 可复核供应商、模型与 Prompt 版本 |
| claims | AIClaim[] | R | — | 至少 1 条，全部通过验证后才可发布 |
| grounding_status | GroundingStatus | O | pending | 所有 claim validated 才能 validated |

claims 按 section 固定顺序 summary→attack_path→attack_mapping→risk→recommendations及 claim_id 持久化，渲染摘要/路径/映射/风险/建议/报告，不按 LLM 返回顺序定身份。Markdown/JSON 除模板导航外全部来自 validated claims，禁自由 report_text 绕过校验；pending/rejected 草稿不作正式结论。AI 失败不改变算法成功状态。

## 13. 分析快照、存储与 API 补充契约

AnalysisRecord 字段：

| 字段 | 类型 | R/O | 默认 | 含义与可为空规则 |
| --- | --- | --- | --- | --- |
| analysis_id | ID(ana) | R | — | 输入 + 配置 + 版本的稳定快照身份 |
| input_alert_ids | ID(alt)[] | R | — | 非空输入告警集合 |
| config_hash | string | R | — | 有效配置规范 JSON SHA-256 |
| config_snapshot | object<string, Json> | R | — | 完整解析后配置，不包含密钥 / 真值 |
| algorithm_version | string | R | — | 明确实现版本，不采用运行时间 |
| dataset_digest | string | R | — | 输入告警集合与 raw_fingerprint 的规范摘要，不含路径或运行时间 |
| config_digest | string | R | — | 与既有 config_hash 相同的有效配置 SHA-256；二者必须一致 |
| mapping_digest | string | R | — | 实际使用的版本化映射内容摘要，不以文件路径代替内容 |
| diagnostics_ref | string | R | — | `outputs/analyses/{analysis_id}/diagnostics.jsonl` |
| frequency_snapshot_ref | string | R | — | `outputs/analyses/{analysis_id}/frequency_snapshot.json` |
| is_complete | boolean | R | — | 仅 status=completed 且无资源截断、遗漏、资源中止时 true；v1.1 局部 policy_pruned 允许 |
| incomplete_reason | string \| null | R | — | failed / incomplete 必须非空；未结束与 completed 为 null |
| status | AnalysisStatus | O | queued | 算法状态 |
| candidate_truncated | boolean | O | false | v1.1 已准入候选的执行资源截断则 true，不能标 completed；局部 policy_pruned 不置 true；旧快照语义不变 |
| errors | string[] | O | [] | 结构化错误码；failed / incomplete 非空 |
| metrics | AnalysisMetrics | R | — | 有限非负值；运行前可为零，不代表实验结果 |

AnalysisMetrics 所有字段 R、无默认、非 null：`alert_count, representative_count, candidate_pair_count, candidate_dropped_count` 为非负 integer；`correlation_runtime_seconds, clustering_runtime_seconds, chain_runtime_seconds, total_runtime_seconds, peak_memory_mb` 为非负 number。运行时间 / 内存不参与身份或算法结果相等比较。v1.1 candidate_pair_count 为实际完成评分的已准入候选数，candidate_dropped_count 为全局资源预算未调度的已准入 pair 数，不包括局部策略提议损失；旧快照不重解释。

DuckDB/Parquet 按 analysis_id 分区；嵌套数据用规范 JSON或关联表，API 还原契约类型。原告警完整供证据 UI，不另查运行日志。

固定诊断目录 `outputs/analyses/{analysis_id}/` 包含 diagnostics.jsonl、frequency_snapshot.json、manifest.json；领域结果仍在 data/processed，evaluation 独立导出。AnalysisRecord 只存摘要/引用，引用限本 analysis 目录。

diagnostics.jsonl 保存候选产生/拒绝、全成员 pair 分解、support_pair/support_key、target key/provenance、传播 Reason、接受/拒绝、裁剪/incomplete 原因；用未舍入分，不作正式事实。frequency_snapshot.json 保存固定 N/df(e)/scope/实体身份；manifest.json 保存 analysis_id、输入/配置/映射摘要、算法/Schema 版本、配置快照、文件引用、完成状态/原因。按稳定阶段/对象/pair 顺序记录，运行时间不作身份或结果相等依据。

dataset_digest=SHA-256(按 alert_id 排序的输入 `(alert_id,raw_fingerprint)` 集合规范 JSON)；config_digest=config_hash 摘要完整有效配置，mapping_digest 摘要实际 schema_version/mapping_type/source_type/default/rules（rules 按唯一 id），排除绝对路径。快照含实际映射内容，改变映射须改变 config_hash/analysis_id，不覆盖旧结果；均为小写完整 SHA-256。queued/running 引用固定位置，不称文件齐全；failed/incomplete 同步 status、is_complete=false、incomplete_reason、errors；candidate_truncated=true 必须 incomplete。

Task 05.2 快照摘要 / Analysis Detail / manifest 新增 candidate_contract_version=v1.1；algorithm_version 明确更新但领域 schema_version 仍1.0。AnalysisRecord 字段不扩充，版本及诊断计数保存在既有 run/manifest.summary 与诊断引用中，manifest 顶层也记录版本。新增 potential_pair_stats（raw_potential_discoveries/unique_potential_pairs/duplicate_potential_discoveries）、candidate_admission_stats（代表处理数/admitted/scheduled/scored/policy/resource）、policy_pruned_count/resource_truncated_count/admitted_candidate_count/scored_candidate_count；精确定义见 ALGORITHM_CONFIG §3。详细策略/排名/hot/关系 provenance 仍在 diagnostics，不作为正式事实。所有已准入 Candidate 必须完整评分，全部后续算法完成且无原有不完整原因才 completed；异常时未知的未处理 pair 数不填虚假精确值，另记 resource_truncation_events。

API 最低冻结路由为需求 §22 的全部接口：`POST /api/v1/analyses`、`GET /api/v1/analyses/{analysis_id}`、`GET /api/v1/alerts`、`GET /api/v1/alerts/{alert_id}`、`GET /api/v1/incidents`、`GET /api/v1/incidents/{incident_id}`、`GET /api/v1/incidents/{incident_id}/chain`、`GET /api/v1/incidents/{incident_id}/timeline`、`GET /api/v1/edges/{edge_id}`、`POST /api/v1/incidents/{incident_id}/explain`、`GET /api/v1/evaluation/runs/{run_id}`。边详情 route 返回 ChainEdge，并带所引用 CorrelationEdge；不返回虚构方向。

查询显式 analysis_id（分析详情除外），不隐取最新。分页 page=1/page_size=20，page 正整数、size 1–100；响应 `{items:T[],page:integer,page_size:integer,total:integer}`，拒绝 offset/limit。Analysis/Incident 按最新事件 DESC、稳定 ID ASC（分别输入最大 timestamp/end_time）；Timeline 按 event_time ASC、ID ASC（告警 timestamp/节点 start_time），排序不表示因果。

创建仅输入数据引用+配置版本引用，禁止提交派生对象/评分；安全告警路径 allowlist、固定版本解析及 GT 拒绝后返回 HTTP 202 `{analysis_id,status}`。时间筛选为带时区 ISO-8601→UTC `[start_time,end_time)`；非法/未知过滤、分页、时间区间400，其他请求体/Schema错误422，引用缺失404，分析未就绪/解释缺 Grounding409。Timeline 仅已有 alert/node 引用、UTC时间、source_type/sensor 泳道。

EvaluationSummaryExport 仅由 evaluation 写入 `data/processed/evaluation_exports/<run_id>.json`，生产 API 只读严格字段白名单：`run_id:string, config_hash:string, algorithm_version:string, split:string, metrics:object<string,number|null>, metric_status:object<string,enum(available,not_applicable,unavailable)>, evaluation_coverage:number, counts:object<string,integer>, runtime:object<string,number>, limitations:string[]`（全部 R、非 null，缺真值或空分母的 metric 为 null 并说明原因；空分母状态为 not_applicable，缺真值为 unavailable；evaluation_coverage 范围 [0,1]）。不含 Label、IP / Host 真值、攻击时间、描述、Gold Chain、样本级答案或真值路径；backend 不导入 evaluation、不查询真值。run_id 由 evaluation 按配置 / 划分 manifest / 方法版本 hash 生成并安全校验，不能用用户输入拼接任意路径。

### 13.1 Evaluation 边界（v0 Frozen）

Incident Jaccard、节点 alert overlap+category 核心匹配条件及阈值沿用 Task 08（原028）。合法 Pred↔GT 候选做一对一最大总权重匹配；并列将 `(pred_id,gt_id)` 列表排序，以字典序最小列表确定，不依赖库遍历顺序。

Incident：匹配数TP、未匹配预测FP、未匹配GTFN；节点限已匹配 Incident，同法计数。RQ1仍计告警pair，遗漏候选正例算FN；RQ3边/方向/stage条件不改。Precision=TP/(TP+FP)、Recall=TP/(TP+FN)、F1=2TP/(2TP+FP+FN)；各自分母零返回 null+not_applicable，不填0/1。未标注样本排除分母，报 evaluation_coverage及标注/全输入范围；缺GT为unavailable，不伪造Gold。

## 14. 冻结差异与外部输入状态

| 需求表述差异 | 冻结执行解释 |
| --- | --- |
| 旧文件名 / 粘贴章节编号 | 使用 AGENTS §1 的三份实际原文；仓库 §21 是界面、§22 是 API、§19.1 是 AI Grounding，不改原文编号 |
| §6 / §42 简图、§39 抽取后去重 | 保留 AGENTS §2 完整流程；Adapter 基础规范化→去重候选→去重→完整实体层→相关性候选 |
| §19.1 三类引用、schema_version 范围、关系类型、集合身份 | 分别按本文件 §12、§1、§1.1 / §10、§2；独立枚举不授权增加关系或放宽准入 |
| §35 reasons / score_breakdown | 各算法固定输入 / 输出并完整输出各自已有契约字段，不向只定义 reasons 的对象补 breakdown |
| source_type / namespace / sensor | SourceType 是产品枚举，namespace 标识源实例，sensor 是设备展示名；转发血缘独立保存 |
| 时间 / severity / 枚举 / 理由 / 分解 | 本文件为工程细化，不称作需求原文已规定；confidence 为算法分，非校准攻击概率 |

本节差异均按已确认冻结解释执行，不是算法设计阻塞；具体门槛见 ALGORITHM_CONFIG，事实发布见 §12。

真实两源样本、namespace/timezone、资产映射、AI provider/model、ATT&CK catalog、split 为 External/Input Pending，不阻塞骨架；真实支持仍须材料与验收，不猜测或用 synthetic 冒充。新增枚举、identity或能力须显式版本变更。

## 15. 用户授权 Correlation v2 兼容扩展（2026-10-09）

领域 schema_version 仍为 1.0，算法/内嵌审计显式 v2；CanonicalAlert、EvidencePointer、Stable ID、冻结关系、API 路由、AI 白名单及 ATT&CK 不变。旧输入不要求新字段；缺省扩展在旧对象序列化时省略，保持历史字节/摘要语义。新增模型严格拒绝未声明键。

ScoreBreakdown 可选 `evidence_v2: EvidenceV2|null`，缺省 null 且序列化省略。v0 七项 contribution 仍严格核验 weight×raw；无 evidence_v2 时总分规则沿用 §6.2。有扩展时，raw_total 改按 ALGORITHM_CONFIG §8 的 quality/mass/原惩罚计算；不能以旧 signed sum 冒充新总分。EvidenceV2 必需字段：version=v2、quality_factor/mass_factor、五项 family_weights/family_strengths、排序唯一 dimensions、available_weight/matched_weight/total_configured_weight、normalized_quality/evidence_mass、available/matched/mismatched/unavailable/not_applicable_evidence、strong_evidence_count/supporting_evidence_count、evidence_gate_passed/gate_reason、threshold/threshold_passed/decision。状态和 ACCEPT/REJECT_LOW_SCORE/REJECT_INSUFFICIENT_EVIDENCE/REJECT_GUARD/REJECT_NO_RELATION 为本扩展枚举。每维度含 dimension/family/state/weight/strength/entity_ids；实体 ID 仍须已有；语义索引 key 不作实体引用。严格重算家族、权重、quality/mass、分区和最终分；正式 CorrelationEdge 必须 gate/threshold/decision 均接受。REJECT_NO_RELATION 是链转换诊断，不阻止合法无向关联。

Incident 可选 `single_alert_triage: SingleAlertTriage|null`，仅 alert_ids 恰好一个且与 triage.alert_id 一致时非空，缺省 null 并省略序列化。身份仍由成员集合确定。必需字段：version=v2、alert_id/description、single_alert_risk_score/risk_level/recommended_priority、available_weight/matched_weight/rarity_only_cap、risk_reasons/evidence_refs/unavailable_evidence、candidate_count/gate_passed_count/formal_edge_count/rejection_counts、correlation_diagnostic/search_complete。RiskReason 含 severity/category/rarity 的 field、value、strength、weight、contribution、message 和绑定 EvidencePointer 的 evidence_refs；指针只属当前告警并可解析；风险与查看优先级不修改原 severity，不等于攻击已确认。检索诊断只说明已准入候选；不完整或局部策略裁剪不能表述为全数据不存在关系。

AnalysisRecord 不扩字段；详细 v2 score 统计/Top20 保存本 analysis 的 `correlation_v2_scores.json`，既有 run/manifest summary 保存摘要、同 analysis 引用与 SHA-256；成员完整评分仍在 diagnostics.jsonl。Analysis Detail 兼容承接既有 dataset_metadata（修复原已写入却未声明的 transport 字段）与可选 correlation_v2 摘要。来源元数据不作关联证据，正式 AI 输入不包含拒绝候选/triage 新事实字段。

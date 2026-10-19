# TraceBack 算法配置：v0 baseline

依据需求 §11–17、§27–35及用户冻结要求。v0 数值/矩阵/预算/置信策略未经验证；仅在开发划分记录版本与实验，不用测试答案调参。字段准入、来源独立性、检索顺序及阈值边界不可用参数绕过；架构按 AGENTS。

## 1. 配置载入与可复现

Frozen：AlertRelationType 用于 relation.scores，ChainRelationType 五值/映射/优先级/准入见 §6，支撑边/Target Set见 §5.1/§5.2；require_explicit_propagation=true 不可绕过。字段/AI/API/评测见 DATA_CONTRACT，验收见 CODEX_TASKS。

Task 01加载器严格校验 YAML：缺项、未知 key、非法枚举/窗口/权重 fail fast；业务无另设默认值。覆盖顺序 baseline→显式部署→显式实验；禁未记录环境变量改变算法，LLM密钥不入快照。

完整有效配置含实际映射，按 DATA_CONTRACT 规范 JSON 计算 config_hash=config_digest，保存输入/映射摘要及算法版本；快照与固定 outputs/analyses/{analysis_id}/三类文件按 DATA_CONTRACT §13。算法不用 LLM，排序稳定。最低阈值 `>=`、展示上界 `<`、候选窗口 `<=`，均用未舍入值。

## 2. 第一版配置清单

以下 YAML 为 v0 初值；表项须完整录入，空列表不提供隐式映射。

```yaml
version: v0
normalization:
  timestamp_precision: microseconds
  missing_timestamp: quarantine
  missing_timezone: require_source_timezone
  unknown_category: unknown
  unknown_severity: unknown
  source_timezones: {}
  host_aliases: {}
  category_mapping_files: []
  category_priority: [web_attack, command_execution, process_execution, privilege_escalation,
    lateral_movement, credential_access, persistence, defense_evasion, command_and_control,
    exfiltration, impact, initial_access, reconnaissance, authentication, discovery, collection, unknown]
  severity_mapping_files: []
candidate:
  time_only_window_seconds: 60
  default_window_seconds: 1800
  max_window_seconds: 7200
  source_complement_window_seconds: 300
  explicit_relation_window_seconds: 7200
  behavior_override_channels: [IP, HOST, ACCOUNT, SESSION, PROCESS, URL, DOMAIN, FILE, COMMAND, explicit_relation]
  behavior_window_overrides:
    - {from_category: web_attack, to_category: process_execution, window_seconds: 300}
    - {from_category: web_attack, to_category: command_execution, window_seconds: 300}
    - {from_category: initial_access, to_category: lateral_movement, window_seconds: 7200}
    - {from_category: authentication, to_category: lateral_movement, window_seconds: 3600}
  per_channel_neighbors: 50
  time_only_neighbors: 20
  max_neighbors_per_alert: 200
  max_candidate_pairs: 2000000
  overflow_policy: mark_incomplete
  hot_entity_ratio: 0.10
  hot_entity_min_count: 100
  hot_entity_neighbors: 10
  entity_windows_seconds:
    IP: 600
    HOST: 1800
    ACCOUNT: 3600
    SESSION: 3600
    PROCESS: 600
    URL: 600
    DOMAIN: 600
    FILE: 1800
    COMMAND: 600
time:
  method: exponential_half_life
  default_half_life_seconds: 300
  clock_skew_seconds: 2
  transition_half_lives: []
entity:
  weights: {IP: 0.25, HOST: 0.55, ACCOUNT: 0.70, SESSION: 0.90,
    PROCESS: 0.80, URL: 0.85, DOMAIN: 0.35, FILE: 0.90, COMMAND: 0.90}
  role_factors: {same_role: 1.0, src_dst_bridge: 0.8, other_role: 0.5}
  process_descriptor_factor: 0.25
  rarity_enabled: true
  rarity_floor: 0.10
  rarity_smoothing: 1
  rarity_scope: analysis_representatives
  frequency_unit: dedupe_group
  max_contributors_per_type: 3
relation:
  scores: {target_to_process: 0.9, parent_child_process: 1.0,
    account_host_pivot: 0.8, network_pivot: 0.8, session_continuity: 0.9}
behavior:
  same_category: 0.4
  unknown_category: 0.0
  unlisted_transition: 0.1
  transitions: []
source:
  same_sensor_score: 0.0
  same_type_independent_score: 0.2
  different_type_confirmed_independent_unlisted_score: 0.3
  unknown_independence_score: 0.0
  independence_mapping_files: []
  require_context_bridge: true
  forwarded_same_origin_score: 0.0
  complement_rules: []
score:
  weights: {time: 0.20, entity: 0.30, relation: 0.20, behavior: 0.20,
    source: 0.10, conflict: 0.45, duplicate: 0.40}
  correlation_threshold: 0.65
  require_non_time_support: true
duplicate:
  candidate_indexes: [source_record, origin_record, payload_target_rule_time]
  window_seconds: 30
  half_life_seconds: 10
  threshold: 0.93
  suspected_floor: 0.50
  feature_weights: {rule: 0.25, payload: 0.35, target: 0.30, time: 0.10}
  require_payload_and_target: true
  grouping: complete_link
  representative: minimum_alert_id
  payload_mapping_files: []
  rule_equivalence_mapping_files: []
conflict:
  combine: maximum
  hard_rules: [cross_namespace_without_bridge, verified_incompatible_session]
  strengths: {different_target_without_bridge: 0.8, no_context_bridge: 0.5,
    beyond_behavior_window: 0.6, reversed_explicit_relation: 1.0, incompatible_session: 1.0}
clustering:
  method: controlled_components
  edge_threshold: 0.70
  max_incident_span_seconds: 7200
  max_representatives: 500
  bridge_min_edges_between_non_singletons: 2
  bridge_min_edges_with_singleton: 2
  bridge_min_edges_between_singletons: 1
  permit_explicit_relation_single_bridge: true
  reject_component_hard_conflict: true
  keep_singletons: true
chain:
  edge_threshold: 0.70
  direction_threshold: 0.75
  direction_margin: 0.15
  require_explicit_propagation: true
  direction_weights: {chronology: 0.40, relation: 0.35, behavior: 0.20, source: 0.05}
  explicit_relation_minimum: 0.8
  relation_type_mapping:
    parent_child_process: PROCESS_CAUSAL
    target_to_process: REQUEST_TO_PROCESS
    account_host_pivot: ACCOUNT_PIVOT
    network_pivot: NETWORK_PIVOT
    session_continuity: SESSION_FLOW
  relation_priority: [parent_child_process, target_to_process, account_host_pivot, network_pivot, session_continuity]
  merge_synonymous_actions: false
  node_confidence_base: 0.50
  node_confidence_category_bonus: 0.15
  node_confidence_context_bonus: 0.10
  node_confidence_independent_source_bonus: 0.10
  node_confidence_cap: 0.85
  graph_policy: dag
  cycle_policy: descending_confidence_then_edge_id
evaluation:
  baseline_window_seconds: 300
  thresholds: [0.55, 0.60, 0.65, 0.70, 0.75, 0.80]
  window_multipliers: [0.5, 1.0, 2.0]
  weight_multipliers: [0.5, 1.0, 1.5]
  noise_ratios: [0.0, 0.25, 0.5, 1.0]
  seed: 42
```

实施时按下表和真实告警字段补全 transition_half_lives/transitions/complement_rules及 severity/category/payload映射。timezone/namespace/alias 仅明确部署声明；severity按 DATA_CONTRACT §1.2，AMiner量纲未确认用unknown。

independence_mapping_files 仅真实血缘/有据部署拓扑规则，未声明为unknown；零奖励与字段门槛不可覆盖。behavior_window_overrides 与半衰期表独立，后者不自动注册候选窗口；窗口≤max_window，覆盖不含time-only/source-complement。

### 2.0 Mapping File Contract v1（Frozen）

Mapping v1：公共 source_type、文件内唯一 rule ID，仅类别使用 category_priority；拒绝旧文件 version/rule priority/全局唯一ID协议。算法参数与领域 Schema不变。

实际映射进入快照/hash；算法 version:v0 和 ATT&CK catalog_version不受映射头替换影响。

#### 2.0.1 文件与规则结构

仅五类 YAML映射：category/severity/payload/source_independence/rule_equivalence；公共结构（尖括号为占位符）：

```yaml
schema_version: "1.0"
mapping_type: <mapping type>
source_type: <SourceType>
default: <type-specific default>
rules:
  - id: <unique non-empty string>
    match:
      all:
        - field: <allowed field>
          op: <allowed operator>
          # 参数仅使用 §2.0.2 对该 op 规定的 key
    output: <type-specific output>
```

文件仅允许且必需 schema_version/mapping_type/source_type/default/rules；schema_version 为字符串"1.0"，source_type按 DATA_CONTRACT枚举。rules 为列表，每项仅且必需 id/match/output，id 非空且文件内唯一；match仅且必需 all（条件AND列表），条件必需field/op及规定参数，拒绝extra key。

rules为集合语义，物理顺序不影响执行/快照/digest；不得首条获胜。provenance保留全部命中ID及所属文件，跨文件同ID不当同一规则。

#### 2.0.2 match 操作符与参数形状

| op | 必需且仅允许的条件 key | 匹配语义 / 参数校验 |
| --- | --- | --- |
| `eq` | `field / op / value` | 字段严格等于 `value`；不做隐式类型转换 |
| `in` | `field / op / values` | 标量字段属于非空 `values` 数组；比较不做隐式类型转换 |
| `contains` | `field / op / value` | 数组字段包含 `value`；元素比较不做隐式类型转换 |
| `exists` | `field / op / value` | `value` 必须是 boolean；`true` 匹配字段存在且非 null，`false` 匹配该条件不成立 |
| `range` | `field / op / min / max` | 字段为有限数值并位于闭区间 `[min,max]`；`min / max` 均为有限数值且 `min <= max`，boolean 不作为数值 |

仅上述五种op，拒绝regex/脚本/表达式/模板/LLM及隐式转换；in/contains/range按规定类型，不转换标量/数组或字符串/数字。

#### 2.0.3 受控 mapping context 字段白名单

白名单仅用于Adapter受控context，不能匹配任意 raw_alert.*，也不授权新增字段抽取/事实推断。

`category / severity` 仅允许匹配：

```text
source_type
source_namespace
sensor
rule_id
alert_type
signature
vendor_category
raw_severity
rule_groups
```

`payload` 仅允许匹配下列字段；该列表同时是 `output.fields` 的唯一白名单：

```text
source_type
rule_id
alert_type
signature
src_ip
dst_ip
src_port
dst_port
host
account
session
process
parent_process
url
domain
file
command
```

`source_independence` 仅允许匹配：

```text
left.source_type
left.source_namespace
left.sensor
left.origin_namespace
right.source_type
right.source_namespace
right.sensor
right.origin_namespace
```

`rule_equivalence` 仅允许匹配：

```text
source_type
source_namespace
rule_id
alert_type
signature
```

#### 2.0.4 各类型 default / output

| mapping_type | default | rules[].output |
| --- | --- | --- |
| `category` | 固定为当前 `normalization.unknown_category`（v0 为 `unknown`） | DATA_CONTRACT §1.1 的合法 Category 值 |
| `severity` | 固定为当前 `normalization.unknown_severity`（v0 为 `unknown`） | DATA_CONTRACT §1.1 的合法 Severity 值 |
| `payload` | 固定为 `null` | 仅允许 §2.0.6 的 `fields` 结构 |
| `source_independence` | 固定为 `unknown` | 仅允许 `confirmed_independent` |
| `rule_equivalence` | 固定为 `null` | 仅允许下述 `equivalence_key` 结构 |

default须显式且符合上表，category/severity与有效normalization一致，代码无fallback。source_independence的同origin零分不变量及 §4.5血缘/上下文/侧面门槛不可由mapping覆盖。

rule_equivalence.output仅允许下列结构，equivalence_key为非空稳定字符串：

```yaml
output:
  equivalence_key: <non-empty stable string>
```

仅两个告警获相同非空equivalence_key才跨源signature等价（§2.1/§4.7）。由duplicate.rule_equivalence_mapping_files加载；与payload_mapping_files一样，[]表示无声明，不猜测。

#### 2.0.5 命中与冲突处理

除category_priority外，命中处理如下：

| 命中情况 | 结果 |
| --- | --- |
| 0 个规则命中 | 使用显式 `default` |
| 1 个规则命中 | 使用该规则 `output` |
| 多个规则命中，规范化 output 完全相同 | 接受该 output，保存全部命中 rule ID |
| 多个规则命中，规范化 output 不同 | 报告 `MappingConflict`，不生成任意结果 |

类别多值按category_priority并保留全部provenance；severity不同值报MappingConflict。加载可判冲突立即失败，输入才暴露的冲突也报配置失败，不按YAML顺序决胜；default/output不豁免字段/时间隔离及独立性不变量。

#### 2.0.6 payload output 与 fingerprint

payload.output仅允许以下结构：

```yaml
output:
  fields:
    - <payload field>
```

fields非空、唯一且限 §2.0.3白名单；集合规范化，不因重排改变执行/output比较/快照/digest。

fingerprint=完整SHA-256(声明字段名及context值的规范JSON)，字段名排序，规范化按DATA_CONTRACT §2。任一字段缺失/null则不生成，不能删字段后摘要。禁止raw_fingerprint/文案/日志/AI替代；多命中先按 §2.0.5核对完整output，缺值不能跳过冲突。

#### 2.0.7 快照、digest 与 fail fast

快照及mapping_digest包含全部文件 schema_version/mapping_type/source_type/default/rules（规则id/match/output），按DATA_CONTRACT §2规范JSON，并纳入config_hash=config_digest；不只摘要路径或已命中规则。

规范顺序：object key递归排序、rules按文件内id、payload.fields按字段名；仅重排不改快照/digest/hash，实际规则/default/field/op/output改变必须改摘要。

未知key/type/version/source_type/field/op、错误参数形状、重复ID、非法default/output均fail fast，无隐式转换。输出保留字段provenance及全部命中引用，不扩领域Schema。

真实映射/namespace/资产仍为External/Input Pending；不按数据集答案映射或读取labels.csv。各模块仅在授权阶段实现，Data Readiness Gate按AGENTS。

## 2.1 Duplicate Candidate Generation（去重内部阶段）

顺序：`Adapter 基础 Normalization → Duplicate Candidate Generation → Dedupe → 完整 Entity Extraction → Correlation Candidate Generation → Correlation → Incident → Chain`。去重候选仅基础字段/provenance及纯normalization helpers，不依赖后续Entity/相关性索引。

| 索引 | key / 检索 | 用途 |
| --- | --- | --- |
| source_record | `(source_namespace, source_record_id)`，再按 raw_fingerprint 分桶 | 相同记录与内容的精确重复；同 ID 不同内容保留冲突诊断 |
| origin_record | 真实 `(origin_namespace, origin_record_id)`；无转发时本源 `(source_namespace, source_record_id)` 可作为其自身来源键 | 原源与转发记录及多次转发之间的精确候选；每次合并仍核验关键事实无矛盾 |
| payload_target_rule_time | `(payload_fingerprint, scoped target, rule_equivalence_key)` 复合桶，timestamp 有序范围查询 | 30 秒内的近似重复候选；target 与 rule_id / signature 使用 §4.7 的同一规范化 / 等价配置 |

key不得缺值；payload仅告警内声明字段摘要。target按 §4.7 scoped host/完整dst_ip+port；两种目标键均合法则入两桶取并集。规则key保留namespace，跨源共桶须明确等价；origin不猜、裸record_id不跨源比。

精确重复hash分桶/事实检查，不受30秒窗；近似在复合桶内有序索引/滑窗枚举，gap≤配置窗后算dup，去自配对、按alert ID去重。当前0.93阈值下缺rule/payload/target最高分别0.75/0.65/0.70；改阈值/权重须重算上界，复合桶无法覆盖全部合法组合则拒绝配置并要求修订索引，不静默漏召回。

索引只产候选，合并按 §4.7。complete-link核验全部跨组pair，包括未枚举pair，可缓存且首失败停止合并。后续每个相关性candidate均计算DuplicatePenalty，不要求曾入去重候选。

单独记录去重索引/候选/dup/拒绝/冲突/耗时，不用相关性预算。禁止全30秒窗两两扫描；高密度同桶及complete-link仍可能平方成本，不承诺线性。无去重截断预算，不套top-K；资源不足记录原因并Analysis incomplete。

## 3. Candidate Admission Contract v1.1

Task 05.2 用户授权版本化修改（v1.1）：Representative → Potential Neighbor Retrieval → Candidate Admission → Candidate → Correlation Score → CorrelationEdge。

Potential Pair 是索引、实体或时间约束发现的潜在邻居，尚非 Candidate；Candidate 是有合法非时间提名、通过时间资格及确定性局部 Top-K 的唯一无向代表 pair，集合有限、确定、可复现并有 provenance；CorrelationEdge 是 Candidate 完整七项评分后满足原阈值、hard guard、非时间支撑等冻结准入条件的正式边。本版本不改评分、正式边、聚类或方向规则。

输入为代表及全成员规范事实/Entity索引，输出唯一无向 Candidate pair 及理由；时间/倒排索引检索、通道并集、排自配对/同组、端点按ID排序，不做全量N²扫描。来源相同不排除，来源不同不自动入选。

| 通道 | 时间窗（秒） | v0 候选规则 |
| --- | --- | --- |
| Time only | 60 | 仅统计时间潜在邻居；Time proximity alone MUST NOT nominate a Candidate；time_only_neighbors 保留为旧配置兼容项，不执行时间 Top-K 提名 |
| IP | 600 | 同 network scope 的相同 src / dst IP；保留角色，src↔dst 仅作传播候选，不直接认定 pivot |
| Host | 1800 | 同资产 scope 的同主机 / 明确 alias；不自动合并短名与 FQDN |
| Account | 3600 | 同 realm 的相同账号；跨 host 可候选，但需登录 / 访问字段支持才形成 account_host_pivot |
| Session | 3600 | 同 scope 的相同会话，短 ID 跨应用不匹配 |
| Process | 600 | 同主机同进程实例 / 有父子实例指针；进程描述也可弱候选，不能按 pid 或 name 直接认定实例关系 |
| URL | 600 | 同目标 scope 的完整规范 URL；保留 query，不用 `/login` 全局聚合 |
| Domain | 600 | 相同规范 domain；公共 / 高频域名按 hot entity 策略限制 |
| File | 1800 | 同 host scope 的规范路径 / 文件身份；跨 host 同名文件不直接匹配 |
| Command | 600 | 同 host scope 的完整 command；不靠 AI 判断命令同义 |
| Source complement | 300 | 已有 host / session / 显式关系桥接，且 source complement 表匹配；仅来源不同不候选 |
| Explicit relation | 7200 | 告警结构化关系连接，索引相关实体，来源字段可回溯 |

每告警每非时间通道最近50，按abs(gap)/neighbor ID；hot=df/N≥0.10且df≥100时最近10，频率只来自输入。合并后每端提议≤200，优先级：显式关系→SESSION/实例→其他实体（weight×rarity降序）→互补源，同级gap/ID；双端提议并集计唯一pair，200不是最终图度数。

通道最近 K、hot 最近 K 和单端最多200是 Candidate Admission Policy，未通过者为 policy_pruned，正常允许 completed。局部规则、hot=df/N 判定、rarity 与排序数学定义不变；Stable ID lexical tie-break 保持既有实现。双端准入取并集，先合并全部已枚举发现的通道/实体/成员/排序证据，不能因早期 pair 去重丢 provenance。

总 Candidate≤2,000,000 是全局执行资源预算；超限按既有稳定优先级调度，其余已准入 Candidate 为 resource_truncated，candidate_truncated=true、status=incomplete。内存/超时/代表未遍历/准入未完成/已准入候选未评分/异常中断也破坏完整性，不可改名为策略剪枝。proposed/retained/dropped 逐阶段诊断明确 decision=policy_pruned 或 resource_truncated；不将多通道重叠的提议损失冒充 unique pair 损失。

每个 Candidate 保存 support_key 作为 pair identity、channels、entity IDs、结构化关系事实、成员及时间差、检索/有效窗口、hot/K、nearest ranking、最终 priority 和 admission reason。集合/排序不依赖 set/dict/文件/数据库偶然顺序。time-only 潜在邻居可计入诊断，但不得出现在 Candidate 提名通道中；TimeScore、方向时间事实和非时间通道时间窗口均保留。

诊断口径：raw_potential_discoveries 为各成员索引查得的有效邻居组重复发现；unique_potential_pairs 为所有通道（含仅观测时间）并集；policy_pruned_count=unique_potential_pairs-admitted_candidate_count，为唯一未准入 pair；resource_truncated_count 为全局预算未调度的已准入 pair；未知数量的执行中断另记资源事件与原因，不伪造 pair 数。admitted_candidate_count 在全局执行预算前计数，scored_candidate_count 在全部 G1×G2 核验后计数。正常执行须 admitted=scored+resource_truncated；策略提议 dropped 仅作重叠诊断。

completed 须全部输入预处理、代表检索、准入策略、已准入评分、正式边、Incident、AttackChain 均执行完成，无资源截断、遗漏或失败。policy_pruned>0 不破坏完整性；拒绝输入与其它原有完整性条件继续有效。新快照/Analysis Detail/manifest 记 candidate_contract_version=v1.1，algorithm_version 同步显式版本；旧 v1.0 快照保留原 status/原因/诊断，禁止重解释或覆盖。潜在pair可平方，实际枚举由局部策略及全局资源预算控制。

无专门项默认窗1800，通道表优先，绝对上限7200。显式behavior overrides：Web→Process/Command300，initial_access→lateral_movement7200，authentication→lateral_movement3600；只覆盖声明的实体/关系通道，不扩time-only/source-complement，不用攻击真实时间。

先检索上界→pair过滤→准入策略→执行预算：`retrieval_window(c)=min(max_window_seconds,max(base_window(c),该通道全部合法override窗口))`。同scope/key检索后按早→晚category transition求effective_window（命中override用其值，否则基础窗；同时间取两序最大，仅无向候选）。保留abs(gap)≤effective_window，才执行通道/hot/单端准入及总执行预算；迭代索引不能先top-K再过滤。由其他合法通道入选的超窗pair仍评分。

HOST先检索7200：5000秒initial_access→lateral_movement按7200保留，不能先查1800；无override仍1800，Web→Process300。诊断保留channel/retrieval_window/effective_window/匹配覆盖/裁剪原因。

## 4. Correlation Score：七项原值与权重

### 4.0 去重组的完整成员对评分（v0 Frozen）

每个入选代表对完整计算G1×G2全部原始成员pair的七项分/Reason/guard，不只代表或候选命中成员；单告警为一元素组。固定N/df按组计，每pair仅用自身实体，缺字段零分/unknown，不重分权重。

有效pair须独立通过时间/类别/来源/实体/关系/非时间支撑/guard；最高未舍入完整分为组间分与support_pair，阈值不改，无有效pair则无正式边。禁止拼接各项最高或跨成员补字段。

representative ID固定G1/G2；并列按 `(src.event_time,dst.event_time,src.alert_id,dst.alert_id)` 升序（event_time=timestamp）。正式时间/类别/来源/实体/关系/惩罚/Reason/Breakdown全部来自胜出pair，其余诊断；全组TargetSet仅guard摘要，不提高pair分。

support_pair为原成员证据，support_key为代表身份，每代表pair只计一条。内部核验不抽样/不套候选预算；未完成须incomplete，不称获得完整max。

```text
raw = 0.20*T + 0.30*E + 0.20*R + 0.20*B + 0.10*S - 0.45*C - 0.40*D
score = clamp(raw, 0, 1)
```

七项原值∈[0,1]，无字段/匹配为0，不重分权重；正权重和1。完整保存weight/raw/contribution/raw_total/final_score/config_hash。score≥0.65且有真实非时间上下文并通过guard才正式入边，TimeScore单独不足。

### 4.1 TimeScore

`T=exp(-ln(2)*abs(tB-tA)/half_life_seconds)`。按(timestamp,alert_id)顺序取行为参数但ID不赋因果；对称关系取较大半衰期并记录。其他通道召回的超窗pair仍衰减并按行为窗施加conflict。

| 行为对（按早→晚） | 半衰期秒 | 配套合理窗口秒 |
| --- | --- | --- |
| 默认 / 未知 | 300 | 使用候选通道窗口 |
| web_attack → process_execution | 60 | 300 |
| web_attack → command_execution | 60 | 300 |
| process_execution → privilege_escalation | 300 | 1800 |
| authentication → lateral_movement | 600 | 3600 |
| initial_access → lateral_movement | 1200 | 7200 |
| lateral_movement → command_and_control | 600 | 3600 |
| collection → exfiltration | 600 | 3600 |

同时间T=1，半衰期T=0.5；skew=2秒仅方向容差，不改timestamp或强行定向。

### 4.2 EntityScore 与 rarity

N为本次去重组数，df(e)为含e的组数（同组只一次）；评分前冻结，不随遍历改变。

```text
rarity(e) = clamp(log((N+1)/(df(e)+1)) / log(N+1), 0.10, 1)
x(e) = clamp(type_weight(e) * rarity(e) * role_factor(e) * descriptor_factor(e), 0, 1)
E = 1 - product(1 - x(e))
```

N≥1，空共享E=0；关闭rarity时取1，不改其他配置。每类型最多3实体，按x降序/entity_id并列，避免数量刷分。

| 类型 | 权重 | 注释 |
| --- | --- | --- |
| IP | 0.25 | 常见基础设施 IP 较弱；scope 必须一致 |
| HOST | 0.55 | 同主机仍不足以确认同攻击 |
| ACCOUNT | 0.70 | realm 一致 |
| SESSION | 0.90 | 具体会话上下文 |
| PROCESS | 0.80 | 实例；描述实体再乘 0.25 |
| URL | 0.85 | 完整且有目标 scope |
| DOMAIN | 0.35 | 高频 domain 会进一步降权 |
| FILE | 0.90 | 主机范围内具体文件 |
| COMMAND | 0.90 | 主机范围内完整命令 |

角色因子：同角色1、src_ip↔dst_ip0.8、其他0.5；每实体取最高合法值仅贡献一次；不同network_namespace不视为共享IP。

### 4.3 RelationScore

表中类型为AlertRelationType（供explicit_relation Reason）；经字段准入后按 §6映射独立ChainRelationType，不直接复用。

仅回溯结构化字段/实体关系，多匹配取最高分并保留全部理由，不叠加。

| relation_type | 分值 | 必需事实依据 |
| --- | --- | --- |
| target_to_process | 0.9 | 前告警明确目标 host，后告警有同 host 的进程实例，类别为 web_attack / initial_access → process_execution / command_execution；还必须有告警字段明确连接前请求 / 操作与后进程：可回溯的 request/session 操作记录含启动进程实例引用，或触发上下文 / process lineage 明确指向前请求。两端仅共享 request_id / session 值仍须有请求触发该进程的关系字段 |
| parent_child_process | 1.0 | 同主机进程实例与 parent_process 实例匹配，不能凭相同可执行文件名 |
| account_host_pivot | 0.8 | 同 realm account / session，前主机到后主机访问 / 登录方向字段可核验 |
| network_pivot | 0.8 | 前目标与后来源相连且告警端点 / 资产桥接明确，不以共享 src_ip 冒充 pivot |
| session_continuity | 0.9 | 同 scope 具体 session，告警内请求 / 操作顺序可核验，单纯会话相等不产生因果方向 |

无传播R=0，共享host仅EntityScore。匹配生成explicit_relation及绑定EvidencePointer；target_to_process须覆盖连接关键字段，其他关系按各自定义（不要求都有进程）。仅host/time/category不合格。WAF Web与30秒后同主机EDR Process无触发字段时R=0，不满足单桥/方向前提；任何其他高分或源互补都不能发布该传播关系。

### 4.4 BehaviorCompatibilityScore：配置转换矩阵

类别来自规则映射；下表为非默认转换，相同category0.4、含unknown0、未列不同类别0.1，fallback同样配置。按真实时间/明确关系顺序查，不由LLM/ATT&CK决定。

| from_category | to_category | B |
| --- | --- | --- |
| reconnaissance | initial_access | 0.8 |
| reconnaissance | web_attack | 0.8 |
| initial_access | process_execution | 0.9 |
| initial_access | command_execution | 0.9 |
| initial_access | lateral_movement | 0.7 |
| web_attack | process_execution | 1.0 |
| web_attack | command_execution | 1.0 |
| authentication | process_execution | 0.7 |
| authentication | lateral_movement | 0.8 |
| process_execution | command_execution | 0.8 |
| process_execution | privilege_escalation | 0.9 |
| command_execution | privilege_escalation | 0.9 |
| process_execution | persistence | 0.8 |
| command_execution | defense_evasion | 0.7 |
| privilege_escalation | credential_access | 0.8 |
| credential_access | lateral_movement | 0.9 |
| discovery | lateral_movement | 0.8 |
| lateral_movement | process_execution | 0.8 |
| lateral_movement | command_and_control | 0.8 |
| process_execution | command_and_control | 0.7 |
| command_and_control | collection | 0.7 |
| collection | exfiltration | 0.9 |
| command_execution | impact | 0.7 |

矩阵不要求固定攻击阶段序列；未列反向不hard reject，仅字段证明反向冲突才惩罚。重叠时无向B可取两向最大，重构仍分别查。

### 4.5 SourceComplementScore

pair状态三值：同origin/转发同告警→confirmed_same_origin；真实血缘或有据拓扑证明独立且无同origin→confirmed_independent；其余unknown。同origin优先，矛盾记诊断不给奖励；产品/namespace/sensor不同或缺转发字段不证明独立。

same_origin/unknown/同sensor均S=0；confirmed_independent仍须上下文及不同侧面才查表，否则0。满足门槛的不同类型未列项fallback0.3，同类型独立sensor0.2；这不是独立性先验。同时检查产品及告警category，不把Wazuh一概作EDR。

| source pair（无序） | 行为 / 侧面条件 | S |
| --- | --- | --- |
| waf + edr | web_attack ↔ process_execution / command_execution，目标 host 桥接 | 1.0 |
| suricata + edr | 网络 initial_access / command_and_control ↔ 主机进程行为，目标 / 主机桥接 | 0.9 |
| wazuh + aminer | 字段确认分别来自主机行为与网络 / Web 行为，独立检测器、host / session 桥接 | 0.7 |
| waf + wazuh | web_attack ↔ 已确认的主机进程 / 命令行为，非转发、目标 host 桥接 | 0.8 |
| ids + edr | 网络告警 ↔ 主机进程行为，明确端点 / 主机桥接 | 0.8 |

表项全部先过独立门槛；host桥不证明因果/不替代 §4.3。状态与S分开，Reason/诊断也记录unknown/零分依据；同底层事实由Dedupe/DuplicatePenalty控制，不作独立阶段加分。AMiner格式未知不按产品名猜侧面，S=0。

### 4.6 ConflictPenalty 与 hard guard

| rule_id | v0 强度 | 触发条件 |
| --- | --- | --- |
| different_target_without_bridge | 0.8 | 明确不同目标，且无 account / session / 实例 / 端点传播等桥接；不能因目标不同就否认横向移动 |
| no_context_bridge | 0.5 | 只有时间 / 来源邻近，没有真实实体或显式关系 |
| beyond_behavior_window | 0.6 | 超过该行为对显式合理窗口；不对未知类别猜窗口冲突 |
| reversed_explicit_relation | 1.0 | 告警字段证明的操作关系与时间 / 候选方向矛盾，超出时钟容差 |
| incompatible_session | 1.0 | 同应用 / 操作上下文中两个明确互斥 session；会话值不同本身不算互斥 |

C取最大匹配强度，缺字段不算冲突。hard：明确隔离namespace无桥或字段核验互斥session直接拒绝关联/聚类/方向，留评分与拒绝诊断；高分仅可抵soft，不可抵hard。Conflict消融默认只移soft C，另移聚类语义保护须独立命名。

### 4.7 DuplicatePenalty 与去重阈值

精确重复：同source_namespace+source_record_id+raw_fingerprint，或确认同origin_namespace+origin_record_id且关键事实不矛盾；直接同事实组，不受时间窗。ID重用内容冲突报告，不自动删。

近似重复30秒窗内计算：

```text
dup = 0.25*rule_match + 0.35*payload_match + 0.30*target_match
      + 0.10*exp(-ln(2)*gap_seconds/10)
```

rule_match：同源rule_id/配置跨源signature等价；payload_match：声明的告警关键payload fingerprint相同；target_match：明确同目标host/完整dst_ip+port；匹配1否则0，缺失为0，不重归一化，不以absent==absent匹配，不从日志补payload。

dup≥0.93且payload/target存在并匹配才近似去重。complete-link核验所有成员pair，候选按dup降序/alert pair ID，代表最小alert_id，保留全部成员/理由。组duplicate_score取全部i<j最小dup，单成员/精确pair为1.0，不取均值/最大，不传递误合并。

未去重疑似pair：dup<0.50时D=0，否则D=(dup-0.50)/(1-0.50)夹[0,1]。同事实组不重构两个步骤；额外same-action合并默认关闭，启用须明确同请求等强依据及独立测试。

## 5. Incident 受控聚类

展示边0.65≤score<0.70；聚类score≥0.70，均未舍入且配置载入（clustering.edge_threshold≥score.correlation_threshold）。达标仍须guard；按score降序/edge_id升序，从代表singleton受控union：

1. 任何 hard conflict、跨 namespace 无桥接，禁止合并。
2. 合并后跨度≤7200 秒、代表数≤500；不满足则保留分量并记录 clustering_guard。
3. 两个 singleton 之间以 1 条达阈值边建立初始分量（bridge_min_edges_between_singletons）；singleton 加入 non-singleton 默认至少 2 条独立达阈值支撑边（bridge_min_edges_with_singleton=2）；两个 non-singleton 默认也至少 2 条（bridge_min_edges_between_non_singletons=2）。仅有 §4.3 字段证明的 explicit propagation，permit_explicit_relation_single_bridge=true 才允许 1 条达阈值边的例外；不能豁免 hard conflict、目标保护、跨度或规模上限。所有计数按合并时当前分量大小决定，不能按告警最初是 singleton 永久沿用起步条件。
4. 若两个分量的目标集合不同且没有真实上下文传播桥，拒绝合并；只有共用基础设施 IP 的链式连通不能无限吞并事件。

仅用已评分正式边及摘要计桥，不临时补算/假装缺边有分。每次union更新摘要，后续有新支撑可重评，确定顺序迭代至无合并，至多N-1轮，记录接受/拒绝。最终展开全部原始成员，每告警恰属一个Incident，保留singleton。

### 5.1 独立支撑边规则（v0 正式冻结）

支撑计数与其余guard同时适用。

独立支撑仅指不同代表pair：`support_key=sorted(representative_alert_id_A,representative_alert_id_B)`。仅跨当前两分量、达聚类阈值且过guard的正式边计数；同pair的edge/reason/relation/sensor/原始成员包装不额外计。singleton加入须连两个不同代表；两非单点的两pair可共享一端。不意味着统计独立或SourceIndependence已确认。

单桥须来自当前两分量支撑成员的 §4.3字段传播，不能借分量内部关系。A—B起步后仅B—C/C—D/D—E普通单桥不能吞并；A—C+B—C可加入C，或B—C本身有合法传播。其余guard仍检查。

### 5.2 Target Set 与上下文传播桥规则（v0 正式冻结）

TargetSet取全组真实目标字段、component并集排序；仅 `(HOST,asset_scope,normalized_host)` 或 `(ENDPOINT,network_scope,normalized_dst_ip,dst_port)`（port必需）。host须目标/执行主机，不是采集主机；src_ip不计，URLhost/domain仅字段/有据资产映射证实时折叠。HOST/ENDPOINT仅明确资产映射归同目标，不猜DNS/去port/忽略namespace。

缺目标为unknown：两空不证明相同，不因缺失hard conflict。一旦双方明确且集合不同（即使有交集），须跨分量正式边explicit_relation覆盖两侧support_pair，字段证明不同目标操作/实体流转：访问登录方向、进程lineage、src→dst pivot或有序session（§4.3）。仅账号/session/IP/time/behavior/source互补不算桥；单侧unknown仍照常两桥/显式例外及其余guard，不豁免。

诊断保留support_key、两侧目标键/provenance、传播alert/Reason及决定；每union重算，产品差异不替代条件。本TargetSet仅聚类，去重target仍 §4.7。

## 6. 节点、重构方向与冲突控制

仅字段合法的正式CorrelationEdge按下表映射ChainEdge；两个关系枚举独立：

| 合法 AlertRelationType | v0 ChainRelationType |
| --- | --- |
| parent_child_process | PROCESS_CAUSAL |
| target_to_process | REQUEST_TO_PROCESS |
| account_host_pivot | ACCOUNT_PIVOT |
| network_pivot | NETWORK_PIVOT |
| session_continuity | SESSION_FLOW |

核验 §4.3语义/方向及指针/provenance，证据仅选定跨节点support_pair，不能拼成员；节点区间chronology仍适用。Host/time/其他高分/任意指针都不替代传播。

同向关系按parent_child_process > target_to_process > account_host_pivot > network_pivot > session_continuity选择类型，其他理由保留；优先级不改变最高RelationScore或关联分。

chain.relation_type_mapping/relation_priority严格对应表和顺序，无缺/重/额外/fallback。无合法关系保留无向边/unresolved/诊断；behavior_transition/entity_propagation/source_complement/mixed_evidence均非v0类型。

同时过关联/方向阈值、margin、chronology/skew、explicit_relation_minimum、hard/time/DAG guard；require_explicit_propagation不可关闭。未来准入变更须显式版本。

节点每去重组/单告警一个，类别按标准化字段。confidence=0.50+已知类别0.15+任一host/scoped session/进程实例0.10（仅一次）+组内确认独立源0.10，上限0.85；转发包装不奖励，各项记录node_basis。仅启发式，不是攻击概率。

仅同Incident跨节点边，支撑score≥0.70，方向≥0.75；两方向分别计算：

```text
direction = 0.40*chronology + 0.35*directed_relation + 0.20*directed_behavior + 0.05*source
confidence = min(selected_correlation_score, direction)
```

- chronology：源节点 end≤目标 start 为 1；在 2 秒 skew 内重叠为 0.5；其他为 0。相同时间只给 0.5，不能依 ID 作因果裁决。
- directed_relation：按 RelationScore 表，但关系必须支持该方向；反向字段关系不匹配为 0。最低 0.8 且 raw pointers 证明传播字段是 hard prerequisite；达到数值、存在任意字段指针或两类行为兼容都不能替代它。target_to_process 必须通过 §4.3 的触发 / lineage 核验。
- directed_behavior：按矩阵；不同方向分别查，不取最大；source 沿用互补原值。
- 优胜方向≥0.75 且与另一方向差≥0.15；同时满足显式传播 prerequisite、hard guard 和时间合理性。重叠时间只有字段关系足够明确才可能定向，反向时间超 skew 直接拒绝。
- 多个合法 AlertRelationType 匹配时使用 chain.relation_priority 的既有顺序，再按 chain.relation_type_mapping 选择正式 ChainRelationType；其余合法匹配写入 reasons / diagnostics，类型选择不能替代任何方向准入条件。

未定向保留无向/unresolved，不补边。允许孤立/分支；按confidence降序/edge_id升序增边，cycle拒绝并记诊断，不删节点/改时间。

方向权重/margin/节点confidence/映射优先级全入配置；score_breakdown原样引用最强支撑边，方向分另存；LLM不参与分数。

## 7. 参数调整、实验与结果边界

Evaluation匹配/分母/coverage按DATA_CONTRACT §13.1，AI/API分别 §12.2/§13；核心条件和阈值不变。

比较Time Only、Time+IP、Time+All Entities、Full；前三默认窗300秒，同输入/normalization/dedupe/split，不用behavior/source/soft conflict/duplicate奖励。baseline时间边仅evaluation，不改生产非时间门槛；披露候选/预算差异，Full漏候选仍Recall FN。

逐项移Entity Rarity/Relation/Behavior/Source/Conflict/Duplicate，正权重默认不重归一化，阈值固定；重调阈值独立实验。注明score-only与end-to-end，后者同时禁对应候选奖励/方向贡献，仍保留身份/证据hard guard；移Relation后方向不满足如实报告，不用AI替代。

分别变化：阈值0.55–0.80；窗口倍率0.5/1/2（同步max_window）；单正权重倍率0.5/1/1.5后归一化，惩罚权重独立。噪声0/25%/50%/100%，改变源比例、跨场景/数据集；seed=42仅evaluation抽样。

记录Pairwise/Incident/Node/Edge F1、contamination、direction、stage coverage/order、grounding、误关联及runtime/memory。缺真值unavailable，不造结果；无规模/硬件约束不设虚假SLA/F1门槛，资源预算须实测。

调参记录开发/测试划分、input fingerprint、配置diff、指标/限制；GT仅evaluation读取，生产仅通用配置。发布配置须独立评测说明依据，不将v0称最优。

所有原告警可追溯，不因无关联删除，未关联作为singleton保留。

## 8. 用户授权 Correlation v2（2026-10-09）

本次显式版本升级替代 §4.0 的 v0 固定缺失零分规则，仅对 `version: v2` 生效；`configs/algorithm-v0.yaml`、旧快照和上述 v0 解释保持原义。v2 完整配置位于 `configs/algorithm-v2.yaml`，源映射仍按 §2.0 装载。阈值 0.65、聚类 0.70、五类关系、方向/Target Set/两桥/来源独立性/GT 隔离不变。

五家族复用正权重 time/entity/relation/behavior/source。每个维度显式区分 AVAILABLE_MATCH、AVAILABLE_MISMATCH、UNAVAILABLE、NOT_APPLICABLE。Entity 按双方存在的 scoped 实体类型计算加权均值；不匹配贡献 0，单侧缺失不进入该家族分母。匹配强度保留角色/进程描述因子；rarity 用配置 floor+(1-floor)×rarity 修饰质量，并保持 hot 与强标识保护。Semantic 使用已映射类别兼容、同源 rule/signature/alert_type 精确比较；供应商字符串不作跨源等价。Topology 取已核验关系与同 scope dst→src 连续性的最大强度；端点连续性不创建 AlertRelation 或 ChainEdge。Context 仅已确认独立且互补的来源可以贡献。Time 继续使用 §4.1 指数半衰期。

`available_weight=Σ可观测家族权重`；`matched_weight=Σ家族权重×家族强度`；`quality=matched/available`（空分母 0），`mass=matched/Σ配置正权重`；`raw_v2=quality_factor×quality+mass_factor×mass−wc×C−wd×D`，最终 clamp 到 [0,1]。初值 factors=0.65/0.35，entity_quality_rarity_floor=0.8，minimum_mass=0.25，均为未校准假设。七项 v0 原值与 signed contributions 仍完整保留作为审计层，不冒充 v2 总分分解。

Gate 在绝对 mass 合格后要求：A 非 hot 强上下文实体/端点连续性加独立 time/semantic 支撑；B semantic+非 hot topology+time；或 C 已核验关系/完整进程实例/有明确 scope 且稀有的 session。描述进程、普通 IP、DOMAIN、hot host/destination、单一 rule/category/signature/sensor/time 均不能独立满足 gate。具体强类型、specific rarity、time/semantic/topology 下限由 v2 配置加载。高分仍可能 REJECT_INSUFFICIENT_EVIDENCE；hard guard 优先 REJECT_GUARD。无合法关系的高分关联可以无向接受，链诊断为 REJECT_NO_RELATION，不能拒绝所有无方向的关联。G1×G2 全成员评分、未舍入比较、唯一有效 support_pair 规则保持。

候选已有九实体索引覆盖稀疏 host/account/session/network。v2 仅为 entity-free 告警增加同源 semantic 倒排索引；使用 300 秒配置窗、现有 hot/per-channel/单端准入与全局预算。time-only 仍不提名。semantic 索引键是诊断 key，不是 Entity。scope/未知字段不造实体；新通道也记录 policy/resource 区别。

独立 Single Alert Triage 使用已有 severity、已映射 category 与 `(source_namespace,rule_id)` 的事实组频率；分别配置风险映射与 0.65/0.25/0.10 权重，只有可观测项参与分母，rarity-only 最高 0.30。risk_level 使用现有 low/medium/high/critical/unknown 词汇；P4/P3/P2/P1/UNRATED 是查看优先级，不是自动处置。设备 severity 不变；triage 不输入关联/聚类/方向。未知资产敏感性、来源可靠性、外网方向不猜测。

完整设计和真实验证见 `outputs/correlation_v2/CORRELATION_V2_DESIGN.md` 与 `CORRELATION_V2_REPORT.md`。可通过现有 POST 的 `config_version: v2` 选择；v0 引用继续解析旧算法，不重解释历史结果。

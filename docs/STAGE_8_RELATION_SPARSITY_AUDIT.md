# ⑧ Stage Relation Graph 稀疏性审计

本轮仅诊断。原样重放正式⑦和⑧并逐字段比对冻结输出；不运行①～⑥、不调用历史关联、不执行⑨，不读取 GT 作语义判断。

## 漏斗

42 Stage → 861理论Pair → 165候选（⑦排除696） → 165进入⑧ → 142拒绝 → 23关系 → 18有边节点、24个degree=0节点。

直接统计⑧图的多节点分量大小为[8, 10]；不生成Chain，不调用⑨。

⑦排除是现有倒排索引、Context-only/common weak posting、角色及时间分支的结果；逐对真实执行路径见 pairs.json。⑧拒绝原因见 rejected_pairs.json。

## 六个核心问题

1. 理论空间压缩主要发生在⑦（排除696/861，80.84%）；但24个孤立Stage中23个已有候选，孤立的直接原因主要是⑧没有足够直接关系证据，不能归咎于⑦完全不召回。⑧拒绝142/165（86.06%）。

2. ⑦完全没有候选：1个。完整ID及原始特征路径见下表和isolated_stages.json。

3. 有候选但⑧全部拒绝：23个。138对只有已验证Context membership，4对没有任何有效Claim。共享Context不是缺失的直接关系边。

4. 已有可信绑定未正确投影的证据：本快照中发现0项。原Profile绑定、Stage实体摘要、⑦Feature、⑧Observation及已归档Host/Auth投影逐项核对见projection_audit.json。缺少跨源网络权威声明与Stage聚合丢证据是不同问题。

投影检查范围：冻结文件没有单独保存⑤CommunityResult.matching_evidence日志；本次按现有Alert/Entity/Context IDs、Stage聚合依据及⑤/⑥原始消费代码检查承接，不补造或重放⑤日志。⑤正式代码直接承接已绑定Alert/Entity，⑥Stage保留原Alert IDs；⑦/⑧仍逐个读取原始member Alert，而不是仅使用Stage摘要。

5. WEAK_DIRECTED=0由正式契约和代码路径决定：stage-evidence-v2只有DIRECTED_EDGE / UNDIRECTED_EDGE / NO_RELATION，不是本数据恰好未满足弱边条件。历史stage_relations实现有WEAK_DIRECTED，但正式pipeline不调用。

6. 按当前可观察可信证据和正式语义，合法孤立24个，疑似假孤立0个，未知0个。这里只判断现有证据是否足以建关系，不判断Stage是否良性，也不推断未观测的攻击步骤。

## ⑧拒绝与接受证据

最终拒绝类别：`{"NO_VALID_EVIDENCE":4,"SHARED_CONTEXT_ONLY":138}`。没有Hard Conflict或无效Claim。不存在单独因方向未知而整体拒绝；有直接关联但方向未知的1对已按无向关系接受。

138个SHARED_CONTEXT_ONLY是当前正式语义主动保留“共同参与上下文、但不确认Stage间直接关系”的结果，尤其是覆盖多个Stage的Flow/Process/Session。完整上下文没有丢失；它不满足当前“独占双Stage完整且未污染身份，或独立直接关系Claim”的建边要求。这是关系成立条件的设计后果，不能说成没有任何绑定，也不能说成方向未知被拒绝。

23条边的主证据：`{"AUTH_ESTABLISH_USE":9,"OBJECT_HANDOFF":1,"PARENT_CHILD_PROCESS":12,"SAME_STRONG_SESSION":1}`。按每条边全部有效Relation Claim去重计数（可重叠）：`{"AUTH_ESTABLISH_USE":9,"OBJECT_HANDOFF":1,"PARENT_CHILD_PROCESS":12,"SAME_SCOPED_OBJECT":1,"SAME_STRONG_SESSION":2}`。支持证据不计作建边主证据。

接受Pair中全部Claim类型的出现次数（含Context/Supporting，每Pair每类型只计一次）：`{"AUTH_ESTABLISH_USE":9,"NETWORK_ENDPOINT_OVERLAP":1,"OBJECT_HANDOFF":1,"PARENT_CHILD_PROCESS":12,"SAME_ACCOUNT":9,"SAME_COMMAND":1,"SAME_HOST":23,"SAME_PROCESS_INSTANCE":1,"SAME_SCOPED_OBJECT":1,"SAME_SCOPED_REQUEST":2,"SAME_STRONG_SESSION":19,"SHARED_FILE_PATH":3,"SHARED_PROCESS_DESCRIPTOR":1}`。

## Community、时间与网络身份边界

理论同Community Pair 316，跨Community 545；候选分别158、7；接受分别19、4。正式⑦没有same-community硬边界，因此没有因Community禁比而排除的Pair。

⑦时间分支裁剪15次posting-pair访问，涉及13个不同Pair；最终因此完全未入候选1对。不能将posting访问次数当成最终Pair丢失数。分布（秒）：`{"all_possible":{"count":861,"max":1986.0,"median":636.0,"min":0.0,"p75":1296.0,"p90":1578.0},"candidates":{"count":165,"max":472.0,"median":84.0,"min":0.0,"p75":163.0,"p90":240.0},"noncandidates":{"count":696,"max":1986.0,"median":915.0,"min":0.0,"p75":1374.0,"p90":1599.0},"stage7_temporally_excluded_pairs":{"count":1,"max":460.0,"median":460.0,"min":460.0,"p75":460.0,"p90":460.0},"stage7_temporally_pruned_visits":{"count":15,"max":460.0,"median":150.0,"min":125.0,"p75":171.5,"p90":190.0},"stage8_rejected":{"count":142,"max":472.0,"median":84.0,"min":0.0,"p75":149.75,"p90":211.30000000000004}}`。

696个非候选的互斥归因组合：`{"COMMON_WEAK_KEY_REQUIRES_INDEPENDENT_KEY":61,"COMMON_WEAK_KEY_REQUIRES_INDEPENDENT_KEY + CONTEXT_OUTSIDE_LOCALITY_WINDOW + CONTEXT_REQUIRES_INDEPENDENT_KEY":1,"COMMON_WEAK_KEY_REQUIRES_INDEPENDENT_KEY + CONTEXT_REQUIRES_INDEPENDENT_KEY":18,"CONTEXT_REQUIRES_INDEPENDENT_KEY":2,"NO_SHARED_RETRIEVAL_KEY":614}`。NO_SHARED_RETRIEVAL_KEY是审计对真实倒排交集为空的缺席标签，其余名称均来自原始执行分支，并非新增生产拒绝状态。

⑧没有通用关系年龄上限，只对方向证据做各证据类型的倒序检查；当前无TEMPORAL_CONFLICT。Host/Account/IP相同、共享多Stage Flow或时间接近均不自动构成关系。

4个NO_VALID_EVIDENCE Pair均由SHARED_CONNECTION_TOKEN_AND_ENDPOINT_PAIR召回。它只声明候选线索；Firewall/EDR/Auth的connection/session scope仍含不同来源或host_scope，当前没有可信跨源网络身份投影。相同token和端点可见，但不等于已有可信跨源binding在Stage层丢失。详见network_scope_audit.json。

## 各类绑定是否仍可见

| 检查项 | 真实输入与消费结果 |
|---|---|
| Host Binding | 85条Host绑定记录均可见；2条归档HostAlias覆盖85条观测，其中9条属于孤立Stage。⑧将共享Host视为SAME_HOST支持证据，不独立建边。 |
| Account Binding | 61条host_account记录的实体/指针可见；⑧通过entity.ACCOUNT/HOST读取，属于支持上下文。 |
| Process Binding | 112条完整process_instance记录保留；12条不完整实例的host_process记录仅作为实体描述上下文。完整父子角色支撑12条正式边。 |
| Request Binding | 34条原Request绑定保留；纯共享Request在多Stage时属于Context，显式request/response操作才可能提供方向。 |
| Flow Binding | 72条完整tuple可见，并另保留native flow+tuple上下文。孤立Stage包含49条tuple投影，没有从Stage中丢失。多成员Flow身份不自动变成pairwise边。 |
| Auth Session Binding | 原6条权威AuthSession投影共46条观测，全部保留；没有观测属于当前孤立Stage。有效建立/使用角色产生9条主证据边。 |
| Network Session Binding | 40条原connection绑定记录保留（其中20条属于孤立Stage），scope保持来源/Host边界；没有跨源Network authority，不能把相同token自动视为可信跨源binding。 |
| Cross-Source Identity Projection | HostAlias与AuthSession按原权威scope消费；没有已有Process continuity或Network identity projection可被误称为Stage层丢失。 |

## 42个Stage

完整基础信息、实体/绑定ID、行为、来源覆盖与degree见stages.json。表内ID为缩写；可通过同名JSON查完整稳定ID。

| Stage | Community | Alerts | Behavior | Degree | Isolated |
|---|---|---:|---|---:|---|
| stg_0162caf00773 | com_852f7a8a4e4b | 1 | NETWORK_ACTIVITY | 0 | true |
| stg_0729c64eebea | com_534fe02900d9 | 10 | NETWORK_ACTIVITY | 0 | true |
| stg_12cb2c433248 | com_852f7a8a4e4b | 1 | WEB_EXPLOIT | 0 | true |
| stg_18cf810062fd | com_534fe02900d9 | 1 | FILE_ACTIVITY | 1 | false |
| stg_1b8e6879dc95 | com_2f866f370eae | 1 | UNKNOWN | 4 | false |
| stg_1cba0377af41 | com_852f7a8a4e4b | 1 | UNKNOWN | 0 | true |
| stg_1e5c637a8067 | com_534fe02900d9 | 1 | FILE_ACTIVITY | 1 | false |
| stg_204a14c2f77c | com_534fe02900d9 | 1 | EXECUTION | 1 | false |
| stg_2101a5462914 | com_852f7a8a4e4b | 1 | UNKNOWN | 0 | true |
| stg_2ceb3ea18888 | com_534fe02900d9 | 2 | UNKNOWN | 0 | true |
| stg_38391c193c06 | com_2f866f370eae | 15 | FILE_ACTIVITY | 4 | false |
| stg_41a6e21d56f9 | com_534fe02900d9 | 1 | EXECUTION | 1 | false |
| stg_43b5b127059b | com_2f866f370eae | 5 | EXECUTION | 3 | false |
| stg_4ea69ee2c0dd | com_852f7a8a4e4b | 1 | UNKNOWN | 1 | false |
| stg_5c819f3778de | com_852f7a8a4e4b | 1 | UNKNOWN | 0 | true |
| stg_6105e882735a | com_852f7a8a4e4b | 1 | NETWORK_ACTIVITY | 0 | true |
| stg_6187b9282a03 | com_852f7a8a4e4b | 1 | UNKNOWN | 0 | true |
| stg_64c5ca4d2078 | com_852f7a8a4e4b | 2 | UNKNOWN | 0 | true |
| stg_66e73630d582 | com_534fe02900d9 | 1 | UNKNOWN | 0 | true |
| stg_751bc093457c | com_534fe02900d9 | 1 | UNKNOWN | 0 | true |
| stg_76b8c34dd178 | com_534fe02900d9 | 1 | FILE_ACTIVITY | 1 | false |
| stg_7e951854ce84 | com_852f7a8a4e4b | 4 | UNKNOWN | 0 | true |
| stg_82a13243d7d9 | com_852f7a8a4e4b | 1 | WEB_EXPLOIT | 0 | true |
| stg_89ffedad3d3e | com_852f7a8a4e4b | 1 | UNKNOWN | 0 | true |
| stg_95fe524e6777 | com_534fe02900d9 | 1 | EXECUTION | 1 | false |
| stg_9849909a6174 | com_852f7a8a4e4b | 1 | WEB_EXPLOIT | 0 | true |
| stg_99fe92846c2e | com_2f866f370eae | 8 | EXECUTION | 4 | false |
| stg_9dcd78f543f7 | com_852f7a8a4e4b | 14 | UNKNOWN | 5 | false |
| stg_9f7118dd1b89 | com_852f7a8a4e4b | 1 | UNKNOWN | 0 | true |
| stg_a504ee355dcc | com_534fe02900d9 | 1 | UNKNOWN | 0 | true |
| stg_abe9f4e0e33e | com_852f7a8a4e4b | 2 | UNKNOWN | 0 | true |
| stg_acbff36c8512 | com_2f866f370eae | 4 | FILE_ACTIVITY | 3 | false |
| stg_b38b5a11464f | com_2f866f370eae | 4 | NETWORK_ACTIVITY | 4 | false |
| stg_b83800e80d59 | com_852f7a8a4e4b | 1 | UNKNOWN | 0 | true |
| stg_bbd2521c7a52 | com_534fe02900d9 | 4 | NETWORK_ACTIVITY | 1 | false |
| stg_bf1403b99ae1 | com_534fe02900d9 | 1 | EXECUTION | 1 | false |
| stg_bf4790cc9978 | com_852f7a8a4e4b | 1 | WEB_EXPLOIT | 0 | true |
| stg_c8ee355ab042 | com_852f7a8a4e4b | 1 | UNKNOWN | 0 | true |
| stg_df82e342b81e | com_534fe02900d9 | 12 | AUTHENTICATION | 9 | false |
| stg_f0519a7e90bd | com_2f866f370eae | 10 | NETWORK_ACTIVITY | 0 | true |
| stg_f40f3ce3839c | com_534fe02900d9 | 1 | FILE_ACTIVITY | 1 | false |
| stg_f9053c4d234e | com_852f7a8a4e4b | 2 | UNKNOWN | 0 | true |

## 24个孤立Stage逐项归因

| Stage | Candidate | Non-candidate | Rejected | Primary | Secondary |
|---|---:|---:|---:|---|---|
| stg_0162caf00773 | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_0729c64eebea | 1 | 40 | 1 | CANDIDATES_ALL_REJECTED | {"NO_VALID_EVIDENCE":1} |
| stg_12cb2c433248 | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_1cba0377af41 | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_2101a5462914 | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_2ceb3ea18888 | 3 | 38 | 3 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":3} |
| stg_5c819f3778de | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_6105e882735a | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_6187b9282a03 | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_64c5ca4d2078 | 17 | 24 | 17 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":17} |
| stg_66e73630d582 | 3 | 38 | 3 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":3} |
| stg_751bc093457c | 3 | 38 | 3 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":3} |
| stg_7e951854ce84 | 0 | 41 | 0 | NO_CANDIDATE_GENERATED | {} |
| stg_82a13243d7d9 | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_89ffedad3d3e | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_9849909a6174 | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_9f7118dd1b89 | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_a504ee355dcc | 3 | 38 | 3 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":3} |
| stg_abe9f4e0e33e | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_b83800e80d59 | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_bf4790cc9978 | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_c8ee355ab042 | 9 | 32 | 9 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":9} |
| stg_f0519a7e90bd | 2 | 39 | 2 | CANDIDATES_ALL_REJECTED | {"NO_VALID_EVIDENCE":2} |
| stg_f9053c4d234e | 17 | 24 | 17 | CANDIDATES_ALL_REJECTED | {"SHARED_CONTEXT_ONLY":17} |

零候选Stage完整ID：`stg_7e951854ce84eec740043576654349ff11fa133b153bec8c5a3ca811c912175e`（4条Suricata告警，UNKNOWN）。31个其它Stage没有共享检索键；其余10个虽共享IP端点，但公共弱键及Context-only键不独立召回。唯一未被这些键限制的url_endpoint_pair提示与另一Stage相隔460秒，被现有120秒窗口排除。它的完整native Flow/五元组没有其它Stage使用相同键。这里没有证明该弱提示应建立关系，也没有对未进入⑧的Pair进行反事实决策。其现有特征及非候选排除路径见zero_candidate_stage.json；不根据⑨定义孤立。

## 文件与核验

- summary.json / acceptance.txt：全部要求的验收字段。
- stages.json：42个Stage及来源覆盖；pairs.json：861个Pair及⑦实际代码路径。
- decisions.json / accepted_relations.json / rejected_pairs.json：165个正式Decision及证据。
- isolated_stages.json：24个degree=0节点逐个根因、候选数及证据分类。
- projection_audit.json / stage8_postings.json：绑定、实体、投影和原始索引核对。
- network_scope_audit.json：4个Connection召回线索未形成可信Relation的原始scope。
- trace_tables.json：原始Claim/Context/Observation/Validation/Raw Pointer及解析值。
- execution.json：原正式函数调用统计、原始源代码定位和源码哈希。
- integrity.json：已有生产代码、配置、⑨输出及Dataset/GT文件哈希核验。

诊断复现：`.venv\Scripts\python.exe -B scripts/audit_stage8_relation_sparsity.py --output outputs/stage8_relation_sparsity_audit_repeat`。首次运行在新输出目录自动建立只读保护基线。

测试：`.venv\Scripts\python.exe -B -m pytest tests/audit-only/test_stage8_relation_audit.py -q -p no:cacheprovider`（测试默认核验本轮outputs/stage8_relation_sparsity_audit下的完整审计结果）。

所有根因均基于当前代码、原始输出与实际执行分支；没有重接纳Pair，没有改变关系、阈值、数据或GT。

## 验证记录

20项诊断测试全部通过。419个既有文件哈希均未变化，其中包含18个Dataset/GT文件；GT仅参与字节哈希保护，未解析内容、未用于归因。⑦/⑧完整重放输出逐字段等于冻结结果，已有⑨代码与产物未变。

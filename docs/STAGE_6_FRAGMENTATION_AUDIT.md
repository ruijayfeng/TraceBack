# ⑥ Community → Stage 孤立Stage过度切分审计

## 1. 正式输入与完整性

**输入差异：** 当前125 Alert / 42 Stage / 23 Relation对应冻结after.json实际为3个Community；5个来自身份投影修复前before.json。没有把旧5个Community与当前23条关系混用，没有补造两个Community。社区成员由冻结Stage.community_id与Alert IDs汇总，不重跑⑤。

只读取冻结Stage、BehaviorAnnotation、aggregation_basis、diagnostics、Entity/Context/raw；读取⑧关系端点仅用于degree及禁止误合并。没有执行Stage Builder、pair_evidence、Weak Bridge恢复、⑦、⑧或⑨。

输入：[after.json](D:/Code_WorkSpace/TraceBack/outputs/stage2_identity_projection/after.json)。SHA-256：`51f9b9a50b55405c6380788f3cdd0d36854ad47f33c2d80554823eb4282464df`。原有489个受保护文件逐字节哈希不变，其中18个Dataset/GT文件仅作完整性哈希，GT不参与判断。

## 2. 42个Stage粒度统计

Stage大小分布：`{"1":27,"2":4,"4":4,"5":1,"8":1,"10":2,"12":1,"14":1,"15":1}`。单告警27、多告警15；孤立Stage中单告警17、多告警7。15个多告警Stage承接98条Alert，不能仅根据27个singleton断定整体过切。

42个现有Stage均保留一致Behavior与连通聚合证据；229条最终聚合依据全部STRONG。Stage内未直接连边的Alert Pair仍可通过其它Alert连通，因此不能把所有被拒Alert Pair都当成Stage边界。

真实入口为`backend/app/stages/aggregation.py::aggregate_stages`，调用`community_graph`后按`connected_components`形成Stage。冻结记录1510次候选Alert Pair判定，229条保留、1281条拒绝；Component conflict拒绝0、Index pruning 0。42是保留图的连通分量数，singleton也是合法分量。全部成员对已核验无hard_conflict，每条冻结聚合边的原始证据指针与时间准入均通过核验。每个Stage的全部原始字段、成员注释和规则依据见stages.json及stage6_rule_references.json。

## 3. 5个Community内部Stage分布

本节沿用请求标题，但实际输入只有下面3个Community。HIGH_FRAGMENTATION_COMMUNITY_CANDIDATE只表示含孤立singleton的审计优先对象，不是生产阈值或过切结论。

| Community | Alerts | Stages | Sizes | Isolated | Relation participants |
|---|---:|---:|---|---:|---:|
| com_2f866f370eae25f3b33356aa671be707c9160d8cebe5ca2b529d54683593881e | 47 | 7 | [1, 4, 4, 5, 8, 10, 15] | 1 | 6 |
| com_534fe02900d93d95209bed576d92290453728f775895c6659df7eeaa0f048798 | 39 | 15 | [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 4, 10, 12] | 5 | 10 |
| com_852f7a8a4e4bb0c08a117e44a093813ab3e9085c4715c9b9a3c6bddc839f77d3 | 39 | 20 | [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 4, 14] | 18 | 2 |

## 4. 24个孤立Stage逐项分析

完整ID、最近邻、同身份与支持背景、真实hard conflict、潜在审计目标及置信度说明均在isolated_stages.json；所有neighbor_pairs只来自同Community且至少一端孤立。

| Stage | Alerts | Behavior | Nearest gap(s) | Class |
|---|---:|---|---:|---|
| stg_0162caf00773edb255001b8291c60bdc458e8ca32161f1fa3e54486794ca62b4 | 1 | NETWORK_ACTIVITY | 0 | LEGITIMATE_SINGLETON_STAGE |
| stg_0729c64eebea5a424eb7688e93610325498973af94d249bf07f356d471a570b7 | 10 | NETWORK_ACTIVITY | 0 | AMBIGUOUS |
| stg_12cb2c4332489751b0fa07d383423c590dda89c2d887e4ee5830d3e3fa6d3f5b | 1 | WEB_EXPLOIT | 0 | LEGITIMATE_SINGLETON_STAGE |
| stg_1cba0377af410e8a3668a23a3d5f50eecd8505a6befd4401024a1799192a7016 | 1 | UNKNOWN | 28.0 | LEGITIMATE_SINGLETON_STAGE |
| stg_2101a5462914cd4686d80d013a18c75fc7f8b003356ac9fcdda9e040994577e9 | 1 | UNKNOWN | 28.0 | LEGITIMATE_SINGLETON_STAGE |
| stg_2ceb3ea188884947c6587d509a7dc861121f497703ac6fec976d65684da16375 | 2 | UNKNOWN | 0 | POSSIBLE_TIME_OVER_FRAGMENTATION |
| stg_5c819f3778de432318fc0615ccc56141a920c83c348d9c8cc89d2251ffbb56ee | 1 | UNKNOWN | 28.0 | LEGITIMATE_SINGLETON_STAGE |
| stg_6105e882735afc81965ffaeaa52147e5ea9dc31523ef284130575e28d46a6912 | 1 | NETWORK_ACTIVITY | 21.0 | LEGITIMATE_SINGLETON_STAGE |
| stg_6187b9282a030649d5a7c5abaada1c0d0a09eb0d4da4ea8e8bc6cf33c3dd2561 | 1 | UNKNOWN | 28.0 | LEGITIMATE_SINGLETON_STAGE |
| stg_64c5ca4d20787d0ed00fd2db32b8b68e5fb9e7b530bf13abf2348cc8bcb5b952 | 2 | UNKNOWN | 21.0 | LEGITIMATE_SEPARATE_STAGE |
| stg_66e73630d582250e4743d6852be30b293ef5c4048a7c0e2f399dce0b634c781f | 1 | UNKNOWN | 0 | POSSIBLE_TIME_OVER_FRAGMENTATION |
| stg_751bc093457c6e2a7f68655e784cd359f1c16a36b444ced4d4c241274bb6bed2 | 1 | UNKNOWN | 0 | POSSIBLE_TIME_OVER_FRAGMENTATION |
| stg_7e951854ce84eec740043576654349ff11fa133b153bec8c5a3ca811c912175e | 4 | UNKNOWN | 0 | LEGITIMATE_SEPARATE_STAGE |
| stg_82a13243d7d92a57323b4465a35c8e4083218d26de96df98308a136ac9a1417f | 1 | WEB_EXPLOIT | 21.0 | LEGITIMATE_SINGLETON_STAGE |
| stg_89ffedad3d3e70ec2e7f5f5df3c0af6cec5a51048df641efdebdcba4fb786e4e | 1 | UNKNOWN | 28.0 | LEGITIMATE_SINGLETON_STAGE |
| stg_9849909a6174fc269a0955c873282ef48a58146eb9225591dab29c035d288511 | 1 | WEB_EXPLOIT | 21.0 | LEGITIMATE_SINGLETON_STAGE |
| stg_9f7118dd1b89c7f2022f16f8cea77c02a6f22d734237f9cc4df4a1a6adc1877d | 1 | UNKNOWN | 28.0 | LEGITIMATE_SINGLETON_STAGE |
| stg_a504ee355dcc7b2ec516b34fc57e7a0a6e607a778eba507956875cd85c4eb1ca | 1 | UNKNOWN | 0 | POSSIBLE_TIME_OVER_FRAGMENTATION |
| stg_abe9f4e0e33e8c530d39213dae601354a4f50d205966018d5e40022c9d236458 | 2 | UNKNOWN | 0 | LEGITIMATE_SEPARATE_STAGE |
| stg_b83800e80d59b6027a725797c5d5d34eab3f0ec252cfcdaf5a84e2defd24915f | 1 | UNKNOWN | 0 | LEGITIMATE_SINGLETON_STAGE |
| stg_bf4790cc9978744dd19905ad6762de210ef9edc8f15801e9470061380dac6462 | 1 | WEB_EXPLOIT | 0 | LEGITIMATE_SINGLETON_STAGE |
| stg_c8ee355ab0424764248473d5f1c1e52260008f7958b10dd7fba6b3004c1fef1a | 1 | UNKNOWN | 21.0 | LEGITIMATE_SINGLETON_STAGE |
| stg_f0519a7e90bd5c61a5ef819b56f94daaea789b8faa9e86a846029a47733a87d3 | 10 | NETWORK_ACTIVITY | 286.0 | AMBIGUOUS |
| stg_f9053c4d234edbeb5dc1ab07f20b26998d8870c1642ab2ce1fab176fbf480d74 | 2 | UNKNOWN | 21.0 | LEGITIMATE_SEPARATE_STAGE |

[24项完整字段表](D:/Code_WorkSpace/TraceBack/outputs/stage6_fragmentation_audit/ISOLATED_STAGE_DETAILS.md)逐项包含请求的全部字段；[全部255对邻居证据](D:/Code_WorkSpace/TraceBack/outputs/stage6_fragmentation_audit/neighbor_pairs.json)保留原始拒绝记录及成员级审计。

## 5. Behavior / UNKNOWN影响

39条Alert的原注释为UNKNOWN，形成19个Stage，其中16个孤立。原始原因全部mapping_no_reliable_match:provider_not_configured；没有聚合后丢标签或多行为冲突变UNKNOWN的证据。不能将无可靠匹配直接说成Mapping缺陷。

unknown_requires_typed_binding实际拒绝数为0。另有4对在Stage6五元组口径下只被UNKNOWN/已知标签边界阻断，但缺少可信跨源原生Flow身份，涉及5个孤立Stage；不据此重标Behavior或认定同一动作。

## 6. Identity连续性分析

孤立Stage同Community邻居中：相同完整当前Process实例0对，父子Process0对，仅描述符0对。Auth/Request/Object及网络实例按现有scope分开，不把Host/Account/IP相同当实例证据。

相同Auth Session、Request、Object和network_session的孤立端点邻居Pair均为0；因此本次没有可判为auth establish/use或request/response的同实例边界。不依据同Account、同Host或操作词自行生成角色关系。Web支持事实另记录原始URL、endpoint(ip,port)、method和方法字段原始指针；它们不替代Request实例。

现行⑥flow Binding是完整五元组（仅在声明时附network_namespace）；它不同于⑧原生flow_id+source scope+tuple。两对Firewall↔EDR边界虽匹配⑥tuple，但没有跨源网络authority，标AMBIGUOUS，不认定过切或重复。

## 7. 时间约束分析

最近Stage间隔分布：`{"count":24,"max":286.0,"median":21.0,"min":0,"p75":28.0,"p90":28.0}`。实际阈值来自同Community、同Behavior的先前Alert历史：不足3个历史interval用30秒，否则mean+std并限制在[5,300]秒。当前Alert不参与自身阈值训练。

明确的局部设计疑点：同源IDS的5条Repeated uncommon outbound polling，具有同一原生Flow、相同完整tuple、相同/health/poll URL、相同签名和UNKNOWN标签，每42秒出现一次。前三条边界因30秒fallback被切开，直到先前历史已有3个interval后阈值成为42秒，最后两条形成一个Stage。结果为4 Stage（1/1/1/2 Alert），没有成员hard conflict。只报告冷启动过切可能性，不调整fallback或Mapping。

满足同实例、连续观测且全部成员无冲突的时间边界审计Pair为3对，涉及4个孤立Stage。

配置中的max_stage_span_seconds/unknown_max_stage_span_seconds并未被当前threshold-graph Stage Builder读取为全Stage时间上限；实际依据是动态局部边与连通性，不能拿这两个字段替代真实切分路径。

## 8. Hard Conflict分析

同Behavior邻居实际被hard-conflict谓词拒绝的Stage Pair为81。真实类型见hard_conflict_audit.json。另3个看似时间相近、共享Flow的Stage（stg_64c5…、stg_c8ee…、stg_f905…）存在成员级distinct_strong_context，不能仅用干净的一对成员证明整个Stage可合并。

生产统计字段HARD_CONFLICT_REJECT_COUNT=1281同时计入semantic_conflict与dynamic_time_conflict；本报告不把1281全部说成实体hard conflict。

跨Stage原始拒绝原因：`{"distinct_observed_command":55,"distinct_observed_url":210,"distinct_strong_context":6,"dynamic_time_conflict":106,"semantic_conflict":715}`，总计1092次Alert Pair判定；另189次dynamic_time_conflict发生在同一Stage成员之间，仍通过其它边连通，不能计作189个Stage切分。真实hard conflict类型为distinct_observed_url、distinct_observed_command、distinct_strong_context。完整诊断保留于split_reasons.json，不发明新的生产拒绝状态。

## 9. Weak Bridge Removal分析

冻结结果WEAK_STAGE_EDGE_COUNT=0、WEAK_BRIDGE_REMOVED_COUNT=0，没有Stage由弱桥删除形成。BRIDGE_EDGE_COUNT=34是结构桥数量，不是被删除弱桥数量。本次不调用weak_bridge_check或恢复任何边。

## 10. 跨源重复观测分析

未发现有可信同实例、同语义、重叠观测且无冲突的孤立Stage重复证据。仅完整五元组相同而source scope未认证的跨源Pair仍不确定；WAF/IDS观测若UNKNOWN与已知语义不同也不能直接改标签合并。

duplicate_observation_audit.json逐对保留筛选结果：重复观测要求原标签一致、可信同实例、成员无冲突、无Process进展角色及时间区间重叠；跨源疑似同动作要求有可信同实例且局部时间合格的实际成员见证。结果均为0，表示本轮范围内未证明，并非断言跨源重复永远不存在。

## 11. 疑似过度切分Stage

24个孤立Stage分类：`{"AMBIGUOUS":2,"LEGITIMATE_SEPARATE_STAGE":4,"LEGITIMATE_SINGLETON_STAGE":14,"POSSIBLE_OVER_FRAGMENTATION":0,"POSSIBLE_TIME_OVER_FRAGMENTATION":4,"POSSIBLE_UNKNOWN_BEHAVIOR_FRAGMENTATION":0,"POSSIBLE_WEAK_BRIDGE_OVER_PRUNING":0}`。整体42个：合理36、疑似过切4、不确定2。整体口径为42个内部冻结证据核验加孤立Stage同Community边界审计，没有对非孤立Stage任意全Pair推断合并。

## 12. WHAT-IF Merge分析

严格仅对POSSIBLE_OVER_FRAGMENTATION类别C允许endpoint folding。本轮类别C为0；时间类别D仍违反当前时间准入、没有被授权按放宽规则合并，因此WHAT_IF_MERGE_PAIR_COUNT=0，Stage数42，孤立数24。23条关系仅逐条映射原端点，不新增关系、不重跑⑧。

GRAPH_BEAUTIFICATION_NOT_USED_AS_EVIDENCE=true。没有用合并后图更漂亮或孤立减少判断正确性。

## 13. 是否应该修改⑥

不支持整体重设计或放宽实体/行为条件。值得下一阶段单独验证动态时间冷启动：已有42秒稳定周期、但当前尚不足3个历史interval时fallback固定30秒的局部影响。先定义验证口径和独立数据，再决定是否修改；本轮不提出新的阈值、不修复。跨源tuple没有可信scope的两例先补证据审计，不能直接合并。

## 14. 最终结论

STAGE6_FRAGMENTATION_PARTIAL：只发现4个同源轮询Stage的局部时间切分疑点；未发现整体系统性过切。UNKNOWN专属拒绝、Weak Bridge删除、可信Process/Auth/Request重复切分均未被证明为本批孤立的根因。

这些Stage仍满足当前正式时间规则；“局部疑点”是规则设计值得验证，不能写成已经证明实现违反合同。下一步仅值得单独验证冷启动历史不足的时间影响，尚不支持修改Mapping、Identity、Source scope或Weak Bridge政策。

最终验收字段：

```text
TASK_RESULT="SUCCESS"
AUDIT_ONLY=true
STAGE_6_FRAGMENTATION_AUDIT="PASS"
FINAL_DIAGNOSIS="STAGE6_FRAGMENTATION_PARTIAL"
INPUT_ALERT_COUNT=125
INPUT_COMMUNITY_COUNT=3
REQUESTED_BACKGROUND_COMMUNITY_COUNT=5
INPUT_COMMUNITY_COUNT_MATCHES_REQUEST=false
INPUT_COMMUNITY_COUNT_DISCREPANCY="5 is pre-identity-projection snapshot; the frozen current 23-relation snapshot has 3."
INPUT_STAGE_COUNT=42
INPUT_ISOLATED_STAGE_COUNT=24
SINGLE_ALERT_STAGE_COUNT=27
MULTI_ALERT_STAGE_COUNT=15
ISOLATED_SINGLE_ALERT_STAGE_COUNT=17
ISOLATED_MULTI_ALERT_STAGE_COUNT=7
STAGE_ALERT_COUNT_DISTRIBUTION={"1": 27, "10": 2, "2": 4, "15": 1, "5": 1, "4": 4, "8": 1, "14": 1, "12": 1}
UNKNOWN_STAGE_COUNT=19
ISOLATED_UNKNOWN_STAGE_COUNT=16
UNKNOWN_ALERT_COUNT=39
ISOLATED_STAGE_WITH_SAME_BEHAVIOR_NEIGHBOR_COUNT=24
POTENTIAL_FRAGMENTATION_DUE_TO_UNKNOWN_BEHAVIOR_COUNT=0
UNKNOWN_RESTRICTIVE_GATE_REJECTION_COUNT=0
UNKNOWN_LABEL_ONLY_BLOCK_WITH_STAGE6_TUPLE_PAIR_COUNT=4
UNKNOWN_LABEL_ONLY_BLOCK_WITHOUT_TRUSTED_CROSS_SOURCE_IDENTITY_STAGE_COUNT=5
SAME_PROCESS_INSTANCE_STAGE_PAIR_COUNT=0
PARENT_CHILD_PROCESS_STAGE_PAIR_COUNT=0
PROCESS_DESCRIPTOR_ONLY_PAIR_COUNT=0
IDENTITY_COUNT_SCOPE="unique same-Community neighbor pairs incident to at least one frozen degree-zero Stage"
HARD_CONFLICT_FRAGMENTATION_PAIR_COUNT=81
ISOLATED_STAGE_CREATED_BY_WEAK_BRIDGE_REMOVAL_COUNT=0
FROZEN_WEAK_BRIDGE_REMOVED_COUNT=0
FROZEN_STRONG_EDGE_COUNT=229
FROZEN_NORMAL_EDGE_COUNT=0
FROZEN_WEAK_EDGE_COUNT=0
POTENTIAL_TIME_OVER_FRAGMENTATION_COUNT=4
POTENTIAL_TIME_OVER_FRAGMENTATION_PAIR_COUNT=3
POTENTIAL_DUPLICATE_STAGE_PAIR_COUNT=0
POTENTIAL_CROSS_SOURCE_DUPLICATE_STAGE_COUNT=0
LEGITIMATE_SINGLETON_STAGE_COUNT=14
LEGITIMATE_SEPARATE_STAGE_COUNT=4
POSSIBLE_OVER_FRAGMENTATION_COUNT=0
POSSIBLE_TIME_OVER_FRAGMENTATION_COUNT=4
POSSIBLE_UNKNOWN_BEHAVIOR_FRAGMENTATION_COUNT=0
POSSIBLE_WEAK_BRIDGE_OVER_PRUNING_COUNT=0
AMBIGUOUS_ISOLATED_STAGE_COUNT=2
ISOLATED_STAGE_CLASS_COUNTS={"LEGITIMATE_SINGLETON_STAGE": 14, "LEGITIMATE_SEPARATE_STAGE": 4, "POSSIBLE_OVER_FRAGMENTATION": 0, "POSSIBLE_TIME_OVER_FRAGMENTATION": 4, "POSSIBLE_UNKNOWN_BEHAVIOR_FRAGMENTATION": 0, "POSSIBLE_WEAK_BRIDGE_OVER_PRUNING": 0, "AMBIGUOUS": 2}
LEGITIMATE_STAGE_COUNT=36
POTENTIALLY_OVER_FRAGMENTED_STAGE_COUNT=4
AMBIGUOUS_STAGE_COUNT=2
GLOBAL_CLASSIFICATION_SCOPE="all 42 frozen intra-stage proofs plus isolated-stage same-Community boundaries; no arbitrary non-isolated/non-isolated merge search"
WHAT_IF_MERGE_PAIR_COUNT=0
WHAT_IF_STAGE_COUNT=42
WHAT_IF_ISOLATED_STAGE_COUNT=24
GRAPH_BEAUTIFICATION_NOT_USED_AS_EVIDENCE=true
PRODUCTION_STAGE6_MODIFIED=false
PRODUCTION_STAGE7_MODIFIED=false
PRODUCTION_STAGE8_MODIFIED=false
PRODUCTION_STAGE9_MODIFIED=false
RELATION_CREATED=false
THRESHOLD_MODIFIED=false
BEHAVIOR_MAPPING_MODIFIED=false
DATASET_MODIFIED=false
GROUND_TRUTH_MODIFIED=false
STAGE_SPLIT_REASON_COUNTS={"dynamic_time_conflict": 106, "semantic_conflict": 715, "distinct_observed_url": 210, "distinct_strong_context": 6, "distinct_observed_command": 55}
ALL_FROZEN_REJECTION_REASON_COUNTS={"dynamic_time_conflict": 295, "semantic_conflict": 715, "distinct_observed_url": 210, "distinct_strong_context": 6, "distinct_observed_command": 55}
INTRA_STAGE_REJECTION_COUNTS={"dynamic_time_conflict": 189}
OFFICIAL_HARD_CONFLICT_COUNTER_LABEL_INCLUDES_SEMANTIC_AND_TIME=true
NEAREST_STAGE_GAP_DISTRIBUTION={"count": 24, "min": 0, "median": 21.0, "p75": 28.0, "p90": 28.0, "max": 286.0}
NEIGHBOR_STAGE_PAIR_COUNT=255
ALL_EXISTING_STAGES_SATISFY_CURRENT_FROZEN_CONTRACT=true
FILES_CHANGED=["scripts/audit_stage6_fragmentation.py", "tests/audit-only/test_stage6_fragmentation_audit.py", "docs/STAGE_6_FRAGMENTATION_AUDIT.md", "outputs/stage6_fragmentation_audit/"]
```

复现：`.venv\Scripts\python.exe -B scripts/audit_stage6_fragmentation.py --output outputs/stage6_fragmentation_audit_repeat`。测试：`.venv\Scripts\python.exe -B -m pytest tests/audit-only/test_stage6_fragmentation_audit.py -q -p no:cacheprovider`。

验证结果：28项诊断测试通过，测试结果见 outputs/stage6_fragmentation_audit/diagnostic_tests.xml。原有489个文件（含18个Dataset/GT文件）哈希保持不变，原始证据指针解析6601次成功。完整性证据见 integrity.json。

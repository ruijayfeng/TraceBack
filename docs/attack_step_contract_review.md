# Attack Step 契约校准、案例走查与评估冻结 v1.1

日期：2026-10-22；结论：契约可冻结用于后续独立授权的离线只读原型。**本次没有生成真实语义分组结果，也没有实现或执行语义评估器。** 四案结论是对封存证据的契约预期，不能当作算法成绩。

## 1. 实际核查范围与封存依据

设计基线：`docs/ATTACK_STEP_SEMANTIC_CONTRACT.md` 原 v1.0。已核查 `stages/models.py`、聚合/证据逻辑，`stage_candidates/models.py`，`stage_evidence/contracts.py/config.py/extraction.py/claims.py`，`stage_chains/reconstruction.py/pipeline.py`，`entities/identity_projection.py/extraction.py`、`models/alerts.py`，`community/models.py` 及 `services/stage_pipeline.py` 正式依赖链。旧兼容模型不能按同名替代正式接口。

下列要求文件全部找到，路径相对于项目根目录：

| 文件 | 实际位置与用途 |
|---|---|
| stage8.json / stage9.json | `outputs/stage9_formal_acceptance_20261022/run1/`；同目录 run2、⑥审计 formal_run 为一致副本 |
| stage6_input_snapshot.json | `outputs/stage6_oversegmentation_audit_20261022/`；只读输入快照审计 |
| algorithm_stages.json | 同上；动作 Stage 明细审计 |
| gt_stage_fragment_mapping.json | 同上；仅离线案例导航 |
| stage_fragment_pair_audit.jsonl | 同上；13 个同 GT 分片 pair 审计 |
| evidence_trace_paths.json / evidence_trace_summary.json | `outputs/stage9_formal_acceptance_20261022/`；原始引用链检查报告 |
| 补充证据 | ⑥目录中 `alert_pair_decision_decomposition.jsonl`、`component_union_rejection_ledger.json`、`cross_gt_rule_risk_witnesses.json`、`alert_input_descriptors.json`、`evidence_examples.json`、`successful_stage_controls.json` |

正式输入 SHA256：`e9b34c8025372ef2e5a942bde0106f3e3633668fdc2213726f4afc5b9f399ac8`。

S8 字节 SHA256：`ef5eefa0a8957a7e30716c609bf3887f4dcf373336d57f04e1912ce22f0cd1c9`。

S9 字节 SHA256：`6f315331edb928cdd7b0dd436e999df342252ea04f050916d47806a2bed0c40d`。

S9 graph input digest：`4cbbae7592afde8819abbea025875a613aad41ac0fba9d68b0c1878f16f29825`，不是 S9 文件 SHA。

封存基线为 125 告警、1 Community、15 Action Stage、9 有向关系、3 无向关系、17 NO_RELATION、7 Chain（1 个 9 Stage 分量与 6 singleton）。原追溯报告记录 141 claims、3731 observations、998 pointer records；路径出现次数为 Stage 15、relation 12、witness 6539、raw evidence 13772；去重后 125 告警/702 raw locations。计数单位不可混用。这些是上游已封存验收结果，不是新语义层的指标。

本轮将四案真实 Stage ID、代表 alert、12 条接受关系及其首个完整 trace 摘录到 `outputs/attack_step_contract_freeze_20261022/review_evidence_extract.json`。文件明确标记 audit_only_contains_gt，禁止进入未来分组输入。

## 2. 四案逐项走查

以下 GT-Sxx 只作历史审计标题；运行时不能读取它们、GT 名称、阶段序号或预期组数。短 ID 仅用于本段排版，完整 ID 在上述摘录及原表中。

### 案例 A：GT-S02，不同 HTTP 活动

1. **已有证据：**5 个 Stage：`429808…` 1 条 `/api/upload/init?filename=invoice.cgi`；`828cf9…` 5 条 `/phpinfo.php`；`ace7b6…` 3 条 XSS `/search?q=…script…`；`f15ad2…` 3 条 SQL `/search?q=…OR…`；`f78cc7…` 3 条 traversal `/download?file=../../etc/passwd`。同 TCP flow、同社区，存在不同精度的 IDS/WAF 观测。九次组级合并 veto 已封存。
2. **保留差异：**完整 URL/query、请求角色、上传初始化与探测行为、不同 source/behavior。XSS 部分 WAF block 映射 NETWORK_ACTIVITY，SQL/traversal 映射 WEB_EXPLOIT；本轮不纠正映射或抹掉区别。
3. **直接跨动作证据：**五个分片之间没有已接受⑧关系；同流是上下文，不等于同 request 或同一高层目的。⑥部分 pair 曾通过不等于整个语义组证明通过。
4. **高层步骤支持：**四种探测可以提出有限“相关 Web 活动”假设，但不足确认；不能从探测类别进一步宣称相同攻击者意图。上传初始化与它们的共同目的更不明确。
5. **预期状态：**四类探测之间的六个 pair 可为 WEB_ACTIVITY_CANDIDATE / CANDIDATE / E3；涉及初始化的四个 pair 为 UNRESOLVED。整个五 Stage 提案为 UNRESOLVED。全部主归属 null；无接受边，真实断连。此前⑥审计的 POSSIBLY_MERGEABLE / SHOULD_NOT_MERGE 是动作契约评价，不直接复制成本层状态。
6. **不得推断：**相同 flow 不推出同 request/session 生命周期、同攻击目的或新的跨 Chain 边；不同 URL 也不自动证明高层活动互斥。
7. **确认阻碍：**没有满足 P1 的 REQUEST_RESPONSE、同一完整 request 与全部告警覆盖。现有证据不会因同 GT 而补齐。
8. **原型测试：**正例是“可表达差异的候选并保留断连”；确认正例需另用完整 typed 请求/响应测试夹具。反例包括共享 TCP flow 的多请求、通用 IDS 观测桥接不同具体 URL、将五个分片强制合为一组。预期不得 CONFIRMED。

### 案例 B：GT-S04，ApplicationRequest 与子 Shell

1. **已有证据：**`stg_cb94b77d4371e92f997ed8d36aa5491e13e8096d34d68a54f74cd9787d89f6d6` 为 1 条 ApplicationRequest、nginx worker、UNKNOWN；`stg_f1e575748b70996517070ec2fb1e3c2af4a35dbb1b83f86743e83bd27bfa1e2c` 为 9 条执行/文件活动，命令 `/bin/sh /var/www/uploads/invoice.cgi`。请求、host/account、auth session 与父子身份有现有绑定支持。
2. **保留差异：**父进程 nginx 1820 与子 shell 2800、请求动作与执行/文件动作、UNKNOWN 与 EXECUTION/FILE_ACTIVITY、原时间和命令。
3. **直接证据：**有接受关系 `scp_84a572164eb3c647f81d029ec2ed784244aa2cca446d34d3bd8080e05e73d3bf`；primary claim `ecl_ade08f85c479c807e75a4d00722db9a731a58af43c2664ca4e3ed8d818b3eb08` 为 PARENT_CHILD_PROCESS，9 observations。这是 E2 的关联证明，不是 REQUEST_RESPONSE。
4. **高层步骤支持：**可以提出“请求关联执行”的具体假设；父子和请求上下文尚不能证明每个成员都属于同一个边界明确的高层步骤。
5. **预期状态：**REQUEST_EXECUTION_CANDIDATE / CANDIDATE / E2；同 Chain 且该 pair 有接受连接，disconnected_members=false；主归属 null。
6. **不得推断：**父进程全部请求、全部子进程同目的；时间相隔 12 秒是因果；请求成功导致攻击成功。⑥的 9 pair 首次不足语义条件及潜在不同命令，不自动变成本层硬冲突。
7. **确认阻碍：**没有 P1 角色证明；没有冻结的请求触发 shell 的全成员目的档案。关系 witness 可追溯并不填补目的缺口。
8. **原型测试：**正例保留父子关联及候选解释；反例同一 Web worker 服务多个请求、子进程执行后续独立动作、相同 PID 不同启动时间、缺 request authority。不得因 parent-child 自动确认。

### 案例 C：GT-S05，读取与使用 SSH 私钥

1. **已有证据：**`stg_e162b931677ed97b3c416141cb27c5184c70b1f84915c120f069012dccc1a280` 为 23 条执行/文件观测，命令 `cat /var/lib/backup/.ssh/id_ed25519`；`stg_77eeabec52ab3cb1acaa9f76df40979c6601a85e0b5453d5fba82740a9c1ccc2` 为 4 条网络观测，命令 `ssh -i /var/lib/backup/.ssh/id_ed25519 svc_backup@10.0.1.51`。host/account、auth session、lineage 有证据。
2. **保留差异：**读取文件与启动 ssh/网络行为、2800 与 2900 两个进程、不同命令及远端主机；不可把 network Stage 改成“已成功登录”。
3. **直接证据：**接受关系 `scp_65332ef6a64eb28ebb0e27eb2d2c81c785153df127f8a9bd7bd8ed87476d0dd5`；primary claim `ecl_8490592e018ba9624746d96d1de7a067de179ca3e0408ca76e7d7e0c21716f30` 为 PARENT_CHILD_PROCESS，92 observations。命令含同一路径可作为有限描述，但不等于原生 credential material 身份与使用成功证明。
4. **高层步骤支持：**支持“疑似凭据相关活动”候选，不足确认同一高层目的；读取、指定身份文件和认证成功是不同断言。
5. **预期状态：**CREDENTIAL_ACTIVITY_CANDIDATE / CANDIDATE / E2；现有 pair 连通；主归属 null。
6. **不得推断：**路径字符串等同文件内容/密钥身份；`-i` 一定被实际采用或认证成功；同 session/lineage 的其他文件操作都属于该步骤。不新增命令解析器、credential field 或 relation。
7. **确认阻碍：**现模型无已冻结的“读取—实际使用”目的证明档案；命令字符串不提供全部成员凭据角色/对象版本绑定。P1 不适用。
8. **原型测试：**正例能忠实引用命令、路径和父子关系而停留候选；反例同路径但文件被替换、ssh 使用另一凭据/认证失败、同父进程其他活动、只出现命令文本而无执行证据。

### 案例 D：GT-S07，入站 SSH transport 与主机活动

1. **已有证据：**`stg_7e46d13cb4396e0f7873b1ff65edb608208bee5ff11b4315d1b5c1a452274106` 为 10 条 FW 入站 SSH；`stg_69a22fb548cfdf87f7e2d6ba0ac9ce9ee9b877cff175d7602a5aa2e2dc0e6f02` 为 12 条 EDR 执行/文件/网络活动，`bash /tmp/health-poll.sh`。入站 tuple 为 `10.0.1.5:51220 → 10.0.1.51:22`，connection `130ed8ffee09f24743dea5bc`；后续 EDR 出站为 `10.0.1.51:53310 → 203.0.113.99:443`，connection `8588bb0dcc1b46c2729f2889`；auth logon `5f56dde0506552b6c4b9943e` 是另一身份域。
2. **保留差异：**入站 transport、主机执行、出站连接、端口、角色及作用域；不能把入站 SSH 与出站 443 当同一连接。
3. **直接证据：**这两个分片之间没有接受关系。120 个跨分片 alert pair 没有完整共同 typed binding；其中 40 个网络 pair 有同权威不同 token 冲突，另 80 个 process/file 与 FW pair 缺精确 recall key。
4. **高层步骤支持：**目前无法证明入站连接与后续全部主机活动属于同一步骤；共同主机/时间不能填补认证到 transport 的缺口。
5. **预期状态：**整个两 Stage 提案为 UNRESOLVED / E3（仅上下文）；不同 Chain，disconnected_members=true，主归属 null。若提案进一步声称入站和出站是“同一 connection”，该更强提案按 D07 REJECTED；不能把此拒绝扩张为否认任何高层关联。
6. **不得推断：**日志中缺失的 transport→auth→process 绑定、入站 session 驱动每个后续进程、未出现的关系边或连续路径。
7. **确认阻碍：**没有跨两 Stage 的直接全路径证据，也没有适用目的档案。跨 Chain 确认本版本明确不支持。
8. **原型测试：**正例是如实表达未知、保留两个原 Chain；反例为因主机、时间、SSH token 复用而补边，或把入站/出站 identity 混为一谈。

四案均没有 REQUEST_RESPONSE claim；整个封存⑧中该类型数量也为 0。因此不能以本次审阅宣称任何真实 P1 确认正例通过。合成 Schema 例仅证明结构约束；未来 P1 行为测试须另行提供完整证据夹具。

## 3. 跨 GT 误合并反例

标签用于评估错误性质，不参与阻止规则本身。运行时拦截依据均为“关联不能代替目的/全组覆盖”，不比较 GT ID。

| 实际反例 | 真实证据 | 契约预期 |
|---|---|---|
| S03→S04、S03→S05、S04→S05 的 parent-child | 如 `scp_4a27eb49a48bc49f0f111fcb5e3e6a61c858b1af3dc0998423ca9e39e4d26a6c`，primary `ecl_1e153436a7dd041cbe5c0fd4ecdd4a6eb7afb85c99c62ab8ed92986db57361e5`，322 observations | 同 lineage 可以跨高层步骤；最多有限候选，无目的不能确认。不是删除原有向关系 |
| S06/S07 authentication establish/use | `scp_cba1002d486cdaee5a0c05e9258898e946c402eb2fc6a2c5c1a7e8e023400af6`，AUTH_ESTABLISH_USE，12 observations | 同 auth session 不能吞并所有后续主机活动；保留既有方向，不升级高层同一步骤 |
| 入站 SSH connection 跨 S05/S06/S07 | `scp_4da092f3014f5bf9cfbbc222d60e314b9481a944b066101d032b0985ffdac0c9` 为 S06/S05 的 CONNECTION_ESTABLISH_ACCEPT；其余参见⑥共享绑定见证 | connection 证明 transport 身份，不等于任意后续行为目的；不能传递闭包合组 |
| 出站连接跨 S07/S08 | `scp_1f44fa6a85f20b54008dd1bdbdda2a03fbbb11d4f099ccf965e346b3fe7c54e7`，SAME_TRUSTED_CONNECTION，40 observations，UNDIRECTED_EDGE | 无向关系保留；共享连接既不赋方向也不自动同一步骤 |
| 同 process instance 跨 S03/S04 或 S04/S05 | `scp_4fbcdb431e4d16687d81cc51d42c4641acce975f3f9fc86d404df5731eb34742`、`scp_27791fb97401b4b9570fdc090367635bdf8a63de0d175374334508d1aa1b9592` | 进程实例可执行多个阶段动作；同进程不是目的边界 |
| 时间邻近/上下文近似 | `cross_gt_rule_risk_witnesses.json` 中 insufficient_semantic_context 372、semantic_conflict 269、distinct URL 110、command 55、strong context 26、action roles 14、dynamic time 80 个 first-gate 见证 | 这些是历史动作层风险分类，非本层硬阈值；不通过放宽时间/忽略 command 获得确认。无证据为 UNRESOLVED，有具体身份反证才 REJECTED |

原型正反测试须同时包含：相同 token 不同 authority、相同 host 不同 lifecycle、父进程多子活动、同连接跨阶段、缺 witness、组内部分覆盖、同 Chain 非连通子集、跨 Chain 候选、多个确认提案重叠、无向与被拒关系、全部 Stage 未分配。不能只测试四个同 GT 正向合并愿望。

## 4. 独立评估接口（定义，未实现）

### 4.1 顺序、人口与映射

1. 原型输入只用主契约白名单；记录实际打开的输入路径/摘要。运行时禁止导入 GT 映射、案例摘录、评估报告、预期组数或与 GT 对应的规则。
2. 生成语义 JSON 并完成 V01–V12；封存语义文件 SHA、输入/策略/目录 SHA、软件版本及执行 receipt。封存之后评估进程才读取 GT。记录封存时间及评估读取开始时间。
3. 固定评估人口 A 为封存 S8 的全部 CanonicalAlert ID，Stage 不可拆。ATTACK125 本次为 125；未来不能硬编码该数。
4. 独立 evaluator 通过数据发布的原始记录身份映射到 GT observation，再到 GT Stage。优先使用有 namespace 的原始记录 ID 与已验证发布映射；不得按时间、标题、序号或 semantic label 猜匹配。多解、缺失、重复、未知 GT 标签均记录完整清单。
5. 设 M 为 A 中恰有一个有效 GT Stage 标签的告警。映射完整率 `|M|/|A|`，另报 GT 中未进入 A 的记录数量及上游过滤原因。`|M| != |A|` 时全部 GT 质量指标标 `NOT_EVALUABLE: INCOMPLETE_GT_MAPPING`；可以另报显式的 mapped-only 诊断，但不得当总成绩或用于过门槛。A 为空则 `NOT_EVALUABLE: EMPTY_POPULATION`。

评价报告作为独立文件包含：evaluation_contract_version、sealed_output_sha256、gt_artifact_digests、population、mapping_failures、metrics（每项 value/ numerator/denominator/status/reason）、integrity_results、repeatability、promotion_gate_results。该报告绝不写入语义输出或反馈分组。

### 4.2 指标口径与空分母

定义 C 为 CONFIRMED 组集合；U 为原 Stage 集合；每个未确认 Stage 保留一个独立 fallback bucket，保证全部告警参与恢复诊断，但 **fallback 不是预测的正向语义分组**。CANDIDATE/UNRESOLVED/REJECTED 提案都不产生预测正 pair。

令 P 为 A 中同一 CONFIRMED 组内的所有无序不同告警对；T 为同一 GT Stage 的所有无序不同告警对。P 包含同一原 Stage 内的告警对，但仅当该 Stage 有确认主归属；未确认的内部 pair 不凭原 Stage 合法性算语义正例。报告可另给 Stage 层诊断，但必须标粒度，不能与本 alert-pair 主指标混算。

| 指标 | 固定计算与边界 |
|---|---|
| GT Stage 恢复 | 对每个 GT Stage t，列其告警落入的确认组/未确认 Stage buckets、覆盖率、碎片数、混入告警。exact recovered 当且仅当存在一个 CONFIRMED 组，其全部成员告警集合恰等于 t；未确认 singleton 即使恰相等也不算恢复。恢复率=exact recovered GT stages / A 中有观测的 GT stages；无 GT stage 则 N/E |
| Pairwise Precision | TP=`|P∩T|`，FP=`|P−T|`；Precision=TP/(TP+FP)。P 空时 N/E:NO_PREDICTED_POSITIVES，绝不记 1 |
| Pairwise Recall | FN=`|T−P|`；Recall=TP/(TP+FN)。T 非空而 P 空时 0；T 空则 N/E:NO_GT_POSITIVE_PAIRS |
| Pairwise F1 | `2TP/(2TP+FP+FN)`；分母 0 则 N/E:NO_POSITIVE_PAIRS；P 空但 T 非空时为 0，即使 Precision 为 N/E |
| 跨 GT 混合率 | mixed group 指含 >1 GT Stage 的确认组。主值=`mixed confirmed groups / |C|`；C 空则 N/E:NO_CONFIRMED_GROUPS。另报 mixed groups 告警数/|A|、跨 GT FP 对数，避免组大小掩盖污染 |
| 确认证据完整率 | 满足 P1 全条件、全部成员覆盖及引用解析的确认组数/|C|；C 空则 N/E。另报缺失 refs 和未覆盖告警，不能仅凭 evidence_level 或 integrity true 计通过 |
| 候选及无法判定比例 | 提案维度分别 `#CANDIDATE/#all proposals`、`#UNRESOLVED/#all proposals`，REJECTED 同时报；空提案 N/E。Stage 维度报“至少涉及该状态提案的 Stage 数/|U|”（可重叠，不求和为 1），并报 confirmed coverage、unassigned rate。Alert 维度同理，不删除未判定样本 |
| 原始完整性 | S8/S9/input 字节摘要逐一相同；Stage 成员、⑧全部接受/拒绝决策、⑨归属/entry/exit/环完全保留；投影与原接受关系逐一对应。分别报告 Stage、Relation、Chain 保留率及差异清单；空集合用 vacuous integrity pass 并报告 count=0，不伪造召回值 |
| 证据追溯完整率 | 所有实际引用出现次数中，成功解析次数/总次数；按 stage/relation/claim/observation/pointer 分层，并另报 unique target 数。零引用则 N/E:NO_REFERENCES；确认组不可因此通过证据门槛。总引用范围包括组、ledger、contradictions；共享引用多次计 occurrence，去重另报 |
| 重复一致性 | 至少两次相同冻结输入、软件版本和策略运行，JCS 规范化语义输出及内容 ID 完全相等；列表按契约排序，独立执行 receipt 时间不参与。单次为 N/E:REPEAT_NOT_RUN；额外测试输入集合排列变化不应改变语义输出 |

所有 N/E 必须带原因、分子/分母和缺失清单；不转换成 0、1 或删除记录以通过验收。若 GT 本身缺少关系/因果标注，Chain 因果正确性报告 N/E；图保留通过只说明语义层未篡改原图，不证明原图对 GT 正确。

### 4.3 离线实验前冻结的推广门槛

门槛版本 `attack-step-evaluation-v1.1`；以下是前瞻工程验收政策，不是由本次数据拟合的阈值，也不是生产配置修改。不得看实验结果后降门槛。本次没有执行语义实验。

| 门槛 | 要求 |
|---|---|
| G0 隔离 | 输入白名单审计通过；GT 首次读取晚于语义封存；不存在 GT ID/名称/组数决策依赖；违规一次即失败 |
| G1 完整性 | V01–V12 全通过；输入/Stage/全部关系/Chain 改动数 0；新增/反向边 0；重复主归属 0；全部原 Stage 保留 |
| G2 可评估性 | GT 告警映射 100%；主要 GT 指标及确认证据指标必须可评估，不能凭全弃权获得推广通过 |
| G3 证据 | CONFIRMED 的目的覆盖和追溯完整率 100%；所有实际输出引用解析率 100%；不允许已知 dangling 引用进入推广（探索输出可保留缺失并不推广） |
| G4 质量 | alert pair Precision ≥0.95，Recall ≥0.80，F1 ≥0.85；跨 GT 确认混合组数=0。三项及零混合必须同时满足。报告置信区间/样本量，但不以区间替代固定点估计门槛 |
| G5 稳定 | 至少两次相同输入结果一致，输入排列不敏感；文档规定的正反例全部通过，无边方向或断连表示回归 |
| G6 推广范围 | ATTACK125 仅为已见审计集；生产推广前还需独立未参与本契约设计的冻结留出数据集，同样通过 G0–G5，范围/采样在实验前登记。尚无留出集时明确 NOT_READY，不宣称泛化 |

P1 是保守最小档案，未必能达到 GT 高层恢复门槛；本次真实产物没有 P1 claim，预期不能获得有效确认质量成绩。这是可明确评估的能力不足，不是放宽规则或凑 8 组的理由。契约冻结通过与未来推广失败可以同时成立。新增目的档案须新版本、新预注册实验，不能追改当前评分定义。

## 5. 内部一致性及本轮验收证据

| 核对项 | 结论与边界 |
|---|---|
| 输入来源 | 映射表涵盖 Stage/Relation/Chain/元数据；真实、解析、可选、缺失、未来接口分别标注。Run ID/数据版本/语义目录未伪称已有 |
| 输出覆盖 | Schema 含全部要求字段，strict additionalProperties、ID/digest 格式、状态/方向/断连条件；跨文件约束明确委托 V01–V12 |
| 状态闭合 | D01–D24 覆盖四状态；确认 P1、候选有限假设、未知缺证明、拒绝实际反证；优先级与 overlap 降级明确 |
| 四案预期 | S02 候选/未知保留 HTTP 差异，S04/S05 E2 候选，S07 未知且断连；没有靠 GT 确认 |
| 跨 Chain / 无向 / rejected | 不确认跨 Chain，不定向无向，不投影拒绝边；同 Chain 子集仍检查诱导连通 |
| 证据缺失 | 缺关键证据不确认；缺核心输入 intake 失败；schema 自报 RESOLVED 不替代解析 |
| 未分配与重叠 | 全部原 Stage 进入 index；候选可重叠；主归属仅确认且唯一；未确认 null |
| GT 泄漏风险 | 审计目录/摘录不得进入运行白名单；先封存后独立评价；自由文本字段仍需输入访问审计，Schema 无法证明无信息泄漏 |
| 算法边界 | 当前没有新语义算法、序列化器、API、前端或评估器；文档 fixture 不是真实运行输出 |

本轮结构验证记录见 `outputs/attack_step_contract_freeze_20261022/schema_validation.json`；使用隔离安装的标准 `jsonschema==4.23.0` Draft202012Validator，检查 schema 本身及有效/无效文档夹具。例中合成 ID/摘要仅用于结构测试，不能通过真实 V01–V12；该限制在夹具文件首项明确声明。

保护校验见本轮 `protected_before.json`、`integrity_verification.json`。3536 个基线文件中，3535 个字节摘要不变，仅允许修改的主契约发生变化，无基线文件删除。既有工作区本来有大量未提交改动，因此不把整仓库 git diff 误算成本轮贡献。旧验收的 531 个 `*_tmp` 测试临时文件未纳入初始摘要；结束盘点时确认其修改时间均早于基线并单独列出，不冒称对它们完成了前后字节比较。正式历史产物及数据集均在保护范围内。

已知能力边界不是未定义设计项：未来 provenance receipt 的生产接口、分组器及 V01–V12 校验器都尚未实现；本轮冻结其字段和要求，策略摘要直接取已冻结主契约文件。未来实现须独立授权，不可直接生产推广。

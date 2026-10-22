# ②/⑤身份交接与⑧关系证据修复验收

**FINAL_ACCEPTANCE=PARTIAL**。②/⑤与⑧的确认缺陷已修复并有正反例；冻结⑥在新上游身份下出现新的语义回归，未修改⑥。不能因 Community/Stage 数减少而判为全链路成功。

## 冻结与执行顺序

首先通过正式 `load_stage_pipeline` 和⑨消费器回放，before.json 的告警、实体、Community、Stage、候选、关系、链、投影和统计均与 `outputs/gt_s02_boundary_audit_20261021/after_runtime.json` 完全相等。确认既有 15 Stage、F1 83.2698%、125/125、GT-S02 为 5 Stage。见 stage6_freeze_receipt.json。之后依次完成②/⑤、277项回归与 stage25_final 正式回放；该进程结束后才修改⑧。最后执行新的①～⑧、⑨和逆序输入复跑。没有重新审计或修复⑥。

⑥生产文件、④行为语义、⑥已有测试预期、⑦和⑨算法及其配置均按执行前后SHA256核验不变。community/builder.py 的探索性改动已恢复为开始时逐字节内容，未计入最终变更。

## 根因、修复和差异

1. **②**：REQUEST/CONNECTION ContextRef 使用 source namespace 和 host scope，即使原生 ID 与端点证据相容也不能跨源交接。现有 HostAlias/AuthSession 投影无需重写，HOST、ACCOUNT、PROCESS 实体前后完全一致，无新增 PID 连续性推断。在既有提取器内加入单独声明的 ContextAuthority：request 要求相同 canonical HOST；connection 要求兼容 authority/deployment/network、原生 ID、完整五元组见证及每成员至少三项显式端点事实。认证 host_ip 作为目的地址须经显式字段契约声明。时间只限制身份有效期，端点、scope、epoch或年龄冲突拒绝投影，缺失字段不能在冲突元组间选边。源 ContextRef、ID、端点、时间和scope原始指针归档在 context_bindings；规范告警的原始payload和进程字段不改写。13条投影含2条跨源连接，连接观测规模26/14；其余为请求，其中一条24观测。
2. **⑤**：完整跨源进程实例虽然已由匹配端点验证，仍被当作弱上下文，受到无关成员的组件主机/账户、弱成员20上限及稀释节奏的限制。只把两个独立来源共同观测的完整、同主机作用域进程lifetime标为 cross_source_process_instance 绑定。原成员级主机、账户、上下文、原生进程实例、common-parent检查和候选时间窗口保留；PID-only/描述符不提升，同源既有时间规则不改。该绑定直接消费②的实体，不复制进程启动字段。GT-S07 的22告警从两个Community的12/10分布变为同一个Community；GT-S02始终同Community，未用其证明⑤有缺陷。最终社区所有归属证明来自flow、connection、session、application_session、request及1条cross_source_process_instance，无主机/IP弱证据单独合并。
3. **⑧**：原进程全局posting将current和parent角色混为同一排他范围，两个current Stage因第三Stage只提及parent而错误降为CONTEXT。保留完整全局footprint，仅在完整无污染身份的current角色恰好覆盖两个Stage时允许其SAME_PROCESS_INSTANCE为无向关联；三个current Stage仍全部只作context。同步修正合同验证，已有父进程footprint测试保留三Stage记录并更新⑧的关联预期，没有修改⑥测试。
4. **⑧**：connection被套入AUTH_ESTABLISH_USE，形成“认证接受→早先网络发起”的反向Claim，并在时间门槛拒绝；当观测顺序反转时还可能接受错误箭头。新增证据类型CONNECTION_ESTABLISH_ACCEPT（关系类型仍只有DIRECTED_EDGE/UNDIRECTED_EDGE/NO_RELATION），要求②已投影的声明连接issuer、相容端点、完整发起五元组、NetworkConnection和credential_accepted互补原生角色；方向来自INITIATE/ACCEPT，时间只否决反转。connection不再套用认证session建立/使用规则。无全局阈值降低、无WEAK_DIRECTED、无⑨修改。

所有实际源码行差异见 task_changes.diff（相对任务开始工作区，未与git HEAD混淆）；逐文件前后哈希见 integrity.json。各实现、配置与测试文件见 acceptance.json 的 FILES_CHANGED。

## 实测指标

| 指标 | 执行前 | 最终 |
|---|---:|---:|
| 告警/唯一Stage分配 | 125/125 | 125/125 |
| Community / sizes | 3 / 39,39,47 | 1 / 125 |
| GT-S07社区成员分布 | 12 + 10 | 22 |
| Stage | 15 | 12 |
| GT-S02 Stage | 5 | 5 |
| Stage成对Precision | 100.000000% | 76.247505% |
| Stage成对Recall | 71.335201% | 71.335201% |
| Stage成对F1 | 83.269755% | 73.709600% |
| TP / FP / FN | 764 / 0 / 307 | 764 / 238 / 307 |
| ⑦候选 | 29 | 23 |
| ⑧有向 / 无向 / 拒绝 | 8 / 0 / 21 | 7 / 1 / 15 |
| ⑨链 | 9 | 6 |

②/⑤修改后的固定输入，⑧前为6有向、1无向、16拒绝；⑧后为7有向、1无向、15拒绝。该阶段告警、实体、身份绑定、Community、Stage、⑦候选逐字段不变，见 stage8_upstream_freeze.json。完整候选逐项判定、端点、Claim、时间/冲突与原始指针都在 final.json；变化在 stage8_relation_changes.json。不能把前后不同Stage分区的关系数量直接作为准确率指标。

## 冻结⑥的新回归与剩余关系

新身份暴露⑥三组跨真实阶段聚合，总计238错误成员对，见 stage6_new_regressions.json（每一对、完整成员和真实阶段组成）：

- stg_0217d4d89cb61f120eddfed4fc4409b21cb6a899d8baece0f386f7d7871b0927: {'GT-S03': 18, 'GT-S04': 1}；错误配对18
- stg_88b6d87c0e2f07335dff8c71a008b76d9f8c8b70ecb158cc9a86fc3caf2c3676: {'GT-S07': 12, 'GT-S08': 15}；错误配对180
- stg_ef0a47d49f006ce4faec2d5ff5a6853c7bd31a748f91b3afa637e2fe6fa9a5f9: {'GT-S05': 4, 'GT-S07': 10}；错误配对40

代码位置：backend/app/stages/evidence.py:173, backend/app/stages/evidence.py:67, backend/app/stages/aggregation.py:23。它们通过新增同请求或网络/进程动作绑定触发现有通用观测语义兼容和连通聚合。问题属于冻结⑥对新上游输入的消费，按用户要求仅记录，不改其算法、配置、阈值或测试预期。GT-S07仍为两个Stage，是不同原生动作与同连接网络观测的阶段粒度，未尝试优化⑥。

独立GT关系逐见证结果（标签在正式执行结束后才读取）：

| 独立关系 | 最终结果与边界 |
|---|---|
| E01 | 已有⑦候选，只有多Stage共享flow背景，仍NO_RELATION；没有用时间先后或相同网络会话强造因果 |
| E02 | OBJECT_HANDOFF有向关系保留 |
| E03 | 见证端点已被冻结⑥并入同一预测Stage，⑦不生成self候选；不能误报为⑧拒绝 |
| E04 | 两个current Stage的完整进程实例形成UNDIRECTED_EDGE；未由时间推导因果方向 |
| E05 | CONNECTION_ESTABLISH_ACCEPT有向关系；方向来自原生发起和接受角色 |
| E06 | AUTH_ESTABLISH_USE有向关系保留 |
| E07 | 见证端点被冻结⑥并入同一预测Stage，⑦不生成self候选；不能由⑧绕过 |

完整逐见证映射见 final_gt_traces.json。没有本应为跨Stage、却被⑦漏召回的指定见证；E03/E07的缺席是上游同Stage归属。没有声称恢复全部7条真实有向关系。

## 验证与实际命令

最终相关测试 **551 passed / 0 failed / 0 error**，含27项新增正反例，覆盖跨源投影、端点/authority/scope/epoch/时效冲突、PID-only、不同账户/主机/进程启动/common parent、已有弱关联隔离、⑥固定测试、⑦候选、⑧Claim/指针及⑨重构。生产逆序输入对告警、实体、投影、Community、Stage、候选、证据全部相等。⑨ EVIDENCE_TRACE_PRESERVED=true，DANGLING_REFERENCE_COUNT=0。所有原始证据指针由正式Pipeline和⑨实际解析。

本次全量 backend/tests 确实执行，仍在收集阶段2 errors：test_demo.py/test_demo_integration.py 缺 data/ait_ads/dataset.yaml。无测试断言运行，未标为通过。日志 full_tests.log、JUnit full_tests.xml。开发期间出现的临时目录权限问题已改用工作区独立basetemp；StrictModel冻结赋值、tuple反序列化和YAML merge-key限制导致的初始失败均已修正，保留各次日志/XML，详情test_results.json。刻意禁用修复的red用例分别复现②2失败、⑤1失败、⑧3失败；不计入最终通过数。

工作目录 D:/Code_WorkSpace/TraceBack，实际执行的最终命令（其余开发轮次见同目录XML/日志）：

```powershell
.venv/Scripts/python.exe -B scripts/verify_identity_relation_handoff.py before
.venv/Scripts/python.exe -B scripts/verify_identity_relation_handoff.py stage25_final > outputs/identity_relation_handoff_20261021/stage25_final_capture.log 2>&1
.venv/Scripts/python.exe -B scripts/verify_identity_relation_handoff.py final > outputs/identity_relation_handoff_20261021/final_capture.log 2>&1
.venv/Scripts/python.exe -B -m pytest backend/tests/test_relation_evidence_handoff.py backend/tests/test_context_identity_handoff.py backend/tests/test_identity_projection.py backend/tests/test_entity_extraction.py backend/tests/test_entity_binding_index.py backend/tests/test_community_builder.py backend/tests/test_community_optimization.py backend/tests/test_alert_pipeline.py backend/tests/test_stage6_http_observations.py backend/tests/test_stage6_fragmentation_repair.py backend/tests/test_stage_aggregation.py backend/tests/test_stage_graph.py backend/tests/test_stage56_repair.py backend/tests/test_stage_candidates.py backend/tests/test_stage_evidence.py backend/tests/test_stage_evidence_claims.py backend/tests/test_stage9_reconstruction.py backend/tests/test_evidence_trace.py backend/tests/test_stage_attack_chains.py backend/tests/test_stage_relations.py -q --tb=short -p no:cacheprovider --basetemp=outputs/identity_relation_handoff_20261021/delivery_related_tmp --junitxml=outputs/identity_relation_handoff_20261021/delivery_related_tests.xml > outputs/identity_relation_handoff_20261021/delivery_related_tests.log 2>&1
.venv/Scripts/python.exe -B -m pytest backend/tests -q --tb=short -p no:cacheprovider --basetemp=outputs/identity_relation_handoff_20261021/full_tmp --junitxml=outputs/identity_relation_handoff_20261021/full_tests.xml > outputs/identity_relation_handoff_20261021/full_tests.log 2>&1
.venv/Scripts/python.exe -B outputs/identity_relation_handoff_20261021/finalize.py
```

capture拒绝覆盖已有同名快照；复验时应指定新label，或在独立产物目录运行复制的验收器，保留已有历史产物。GT只在受保护生产函数全部退出之后用于独立评测；生产audit hook禁止ground_truth/evaluation/outputs读取、网络和写操作。数据18文件哈希均不变，没有GT特征、Stage标签或指定关系进入生产。

```text
STAGE_6_FROZEN=true
STAGE_6_CODE_MODIFIED=false
STAGE_2_FIX_RESULT=PASS
STAGE_5_FIX_RESULT=PASS
STAGE_8_FIX_RESULT=PASS
FILES_CHANGED=acceptance.json / task_changes.diff
BEFORE_AFTER_METRICS=before_metrics.json / stage25_final_metrics.json / final_metrics.json
REGRESSION_TEST_RESULT=551 passed; full backend collection blocked by 2 historical Demo errors
DOWNSTREAM_COMPATIBILITY=structural PASS; frozen Stage6 semantic regression (238 pairs)
DATASET_MODIFIED=false
GROUND_TRUTH_MODIFIED=false
GROUND_TRUTH_USED_IN_PRODUCTION=false
FINAL_ACCEPTANCE=PARTIAL
```

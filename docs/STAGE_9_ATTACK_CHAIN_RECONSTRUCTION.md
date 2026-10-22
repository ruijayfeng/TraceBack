# ⑨ 攻击链重构

正式实现为 `backend/app/stage_chains/reconstruction.py`。⑨接收已经完成的⑧结果，只输出 Chain、Stage/Relation membership 和结构元数据。没有修改①～⑧入口、算法或配置，没有启动⑩、API、前端或 AI 任务。

## 正式输入与原始关系契约

当前 `load_stage_pipeline()` 输出 `stage-evidence-v2`，关系表是 `evidence_result.decisions`。真正的现有边使用 `DIRECTED_EDGE`、`UNDIRECTED_EDGE`；`NO_RELATION` 是已拒绝的候选决策。正式⑧没有 `WEAK_DIRECTED` 输出。

`FrozenStageGraph.from_stage8(stages, evidence_result, alerts)` 直接消费这些对象或其已有 JSON 表示，不调用 Relation builder、Candidate generator、相似度、规则、评分或⑧的语义验证器。⑨不将现有关系转换为另一种关系模型。Chain 的 `relation_ids` 直接引用原始 Decision 的 `candidate_id`，不分配新 Relation ID。

历史 `STRONG_DIRECTED / STRONG_UNDIRECTED / WEAK_DIRECTED` 可通过 `FrozenStageGraph.from_legacy(existing_snapshot)` 消费，沿用原始 `str_*` ID 和已有 Trace resolver。这是读取已有图的兼容入口，不在当前正式①～⑧结果之外再运行一次历史关联。旧 `scripts/run_attack_chain_reconstruction.py` 保持原状。

验收字段 `STRONG_DIRECTED_COUNT / STRONG_UNDIRECTED_COUNT` 分别统计当前正式 `DIRECTED_EDGE / UNDIRECTED_EDGE`，属于报告字段别名。原始 `relation_type` 不变。报告同时保留 `INPUT_RELATION_TYPES`，明确记录实际契约。

## Chain membership

所有已有有向边和无向边仅在计算 connectivity 时被视为无向邻接。每个连通分量生成一条 Chain，包括孤立 Stage。Context membership、共享 Host/Account/Process、时间、Community、行为标签均不参与分量合并。`NO_RELATION` 及 Context Posting 不参与连通性计算，也不会展开成新边。

Chain 仅保存 `chain_id / stage_ids / relation_ids / single_stage / entry_stage_ids / exit_stage_ids / start_time / end_time / has_directed_cycle` 等元数据。不生成路径、主干、替代边或补齐步骤。Chain ID 仅依赖成员 Stage ID 和原有 Relation ID，不依赖 Community、时间或原始列表顺序。

Entry/Exit 只统计已有有向关系中的参与节点。纯无向多节点链的 Entry/Exit 都为空；混合链中只参与无向关系的节点不被伪称为入口或出口。单节点链沿用已有单节点同时为 Entry/Exit 的契约。历史弱有向关系仍只表示时间展示顺序，`weak_direction_is_causal=false`。有向环、分支和原始边全部保留。

时间仅用于 Chain 的最早 `start_time` 和最晚 `end_time`。不根据时间修改方向、强弱、关系或 Chain membership。

## 不可变 Guard 与证据追溯

冻结时记录关系数量、完整 ID 列表和逐字段内容摘要。完整输入摘要另外覆盖所有 Stage、Alert/raw、Decision（含 NO_RELATION）、Claim、Context、Observation、Validation 和 Raw Pointer。执行前后及退出时检查；数量、ID、端点、类型、方向、置信度、证据或任意嵌套字段变化立即抛错。

证据检查只解析现有引用，不重新决定证据是否支持关系。正式追溯路径为：

```text
Chain.stage_ids → 原始 Stage.alert_ids → 原始 Alert.raw_alert
Chain.relation_ids → 原始 Decision.candidate_id
  → relation/context/supporting/invalid claim IDs
  → 原始 Claim.observation_ids
  → 原始 Observation 的双端 Alert、Validation、Raw Pointer IDs
  → 原始 RawEvidenceReference.raw_pointer → 原始 Alert.raw_alert
```

原始 Context Posting 和 NO_RELATION 的证据仍保存在受 Guard 保护的输入中，不会被改写、丢弃或当成攻击关系。输出的 `source_receipt.json` 记录输入文件 SHA256、原始表路径和 ID 字段；不复制出另一套 Relation/Evidence。

## 历史独立消费验收（2026-10-21）

读取已有 `outputs/stage2_identity_projection/after.json`，该文件记录正式①～⑧完成后的原始 Stage、Alert 和 `stage-evidence-v2` 输出。验收不重跑①～⑧，不读取 Dataset 或 Ground Truth。原始文件 SHA256：

```text
51f9b9a50b55405c6380788f3cdd0d36854ad47f33c2d80554823eb4282464df
```

结果：42 Stage、165原始 Decision，其中23条关系（22 DIRECTED_EDGE、1 UNDIRECTED_EDGE、0 WEAK_DIRECTED），其余142条 NO_RELATION 不参与连通性。得到26条 Chain：24条单节点链、1条8节点链、1条10节点链。关系前后数量均23，ID及内容摘要完全一致，证据悬空引用0。

关系集合前后摘要：

```text
b3db17d3ff948701ea127fad1e173bc5e1c8ba97f75a2c58c8c1d1b3352031ff
```

新增30项测试通过，已有425项相关回归通过。覆盖禁止补边、同 Community 多链、相同 Host 和相邻时间不跨分量合并、无向边不定向、single Stage、三种历史关系、Context-only/NO_RELATION、空图、有向环、分支、关系及嵌套证据篡改、缺失 Raw/Alert/Claim/Observation/Pointer/Validation 拒绝，以及⑨执行期间禁止 IO 与上游算法调用。

完整结果和全部验收字段位于 `outputs/stage9_attack_chain_reconstruction/formal_run/`。本轮仅在既有源码之外新增⑨模块、测试、验收脚本和本文档；已有源码及正式输入的逐文件基线记录位于同级 `protected_before.json`。

## 复现

```powershell
.venv\Scripts\python.exe -B -m pytest backend/tests/test_stage9_reconstruction.py -q -p no:cacheprovider --junitxml=outputs/stage9_attack_chain_reconstruction/unit_tests.xml
.venv\Scripts\python.exe -B -m pytest backend/tests/test_stage_attack_chains.py backend/tests/test_stage_evidence.py backend/tests/test_stage_evidence_claims.py backend/tests/test_stage_candidates.py backend/tests/test_stage56_repair.py backend/tests/test_identity_projection.py backend/tests/test_entity_binding_index.py backend/tests/test_stage_relations.py backend/tests/test_evidence_trace.py backend/tests/test_stage_graph.py backend/tests/test_stage_aggregation.py backend/tests/test_alert_pipeline.py backend/tests/test_noise_filter.py -q -p no:cacheprovider --basetemp=outputs/stage9_attack_chain_reconstruction/regression_repeat_tmp --junitxml=outputs/stage9_attack_chain_reconstruction/regression_tests.xml
.venv\Scripts\python.exe -B scripts/verify_stage9_reconstruction.py --input outputs/stage2_identity_projection/after.json --output outputs/stage9_attack_chain_reconstruction/repeat_run --tests outputs/stage9_attack_chain_reconstruction/unit_tests.xml --regression-tests outputs/stage9_attack_chain_reconstruction/regression_tests.xml
```

验收输出目录必须不存在。`FrozenStageGraph` 和 `reconstruct_attack_chains()` 也可直接接受已完成⑧的内存 handoff，不要求重新读取数据集。当前①～⑧入口继续停在⑧；⑨通过独立消费入口执行。

## 正式全链路验收（2026-10-22）

正式 CLI `scripts/run_stage_pipeline.py` 现已接入⑨。它调用
`app.stage_chains.pipeline.load_attack_chain_pipeline()`，先运行未修改的
`load_stage_pipeline()`，再将返回的 Stage、⑧ evidence_result 和 Alert 原对象
交给 `FrozenStageGraph.from_stage8()` 及现有⑨实现。①～⑧服务仍保持原有边界，
⑨重构算法未修改。上述历史独立消费结果不代表此次全链路验收。

```powershell
.venv\Scripts\python.exe -B scripts/run_stage_pipeline.py --input D:/Code_WorkSpace/TraceBack-Dataset/data/attack125/final/attack125_final.jsonl --output outputs/new_stage9_run
```

`--output` 必须为新目录，保存 `stage8.json`、`stage9.json` 及包含源文件 SHA256
和表定位的 `receipt.json`。不指定输出目录时，CLI 仍执行①～⑨并打印统计。

本次两次独立正式运行均生成 15 个 Stage、9 条有向及3条无向关系、17条拒绝决策，
得到7条链（1条9节点链和6条单节点链）；两次上游及重构产物逐字节一致。
Stage、关系、连通分量、Entry/Exit 和证据追溯验收通过；⑨/接入测试35项、
相关回归537项通过。全后端收集受旧 Demo 的 AIT-ADS 登记文件缺失阻断，未报告全量通过。

独立 Ground Truth 的7条精确绑定中，3条恢复方向、3条仅恢复关联、1条未恢复。
结构运行验收 PASS 与 GT 恢复 PARTIAL 分别记录；没有用 GT 补边或修改上游。
完整证据、测试、差异和最终字段见
`outputs/stage9_formal_acceptance_20261022/report.md` 及同目录 `acceptance.json`。

# ⑦ Stage Pair Candidate Generation

正式入口为 `app.services.stage_pipeline.load_stage_pipeline(input_path)`。
它执行当前①～⑥，并将这次 `aggregate_stages()` 返回的同一个 `StageResult`
直接传入 `app.stage_candidates.generator.generate_stage_pair_candidates()`，然后返回。
不读取历史 snapshot，不调用⑧、⑨、⑩、API或AI解释。

## 输入与输出

⑦使用当前 StageResult、CanonicalAlert、Entity、source settings、CommunityConfig
以及新 CandidateConfig。StageResult 中的 BehaviorAnnotation 只参与输入闭合校验；
不根据行为标签或时间单独创建候选。Community 只记录端点归属，不限制检索范围。

`StagePipelineRun` 保留 `normalized`、`community`、`stages`；新增
`candidate_result: StagePairCandidateResult`，并提供 `candidates` 列表属性。

StagePairCandidate 包含：

- deterministic `candidate_id`，规范端点 `stage_a_id < stage_b_id`；
- `same_community`、`community_a_id`、`community_b_id`；
- 合并去重后的 `candidate_reasons`、`retrieval_keys`、`candidate_sources`；
- `retrieval_features`，包含原始观察的 alert ID、source namespace、ContextRef scope、字段指针；
- `metadata`，记录Stage时间间隔及Community locality hint。

候选没有source/target、关系类型、因果方向、置信度或最终冲突否决。
STRONG/NORMAL/WEAK_RETRIEVAL_HINT 仅表示检索提示类别，不能解释为关系等级。

## 检索规则

先逐Stage、逐成员Alert提取特征，复用 `community.evidence.profile()` 的只读投影；
再建立 `key → Stage postings` 倒排索引。只在合格posting中枚举Stage对，
对规范pair合并所有理由和原始指针。没有全Stage两两完整证据扫描。

| 特征 | 作用域与检索限制 |
|---|---|
| request/session/connection/application_session/task | 保留现有typed binding identity和ContextRef scope |
| native flow | 保留ContextRef scope；不将裸flow ID视为全局身份 |
| 完整网络五元组 | 使用显式network namespace；缺失时保留source namespace |
| 完整进程实例 | 使用现有scoped Process Entity；支持current/parent角色提示，parent-parent不单独召回 |
| object/file/session entity/account@host | 使用已有scoped身份或同一Alert中的复合上下文 |
| file/executable完整路径+host | 只匹配实际字段与Host身份；不在⑦判断创建或执行语义 |
| 稀有host/endpoint pair | posting必须具有选择性，并满足已有时间locality窗口 |
| URL、command、单个IP | 仅保留为context，不独立触发候选 |
| host+URL、host+command、URL+endpoint pair | 同一成员Alert中同时存在，满足locality窗口 |

此外支持三个明确的复合检索提示，保持上游实体与ContextRef不变：

- **已观测hostname+object**：原生记录可能同时带hostname与asset ID。
  用真实CanonicalAlert.host及object字段形成独立检索提示，保留asset namespace与两端指针。
  不合并hostname与asset ID实体。
- **scoped Host Entity+登录ID**：仅使用显式 `logon_id` / `auth_session_id`。
  不同设备可在同一个已绑定Host上记录同一登录；原ContextRef的source scope仍保留。
- **connection token+两个endpoint**：要求三项同时观察到，且满足locality窗口。
  显式network namespace不同则不能匹配；未声明的namespace保持null。
  这个复合键只说明值得跨源进一步验证，不声称双方属于同一个已证明的网络scope。

同Community本身不产生候选。仅时间接近也不产生候选。
不解析command字符串，不从URL猜测object、request或process。

## 公共键抑制与配置

新配置为 `configs/stage-candidates-v1.yaml`，可通过 `candidate_config=` 注入。
`enabled_feature_kinds` 控制键类型。

高频弱键判定复用已有 `CommunityConfig.common_entities.min_count` **且**
`ratio`，计数单位为命中Stage数。公共host或endpoint pair posting在枚举pair之前被抑制；
只能通过另一个独立上下文组成的compound posting继续召回。
强scoped binding不因高频而截断；有多个独立上下文的候选仍可能较多，属于可审核的召回取舍。

稀有host窗口引用 `community-v1.windows_seconds['4']`，URL/command复合上下文窗口引用
`windows_seconds['3']`。具有typed connection token与双endpoint的复合提示使用
原有binding窗口 `windows_seconds['1']`，不套用弱URL/command窗口。
新配置只引用这些既有值，不修改Community阈值或算法。
窗口只剪枝已有非时间特征命中的候选。

## 验证与产物

正式运行：

```powershell
.\.venv\Scripts\python.exe -B scripts/run_stage_pipeline.py --input D:\Code_WorkSpace\TraceBack-Dataset\data\attack125\final\attack125_final.jsonl
```

⑦合成测试：

```powershell
.\.venv\Scripts\python.exe -B -m pytest backend/tests/test_stage_candidates.py backend/tests/test_stage56_repair.py -q -p no:cacheprovider --basetemp outputs/stage7_candidate_generation/pytest_unit
```

ATTACK125离线验收：

```powershell
.\.venv\Scripts\python.exe -B scripts/verify_stage7_candidates.py --tests outputs/stage7_candidate_generation/tests_final.xml
```

验收脚本先在I/O与函数调用guard下调用正式入口。生产期间禁止GT、evaluation、
outputs历史结果读取、写文件、网络及任何⑧以后的执行。
返回后才读取独立GT，通过wrapper event ID →完整raw event digest →当前CanonicalAlert →当前Stage
映射binding witness pair。GT内容不反馈生产算法。

`outputs/stage7_candidate_generation/protected_before.json` 与 `upstream_before.json`
是在本轮修改前记录的SHA256清单和正式①～⑥输出，仅供离线比较，不是生产输入。
所有既有算法、配置、Mapping和完整ATTACK125文件清单进行前后校验；
唯一允许变化的既有生产文件是编排入口stage_pipeline.py。

最终产物位于 `outputs/stage7_candidate_generation/`：

- `summary.json`、`REPORT.md`：真实统计、调用链、测试状态、完成范围；
- `candidate_result.json`：候选、特征、抑制与时间剪枝诊断；
- `gt_candidate_recall.json`：7条GT的候选召回和剩余缺失原因；
- `samples.json`：固定随机种子抽取10个候选与10个未生成pair；
- `integrity.json`：SHA256前后结果、release manifest校验与①～⑥输出一致性。

测试仅修复旧 `test_stage_relations.snapshot()` 的过时调用签名为
`normalize_behavior(alert, policy)` 后绑定合成Community；现有⑧算法保持原样。
运行旧关系测试属于兼容性检查，不代表正式Pipeline执行到⑧。

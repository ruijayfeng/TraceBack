# TraceBack 论文草稿

工作稿，未经验证不得定稿。贡献、最终算法和最终结果保留占位。

## 1 引言

### 1.1 研究背景

SOC 中安全设备产生的离散告警提供局部观测。同一调查上下文可能涉及不同时间、实体和设备，分析人员需要判断其关系及依据。

### 1.2 问题定义

TraceBack 以设备已经产生的安全告警为输入，抽取有据实体、建立可追溯关联、聚合 Incident 并尝试重构有字段依据的攻击步骤关系。告警存在不等于入侵已确认，无法证明的方向保留未决。

### 1.3 本文工作

[核心算法冻结后总结，不提前宣称创新或优越性]

## 2 相关技术与相关工作

Alert Correlation、Attack Graph/Chain、ATT&CK、SOC Triage、Evidence-aware Analytics、LLM Explanation。[可靠文献检索后补充]

## 3 TraceBack 系统设计

### 3.1 系统总体架构

系统采用 Alert-first：告警适配与基础标准化后执行去重、实体抽取、候选生成与确定性评分，再执行受控聚类和攻击链重构。AI 位于确定性流程之后，解释既有结果。架构依据三份统一需求与 AGENTS；具体实现验收以独立任务报告为准。

### 3.2 CanonicalAlert 统一告警模型

统一模型记录来源身份、时间、规则、规范字段、原始安全告警及 provenance。稳定身份支持重复运行对齐，实体引用保留来源字段角色。

### 3.3 实体抽取与证据模型

实体按 scope 区分身份，证据指针绑定具体 alert，正式对象能回溯原始安全告警。共享主机或相近时间不能自动证明进程触发或因果传播。

### 3.4 候选告警生成

候选合同 v1.1 区分潜在邻居、准入候选与正式关联；time-only 不提名。局部 Top-K 策略裁剪与全局资源截断分别记录，后者影响分析完整性。

### 3.5 告警关联模型

输入为候选的完整原始成员对；输出为带 reasons、support_pair 与 score_breakdown 的无向 CorrelationEdge。v5 最终公式 [待验证]。

### 3.6 Incident 聚合

受控组件合并包含目标集合、支撑桥、冲突、跨度和规模保护。其需求与现有实现契约不因诊断分数变化而自动放宽。

### 3.7 Attack Chain Reconstruction

方向需独立字段支持；无法定向的无向关联不补成链边。本阶段未运行新设计的链重构，最终效果 [实验后补充]。

### 3.8 AI Explain 与 Grounding

AI 解释已有算法事实；正式事实陈述须通过白名单命题与引用闭包核验。模型调用失败不改变关联结果。系统目标与实际报告测试证据应分开叙述。

### 3.9 ATT&CK 映射

ATT&CK 用于既有节点的语义表达，不构成新攻击步骤的观测来源。

## 4 告警关联算法

### 4.1 问题形式化

给定规范告警与候选集合，区分证据一致性、证据充分性和明确冲突；分数不解释为已校准攻击概率。

### 4.2 Correlation v4 基线

冻结实验基线为 `alert-correlation-v4-role-context-candidate-v1.1`。该版本已将 quality 与 mass 结合：前者按可用家族归一化，后者仍参照全部配置正权重；其保守 primary、角色、元数据及传播规则保留。

### 4.3 可观测性与证据充分性

字段齐全并不表示具备多种独立攻击关系证据。没有观察到 pivot，也不等于已观察到反驳无向关联的事实。历史完整 t5 可达性审计与当前 10K 实验须分别引用；本节数字与最终解释在实验日志更新后同步。

### 4.4 改进方法

[Correlation v5 设计完成后补充；当前仅诊断候选，生产算法未实现]

### 4.5 复杂度与工程实现

[算法冻结后补充；候选策略和预算差异必须披露]

## 5 实验设计与结果

### 5.1 数据集

当前主任务使用已导入 CPTC-2018 t5 Suricata 告警的 10K 开发选择集；原始规模与 hash 以选择审计及当前 manifest 为准。几乎全部 High completeness，不能据此声称真实稀疏场景已验证。t2 仅为未来独立验证的考虑，本任务未执行。

### 5.2 实验环境

[当前诊断环境见实验日志；最终性能环境待冻结]

### 5.3 Baseline / Ablation

[待算法冻结后设计]

### 5.4 Correlation 实验

[按本阶段真实统计同步；无 pair-level GT，不报告正确率、precision 或 recall]

### 5.5 Attack Chain Reconstruction 实验

[实验后补充；本任务未运行]

### 5.6 Case Study

[待人工核验与具有代表性的链证据，不把高分告警对当成已确认攻击链]

## 6 系统实现与展示

Analysis、Incident、Chain、Evidence、Timeline、AI Report、ATT&CK 与 Rejection Diagnostics。[逐项引用实际验收材料后扩写]

## 7 讨论

单源 IDS 的字段覆盖与关系覆盖不同；多源产品差异不自动证明检测独立。人工 masking 只能检验评分性质，不能替代真实稀疏数据。负对照也不是完整的 pair-level Ground Truth。

## 8 总结与展望

[项目最终完成后撰写]

## 当前诊断实证补记（开发实验，非最终方法）

结果：`V5_DESIGN_PROMISING_BUT_NEEDS_MORE_EVIDENCE`；建议 `Do not implement v5 yet`。当前输入 10000，代表 9263，完整候选 225616，成员对 277937。

| Candidate | observed max | diagnostic admission |
| --- | ---: | ---: |
| A | 0.768361174 | 47 |
| B | 0.768361174 | 47 |
| C | 0.720904038 | 41 |
| D | 0.768361174 | 47 |

RQ1：v4 的 quality 已排除不可用家族；固定 mass 和可观测零 topology 仍限制可达性。RQ2：UNKNOWN（未支持关系）与 CONTRADICTED（观测维度不一致）分开；不能将无 pivot 称为全局反证。RQ3：四个候选已实际运行，但最终公式未冻结。RQ4：最小绝对证据量、primary、依赖组和 guard 共同控制小分母风险，负对照统计全部保留；本轮没有真实 pair precision/recall。A/B/D 在本开发集输出相同，尚无 B/D 增量收益证据；均匀原始控制样本无准入，不能据此声称正负准入分离。条件 Top100 的 time shuffle 每种方案仍准入3对；随机时间恰好保留邻接且实体资源证据未变，详见 [残余准入逐对审计](../../outputs/v5_design_diagnostic/time_shuffle_residual_audit.json)，不删去或称为已确认误报。

[诊断报告](../../outputs/v5_design_diagnostic/V5_DESIGN_DIAGNOSTIC_REPORT.md)、[负对照](../../outputs/v5_design_diagnostic/negative_controls.json)、[masking](../../outputs/v5_design_diagnostic/counterfactual_missing_evidence.json)。真实 Sparse/Medium、多源 capability、独立评测及最终链结果仍 [待验证]。

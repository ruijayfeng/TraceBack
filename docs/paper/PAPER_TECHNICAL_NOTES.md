# 技术笔记（非定稿）

## 事实来源与边界

需求基线为上级目录三份统一需求文档；工程契约为 AGENTS、DATA_CONTRACT、ALGORITHM_CONFIG、CODEX_TASKS。实现与实验事实以实际代码及其产物为准，计划不等于验收完成。

Alert-first 流程：设备安全告警 → Adapter/基础 Normalization → 去重 → 实体抽取 → 候选 → 关联 → Incident → 攻击链 → Grounding → AI/API/UI。设备产生告警是可核验事实，攻击是否成立须另行验证。AI 解释既有结果，不创建关联事实。

CanonicalAlert 保留原始安全告警、字段 provenance、实体角色与绑定告警的证据指针。CorrelationEdge 是无向关联，ChainEdge 另需字段支持的传播方向。ATT&CK 用于语义解释，不补缺失步骤。依据：[数据契约](../DATA_CONTRACT.md)、[算法配置](../ALGORITHM_CONFIG.md)、实际实现 `backend/app/correlation/scoring.py`、`backend/app/correlation/evidence_v3.py`、`backend/app/correlation/evidence_v4.py`。

## 算法演化记录

| 版本 | Problem → Diagnostic → Design Change → Experiment → Result → Decision |
| --- | --- |
| v2 | 固定缺失零分的可达性问题 → availability 审计 → quality + mass + gate → 既有真实回放 → 产出无向边，后续暴露过关联风险 → 保留历史报告，不追认其正确率 |
| v3 | 元数据/重复观测可能冒充独立事实 → 主证据与可靠度审计 → metadata 合并、primary、flow context、role/rarity → 历史回放 → 结果见原报告 → 不覆盖旧设计 |
| v4 | 通用类型/目的 IP/端点邻接过强 → 角色与上下文反例 → destination attenuation、真实 detector、behavior prerequisite → 历史小集及 t5 审计 → t5 固定配方可达性受限 → 开始 v5 诊断 |
| v5 | 缺失、未支持关系与明确冲突的语义区分 → 独立设计实验 → [设计中] → 当前诊断 → [实验产物后同步] → 不实施生产 v5 |

历史证据：[v2](../../outputs/correlation_v2/CORRELATION_V2_REPORT.md)、[v3](../../outputs/correlation_v3/CORRELATION_V3_REPORT.md)、[v4 小集](../../outputs/correlation_v4_small/CORRELATION_V4_REPORT.md)、[t5 根因诊断](../../outputs/cptc_t5_correlation_v4_diagnostic_12/DIAGNOSTIC_REPORT.md)。上述版本不是相同数据与相同预算下的性能比较，不能据此声称优于其他方法。

## 本阶段 Research Questions

- RQ1：不可观测证据是否仍约束评分空间？v4 quality 已排除 UNAVAILABLE，但 mass 的固定配置分母及可观测零 topology 仍会约束可达性。
- RQ2：不存在与存在但不匹配应否分开？需进一步区分“未观察到 pivot”与“否定无向关联的事实”；不同 signature 也不是行为不兼容证明。
- RQ3：有效评分空间是否按观测调整？比较 A 归一化、B relation/confidence、C positive/contradiction/coverage、D quorum；最终公式 [待验证]。
- RQ4：如何避免再次过关联？沿用 frozen primary/duplicate/hard guard，拆分 evidence sufficiency，压缩依赖家族，检查负对照与极端稀疏。

## 实现与验证状态

仅新增独立诊断脚本与测试；生产 v5 未实现。评分协议记录在 `outputs/v5_design_diagnostic/diagnostic_policy.yaml`，最终实验结论待对应产物同步。最终权重、阈值、最终攻击链与最终性能均 [待验证]。

## 本阶段诊断结果同步

结果：`V5_DESIGN_PROMISING_BUT_NEEDS_MORE_EVIDENCE`；建议 `Do not implement v5 yet`。当前输入 10000，代表 9263，完整候选 225616，成员对 277937。

| Candidate | observed max | diagnostic admission |
| --- | ---: | ---: |
| A | 0.768361174 | 47 |
| B | 0.768361174 | 47 |
| C | 0.720904038 | 41 |
| D | 0.768361174 | 47 |

RQ1：v4 的 quality 已排除不可用家族；固定 mass 和可观测零 topology 仍限制可达性。RQ2：UNKNOWN（未支持关系）与 CONTRADICTED（观测维度不一致）分开；不能将无 pivot 称为全局反证。RQ3：四个候选已实际运行，但最终公式未冻结。RQ4：最小绝对证据量、primary、依赖组和 guard 共同控制小分母风险，负对照统计全部保留；本轮没有真实 pair precision/recall。A/B/D 在本开发集输出相同，尚无 B/D 增量收益证据；均匀原始控制样本无准入，不能据此声称正负准入分离。条件 Top100 的 time shuffle 每种方案仍准入3对；随机时间恰好保留邻接且实体资源证据未变，详见 [残余准入逐对审计](../../outputs/v5_design_diagnostic/time_shuffle_residual_audit.json)，不删去或称为已确认误报。

[诊断报告](../../outputs/v5_design_diagnostic/V5_DESIGN_DIAGNOSTIC_REPORT.md)、[负对照](../../outputs/v5_design_diagnostic/negative_controls.json)、[masking](../../outputs/v5_design_diagnostic/counterfactual_missing_evidence.json)。真实 Sparse/Medium、多源 capability、独立评测及最终链结果仍 [待验证]。

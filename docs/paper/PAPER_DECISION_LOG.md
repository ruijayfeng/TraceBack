# 设计决策日志

## Decision: 独立开展 v5 Design Diagnostic，保持生产 v4 冻结

### Background

CPTC t5 历史可达性审计显示冻结评分与该来源可提供的关系证据存在结构性限制。

### Observation

v4 已含 availability-aware quality；不可把它描述成纯固定加权零分。固定 mass 分母、可观测零 topology、metadata cap 和角色可靠度须分开审计。

### Problem

缺失证据、未支持某个关系假设与明确反证不应混为同一状态；直接缩小分母也可能让弱证据虚高。

### Decision

比较 A/B/C/D，复用冻结候选、证据抽取及 guard；不降低生产阈值，不按边数选公式，不用 GT 调参。只在 diagnostic dictionary 上做 perturbation/masking。

### Status

DESIGN。生产 v5 未实施，尚无最终公式。

### Evidence

[历史可达性产物](../../outputs/cptc_t5_correlation_v4_diagnostic_12/score_reachability.json)、`scripts/v5_design_diagnostic.py`、`backend/tests/test_v5_design_diagnostic.py`。

## Decision: Confidence 使用绝对正证据量

### Background / Observation

在正式 v5 评分前，代数检查发现删除弱匹配项可提高 family mean；因此 mean 不能直接当 evidence sufficiency。

### Decision

诊断 confidence 使用家族内有上限的绝对正证据量；保持 normalized relation strength 为独立量。增加删除证据不增加 confidence 的性质测试。

### Status

DESIGN / 单元性质已验证；跨源与真实稀疏记录效果 [待验证]。首次预评分启动在候选生成时被中断，尚未产生评分结果；保留 superseded policy 和 interrupted log，不将其计为候选负面结果，也不声称完成实验。

### Evidence

`outputs/v5_design_diagnostic/pre_scoring_policy_superseded.yaml`、`pre_scoring_interrupted.log`、`diagnostic_tests.xml`。

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

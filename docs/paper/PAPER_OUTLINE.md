# TraceBack 论文材料提纲

状态：持续沉淀，非定稿。项目实现与可复现实验优先；未经验证的内容必须保留占位。

1. 引言：SOC 告警碎片化；证据化关联与重构的问题定义；本文贡献 [算法冻结后总结]。
2. 相关技术与相关工作：Alert Correlation、Attack Graph、ATT&CK、SOC Triage、Evidence-aware Analytics、LLM Explanation。[可靠文献检索后补充，不虚构引用]
3. TraceBack 系统设计：Alert-first、CanonicalAlert、实体与证据、候选、CorrelationEdge、Incident、AttackChain、Grounding、AI、ATT&CK。
4. 告警关联算法：问题形式化；冻结 v4 实验基线；可观测性与证据充分性；v5 [设计中]；复杂度 [冻结后补充]。
5. 实验设计与结果：CPTC t5 开发集；环境；基线与消融 [待验证]；关联实验；攻击链实验 [实验后补充]；Case Study [待验证]。
6. 系统实现与展示：Analysis、Incident、Chain、Evidence、Timeline、AI Report、ATT&CK、Rejection Diagnostics；仅描述实际实现与可核验结果。
7. 讨论：单源 IDS、真实稀疏数据不足、证据充分性、误关联、可解释性、公开数据局限。
8. 总结与展望 [项目完成后撰写]。

材料入口：[技术笔记](PAPER_TECHNICAL_NOTES.md)、[实验日志](PAPER_EXPERIMENT_LOG.md)、[决策日志](PAPER_DECISION_LOG.md)、[正文草稿](PAPER_DRAFT.md)。最终图表必须标注实验 artifact 与 hash；当前不生成无依据的最终图。

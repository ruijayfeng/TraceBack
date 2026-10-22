# SHARED_CONTEXT_ONLY 弱关系资格审计

仅审计冻结⑧的138个SHARED_CONTEXT_ONLY，不重放⑦/⑧/⑨，不改Context/Role/Scope规则。23条正式关系只读取端点供WHAT-IF基线使用；4个NO_VALID_EVIDENCE不参与证据分类。

## 诊断结论

138对引用10个原始Context，Stage fanout为3～10，双Stage独占Context为0。分类为：`{"CONTEXT_BUT_SEMANTIC_CONFLICT":0,"CONTEXT_SCOPE_UNTRUSTED":0,"EXCLUSIVE_LOCAL_CONTEXT":0,"MULTIPLE_SUPPORTING_CONTEXTS":41,"OTHER":0,"PUBLIC_CONTEXT_ONLY":97,"SINGLE_WEAK_CONTEXT":0,"TEMPORALLY_LOCAL_MULTI_CONTEXT":0}`。

按当前可证实事实，明确继续NO_RELATION 97对；弱关系资格已成立 0对；需校准的研究样本41对。不能将研究样本数当作可加入图的弱边数。

95对只共享Flow类身份；另2对仅有一个非派生身份域（Process或AuthSession），Host/Account/descriptor等是身份scope或描述背景。因此97对不具有新的pairwise连续性依据。41对具有Process与AuthSession等不同身份域、不同原始字段的观测锚；它们仍全部来自多Stage Context，弱准入扇出、时间范围及观测独立性均没有正式校准，保留为AMBIGUOUS。

“不同原始字段”只证明不是同一个字段的重复投影，不证明统计独立或共同攻击过程。Flow/tuple/endpoint、Process/descriptor，以及作为scope组成部分的Host/Account不叠加成额外独立锚。

## Context与资格边界

HIGH_FANOUT在本报告仅指结构性fanout>2，与既有双Stage独占例外互补，不是新设置的弱边阈值。10个Context全部满足该结构标签，但不据此把41个多锚样本直接宣告为必然公共或必然弱关系。

正式系统没有对CONTEXT身份定义统一强弱排序，因此PRIMARY_CONTEXT_TYPE全部为UNDEFINED。正式Context catalog只计算原ContextIdentityPosting；Host/Account/Path等支持事实另存supporting_facts.json及全局fanout，避免伪造正式Context。

除正式类型Context外，有7个仅覆盖两Stage的支持事实，涉及6个Pair：URL、Process descriptor、文件路径、Command。它们不是双Stage独占的完整对象/会话实例；例如descriptor只计当前process，而完整Process Context还包含parent_process角色。因此未把这些低扇出支持事实升级为EXCLUSIVE_LOCAL_CONTEXT或弱候选。身份污染标记数为0；高扇出不等于证明身份污染。

共享类型（同Pair可重复计数）：`{"other":137,"shared_account":42,"shared_auth_session":42,"shared_command":37,"shared_endpoint":95,"shared_file_path":41,"shared_flow":95,"shared_host":88,"shared_network_session":0,"shared_object":0,"shared_process":42,"shared_request":1}`。原始Context类型覆盖：`{"FLOW":95,"PROCESS":42,"REQUEST":1,"SESSION":42}`。

Fanout分布：`{"count":10,"max":10,"median":7.5,"min":3,"p75":9.75,"p90":10.0}`；直方图：`{"3":1,"4":1,"5":1,"6":2,"9":2,"10":3}`。具体Stage/Alert/source成员、时间跨度与scope见contexts.json。

## 时间、行为、角色与来源

时间差分布（秒）：`{"count":138,"max":472.0,"median":84.0,"min":0,"p75":148.5,"p90":207.09999999999997}`；区间关系：`{"forward_gap":134,"large_gap":3,"overlap":1}`。30/60/120/300秒仅按用户要求统计，不作为准入规则；large_gap仅采用OVER_300S报告分箱。

行为状态：`{"UNDEFINED":35,"same":21,"unknown":82}`。没有正式跨标签兼容表；不同已知标签的兼容性为UNDEFINED，UNKNOWN不被当作兼容。⑥同Stage的semantic_conflict不移植为⑧关系冲突。

可匹配现有强关系互补角色的Pair数：0。flow/MEMBER、同一process、共同parent均不提供handoff方向。逐Context的真实角色及原始操作见pairs.json。

涉及单一namespace的Stage Pair 100对，涉及多个namespace 38对；其中实际Context观察跨源的只有5对。混合来源Stage不等于跨源identity已合并。

AuthSession权威scope按已有6条归档投影匹配；Process保留原Host作用域内完整实例身份；Flow/Request保留原来源scope。没有跨源Network identity authority，不按相同token或endpoint提升可信度。

## WHAT-IF（纯内存）

资格已成立的候选为0，正式WHAT-IF：`{"component_count":26,"component_sizes":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,8,10],"extra_pair_count":0,"isolated_stage_count":24,"production_direction_assigned":false,"relation_objects_created":0,"temporary_memory_only":true}`。

额外的未校准研究集敏感性分析（不代表推荐加入）：`{"component_count":26,"component_sizes":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,8,10],"extra_pair_count":41,"isolated_stage_count":24,"production_direction_assigned":false,"relation_objects_created":0,"temporary_memory_only":true}`。41对全部位于已有分量内部，故即便全加也不减少孤立Stage。

明确不合格的全138对污染压力测试（负面对照）：`{"component_count":6,"component_sizes":[1,1,1,4,10,25],"extra_pair_count":138,"isolated_stage_count":3,"production_direction_assigned":false,"relation_objects_created":0,"temporary_memory_only":true}`。这不是弱边设计收益，不能据此接纳Flow clique。

全部138对中，跨现有分量95对；连接两个已有非单节点分量的Pair为0。当前没有8节点分量与10节点分量之间的桥；这不构成未来弱桥安全保证。逐对桥接影响见what_if.json。

## 下一阶段需要的设计证据（本轮不实现）

当前样本不足以支持“为减少孤立节点而上线WEAK_DIRECTED”。若继续研究，先独立制定非公共锚、同义/派生证据去重、identity authority与生命周期、低扇出判据、时间局部性、未知行为处理、强角色遗漏检查及弱桥审查标准，再用独立数据校准；不得从138对的图变漂亮程度反推准入阈值。

未来若无正式语义方向，箭头只能表示时间展示顺序；TEMPORAL_ORDER_IS_CAUSAL_EVIDENCE=false。真实互补角色应先检查为何没有成为强Relation Claim，不用弱边掩盖强证据路径问题。

## 产物与复现

pairs.json含138对全部基础字段、证据、上下文成员、角色、scope、资格及分类；weak_candidates.json为空；uncalibrated_review_pairs.json保存41对待校准研究样本。summary.json与acceptance.txt包含全部验收字段。

脚本：`.venv\Scripts\python.exe -B scripts/audit_shared_context_weak_relation.py --output outputs/shared_context_weak_relation_audit_repeat`。读取既有正式快照及同源stage8_postings.json，不调用生产生成器。

测试：`.venv\Scripts\python.exe -B -m pytest tests/audit-only/test_shared_context_weak_relation_audit.py -q -p no:cacheprovider`。

## 验证记录

23项诊断测试全部通过。472个既有文件哈希未变化，包含18个Dataset/GT文件和既有⑧审计、⑨正式产物。GT仅参与完整性哈希，不参与分类或准入。运行时Guard禁止⑦/⑧/⑨及其它生产算法调用；未生成正式关系，未设置弱关系阈值。

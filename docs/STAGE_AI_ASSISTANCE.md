# 正式 Stage Chain 的只读 AI 辅助研判

算法负责关联与重构，告警提供事实与证据，AI 只负责解释。本入口只消费工作台已经采用的正式⑨ `stage8.json` / `stage9.json`，不重跑或修改①～⑨，也不兼容转换旧 Incident/ChainNode 为新版事实。

## 数据与发布边界

`Stage9ArtifactReader → build_stage_context → StageContext(JSON string) → 现有 LLMProvider → StageExplanationDraft → validate_and_render → 独立报告`。

模型只能选择本 Chain 的事实引用、证据满足资格的谨慎行为解释、潜在危害和已确认观测，并组织摘要重点。它不能提交任意事实正文、实体、关系理由或攻击故事。事实发布器按同一条原始告警的字段角色组合“谁、对象、实际操作”，例如具体主机、账户、原始 operation、请求方法/地址/参数、父进程、进程、命令行和文件。命令参数里的文件路径不自动成为文件读取证据；父进程字段不自动成为进程创建事件。

新版 grounding 不比较模型文本和旧 Incident 模板是否完全一致，而是验证严格 JSON 结构、事实与 Stage 的引用闭包、原始 JSON Pointer 的类型和值、解释资格、影响资格、正式 Relation 的身份/方向/成员以及摘要引用。现有 Incident grounding 保留。**自由模型正文无法可靠地由字符串规则证明语义正确，因此 v1 使用受约束的结构化声明再组合自然语言**，而不是仅检查有无“可能”或危险关键词。当前安全语义覆盖进程执行、服务进程关联 Shell、文件操作、凭据材料、认证、网络、HTTP、SQL 注入特征和路径穿越特征；不支持的语义明确返回证据不足，不猜测。

解释资格仅用于 AI 输出校验，不产生检测结果，不写回 Stage Behavior、评分、GT 或图。模型给出的 confidence 仅在解释中显示，未参与任何算法决策。缺失证据按本 Stage 每条原始记录的可用字段生成，不使用其他 Stage 的字段补齐。

完整输入保留本 Chain 全部成员告警。关系输入含每条既有有效 Claim、原有语义/身份/方向，并按 Claim ID 稳定排序取一条已有 observation 作为见证摘录，包含双方告警引用与解析后的原始字段。`total_observation_count` / `omitted_observation_count` 明示覆盖范围，完整见证仍在原证据追溯接口；不筛选或重判关系。模型输入去除重复发布字段，但保留全部原始告警。内部 grounding 保留完整字段角色和值。输入超限则停止该 AI 请求，不静默截断 Chain。

DIRECTED_EDGE 原样保留正式方向，UNDIRECTED_EDGE 固定 `UNRESOLVED`。NO_RELATION 仅作为拒绝信息，不进入可解释边。弱时间关系只能说明观测先后，不能说明因果。摘要直接统计已有邻接关系中的分支、汇聚、环和孤立节点，不遍历出一条人为线性路径，也不合并其他 Chain。

## 潜在危害与已确认后果

潜在危害是条件性的安全知识说明，必须有本次选中的行为证据支持其适用性。已确认后果只允许目前实现的两类明确观测：设备 FileCreate 事件（明确注明缺少独立落盘核验，不证明恶意性或执行成功），以及有 `result=success` 的账户认证成功（明确不证明账户失陷）。失败/拒绝结果不能确认成功。成功认证、FileCreate、网络字节和 HTTP 响应码均不能升级为主机控制、管理员权限、凭据泄露或数据窃取。没有资格证据时 confirmed 数组为空，整体 confirmed 还必须是逐 Stage 已确认项的子集。

## API 与工作台

仅对正式分析 ID 开放，`chain_id` 必须来自当前正式⑨结果：

- `GET /api/v1/stage-analyses/{analysis_id}/chains/{chain_id}/ai-evidence`：实际发送模型的证据包及输入摘要。
- `POST /api/v1/stage-analyses/{analysis_id}/chains/{chain_id}/explain`：显式请求生成，独立返回 `available` / `unavailable`，不改变算法状态。
- `GET /api/v1/stage-analyses/{analysis_id}/chains/{chain_id}/explanation`：读取并重新 grounding 已存报告，未生成/已失效时 `result=null`，不调用模型。

攻击链页现有流程图下方增加一个研判区域。用户点击按钮才调用模型；展开查看逐 Stage 事实、解释、缺失证据、潜在/确认影响，以及关系依据和整体总结。证据按钮打开原始告警或原关系追溯。JSON/Markdown 均从已验证报告导出。React 按文本展示原始字段，Markdown 导出转义 HTML 和链接标记。

报告只存于 `outputs/ai_stage_reports/{input_digest}.json`，独立于正式数据目录。输入摘要覆盖源文件内容哈希、Chain、原始告警、关系及解释版本。读取存档时重新验证 structured selection 并重建/比对正文，拒绝被修改的报告。模型 timeout/retry/HTTP/大小限制沿用现有 provider；缓存按输入和 provider 配置隔离且有数量上限。调用失败、JSON 非法、grounding 拒绝和存储失败不影响正式 Chain/Relation/告警查询。前端对 AI 失败只显示“AI 辅助研判暂不可用”。

## 本地验证与真实模型测试

```powershell
.\.venv\Scripts\python.exe scripts/verify_stage_ai.py
.\.venv\Scripts\python.exe -m pytest backend/tests/test_stage_ai_explanation.py -q
npm.cmd --prefix frontend test -- --run src/__tests__/stageAIReport.test.tsx src/__tests__/stageWorkbench.test.tsx
npm.cmd --prefix frontend run build
```

默认仅选当前正式 ATTACK125 最大的多节点 Chain。脚本保存实际模型输入/messages/schema、真实服务结果、单独标记的确定性 grounding 预览、五类错误注入结果及正式目录全部文件的前后哈希。未配置 model/API 时 `REAL_MODEL_TEST=NOT_EXECUTED`，不会虚构模型名、调用成功或模型输出。`grounding_preview*` 是真实证据上的本地校验样本，绝不作为真实模型报告存入工作台。存在配置时才发起真实模型调用；失败如实记录为 FAILED。

当前部署仍通过项目既有 `configs/llm.yaml` / 忽略的本地密钥配置或 `TRACEBACK_LLM_*` 环境变量提供模型。不要把密钥写入验收产物。新增或调整解释资格/输出结构时需更新 `stage-explanation-v1` 版本及对应安全测试，使旧报告失效。

# 可访问性手动检查清单（VoiceOver / NVDA）

> 自动化覆盖：axe-core 0 violations、Playwright `ariaSnapshot` 结构测试、键盘/焦点/Esc/scroll lock 测试。
> 本文件用于发布前的人工屏幕阅读器检查；当前 macOS 开发环境未运行 VoiceOver/NVDA，标记为待执行。

## 准备工作

- macOS：系统设置 → 辅助功能 → VoiceOver 打开（`Cmd+F5`）。
- Windows：安装 NVDA，浏览器用 Chrome/Edge。
- 测试数据：`analysis_id=ana_c6944bba…bf4dea`，进入工作台与事件详情。

## 检查项

### 1. 工作台 / 列表
- [ ] VoiceOver 转子（`VO+U`）能看到 `main`、`navigation "调查流程"`、`heading "安全事件工作台"`。
- [ ] 列表表格被朗读为表格；表头与行关联；每行可读 `打开安全事件 <id>`。
- [ ] `查看详情 →`、`上一页/下一页`、筛选 select 的名称正确。
- [ ] 复制 ID 按钮朗读为 `复制安全事件 ID`，复制后反馈通过 `role=status` 朗读。

### 2. 事件详情
- [ ] h1 是事件摘要；类型/严重度/状态/攻击链状态 badge 可读。
- [ ] `navigation "页内导航"` 的 5 个链接可跳转，当前项 `aria-current=location`。
- [ ] 攻击链节点/边朗读包含类别、实体、时间、告警数、置信度；方向键/Home/End 可移动选择。
- [ ] 时间线单 marker 与聚合 marker 的 aria-label 可区分；聚合面板可打开/关闭。
- [ ] 同秒密集对象聚合后仍可展开到具体证据。

### 3. 证据抽屉
- [ ] 打开后焦点进入 dialog（`关闭证据` 按钮）。
- [ ] VoiceOver 朗读 dialog 标题为证据标题/对象类型。
- [ ] `支撑告警` listbox 可用方向键切换，选项朗读来源/时间/规则/ID。
- [ ] Esc 关闭后焦点回到触发按钮。
- [ ] 原始告警 raw_alert 展开后的 JSON 文本可逐行朗读，长度不会卡住读屏。

### 4. AI 报告与帮助
- [ ] 报告 TOC 链接可跳转到对应 section。
- [ ] “已拒绝 ≠ 已验证”与诊断折叠内容不会被当作正式结论朗读。
- [ ] `?` 帮助 dialog 可读、可 Esc 关闭；快捷键说明与实现一致。
- [ ] 离线 banner（`role=status`）在断网时朗读一次，不反复打断。

### 5. 全局
- [ ] 跳过链接（`跳到主要内容`）在 Tab 第一下出现并可用。
- [ ] 所有交互元素有可见焦点环；SVG 节点/边有 stroke 焦点。
- [ ] 200% 缩放（浏览器 zoom）无横向滚动；forced-colors 模式边界可见。
- [ ] reduced motion 下无位移动画。

## 记录方式

- 通过：在 PR 评论写 “VoiceOver/NVDA checklist: passed”。
- 失败：记录屏幕、浏览器、朗读文本与期望，按 P0（阻断任务）/P1（可绕过）/P2（润色）分类。

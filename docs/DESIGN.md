# TraceBack UI 设计系统 · v2「framed sheet」

> 状态：2026-10-28，`pr/ui-optimization` 分支。与 [PRODUCT.md](./PRODUCT.md)、[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) 配套阅读。
> 方向来源：Impeccable（Operate 模式 + craft floor）与 taste-skill v2 `framed-sheet`（app、kind=support，seed 1901974840）。
> 本文既是设计规范，也是实现约束：新页面/新组件先对齐这里，再写代码。

## 1. 方向

TraceBack 是**被工作的界面**（Operate），不是被阅读的落地页。判断标准是「一个 SOC 分析员能否立刻信任并完成任务」，不是「第一眼是否惊艳」。

- **世界只借四样东西**：字体、颜色、密度、一个招牌动作。布局、导航、控件沿用平台标准，不做成终端/卷宗的 Cosplay。
- **招牌动作：追溯带（trace strip）**。输入告警 → 标准化告警 → 去重代表 → 安全事件 是页面的第一块内容；后面四个证据计数作为同一行的低一级数字。它回答「这份快照把 3 条原始告警变成了什么」，而不是装饰。
- **外壳是 pale blue-grey 的 L 形框**（侧栏 + 顶栏共用一块 ground），工作区是一张**白色 paper**：右、下各内缩 8px，16px 圆角，1px 边，**无阴影**。层次来自色阶和细线，不来自投影。
- **颜色只给数据、状态和一个主操作**。品牌海军蓝退到正文墨色与 near-black 主按钮；青色只用于数据、选中状态和一处主动作。

## 2. 反模式（v2 明确删除）

| 删除 | 原因 |
|---|---|
| 深海军蓝侧栏 + 青色 active 药丸 + 左侧色条 | 生成式后台第一信号；侧栏回到页面 ground，active 用中性灰 pill |
| 8 张等权 KPI 卡（icon + 大数字 + 阴影） | 改为 1 个 divided strip；数值 24px、标签 12px、无图标、无阴影 |
| 卡片内再套卡片、每个 section 一张卡 | sheet 本身就是面；section 用 1px rule 和间距分组 |
| 全大写/加字距表头、斑马纹、表头底色 | 12px 灰、sentence case、只用行规则与对齐 |
| 标题上方的小 eyebrow / kicker | 标题自己承担层级；元信息放标题下 11px 灰行 |
| 装饰性渐变、玻璃、backdrop-blur、glow | 删除；浮层只用 1px 边 + 低透明度阴影 |
| 编号步骤、彩色分类图标、KPI sparkline | 不承载数据意义的一律删 |
| 全局 `button{}` / `input{}` / `table{}` 元素样式 | 旧层泄漏曾把复制按钮压成 0 宽；v2 的 app.css 全部 class-scoped |

## 3. Token（`frontend/src/styles/theme.css`）

- **Ground**：`--tb-frame #edf1f3`（chrome）、`--tb-sheet #fff`、`--tb-raised #f6f8f9`、`--tb-active #e4eaed`。
- **Ink**：`--tb-ink #1b2a34`（13:1）、`--tb-ink-2 #526874`（白 5.6:1 / frame 4.9:1）、`--tb-ink-3 #5f7480`（白 4.9:1，placeholder 也用它）。
- **唯一数据色**：`--tb-accent #16718f`；浅底 `--tb-accent-weak #e7f1f4`。
- **动作**：`--tb-primary #1b2a34`（near-black，唯一填充主按钮）；每屏最多一个。
- **状态**：success `#246b4b` / warning `#8a5a10` / danger `#a33a2c` + 同色 pale pill；状态色只表达状态，不上 chrome。
- **圆角**：sheet 16、card 10、control 8、chip 4；只允许这两组，不出现 12px 中间值。
- **字体**：系统 grotesk（`--tb-font-sans`）；mono 只有一个工作——稳定 ID、告警 ID、表格时间。**不加载未声明的 Inter**；等宽只做数据。
- **字号**：11 / 12 / 13 / 14 / 16 / 18 / 20 / 24 / 28。页面标题 24（手机 20），section 16，正文 14，表格 13/12，标签 11–12；11px 是地板。
- **层序**：`theme, base, components, utilities`；组件样式在 `app.css` 的 `@layer components`，Tailwind utilities 始终可以覆盖。圆角/阴影/颜色都由 token 推导，不在页面写魔法值。

## 4. 外壳与栅格

- Desktop ≥1101：`232px` 侧栏 + 48px 顶栏 + 白色 sheet；sheet 右侧/底部各 8px；内容最大 1360px，左右 28px。
- 顶栏：左 232px 产品名（TraceBack 智溯），中间 548–620px 分析 ID 搜索（`/` 聚焦、粘贴、打开分析），右 32px 帮助/菜单；chrome 与侧栏同 ground，无分隔线。
- 侧栏：分析范围（短 ID + 复制）→「调查流程」2 个目的地 → 底部快捷键与离线快照声明；active 是中性灰 pill，不是品牌色。空状态明确写「尚未打开分析」。
- 1101–900：侧栏 200px，内容 padding 22。
- ≤900：侧栏折成顶栏菜单 + dialog；sheet 全屏、去圆角；顶栏两行（品牌 + 菜单 / 搜索）。
- ≤720：诊断信息进入 `分析诊断 · 去重 / 分布 / 评分` disclosure；筛选进入 `筛选与时间` disclosure；表格变两行列表（`useMediaQuery('(max-width: 640px)')` 切换，不是 CSS 双渲染）。
- 列表页栅格：6 列（事件 25 / 时间 19 / 计数 13 / 实体 20 / AI 13 / 调查 10）；时间等宽右对齐，数字 `tabular-nums`。

## 5. 组件地图

**coss.com/ui（registry 复制，MIT，见 notices）**
`Button`、`Card`、`Table`、`Sheet`、`Dialog`、`Spinner`、`Kbd`。
本地适配：Card 去阴影、10px 圆角；Table 去掉自带的斑马/hover/尺寸 utility，交给设计系统；Sheet/Dialog 去 backdrop-blur。**表单控件（搜索、日期、筛选 select）保留原生语义**：可键盘、移动端有原生面板、e2e 稳定；只借用 token 的外观，不引入 Base UI Select 的弹层。所有控件高度 32px（表单 34–40）。

**自研组件（`src/components/`）**
`PageHead`（h1 + meta + actions，h1 带 `data-page-title` 程序化焦点）、`Section`（16/600 标题 + 12 灰 hint + actions）、`Pill`（pale 状态）、`Notice`、`EmptyState`、`Pager`、`CopyId`（短 ID + 1 次复制）、`TraceIcon`、`JsonView`（默认不序列化）、`AIStatus`。

**Graph/Timeline/Chain 用本地 SVG**：它们本身就是证据绘制，不是 UI 图标；节点/边 `role="button"`、名称包含可见文本、方向键可遍历；时间线 marker 用本地 glyph（节点方 / 告警圆）。

## 6. 页面蓝图

### 工作台 `/`
1. PageHead：`安全事件工作台`（24/600）+ 分析 ID/时间/冻结快照 11px 灰；右：状态 pale pill + 唯一主操作「查看全部事件」。
2. 追溯带：一条 divided strip，8 个 `.metric`；前 4 个 24px 数值 + 32px 间距 + 细箭号，后 4 个 17px 低一级计数；无图标、无阴影。
3. 两张诊断卡：去重诊断（0 含去重展开的事件 + 一句解释）/ 分布（来源、等级、类别各一列，2px 灰条 + 数字）。
4. 「关联评分诊断 · 未生成」折叠行、`分析诊断 / 可复核配置` 折叠行（不是面板）。
5. `安全事件列表`：h2 + 总数 + 密度 segmented + CSV；搜索（事件/实体）→ 筛选（类型/排序/等级/UTC 起止）；chips；表格。表格首屏至少露出表头和 2 行；≤640 变两行列表，行内不含嵌套按钮。

### 事件详情 `/incident/:id`
面包屑（返回队列 / 安全事件）→ h1 = incident.summary（24/600，手机 20）→ 4 个状态 pill（severity 有色彩，其余中性）+ ID 行 → sticky underline tabs（概况/攻击链/证据/时间线/AI）。
- 概况：左 facts（观察区间、成员、来源、工作流）+ 关键实体；右观测字段行（11px 标签 / 13px 值 / 右侧「证据」文字动作）。无卡片边框。
- 攻击链：toolbar（节点/边/置信分说明 + fit/zoom）+ 浅点阵画布；节点=白底 1px 边、选中 2px 青边、置信条 2px；边 1.5px 灰、选中 2.5px 青；节点/边详情在画布下方平铺，不再套卡。
- 证据：一句边界说明 +「查看全部成员证据 · N」outline 按钮。
- 时间线：UTC 全范围标尺、lane 40px、marker 10px、聚类 pill；精确时间表放下面。
- AI：`AI 研判报告` section + 状态/操作（请求/取消/导出）；report nav 是 underline anchors；claim 行=状态 pill + 13/1.7 文本 + 证据/节点/边文字动作；不用每行卡片。诊断和 raw markdown 折叠。

### 证据抽屉（Sheet ≥580px）
面包屑 → 标题（18/600）+ 关闭（第一个可聚焦）→ ID 行 → 支撑告警搜索 + listbox（选中行用 `--tb-active`，不是品牌色）→ 告警概览 → 绑定指针 → 相关字段（显示投影值 + 原始 pointer/transform）→ 实体 → raw_alert 惰性折叠 → 标准化引用。焦点陷阱、Esc、scroll lock、焦点还原由 Base UI 保证。

### AI 报告
状态诚实：`不可用 ≠ 成功`；确定性模板必须标明；被拒绝内容隔离在诊断折叠里。生成中只保留 rare-ui ai-status 一个动效（lazy chunk），其余不做入场动画。

### 欢迎页
标题 28 + 一句产品说明 + 双栏：最近分析（工作列表）/「这份工作台回答什么」+ 离线快照边界。没有 hero 插画、没有 emoji。

## 7. 交互规则

- **URL 是唯一状态源**：`analysis_id/incident_id/page/page_size/kind/sort/severity/q/entity/start_time/end_time/node_id/edge_id/evidence/timeline_page`；前进/后退/刷新恢复同一视图。
- **键盘**：`/` 搜索、`?` 帮助、`Esc` 关抽屉/清搜索、列表 `j/k` + `Enter/Space`、攻击链方向键/Home/End、抽屉 listbox ↑↓/Enter。
- **状态**：loading 保留旧数据（stale-while-revalidate）用真实尺寸 skeleton，不整屏空白；错误在失败块内「中文标题 + 原样 code + 重试」；空态区分未提供/无匹配/当前页为空。
- **动效**：150–250ms，只表达状态（hover、focus、sheet/dialog、toast、AI 生成）；reduced-motion 压到 0.01ms；不做页面入场。
- **手机**：一屏一个区域；抽屉全屏 bottom sheet；表格两行列表；诊断/筛选折叠；页面级横向溢出必须 0。

## 8. 可访问性基线

- 文本 ≥4.5:1（含 placeholder），图形/焦点 ≥3:1；`muted` 只用在达标组合上。
- 所有图标按钮有 aria-label；装饰图标 `aria-hidden`；SVG 节点的 aria-label 必须等于可见文本拼接；listbox 有 label 与 option 状态。
- 跳转后 h1 接程序化焦点；dialog 焦点进入/还原；表格行可聚焦、可 Enter 打开；证据抽屉是 `role=dialog`。
- axe-core 0 violations（工作台/详情/抽屉/欢迎，1440/390）；detector 0；两套 e2e 保持绿。

## 9. 质量闸门

```bash
cd frontend
npm run typecheck
npm run test:run        # 61 unit tests
npm run test:e2e        # fixture suite (25 passed / 3 @real skipped)
npm run verify          # typecheck + unit + build + bundle budget
node ../scripts/ui_detector_ratchet.mjs --check
```

外加 taste-skill inspector（`inspect.mjs --app <url>`，1440/768/390）与人工截图对比；任何截图里的「未完成感」优先于代码解释。

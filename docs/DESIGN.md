# TraceBack UI 设计系统

> 状态：2026-10-28，`ui/optimization` / PR 分支。与 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) 配套阅读。
> 注：`.dsh/skills` 为本地开发工具，未纳入版本库；上游使用者无需该目录。

## 1. 设计原则

1. **证据优先**：告警、实体、节点、边、指针都是证据事实；AI 文本只做解释。视觉层级必须让“事实”比“推测”更显眼，绝不把 AI 摘要做成页面主角。
2. **可核验**：稳定 ID 永远可复制完整值；原始设备告警默认可折叠读取；被拒绝内容不进正式结论区。
3. **离线快照语义**：界面不暗示实时性；“冻结分析快照”“离线快照 · 可核验证据”等文案保留。
4. **低装饰、高密度**：SOC 工作台以 12–14px 数据文字、6–9px 圆角、1px 边框为主；动效只用于状态变化。
5. **一套系统**：颜色、字号、间距、焦点、动效都有 token 或约定；不为单个页面引入一次性样式。

## 2. 设计 Token（`frontend/src/styles/theme.css`）

- 品牌：navy `#112d3e`（侧栏）、teal `#185976`（主操作），保留 TraceBack 原有海军蓝/青绿识别，不采用 coss 默认中性灰 + Inter。
- 语义色：`--background/--foreground/--card/--popover/--primary/--secondary/--muted/--accent/--destructive/--success/--warning/--info/--border/--input/--ring`；coss 组件额外需要的 `--chart-1..5`、`--code*`、`--sidebar*` 均已补齐。
- 文字用途色：`--tb-text-primary #253440`、`--tb-text-secondary #526a7a`、`--tb-text-muted #5b7384`；均满足 4.5:1（在 `#f3f6f8` 纸张色与白色面板上）。
- 字体：系统栈 `ui-sans-serif, system-ui, …, "PingFang SC", "Microsoft YaHei"`；等宽 `ui-monospace, "SF Mono", …`。**不声明未加载的 Inter**，不引入字体下载。
- 字号：`--tb-text-2xs 11` / `xs 12` / `sm 13` / `base 14` / `md 16` / `lg 18` / `xl 20` / `2xl 28`（px）。11px 是最小功能字号；12px 用于密集数据，14px 用于正文与长文。
- 层级：CSS 层顺序固定为 `theme, base, components, legacy, utilities`；Tailwind utilities 可以覆盖 legacy 工作台样式，coss 组件落在 components/utilities。
- 圆角：`--radius 6px`，`--radius-sm/md/lg/xl` 由它派生；组件沿用 coss 的 rounded-md/lg 但收敛到 TraceBack 半径。

## 3. 组件来源与个性化

| 组件 | 来源 | 个性化 |
|---|---|---|
| Button / Badge / Spinner | coss.com/ui registry（MIT 口径，见 notices） | 通过语义 token 换成 TraceBack 海军蓝/青绿；保留 coss 的 Base UI `render`/loading 能力 |
| Table | coss.com/ui registry，`src/components/ui/table.tsx` | TableCell 允许换行（证据列不能 nowrap）；容器复用 `.table-scroll` 以承接横向滚动与 sticky 表头 |
| Sheet / Dialog | coss.com/ui registry，适配 `@base-ui/react@1.9.0`（无 `Dialog.Viewport`） | 桌面右侧 580px Sheet、移动底部 sheet；焦点陷阱/Esc/scroll lock/焦点恢复由 Base UI 保证 |
| Toast | Sonner（MIT） | 仅用于复制/导出/生成完成等非阻塞反馈；文案避开正式测试断言的短语，不新增 `role=alert` |
| 图标 | Lucide（ISC） | 统一 `TraceIcon` 包装（16px、1.75 stroke、装饰性默认 aria-hidden）；时间线证据标记用本地 SVG，不混用 UI 图标 |
| AI 状态动画 | rare-ui `ai-status`（可选，未接入） | 20KB 组件 + motion 依赖，评估后不进入主路径；AI 生成状态用 coss Badge/Spinner + 文本进度 |

## 4. 交互规范

- **焦点**：全局 `:focus-visible { outline: 2px solid var(--ring); outline-offset: 2px }`；SVG 节点/边额外加 stroke 高亮；跳转后 h1 接收程序化焦点（`data-page-title`，无可见 ring）。
- **键盘**：`/` 聚焦搜索或分析 ID；`Esc` 关闭证据/清空搜索；列表行 `Tab` 可聚焦，`Enter/Space` 打开；j/k 在列表行间移动（不覆盖输入框）；攻击链节点/边支持 Enter/Space 选择与方向键/Home/End 跳转，边列表是图操作的等价主路径。
- **悬停**：hover 只在 `@media (hover:hover) and (pointer:fine)` 生效；移动端无 hover 依赖。
- **动效表面（只保留 5 类）**：按钮 hover/active、Sheet/Dialog 进出、Toast 进出、生成中 Spinner/进度文案、列表加载淡入。数据点、攻击链、时间线、证据不做装饰动画。
- **reduced motion**：全局 `prefers-reduced-motion: reduce` 将动画/过渡压到 0.01ms；Sonner/Sheet 自带动画也遵守。
- **响应式断点**：≥1025 固定侧栏；721–1024 窄侧栏；≤900 侧栏变为顶部栏 + 移动导航 dialog；≤720 顶栏换行、指标 2 列；≤640 列表变卡片。页面级横向溢出在所有断点必须为 0（可用 `documentElement.scrollWidth <= innerWidth + 1` 检查）。
- **错误**：错误文案 = 中文标题 + 原样错误码 + 重试；错误码映射在 `src/lib/errors.ts`，不吞掉后端 code。
- **空状态**：标题说明“什么为空”，描述给下一步行动；保留既有精确文案（如 `当前筛选下没有安全事件。`）供测试与用户预期。

## 5. 可访问性基线

- 文本对比度 ≥4.5:1，图形/焦点指示 ≥3:1；`muted` 不再使用低于阈值的灰。
- 所有可交互控件有可访问名；SVG 图 `role="group"` + 每个节点/边 `role="button"` + 名称包含可见文本。
- 表格有 caption（sr-only），列表行可键盘打开；证据抽屉是 Base UI Dialog（role=dialog、焦点陷阱、Esc、焦点恢复）。
- 图标按钮 aria-label 必填；纯装饰图标 aria-hidden。
- 审计：axe-core/Playwright 对工作台、详情、证据抽屉、欢迎页、390/1440 均 0 violations（2026-10-28）；Impeccable detector 源码 0 findings。复跑命令见 `design-libs/reports/final-audit.md`。

## 6. 不要做的事

- 不要用 coss `init @coss/style` 覆盖全局（会引入 Next/Geist 依赖）；只按 registry 复制组件。
- 不要把 `app.css` 的 legacy 规则移出 `@layer legacy`；否则会压过 Tailwind/coss。
- 不要为“更好看”给证据/攻击链/时间线加动画；不要改变 API 枚举、稳定 ID、证据文本。
- 不要引入未记录许可证的组件；每复制一个组件，更新文件头 + `THIRD_PARTY_NOTICES.md`。

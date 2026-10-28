# Third-Party Notices

TraceBack 的 UI 优化使用/复制以下第三方开源项目。分发本项目或构建产物时请保留本文件及相关许可证文本。

## 前端 npm 依赖

| 项目 | 版本 | 许可证 |
|---|---|---|
| Tailwind CSS / @tailwindcss/vite | 4.3.3 | MIT |
| Base UI (@base-ui/react) | 1.9.0 | MIT |
| class-variance-authority | 0.7.1 | Apache-2.0 |
| clsx | 2.1.1 | MIT |
| tailwind-merge | 3.7.0 | MIT |
| Lucide (`lucide`, `lucide-react`) | 1.62.0 | ISC（Lucide 基于 Feather，Feather 为 MIT） |
| morphicons | 2.0.2 | MIT |
| motion | 14.7.1 | MIT |
| react-use-measure | 2.1.7 | MIT |
| Sonner | 2.0.8 | MIT |
| @axe-core/playwright（dev） | 4.14.0 | MIT；依赖 axe-core（MPL-2.0） |

## 项目级 Agent 工具（本地开发使用，不随仓库/PR 分发）

| 项目 | 许可证 | 说明 |
|---|---|---|
| Impeccable（skill/CLI） | Apache-2.0 | 仅本地开发使用，未提交到仓库；按 Impeccable 的 LICENSE/NOTICE 使用 |
| emilkowalski/skills（13 个技能） | MIT | 仅本地开发使用，未提交到仓库；来源 https://github.com/emilkowalski/skills |

## 已复制/改编到源码的第三方设计系统组件

### coss.com/ui（Cal.com Design System）
- 来源：https://github.com/cosscom/ui；通过 registry 路径（`https://coss.com/ui/r/<name>.json`）与 `npx shadcn@4.23.0 add` 复制。
- 文件（`frontend/src/components/ui/`）：`button.tsx`、`badge.tsx`、`spinner.tsx`、`table.tsx`、`sheet.tsx`、`dialog.tsx`。
- 每文件头保留来源、版权与 TraceBack 修改说明；`coss-ui.LICENSE` 为 MIT 文本。
- 修改：
  - `table.tsx`：TableCell 不再强制 `nowrap/leading-none`，允许证据列换行；容器可渲染为项目 `.table-scroll`。
  - `sheet.tsx` / `dialog.tsx`：`@base-ui/react@1.9.0`（当前最新发布版）没有 `Dialog.Viewport`，因此把 viewport 定位放到 Popup 上，并用 popup 自身 overflow 替代 `@coss/scroll-area` 依赖；焦点陷阱、Esc、scroll lock、焦点恢复仍是 Base UI Dialog 行为。
- 许可证口径：`apps/ui/registry` 在仓库中声明 MIT；`packages/ui` 为 AGPL。本项目**只使用 registry 路径**，未复制 `packages/ui` 源码；公开发布前仍需向 coss.com 书面确认 registry 的 MIT 适用范围。

### rare-ui
- 来源：https://github.com/swamimalode07/rare-ui；复制 `ai-status.tsx` 到 `frontend/src/components/ui/`。
- Copyright (c) 2026 Swami Malode；`rare-ui.LICENSE` 为完整许可证（MIT + Commons Clause v1.0 + Attribution）。
- 当前状态：**未接入页面**。T83 评估后决定不进入主路径（组件 + motion 体积/动效表面与“数据不装饰动画”原则冲突）；保留源文件作为可选试点，若接入必须在页面/README/About 提供指向 https://rareui.com 的可见链接。
- 使用要求：保留版权/许可/来源头；不得单独销售、再许可或再分发组件本身。

## 备注

- 项目 LICENSE 与上游 `zxxxj24/TraceBack` 保持一致：上游 `main` 当前没有根 LICENSE（默认保留所有权利），本分支不新增/更改项目级 LICENSE。第三方组件仍按其各自许可证使用；coss registry 的 MIT 口径与 rare-ui 的 Commons Clause/Attribution 要求见上。本文件不是法律意见。
- detector/axe 审计结果与复跑命令见 `design-libs/reports/final-audit.md`。

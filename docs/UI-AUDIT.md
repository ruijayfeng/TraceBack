# TraceBack UI 优化 · 最终审计与验收（2026-10-28）

分支：`TraceBack/ui/optimization`（未提交）。环境：macOS，Chrome，Vite 5173 + 更新后的 demo backend 8001（`/tmp/tb-demo` 快照）。

## 1. Impeccable detector（T14/T95）

- 4 条历史 `side-tab` warning 全部修复：侧栏原则块改为带边框卡片；error/info notice 改为全边框；finding/technique 改为 1px 全边框 + 顶部 inset 强调线。
- 当前源码扫描 **0 findings**；基线已刷新：`design-libs/baseline/detector/source-baseline.json`（工作区交付物）（0 findings，更新时间 2026-10-28T03:23Z）。
- 命令：
  ```bash
  cd TraceBack/frontend
  npm run detect:ui          # 信息性扫描
  npm run detect:ui:check    # ratchet：当前 PASS
  ```
- 未做 URL detector 全量扫描（需要真实 45k 数据后端）；源码 detector + axe + 视觉基线覆盖当前 demo 快照。

## 2. axe-core 可访问性（T93）

`@axe-core/playwright@4.14.0` + axe-core，tags `wcag2a, wcag2aa, wcag21a, wcag21aa`：

| 场景 | 视口 | violations |
|---|---|---|
| 欢迎页 | 1440 | 0 |
| 安全事件工作台 | 1440 | 0 |
| 事件详情 | 1440 | 0 |
| 证据抽屉打开 | 1440 | 0 |
| 安全事件工作台 | 390 | 0 |

修复记录：
- 图表缩放按钮：`aria-label` 不含可见 `100%` → 改为 sr-only 文本 + 可见百分比。
- SVG 节点：可见 text 与 `aria-label` 不连续 → 节点名称拼接规则与可见文本完全一致，并隐藏纯装饰 text；detail 页面 violations 清零。
- 证据抽屉从自定义 aside 改为 Base UI Dialog（coss Sheet 适配版）：role=dialog、焦点陷阱、Esc、`body overflow:hidden`、关闭后焦点恢复均实测通过。

## 3. 响应式 / 移动端（T32/T48/T60/T65/T92）

Chrome 实测 `documentElement.scrollWidth <= innerWidth + 1`：

| 视口 | 工作台 | 事件详情 | 证据抽屉 |
|---|---|---|---|
| 1440 | ✅ | ✅ | ✅ |
| 1024 | ✅ | ✅ | ✅ |
| 900 | ✅ | ✅ | ✅ |
| 768 | ✅（原溢出 +10px 已修） | ✅ | ✅ |
| 390 | ✅ | ✅ | ✅ |

- ≤900：侧栏变顶部栏 + 原生 `<dialog>` 移动导航；≤640 列表转卡片布局；攻击链移动端 312px 纵向节点；时间线全事件 UTC 刻度 + 缩放；证据抽屉移动端底部 sheet（85dvh）。
- 触控目标：复制按钮 24×24、摘要/文本按钮 ≥24px；移动端无 hover 依赖。

## 4. 极值 / 压测（T94）

`frontend/src/__tests__/stress.test.tsx`：
- 300 行密集列表（长 ID、空实体、超长摘要）渲染通过。
- 5,000 字 claim：默认 4 行 clamp，DOM 保留全文，展开后取消 clamp。
- 大 JSON 仅在 `<details>` 打开后序列化（避免首屏主线程序列化）。
- URL schema：非法 page/page_size/kind/sort/severity/时间被 clamp/回退；q/entity 长度限制 120。

## 5. 动效复审（T96，emil skills 标准）

保留 5 类表面：按钮 hover/active、Sheet/Dialog 进出、Toast、生成中 Spinner/进度、列表加载文案。
- 无数据装饰动画：攻击链、时间线 marker、证据字段、数字计数均无动画。
- `prefers-reduced-motion: reduce`：全局 0.01ms 动画/过渡；Sonner 自身也遵循。
- hover 仅在 `(hover:hover) and (pointer:fine)`。
- 2026-10-28 未发现 Block 级问题；无需引入新的动画库（`motion` 未进入主 bundle）。

## 6. 后端依赖任务（G13）

| 任务 | 结果 |
|---|---|
| T100 `/workbench` 关键词/实体搜索 | ✅ `q`（稳定 ID/summary/payload 子串）+ `entity`（实体值/display_value）SQL 过滤；前端关键词/实体输入 + URL |
| T101 `/workbench` 时间范围 | ✅ `start_time`/`end_time` UTC RFC3339，`epoch(event_time)` 比较；前端 datetime-local(UTC) + URL + chips |
| T102 分析列表 API | ✅ `GET /api/v1/analyses`（ready-only，按 created_at 倒序，最多 20）；前端欢迎页优先 API、localStorage 兜底 |
| T104 page_size 全链路 | ✅ 前端 20/50/100 + URL + 后端分页；后端测试覆盖 |
| T103 AI 异步任务 | ✅ 已落地：`POST /incidents/{id}/explain-job` 返回 job_id；`GET /ai-jobs/{id}` 查询 queued/running/completed/failed/cancelled + 结果；`DELETE /ai-jobs/{id}` 协作式取消（取消后不保存报告）。前端 AIReport 改为 job 轮询（600ms）+ 取消/45s 超时 + 二次确认；后端测试覆盖完成/持久化/取消不落盘/未知 job。 |

后端测试：`PYTHONPATH=backend /tmp/tb-venv/bin/python -m pytest tests/test_workbench.py tests/test_api.py -q` = 61 passed, 1 failed（仅 `test_fastapi_server_startup_and_openapi_smoke` 的 subprocess 缺 `PYTHONPATH`；补 `PYTHONPATH=backend` 单跑通过）。

## 7. 已知限制 / 待 owner 决策

1. 项目根 LICENSE 未定：保持“保留所有权利”，需仓库负责人决定；coss registry MIT 口径需书面确认，rare-ui attribution/Commons Clause 需最终确认。
2. rare-ui `ai-status` 保留为可选试点、未接入（T83 评估：体积/动效表面不划算）。
3. 真实 45k 数据集的 Playwright 用例仍以 `TRACEBACK_REAL_DATA=1` gating；CI 默认跑自包含 fixture 套件。
4. T103 已补异步 job API 与前端轮询；同步 `/explain` 仍保留兼容。
5. 视觉基线为 2026-10-28 当前代码；后续再改 UI 需重跑 `npm run test:e2e:visual`。

## 8. 最终回归（2026-10-28 11:40）

- `npm run test:e2e`：20 passed / 3 skipped（@real），EXIT 0，46.6s；视觉测试同次刷新 16 张基线。
- 修复的 e2e 断言：Base UI Sheet 的 dialog 可访问名来自 SheetTitle（证据标题），不是固定“证据面板”；`a11y-smoke.spec.ts` / `visual.spec.ts` 改为 `getByRole('dialog')`。scroll lock 在退出动画结束后释放，测试改为 `expect.poll`。
- `npm run verify`：typecheck + 52 tests + build + bundle budget PASS。
- `PYTHONPATH=backend pytest tests/test_workbench.py tests/test_api.py`：62 passed。
- detector：0 findings，ratchet PASS。

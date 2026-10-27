# 首页态势总览与导入抽屉验收记录

日期：2026-10-27。实际验收地址：http://127.0.0.1:8765/ 。

## 实现与文件

本次仅调整前端布局、交互和相关测试。工作区原有后端产品化修改保持原样。

| 文件 | 本次变化 |
| --- | --- |
| `frontend/src/App.tsx` | 共享导入控制器保持挂载；批次切换保留当前模块，分析记录选择结果进入总览；修复目录加载期间导航丢失批次 ID 的问题。 |
| `frontend/src/components/StageRunPanel.tsx` | 紧凑标题栏、真实任务状态、批次选择器、原生 dialog 右侧抽屉；历史任务表仅在分析记录页显示；关闭抽屉保留上传校验结果和后台任务轮询。 |
| `frontend/src/styles/stageRuns.css` | 标题栏、工具栏、任务状态、抽屉、校验及日志的蓝白样式和移动端适配。 |
| `frontend/src/pages/Overview/OverviewPage.tsx` | 去除重复标题及刷新入口；保留真实指标和图表；按当前批次显示正式基线或历史快照标识。 |
| `frontend/src/styles/soc.css` | 桌面 10 张指标卡采用 5 列两行，沿用窄屏栅格与现有字号。 |
| `frontend/src/api/client.ts` | 上传接口保持原有路径、请求头、文件体和响应；使用浏览器真实上传完成事件区分上传和服务端校验阶段。 |

相关测试文件：

- `frontend/src/__tests__/stageRunPanel.test.tsx`
- `frontend/src/__tests__/modules.test.tsx`
- `frontend/src/__tests__/stageWorkbench.test.tsx`
- `frontend/e2e/home-ui.spec.ts`
- `frontend/e2e/stage-runs.spec.ts`
- `frontend/e2e/modules.spec.ts`
- `frontend/e2e/overview.spec.ts`
- `frontend/e2e/stage-workbench.spec.ts`
- `frontend/playwright.home.config.ts`

## 操作行为

首页首先显示安全运营态势总览、批次工具栏、真实指标和图表。1440×900 首屏可见全部 10 张指标卡和告警时间分布、关系决策分布两个核心图表。完整历史任务列表移到分析记录页。

标题右侧“导入告警”打开右侧抽屉，支持关闭按钮、Escape 和点击遮罩关闭。抽屉内仍使用现有真实 API 完成文件上传、字段契约校验、错误行/字段/原因展示、任务登记、阶段状态、日志和错误查看。没有模拟进度或日志。

轮询由持续挂载的共享控制器管理，关闭抽屉不取消请求或后台任务。顶部显示真实运行状态，点击可再次查看任务。待查看任务和待自动选择的运行 ID 存于本地，任务和日志仍由后端持久化历史提供。成功且 `result_available` 为真后自动切换本次结果；失败保留错误与日志。即使任务列表尚未返回，先打开面板也能在数据返回后恢复当前任务。

首页批次选择和全部模块共用 URL 中的 `analysis_id`。切换批次会清除旧内容并读取对应的分析和汇总；不可用结果显示实际原因，不回退其他批次。目录尚未返回时点击模块导航仍保留明确选择的批次。

## 实际验证

后端使用现有本地服务，页面加载最新 `frontend/dist`。浏览器测试连接真实 API，并通过正式 CLI 运行独立的 3 条、2 条原生 JSONL 测试批次；没有 Playwright 接口响应替身。

在 `frontend/` 执行：

```powershell
npm run build
npm run test -- --run
npx playwright test --config playwright.home.config.ts
```

最终结果：

- 生产构建通过，包括 TypeScript 编译。
- 前端单元测试：8 个文件、55 项通过。
- Playwright：9 项全部通过，耗时约 2 分钟。
- 覆盖六模块导航、分页筛选、精确链选择、全部链结构与关系图、阶段/关系证据抽屉及原始告警、批次切换和刷新。
- 覆盖无效文件契约错误、真实双批次分析、关闭面板后继续执行、成功后自动切换、任务持久化读取、失败日志恢复和不可用产物明确提示。
- 覆盖 1440×900、1366×768 和 390×844；检查首屏图表位置、页面与抽屉无横向溢出、键盘关闭及焦点恢复。
- 早期回归发现的导航及任务恢复时序问题已修复并重新验证。
- `git diff --check` 通过。

正式浏览器报告：`outputs/home_ui_checks/browser.xml`。

任务开始时记录并在结束后核对 4,266 个受保护文件（后端和 scripts 源码、配置、数据、evaluation 及封存目录），未发现变更或缺失。记录：`outputs/home_ui_checks/protected_before.json`、`protected_after.json`。

## 真实截图

| 截图 | 路径 |
| --- | --- |
| 桌面首页 1440×900 | `outputs/home_ui_checks/home-desktop.png` |
| 桌面导入抽屉 | `outputs/home_ui_checks/import-drawer.png` |
| 移动端首页 | `outputs/home_ui_checks/home-mobile.png` |
| 移动端导入抽屉 | `outputs/home_ui_checks/import-mobile.png` |
| 真实校验通过 | `outputs/home_ui_checks/import-validated.png` |
| 历史失败日志 | `outputs/home_ui_checks/history-failure.png` |

本次范围内无已知未解决问题。

# PR #1 三项审查问题修复（2026-10-28）

## 读取完整性

`Stage9ArtifactReader` 对实际解析的文件字节校验已有 SHA-256：正式基线必须提供原 `artifact_manifest.json`，同时校验 `stage8.json`、`stage9.json` 和 `receipt.json`；历史测量快照及新任务继续使用原执行回执和任务绑定，不生成替代封存值。

读取时核对图输入摘要、回执摘要和链输入摘要一致，阶段与已接受关系必须完整且各出现一次，关系端点必须属于本链。该过程只检查既有结果，不调用攻击链重构算法。总览、统计、证据和原始告警路由在完整性失败时返回 409。

## 输入与保留数量

总览和统计响应的 `input_count` 使用当前产物 `statistics.INPUT_ALERTS`，不再使用过滤后的告警数组长度。统计的 `kept_count` 仍表示保留告警，且与产物和执行回执核对。时间图标明“保留告警按分钟聚合”。真实 CLI 和浏览器回归覆盖输入 2 条、去重后保留 1 条以及刷新后的数量展示。

## 测试依赖

在 `backend[test]` 和可选 `backend[prototype]` 中声明 `jsonschema==4.23.0`；保留工作台核心依赖范围。原型测试和子进程验收不再要求 `TRACEBACK_SCHEMA_VALIDATOR_PATH`。已在新建的独立 Python 3.11 环境仅安装 `backend[test]` 后验证原型测试。

## 验证结果

- 工作台、产物读取、后台任务、AI 说明、离线原型与依赖声明：134 项通过。报告：`outputs/pr_fix_checks/backend.xml`。
- 阶段、候选关系、证据、链重构及噪声过滤：194 项通过。报告：`outputs/pr_fix_checks/algorithms.xml`。
- 独立标准安装环境：55 项通过。报告：`outputs/pr_fix_checks/clean-environment.xml`。
- 前端构建通过；8 个测试文件、55 项单元测试通过。
- 使用真实服务 `http://127.0.0.1:8765` 的 Playwright 验收：10 项通过，没有接口替身。报告：`outputs/pr_fix_checks/browser.xml`。
- 截图：`outputs/home_ui_checks/home-desktop.png`、`outputs/home_ui_checks/import-drawer.png`、`outputs/pr_fix_checks/deduplicated-overview.png`。
- `git diff --check` 通过。

执行过默认全量测试收集，剩余两个旧 Demo 测试因缺少外部 `data/ait_ads/dataset.yaml` 而在收集阶段失败；排除这两个文件后，独立标准环境成功收集 2733 项测试。这不表示全部 2733 项测试已执行通过。

旧 `scripts/check_repository.py` 的全仓库范围审计仍限定 Task 01～05，因后续模块超出旧白名单及五份历史冻结文档缺失而失败。本次只补充实际使用的可选依赖白名单，没有放宽业务代码或冻结文档检查。

本次未修改正式分析 CLI、算法、阈值、任务状态机、输入契约、API 字段契约、封存产物或既有分析记录。

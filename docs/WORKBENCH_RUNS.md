# TraceBack 告警导入与后台分析交付记录

验收日期：2026-10-27（Asia/Shanghai）。

```text
TASK_RESULT=PASS
ALERT_IMPORT=PASS
CONTRACT_VALIDATION=PASS
BACKGROUND_EXECUTION=PASS
REAL_PROGRESS=PASS
FAILURE_DIAGNOSTICS=PASS
AUTOMATIC_RESULT_REGISTRATION=PASS
HISTORY_SWITCHING=PASS
RESULT_ISOLATION=PASS
FORMAL_ARTIFACTS_PRESERVED=PASS
REAL_UI_SMOKE_TEST=PASS
```

## 审计结论与接入点

- 真实入口为 `scripts/run_stage_pipeline.py --input <native.jsonl> --output <new-directory>`。
- 入口调用 `app.stage_chains.pipeline.load_attack_chain_pipeline()`，再调用 `app.services.stage_pipeline.load_stage_pipeline()`，后者通过 `load_alert_pipeline()` 执行现有原生适配、实体绑定、噪声过滤与行为标准化。原有 ①～⑨ 算法调用及顺序保持。
- 输入是 UTF-8 / UTF-8 BOM JSONL，每行是原生信封 `{"source_type": "edr", "event": {...}}`；来源路由取自 `configs/front-data-profiles.yaml`，目前为 ids、waf、edr、firewall、host_audit、authentication。其他来源或格式不声称兼容。
- 原生字段遵守 `MultiSourceAdapter.convert_record()`、来源 extractor、normalization 和 CanonicalAlert 模型。原生 event_id 并非所有来源的必填字段；上传层没有另造字段要求，也不补 ID、时间或实体。CanonicalAlert 的确定性身份生成仍由原适配器完成。
- 原 CLI 成功写入 `stage8.json`、`stage9.json`、`receipt.json`；已有输出目录会失败，绝不覆盖。
- 原工作台固定读取 `outputs/attack125_final_rerun_20261023_measured`。现在明确登记正式基线 `outputs/stage9_formal_acceptance_20261022/run1` 为默认来源，原 measured 目录作为独立历史快照保留，既有 assembly manifest 注册机制保留，新增任务只读自己的 run result。
- 既有 AnalysisService 是历史算法执行器，不适合作为正式算法入口。本次沿用其单工作线程与原子 JSON 的基础模式，新增独立 StageRunService 调度正式 CLI，没有调用历史算法执行器。

## 文件变更及作用

| 文件 | 作用 |
| --- | --- |
| backend/app/api/stage_runs.py | 限流式文件接收、创建任务、状态/历史/日志/校验报告接口及生命周期挂接 |
| backend/app/services/stage_runs.py | 原生契约校验、任务持久化、解释器子进程、超时/失败处理、产物验证和 run 绑定 |
| backend/app/services/pipeline_progress.py | 冻结阶段名称与只读通知，不含算法逻辑 |
| backend/app/api/stage_workbench.py | 明确区分正式基线、既有 measured、legacy assembly、新 run；按 ID 分派读取器 |
| backend/app/api/stage_explanations.py | 既有可选 AI 侧边报告跟随被选中读取器；打开页面不调用模型 |
| backend/app/services/alert_pipeline.py | 共享原生适配器工厂；在既有 ①～④ 调用前后发送可选通知 |
| backend/app/services/stage_pipeline.py | 在既有 ⑤～⑧ 调用前后发送可选通知 |
| backend/app/stage_chains/pipeline.py | 在既有 ⑨ 调用前后发送可选通知 |
| backend/app/stage_chains/stage9_reader.py | 向读取方暴露已计算的 frozen graph digest，供产物一致性核对 |
| scripts/run_stage_pipeline.py | 增加可选 --progress-jsonl；原产物字节与退出行为保持 |
| frontend/src/App.tsx | 在现有布局挂接导入与历史区域；任务结果可用后打开既有工作台 |
| frontend/src/components/StageRunPanel.tsx | 文件选择、校验明细、任务状态、真实阶段、日志、历史切换 |
| frontend/src/styles/stageRuns.css | 新区域的现有风格及移动端布局 |
| frontend/src/api/client.ts | 上传、启动、历史与状态请求；File 本体传输 |
| frontend/src/types/stageAnalysis.ts | 上传校验、run、历史记录类型 |
| frontend/src/test/setup.ts | 为既有页面测试补充默认空任务历史桩 |
| backend/tests/test_stage_runs.py | 输入错误、异步、真实 CLI 双批次、失败/超时/缺产物、篡改、恢复与通知等价性测试 |
| frontend/e2e/stage-runs.spec.ts | 无接口替身的真实浏览器闭环、失败诊断及历史恢复测试 |
| frontend/playwright.home.config.ts | 统一工作台验收配置；任务专项可指定 stage-runs.spec.ts |
| scripts/prepare_stage_runs_smoke.py | 复用已有 3 条原生测试 fixture，另可登记明确标识的故意失败诊断任务 |
| docs/WORKBENCH_RUNS.md | 本交付记录和运行说明 |

## 完整调用链

```text
StageRunPanel 文件选择
 → POST /api/v1/stage-runs/uploads
 → Request.stream → 随机 upload_id/alerts.jsonl
 → native_alert_adapters → convert_record → 校验统计与逐行错误
 → 页面点击开始分析
 → POST /api/v1/stage-runs {upload_id}
 → SHA-256 核对 → 独立 ana_<64hex> → run.json(QUEUED)
 → ThreadPoolExecutor → VALIDATING → 复核输入 → RUNNING
 → sys.executable -u scripts/run_stage_pipeline.py
     --input 本次独立输入 --output 本次新目录 --progress-jsonl
 → 原 ①～⑨ 流水线 → stdout/stderr 合并日志及真实阶段通知
 → 退出码检查 → receipt/产物 hash/input/graph/完整成员分区检查
 → 既有 Stage9ArtifactReader 完整读取投影
 → result_binding.json → run.json(SUCCEEDED)
 → 页面轮询历史 → 选中 run_id 的结果可用
 → 既有 StageWorkbench/Overview/证据详情按相同 ID 读取
```

所有子进程以参数数组、`shell=False` 启动，使用服务器当前 Python 解释器。文件展示名称不进入存储路径；HTTP 不接受任意服务器输入/输出路径。文件实际流量超过 16 MiB 返回 413，仅开放 `.jsonl`。校验有错时启动返回 422，文件被改动返回 409。

## 接口、状态与存储

| 接口 | 行为 |
| --- | --- |
| POST /api/v1/stage-runs/uploads | 二进制 File body，X-File-Name 为 URL 编码的展示名；201 返回校验报告 |
| GET /api/v1/stage-runs/uploads/{upload_id}/errors | 下载全部校验错误，含物理行号、字段与原因 |
| POST /api/v1/stage-runs | 只接收 upload_id；202 返回已登记 run_id，不等待 CLI |
| GET /api/v1/stage-runs | 持久化历史及当前状态 |
| GET /api/v1/stage-runs/{run_id} | 状态、阶段、起止时间、耗时、退出码、失败原因与最近 32 KiB 日志 |
| GET /api/v1/stage-runs/{run_id}/log | 下载完整 stdout/stderr 合并日志 |
| GET /api/v1/stage-analyses | 兼容原目录接口，增加成功任务条目 |
| GET /api/v1/stage-analyses/{run_id}[/summary,/traces/{id},/alerts/{id}] | 兼容原结果接口，严格读取指定 run；不可用时 409 |

```text
outputs/workbench_runs/
  uploads/<random64hex>/
    alerts.jsonl
    upload.json
  runs/ana_<random64hex>/
    input/alerts.jsonl
    run.json
    run.log
    result_binding.json          # 仅成功且检查通过后登记
    result/
      stage8.json
      stage9.json
      receipt.json
```

run.json 使用现有 atomic_json 写入，记录输入 hash、文件名、数量、pipeline、配置文件摘要、实际命令参数、路径、owner/child PID、状态、阶段、时间、退出码、产物 hash、统计与可用性。

状态为 `QUEUED → VALIDATING → RUNNING → SUCCEEDED`；任何输入复核、进程、超时或产物错误均为 `FAILED`。标准输出中的真实阶段开始/完成事件驱动状态；没有伪造百分比或延时日志。阶段运行时间及文件写入完成前的编排步骤也明确显示。

当前采用每应用实例一个线程、串行执行正式 CLI，默认超时 900 秒。应用启动时，登记但 owner 进程已经死亡的活动任务明确改为 FAILED 并保留输入/日志；不会自动重跑。已完成任务直接恢复。当前验收运行使用单个 Uvicorn worker；没有引入分布式队列、自动重试或数据保留清理策略。

## 实际执行的验证

在仓库根目录：

```powershell
.venv/Scripts/python.exe -m pytest backend/tests/test_stage_runs.py backend/tests/test_stage9_pipeline.py backend/tests/test_stage_workbench.py backend/tests/test_stage_ai_explanation.py -q --junitxml=outputs/workbench_productization_checks/backend.xml

.venv/Scripts/python.exe -m pytest backend/tests/test_alert_pipeline.py backend/tests/test_noise_filter.py backend/tests/test_identity_projection.py backend/tests/test_stage56_repair.py backend/tests/test_stage_candidates.py backend/tests/test_stage_evidence.py backend/tests/test_stage_evidence_claims.py backend/tests/test_stage9_reconstruction.py -q --junitxml=outputs/workbench_productization_checks/algorithms.xml

.venv/Scripts/python.exe -m pytest backend/tests/test_stage_runs.py -q --junitxml=outputs/workbench_productization_checks/stage_runs.xml

.venv/Scripts/python.exe scripts/prepare_stage_runs_smoke.py --seed-failure
git diff --check
```

结果：相关后端组 68 passed；算法回归组 251 passed；最后的任务专项复核 10 passed。通知关闭与开启的 `stage8.json`、`stage9.json`、`receipt.json` 逐字节相同，18 个阶段事件按 ①～⑨ 原顺序产生。

在 frontend 目录：

```powershell
npm run build
npm run test -- --run
npx playwright test --config playwright.home.config.ts stage-runs.spec.ts --grep 'reopens previously'
npx playwright test --config playwright.home.config.ts stage-runs.spec.ts
```

结果：生产构建成功；50 个前端测试通过；后端实际重启后的既有结果恢复测试 1 passed；完整浏览器组 3 passed。Windows 沙箱的临时模块读取/本地网络限制通过获准的正常环境重跑解决。

浏览器实际上传已有 native fixture 的 3 条版和 2 条测试副本，验证返回的不同 run_id/output、CLI 日志、9 阶段完成、0 退出码、自动打开、历史切换、原始证据、总览、刷新、正式基线及移动端。临时篡改本次测试结果后验证 409 和不可用提示，最后恢复测试文件。另一条明确命名的诊断任务使用真实子进程向 stderr 写入错误并以 7 退出，页面验证失败阶段/退出码/日志，未创建假成功产物。浏览器未使用接口响应替身。

可查看 `outputs/workbench_productization_checks/` 下的 XML 报告、`ui-runs.json`、`ui-failure-run.json` 和截图：

- ui-validation-errors.png
- ui-real-result.png
- ui-unavailable-no-fallback.png
- ui-failed-cli.png
- ui-mobile.png

## 启动与访问

先在 frontend 运行 `npm run build`，再回到仓库根目录：

```powershell
.venv/Scripts/python.exe -m uvicorn app.api.workbench:create_workbench_app --factory --app-dir backend --host 127.0.0.1 --port 8765
```

访问 `http://127.0.0.1:8765/?view=stages`。也可以运行 Vite 开发服务器，使用既有 TRACEBACK_API_URL 配置指向后端；正式验收使用后端托管的真实生产构建。

## 保护依据与边界

- 开始时登记 `configs/`、`data/`、`evaluation/`、`outputs/stage9_formal_acceptance_20261022/` 和 `outputs/stage_chain_workbench_reseal_20261022/` 内 3,879 个既有文件的 SHA-256。结束复核全部一致，无修改或缺失，见 `protected_before.json` 和 `protected_after.json`。
- ①～⑨算法实现、关联/聚类阈值、映射配置、GT 和正式数据没有修改；三个 orchestration 文件只增加可选观察回调和共享适配器工厂。没有重判、补边、改方向或调用 AI 作算法决策。
- 没有执行 4,500 条全量流水线；正式封存产物只读，实际 CLI 验收全部使用已有 3 条原生测试 fixture 及其 2 条副本。
- 仓库开始时已有多项 docs 删除和其他未跟踪目录，本次未恢复、覆盖或归入本次代码变更。
- 本任务要求的入口闭环已完成，无未解决阻塞。未将分布式调度、自动清理或算法优化扩入本次范围。

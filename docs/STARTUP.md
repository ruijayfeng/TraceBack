# TraceBack 启动与维护指南

[返回 README](../README.md)

快速启动见 README。本指南区分直接查看已有快照与旧版 AIT-ADS Demo；以下命令均在项目根目录执行。

## 查看已有分析快照（推荐入口）

已安装依赖并构建前端时，直接启动工作台。它从已发布快照读取结果，不运行 Demo 的数据集登记检查，也不重新运行生产分析：

```powershell
cd D:\Code_WorkSpace\TraceBack
.\.venv\Scripts\python.exe -m uvicorn app.api.workbench:create_workbench_app --factory --host 127.0.0.1 --port 8000
```

保持终端运行，打开 [http://127.0.0.1:8000](http://127.0.0.1:8000)。停止时按 `Ctrl+C`。如果 8000 被占用，将命令中的 `--port 8000` 改为 `--port 8001`，同时访问 8001；此模式不使用 Vite，不需要设置代理。

首页首先显示安全运营态势总览，无需输入分析 ID。通过“导入告警”可上传原生 JSONL，完成字段校验后启动真实后台分析；关闭操作抽屉不会停止任务，成功后自动打开本次结果，历史任务集中在“分析记录”页。详见[导入与后台分析说明](WORKBENCH_RUNS.md)。

本机当前正式 ATTACK125 基线包含 **125 条告警、15 个阶段、12 条关系、7 条链结构**。换机器查看该基线时，须从原机器复制完整 `outputs/stage9_formal_acceptance_20261022/`，包括 `run1/stage8.json` 和 `run1/stage9.json`。旧 `outputs/attack125_final_rerun_20261023_measured/` 为独立历史快照。这些产物不随 GitHub 分发，安装依赖不会恢复它们；没有既有快照时仍可通过首页导入自己的符合契约的原生告警。

旧版 **47 个阶段 / 255 条关系 / 4 个事件**分析仍可显式打开：

```text
http://127.0.0.1:8000/?view=stages&analysis_id=ana_8fed5306fabb29d1a12812f8f084a6f066bfc30d4e87bc7629f39c62a797ca84
```

阶段分析支持事件切换、包含全部阶段和分支汇合的事件流程图、完整关系列表，以及右侧证据抽屉中的阶段与关系见证告警、字段指针及按需读取的原始告警。流程图默认折叠同种证据、同种关系中可沿其他连线到达的跨线，可展开全部关系，并支持缩放、全图和按宽度适配。打开抽屉保持页面位置，可按 Esc、点击遮罩或关闭按钮退出。弱时间关系不表示因果关系，强无向关系不绘制箭头。入口展示已有结果，不重新运行分析。旧版读取器首次打开会核验整套证据文件，后续请求复用已校验对象并检查文件摘要；正式⑨读取器目前仍会重复加载源文件，不能沿用旧版的缓存和响应时间描述。

换机器时，须保留 Stage Chain manifest 所引用的上游 Relation / Stage / Evidence Trace 及其领域文件。只复制最终的 `stage_attack_chains.jsonl` 不足以打开证据链。

### 查看历史 v4 结果

下方是历史 AIT-ADS 的 4 万多条告警结果，适合回查旧分析；它不是新的 ATTACK125 分析。2026-10-19 曾验证其页面、总览和事件列表接口返回 200：

```text
http://127.0.0.1:8000/?analysis_id=ana_98138a4c0e4260788c8fad5de18e9140edc1c55413e613216e54d81cc85b93aa
```

该 ID 对应本机现存快照，不表示重新执行了分析，也不表示所有后续算法版本已验收。换机器时须保留对应的 `data/processed/<analysis_id>/` 和 `outputs/analyses/<analysis_id>/`；缺失、损坏或未发布完整的快照不能用这个地址恢复。不要从状态为 failed 的 `outputs/task09/demo_manifest.json` 选择 ID。

## 旧版 AIT-ADS Demo（需要原始数据）

以下 `scripts/demo.py` 命令用于原有数据集演示流程。当前副本缺少 `data/ait_ads/dataset.yaml`，须先恢复对应登记文件和真实数据包；安装依赖不会补齐数据，`--warm-only` 也会检查数据与配置。仅查看已有快照时，使用上方工作台入口即可。

TraceBack 面向 SOC 场景，对跨源、跨时间的安全告警进行关联分析、事件归并与攻击链重构，并通过证据约束的 AI 提供可回溯的研判解释。

SOC 的告警字段、来源和时间分散，需要人工整理调查上下文。TraceBack 位于上游检测设备之后：**算法负责关联与重构，告警负责事实与证据，AI 负责解释与研判**。设备产生告警不等于入侵已确认。

```text
Wazuh / AMiner 安全告警 → Adapter 基础 Normalization
→ Duplicate Candidate Generation → Dedupe → Entity Extraction
→ Correlation Candidate Admission → Scoring → CorrelationEdge
→ Incident → AttackChain → Evidence Grounding → AI Explanation
→ 已验证 ATT&CK / JSON / Markdown → FastAPI → React SOC 工作台
```

## 启动方法（Windows / PowerShell）

**仅针对旧版 Demo：**完成下方数据准备后，首次安装参照 README；之后可按本指南的“日常启动：一键 Demo”运行数据集演示。常规工作台启动与 UI 开发参照 README。

以下命令均在仓库根目录执行。每打开一个 PowerShell 终端，先进入项目目录；项目放在其他位置时替换此路径：

```powershell
Set-Location 'D:\Code_WorkSpace\TraceBack'
```

### 1. 首次安装

准备 Python **3.11**（后端限定 `>=3.11,<3.12`）、Node.js **24** 和 npm；下面首选安装方式还需要 `uv`。当前本机验证环境为 Python 3.11.16 / Node.js 24.16.0。依赖版本见 `backend/pyproject.toml` 和 `frontend/package-lock.json`。

```powershell
# 检查工具是否可用
uv --version
node --version
npm.cmd --version

# 创建 Python 3.11 虚拟环境，安装后端及测试依赖
uv venv --python 3.11 .venv
uv pip install --python .venv/Scripts/python.exe --cache-dir .venv/uv-cache --editable './backend[test]'

# 安装前端依赖，生成 Demo 使用的静态页面
npm.cmd --prefix frontend ci
npm.cmd --prefix frontend run build
```

如果没有 `uv`，且已通过 Windows Python Launcher 安装 Python 3.11，可用以下命令替代上面的两个 `uv` 安装命令；前端安装 / 构建步骤相同：

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --editable './backend[test]'
```

后续直接调用 `.\.venv\Scripts\python.exe`，无需激活虚拟环境；不要依赖本机默认 `python` 的版本。使用 `npm.cmd` 可避免 PowerShell 阻止执行 `npm.ps1`。

当前一键 Demo 还依赖以下已验收的真实告警与产物，复制项目到新机器时须一并保留：

- `data/ait_ads/russellmitchell/raw/russellmitchell_wazuh.json`
- `data/ait_ads/russellmitchell/raw/russellmitchell_aminer.json`
- `data/ait_ads/dataset.yaml` 中已登记的场景、输入和已确认源声明（namespace、timezone、Adapter 格式 / 版本）；当前启动脚本从该登记文件加载，不用历史 manifest 替代登记文件。
- 若要复用已有结果，还须保留该分析在 `data/processed/<analysis_id>/` 和 `outputs/analyses/<analysis_id>/` 下的完整快照及诊断文件。

仅有代码和依赖无法运行这套真实 Demo；`--cold-rebuild` 也需要真实输入和已确认源声明。标准生产告警入口仍为 `data/input/alerts/`，当前 Demo 使用上述已登记文件，不会自动分析随意放入该目录的文件。

### 2. 日常启动：一键 Demo

已完成首次安装、前端构建和分析，且数据与快照仍保留时执行；无需重复安装依赖或重新构建未改动的页面：

```powershell
# 复用匹配快照并启动 Demo；缺少快照时直接报错
.\.venv\Scripts\python.exe scripts/demo.py --warm-only
```

该命令先寻找与当前输入 / 配置 / Mapping / 算法版本匹配的快照，验证摘要和证据闭包，再启动 API 并运行真实 A/B/C Smoke；没有匹配快照时报告 `snapshot_missing`，不会执行完整分析。单独检查环境、配置、真实输入和存储可用 `--check-only`，不必在每次日常启动前重复执行。无参数启动会在缺少匹配快照时执行完整分析（Cold），历史实测约 32 分钟，耗时随机器与输入变化。

启动成功后应看到 `Status : completed`、`API:`、`API Docs:`、`Web:` 和 `Analysis ID:`。**在浏览器打开完整的 `Web:` 地址，保留其中的 `?analysis_id=ana_...`。** Demo 自动分配本地空闲端口，每次可能不同，不固定为 8000 或 5173。`API Docs:` 是本次服务的 Swagger 接口文档地址。

Demo 的同一个 API 服务托管已构建 React 页面，无需额外启动 Vite。启动命令结束后，后台 API 仍继续运行。前端代码修改后，重新执行 `npm.cmd --prefix frontend run build`，再启动 Demo。

按需选择其他启动方式，`<analysis_id>` 要替换为已有完整 ID：

```powershell
# 只复用匹配快照；找不到则报错，不触发完整分析
.\.venv\Scripts\python.exe scripts/demo.py --warm-only

# 打开指定快照；会检查其输入、配置、版本和完整性
.\.venv\Scripts\python.exe scripts/demo.py --analysis-id '<analysis_id>'

# 明确执行完整分析，在新隔离分区保存结果，保留旧结果
.\.venv\Scripts\python.exe scripts/demo.py --cold-rebuild
```

本次 PID、端口、日志和 manifest 位于 `outputs/demo/task09-*/`。场景汇总为 `outputs/task09/<dataset>/<scene>/demo_manifest.json`，默认场景还会更新 `outputs/task09/demo_manifest.json`。停止 Demo 时，将下面的 `12345` 替换为**本次终端打印的 PID**，只结束该进程树：

```powershell
taskkill /PID 12345 /T /F
```

### 3. 开发模式：前后端分别启动

完成依赖安装并准备好已有分析快照后，打开两个 PowerShell 终端。此方式只启动服务，不自动执行告警分析；已有 `analysis_id` 可从 Demo 输出或 `outputs/task09/demo_manifest.json` 获取。

**终端 A：启动后端。**

```powershell
Set-Location 'D:\Code_WorkSpace\TraceBack'
.\.venv\Scripts\python.exe -m uvicorn app.api.workbench:create_workbench_app --factory --host 127.0.0.1 --port 8000
```

看到 `Uvicorn running on http://127.0.0.1:8000` 后，接口文档为 [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)。

**终端 B：启动前端开发服务器。**

```powershell
Set-Location 'D:\Code_WorkSpace\TraceBack'
npm.cmd --prefix frontend run dev
```

打开 Vite 打印的 `Local:` 地址，默认通常为 [http://127.0.0.1:5173](http://127.0.0.1:5173)；端口被占用时以实际输出为准。首页自动选择最新已封存的阶段分析。历史分析可访问 `http://127.0.0.1:5173/?analysis_id=<analysis_id>`（替换 ID 和实际端口）。

Vite 默认将 `/api` 代理到 `http://127.0.0.1:8000`。若后端改用 8001，在终端 A 将 `--port 8000` 改为 `--port 8001`，终端 B 启动前设置：

```powershell
$env:TRACEBACK_API_URL = 'http://127.0.0.1:8001'
npm.cmd --prefix frontend run dev
```

两个终端都需要保持运行，分别按 `Ctrl+C` 停止前后端。页面使用 URL 中明确的 `analysis_id` / `incident_id`；刷新、切换和分页保持快照隔离。证据按需读取，`raw_alert` 默认折叠，未定向关联不画箭头。

### 4. 常见启动问题

| 现象 | 处理方法 |
| --- | --- |
| 找不到 `.venv\Scripts\python.exe` / 提示 Python 3.11 required | 先执行首次安装，确认在仓库根目录，并用上述虚拟环境解释器启动。 |
| `uv` / `node` / `npm.cmd` 无法识别 | 安装相应工具并重新打开终端；没有 uv 时可用上述 Python Launcher 替代步骤。 |
| `ModuleNotFoundError: app` 或后端依赖不匹配 | 重新执行后端 editable 安装；确认 uvicorn 使用 `.venv` 的 Python。 |
| `confirmed AdapterSettings missing` / 真实输入缺失 | 恢复已验收且与当前配置匹配的源 manifest 和两份真实告警文件，然后重新执行 `--check-only`。 |
| `build_required` / `Web:` 提示 Build UI | 执行 `npm.cmd --prefix frontend ci` 和 `npm.cmd --prefix frontend run build`，随后重新启动 Demo。 |
| `snapshot_missing` / `analysis_not_found` | 恢复指定快照，或在真实输入 / 源声明齐全时执行 `--cold-rebuild`，然后使用新输出的 Analysis ID。 |
| `snapshot_invalid` / `snapshot_integrity_error` | 检查对应 Demo manifest / `api.log`，恢复完整产物或显式 Cold 重建；不手改摘要绕过验证。 |
| 后端 8000 端口被占用 | 使用其他端口，并同步设置前端终端的 `TRACEBACK_API_URL`。Demo 会自动分配空闲端口。 |
| 页面提示 network_unavailable | 确认后端仍运行、使用本次打印的 URL，开发模式下核对 Vite 代理端口。 |
| 页面要求输入 Analysis ID / 查询 404 | 使用同一后端已有快照的完整 `ana_...` ID，不把 Incident ID 当作 Analysis ID。 |

当前副本缺少旧版 `docs/DEMO.md`，启动与恢复操作集中保留在本指南。

## 数据、结果和边界

本节的数量、耗时、测试结果和验收状态来自原 README 的历史记录，本次文档整理未重新运行或核验，不代表当前场景结果或本次验证结果。

AIT-ADS 接入统一注册于 `data/ait_ads/dataset.yaml`：russellmitchell、fox、harrison、santos、shaw、wardbeck、wheeler、wilson。现有 `<scene>_aminer.json` / `<scene>_wazuh.json` 文件直接引用，不改名、不改内容。Wazuh 内转发 Suricata 沿用现有 Adapter；标准输入仍为 data/input/alerts/。每次 Analysis 只处理一个场景，场景身份由源 namespace 和分析 manifest 元数据追踪，不作为关联评分证据。缺文件返回 `missing_raw_data`，不生成替代数据。

```powershell
.\.venv\Scripts\python.exe scripts/demo.py      # 默认 ait_ads / russellmitchell
.\.venv\Scripts\python.exe scripts/demo.py --dataset ait_ads --scene shaw --check-only
.\.venv\Scripts\python.exe scripts/demo.py --dataset ait_ads --scene fox
.\.venv\Scripts\python.exe scripts/demo.py --dataset ait_ads --scene harrison --cold-rebuild
.\.venv\Scripts\python.exe scripts/ait_ads_inventory.py             # 全 8 场景清点，结构检查 + 有界 Adapter 抽样
.\.venv\Scripts\python.exe -m evaluation.io.ait_ads                 # 独立 GT 元数据解析；不运行生产算法
```

`--scene` 可使用 registry 中任一 enabled 场景；`--warm-only` 要求已有匹配快照，`--cold-rebuild` 显式重跑完整生产分析。不同场景快照按既有 Analysis-ID 目录隔离；默认 Demo 和旧快照继续兼容。算法、权重、Top-K、Guard、阈值及方向准入保持冻结；大场景可触发既有全局预算并返回 incomplete，不能据此调低阈值。软件版本未明确仍记录 unknown，不推定跨源独立性。

实际 GT 仍保留于 `data/ait_ads/russellmitchell/evaluation/labels.csv`，manifest 的 evaluation 区仅供 evaluation 读取。该文件覆盖 8 场景，列为 scenario/attack/start/end；只支持攻击时间窗元数据，无具体告警、Incident 或因果边真值。生产不打开标签，registry 的生产投影 / config snapshot 不含 GT 路径，缺少的 time_label/event_label/attack_stage 保持 null，不从 attack 名称推断阶段。清点产物见 `outputs/ait_ads/SCENE_INVENTORY.json`，GT 分析见 `outputs/ait_ads/GT_ANALYSIS.json`。

| 实际指标 | 数量 |
| --- | ---: |
| Input | 45,544 |
| CanonicalAlert | 45,510 |
| Entity | 13,752 |
| Representative | 45,501 |
| Incident | 45,501 |
| ChainNode | 45,501 |
| ChainEdge | 0 |
| Singleton（成员告警数=1） | 45,492 |
| Multi-alert（成员告警数>1） | 9 |

真实 ChainEdge=0 合法呈现；九个 multi-alert 均为去重组。合成有边功能演示与真实快照完全隔离，醒目标注 Synthetic Fixture / Functional Demonstration。

Provider 配置沿用 configs/llm.yaml；后端环境变量 TRACEBACK_LLM_BASE_URL / TRACEBACK_LLM_MODEL / TRACEBACK_LLM_API_KEY。密钥不进前端或快照。当前未配置外部模型，Explain 正式降级为经过验证的确定性事实报告；Incident / Chain / Evidence 可独立查询。正式报告只发布 validated claims / mappings；Rejected 在独立 Diagnostics，不能加入报告。已发布报告保存在 outputs/workbench/<analysis_id>/，与模型生成缓存分开。

## 验证命令

按修改范围选择验证；这些命令不是每次启动的必做步骤。当前副本缺少 `AGENTS.md`、三份原始需求和 `docs/CODEX_TASKS.md`，涉及这些文件的完整性检查须先恢复原文。

```powershell
.venv/Scripts/python.exe -m pytest backend/tests -q
.venv/Scripts/python.exe -m pytest evaluation/tests -q
.venv/Scripts/python.exe -m pytest backend/tests/test_repository_contract.py -q
npm.cmd --prefix frontend run test -- --run
npm.cmd --prefix frontend run typecheck
npm.cmd --prefix frontend run build
.venv/Scripts/python.exe scripts/check_repository.py
.venv/Scripts/python.exe scripts/verify_demo.py --analysis-id <ID> --url <本次 API URL> --browser-tests
```

Playwright 需要已安装 Chromium；可传 --browser-executable <本机路径>，或按既有 README 流程 `npm.cmd --prefix frontend exec -- playwright install chromium`。生产 API 只读 evaluation 白名单指标导出，GT 仅 evaluation 模块访问。

本次 full pytest 1476 passed / 4 skipped；前端 31 passed，typecheck / build / 5 条浏览器验收通过。Cold 历史实测 1933.58s，Warm 快照加载与验证 7.00s，API startup 8.48s；包含真实完整 Smoke 的本次一键验收 114.22s。

旧版引用的 `docs/DEMO.md`、`docs/EVALUATION_REPORT.md`、`docs/DEFENSE_OUTLINE.md` 当前不存在，本指南不替代缺失的评测、答辩文档或需求原文。历史最终验收见 [TASK_09_REPORT](../outputs/task09/TASK_09_REPORT.md)。本次不修改冻结基线，v0 参数不宣称最优或校准概率。

Task 09 状态 completed_with_known_limitations；外部 LLM 与第二真实数据集能力未验收，当前真实无传播边。完成后停止，不自动推进后续开发。


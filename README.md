# TraceBack · 智溯

面向 SOC 的安全告警研判工作台：关联 Wazuh / AMiner 告警、归并安全事件、重构攻击链，并提供可回溯的证据和 AI 解释。

**算法负责关联与重构，告警提供事实与证据，AI 负责解释。设备告警不等于攻击已确认。**

本仓库发布源码、测试、配置示例与文档。原始数据、分析快照、本地 AI 密钥配置、依赖和运行产物不随 GitHub 分发；下文的历史快照地址仅适用于保留对应快照的本机。

## 第一次使用：安装并启动

**新电脑或尚未安装依赖时，按本节执行一次。** 准备 Python **3.11**（含 Windows Python Launcher）、Node.js **24** 和 npm。

**分析入口与已有快照：**启动后可从首页“导入告警”上传符合原生输入契约的 JSONL 文件，校验通过后运行后台分析。若要查看本机已有正式基线，须从原机器复制完整的 `outputs/stage9_formal_acceptance_20261022/`（包含 `artifact_manifest.json` 及 `run1/` 下的 `stage8.json`、`stage9.json`、`receipt.json`）；原 `outputs/attack125_final_rerun_20261023_measured/` 作为独立历史快照保留。查看旧版分析还需对应的 `data/processed/<analysis_id>/` 和 `outputs/analyses/<analysis_id>/`。这些数据与快照不随 GitHub 分发，安装依赖本身不会生成分析结果。工作台入口无需 AIT-ADS 原始数据登记文件。

打开 PowerShell，按顺序执行（项目路径不同时替换第一行）：

```powershell
cd D:\Code_WorkSpace\TraceBack

# 1. 创建 Python 环境并安装后端依赖
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --editable './backend[test]'

# 2. 安装前端依赖并构建页面
npm.cmd --prefix frontend ci
npm.cmd --prefix frontend run build

# 3. 启动工作台（同时提供 API 和构建后的页面）
.\.venv\Scripts\python.exe -m uvicorn app.api.workbench:create_workbench_app --factory --host 127.0.0.1 --port 8000
```

`test` 安装项包含离线攻击步骤原型测试所需的 `jsonschema`，运行测试无需额外设置 `TRACEBACK_SCHEMA_VALIDATOR_PATH`。只使用离线原型时，可安装 `./backend[prototype]`；工作台核心运行依赖不包含该可选校验器。

看到 `Uvicorn running on http://127.0.0.1:8000` 后，打开[工作台](http://127.0.0.1:8000)。首页为态势总览，自动读取最新正式分析，无需填写 Analysis ID。当前正式快照为 **125 条告警、15 个阶段、12 条关系、7 条链结构**；通过顶部导航进入告警、场景、攻击链和证据页面。历史 **47 阶段 / 255 关系 / 4 事件**快照仍按原分析 ID 保留。工作台展示已有分析结果；启动服务不会重新运行算法。

保持终端运行，按 `Ctrl+C` 停止。这个入口只启动服务，不重新运行告警分析。

无需手动激活虚拟环境。使用 uv 安装的替代命令见[启动指南](docs/STARTUP.md)。

## 已经安装过：日常启动

**之前已完成安装和页面构建，且分析快照仍保留时，只执行下面两行，无需重复安装：**

```powershell
cd D:\Code_WorkSpace\TraceBack
.\.venv\Scripts\python.exe -m uvicorn app.api.workbench:create_workbench_app --factory --host 127.0.0.1 --port 8000
```

看到 `Uvicorn running` 后，打开[工作台](http://127.0.0.1:8000)，自动进入最新正式分析的态势总览。旧版结果仍可通过原有 `?analysis_id=...` 地址查看；点击顶部 TraceBack 标志返回最新总览。保持终端运行，按 `Ctrl+C` 停止。

工作台直接读取已有快照，不经过 `scripts/demo.py` 的 AIT-ADS 数据检查。旧版 Demo 的重新分析、场景切换及其数据前提见[启动指南](docs/STARTUP.md#旧版-ait-ads-demo需要原始数据)。

如果只是重新打开终端，直接日常启动即可；前端代码改动后，使用上述工作台入口前需重新运行 `npm.cmd --prefix frontend run build`；依赖清单或锁文件变动后，再安装对应依赖。8000 被占用时，按[启动指南](docs/STARTUP.md#查看已有分析快照推荐入口)更换端口。

## 导入告警与后台分析

首页以安全运营态势总览为中心，通过标题右侧“导入告警”打开操作抽屉。选择 UTF-8 原生 JSONL 文件（最大 16 MiB）后，系统执行真实字段契约校验，展示通过数量及具体错误行、字段和原因；校验通过后点击“开始分析”。

抽屉显示正式①～⑨流水线的真实阶段状态和日志。关闭抽屉不会取消后台任务，顶部状态可再次打开任务详情；分析成功且产物检查通过后，页面自动切换到本次结果。当前批次工具栏支持历史切换，完整任务列表、失败原因与日志集中在“分析记录”页。

输入、任务登记和结果保存在本地 `outputs/workbench_runs/`，重启后可恢复读取。接口、持久化和验收细节见[告警导入与后台分析说明](docs/WORKBENCH_RUNS.md)，首页布局与截图说明见[首页 UI 验收记录](docs/HOME_UI_ADJUSTMENT.md)。

## 修改 UI 时怎么启动

已有依赖和分析快照时，打开两个 PowerShell 终端，分别进入项目根目录：

**终端 A · 后端**

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.api.workbench:create_workbench_app --factory --host 127.0.0.1 --port 8000
```

**终端 B · 前端**

```powershell
npm.cmd --prefix frontend run dev
```

打开 Vite 打印的 `Local:` 地址，首页自动进入态势总览。历史分析使用带 `?analysis_id=...` 的地址。此模式修改 UI 后会自动刷新；关闭服务时在两个终端分别按 `Ctrl+C`。

工作台采用顶部模块导航：**态势总览 / 安全告警 / 攻击场景 / 攻击链 / 证据追溯 / 分析记录**。总览仅展示指标、分布和 4 条链摘要；告警与证据列表每页 10 条，攻击链页通过“攻击流程 / 阶段列表 / 关系列表 / 拒绝建边”切换内容。选择的分析、链和视图可通过 URL 刷新恢复；手机总览可按需展开关系与来源分布。

首页展示最新正式快照的真实统计；参考设计中的风险评分、处置状态与 ATT&CK 分布，需要对应数据支持后再接入。

## 只读 AI 辅助研判

正式攻击链页面新增 **AI 辅助研判** 区域，点击“生成 AI 研判”后，解释当前 Chain 的三类内容：

- **Stage 具体行为**：结合原始告警中的请求、进程、命令行、文件、账户和主机等字段，分别展示观测事实、谨慎解释与缺失证据。
- **已有 Relation 的关联依据**：说明正式算法已经接受的证据关系，保留原有有向边和未解决方向的无向边。
- **阶段及整体影响**：分别展示潜在危害和有明确证据支持的已确认观测，不把告警、成功认证或网络流量升级为主机失陷、账户失陷或数据泄露。

AI 只读取当前正式⑨结果及其告警、实体和关系证据，不参与①～⑨的算法决策，不修改 Stage、Community、Relation、方向或 Chain，也不补边或合并不同 Chain。输出通过结构、原始字段指针、证据引用与关系一致性校验后才展示；可回查原始证据并导出 JSON / Markdown。打开页面或读取已存报告不会自动调用模型。

**模型配置：**首次配置时参考 `configs/llm.example.yaml` 创建本地 `configs/llm.yaml`，填写 `base_url`、`model` 和 `api_key`；也支持 `TRACEBACK_LLM_BASE_URL`、`TRACEBACK_LLM_MODEL`、`TRACEBACK_LLM_API_KEY` 环境变量。配置文件和密钥不提交到 GitHub，修改后重启后端。缺少配置、模型调用失败或 grounding 拒绝时，仅显示“AI 辅助研判暂不可用”，原始攻击链、关系与告警仍可查询。

核心实现位于 `backend/app/ai/`：`stage_context.py` 整理只读证据输入，`stage_explanation.py` 负责服务和报告，`stage_grounding.py` 校验输出，`stage_knowledge.py` 定义受证据约束的解释与影响规则。接口位于 `backend/app/api/stage_explanations.py`，前端位于 `frontend/src/components/StageAIReport.tsx`。报告独立存放于本地 `outputs/ai_stage_reports/`，不写回正式分析结果。

已有正式 ATTACK125 快照时，可验证主要多节点 Chain：

```powershell
.\.venv\Scripts\python.exe scripts/verify_stage_ai.py
.\.venv\Scripts\python.exe -m pytest backend/tests/test_stage_ai_explanation.py -q
```

验证脚本保存证据包、grounding 预览、错误注入结果与正式文件前后哈希；配置完整时会发起真实模型请求。未配置模型时如实记录 `REAL_MODEL_TEST=NOT_EXECUTED`，确定性预览不计为真实模型输出。详细边界、API 和验证方法见 [Stage AI 辅助研判说明](docs/STAGE_AI_ASSISTANCE.md)。

## 项目目录结构

以下列出主要目录，省略依赖、缓存和构建产物：

```text
TraceBack/
├── backend/                  # Python 后端
│   ├── app/
│   │   ├── adapters/         # 接入不同来源的安全告警，统一格式
│   │   ├── models/           # 领域数据模型与字段校验
│   │   ├── dedup/            # 告警去重，保留原始成员
│   │   ├── entities/         # 抽取主机、账号、进程等实体
│   │   ├── correlation/      # 关联候选生成与评分
│   │   ├── incidents/        # 将关联告警聚合为安全事件
│   │   ├── chains/           # 攻击链节点、方向与边的重构
│   │   ├── evidence_trace/   # 证据追溯与引用核验
│   │   ├── ai/               # 基于已有证据生成解释与报告
│   │   ├── api/              # FastAPI 接口与工作台入口
│   │   └── services/         # 分析流程、快照存储与查询
│   └── tests/                # 后端单元、集成与隔离测试
├── frontend/                 # React + TypeScript 前端
│   ├── src/
│   │   ├── pages/            # 总览、事件列表与事件详情页面
│   │   ├── components/       # 攻击链、证据面板等界面组件
│   │   ├── api/              # 后端请求与数据加载
│   │   ├── styles/           # 页面样式；调整 UI 的常用入口
│   │   ├── types/            # 前端数据类型
│   │   └── __tests__/        # 前端功能与交互测试
│   └── e2e/                  # 浏览器端到端测试
├── configs/                  # 算法、来源与 AI 等配置
│   └── mappings/             # 来源字段和告警类别映射
├── data/
│   ├── input/alerts/         # 标准生产安全告警输入
│   └── processed/            # 按 Analysis ID 保存的分析结果
├── evaluation/               # 独立评测；只有此模块可读取真值
├── outputs/                  # 分析诊断、运行日志与报告
├── scripts/                  # Demo 启动、验证及实验辅助脚本
├── docs/                     # 启动指南、数据契约与算法说明
├── work/                     # 工作过程中的临时验证与实验文件
└── README.md                 # 项目介绍与快速启动
```

## 更多说明

- [Stage AI 辅助研判](docs/STAGE_AI_ASSISTANCE.md)：正式攻击链的只读解释、证据校验、风险分离和模型配置。
- [Stage 1–4 正式流水线](docs/STAGE_1_4_PIPELINE.md)：唯一原生输入入口、Noise→Behavior 交接及历史入口边界。
- [启动指南](docs/STARTUP.md)：数据准备、重新分析、切换场景、停止 Demo、端口设置与排错。
- [验证命令](docs/STARTUP.md#验证命令)：后端测试、前端检查和浏览器验收。
- [结果与能力边界](docs/STARTUP.md#数据结果和边界)：历史结果、AI 配置与评测限制。
- [数据契约](docs/DATA_CONTRACT.md)、[算法配置](docs/ALGORITHM_CONFIG.md)。

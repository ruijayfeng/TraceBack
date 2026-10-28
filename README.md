# TraceBack · 智溯

面向 SOC 的安全告警研判工作台：关联 Wazuh / AMiner 告警、归并安全事件、重构攻击链，并提供可回溯的证据和 AI 解释。

**算法负责关联与重构，告警提供事实与证据，AI 负责解释。设备告警不等于攻击已确认。**

本仓库发布源码、测试、配置示例与文档。原始数据、分析快照、本地 AI 密钥配置、依赖和运行产物不随 GitHub 分发；下文的历史快照地址仅适用于保留对应快照的本机。

## 第一次使用：安装并启动

**新电脑或尚未安装依赖时，按本节执行一次。** 准备 Python **3.11**（含 Windows Python Launcher）、Node.js **24** 和 npm。

**查看结果需要已有分析快照：**保留或从原机器复制对应的 `data/processed/<analysis_id>/` 和 `outputs/analyses/<analysis_id>/`。当前副本已有可查询快照；安装依赖本身不会生成分析结果。查看已有结果使用下方工作台入口，无需 AIT-ADS 原始数据登记文件。

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

看到 `Uvicorn running on http://127.0.0.1:8000` 后，打开[工作台](http://127.0.0.1:8000)，在页面顶部输入已有的 Analysis ID，点击“打开分析”。[本机已验证的快照地址](docs/STARTUP.md#查看已有分析快照推荐入口)可直接复制使用。

保持终端运行，按 `Ctrl+C` 停止。这个入口只启动服务，不重新运行告警分析。

无需手动激活虚拟环境。使用 uv 安装的替代命令见[启动指南](docs/STARTUP.md)。

## 已经安装过：日常启动

**之前已完成安装和页面构建，且分析快照仍保留时，只执行下面两行，无需重复安装：**

```powershell
cd D:\Code_WorkSpace\TraceBack
.\.venv\Scripts\python.exe -m uvicorn app.api.workbench:create_workbench_app --factory --host 127.0.0.1 --port 8000
```

看到 `Uvicorn running` 后，打开[工作台](http://127.0.0.1:8000)，输入已有的 Analysis ID；也可以直接打开之前保存的带 `?analysis_id=...` 的工作台地址。保持终端运行，按 `Ctrl+C` 停止。

工作台直接读取已有快照，不经过 `scripts/demo.py` 的 AIT-ADS 数据检查。旧版 Demo 的重新分析、场景切换及其数据前提见[启动指南](docs/STARTUP.md#旧版-ait-ads-demo需要原始数据)。

如果只是重新打开终端，直接日常启动即可；前端代码改动后，使用上述工作台入口前需重新运行 `npm.cmd --prefix frontend run build`；依赖清单或锁文件变动后，再安装对应依赖。8000 被占用时，按[启动指南](docs/STARTUP.md#查看已有分析快照推荐入口)更换端口。

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

打开 Vite 打印的 `Local:` 地址，在页面顶部输入已有的 Analysis ID 并点击“打开分析”。可使用[已验证快照](docs/STARTUP.md#查看已有分析快照推荐入口)的 ID，不使用失败的 Demo 运行记录。此模式修改 UI 后会自动刷新；关闭服务时在两个终端分别按 `Ctrl+C`。

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

- [启动指南](docs/STARTUP.md)：数据准备、重新分析、切换场景、停止 Demo、端口设置与排错。
- [验证命令](docs/STARTUP.md#验证命令)：后端测试、前端检查和浏览器验收。
- [结果与能力边界](docs/STARTUP.md#数据结果和边界)：历史结果、AI 配置与评测限制。
- [数据契约](docs/DATA_CONTRACT.md)、[算法配置](docs/ALGORITHM_CONFIG.md)。

## License

本项目使用 MIT License，见 [LICENSE](LICENSE)。第三方 UI 组件另有各自许可证，见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 第三方 UI 组件

本项目 UI 优化使用/计划使用以下第三方组件与工具，完整许可证与来源见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)：

- [coss.com/ui](https://github.com/cosscom/ui)（Cal.com Design System，registry 路径，MIT）
- [Rare UI](https://rareui.com)（`ai-status` 组件，MIT + Commons Clause + Attribution）
- [Lucide](https://lucide.dev) / [morphicons](https://morphicons.com) / [Tailwind CSS](https://tailwindcss.com) / [Base UI](https://base-ui.com)

Rare UI 组件使用需保留其版权与许可声明；Rare UI 名称、logo 与站点设计不在组件许可证范围内。

## UI 开发与验收（`pr/ui-optimization`）

设计方向：**framed sheet** —— pale blue-grey 的 L 形外壳 + 白色 paper 工作区，颜色只给数据/状态/一个主操作；工作台第一块是「追溯带」（输入告警 → 标准化 → 去重 → 安全事件），不是 KPI 卡片墙。规范见 [docs/DESIGN.md](docs/DESIGN.md)，产品/信息架构见 [docs/PRODUCT.md](docs/PRODUCT.md)。

```bash
cd frontend
npm run typecheck        # TypeScript
npm run test:run         # Vitest（当前 61 tests）
npm run test:e2e:list    # Playwright 收集检查（无需后端）
npm run test:e2e         # 自包含 Playwright（route 拦截 fixture，端口 4174；含 axe 0 violations）
npm run test:e2e:visual  # 视觉基线截图 → ../design-libs/baseline/visual/
npm run build && npm run preview  # 生产构建 + 4175 预览（验证 minified CSS 与真实 API 代理）
npm run verify           # typecheck + Vitest + build
npm run detect:ui        # Impeccable 设计 detector 源码扫描（信息性）
npm run detect:ui:check  # detector ratchet（只对新增 P0 失败）
```

- 项目级设计技能（本地可选，未纳入版本库）：`TraceBack/.dsh/skills/`（Impeccable 4.8.0 + emilkowalski 13 个技能）与 `TraceBack/.agents/`（taste-skill v2，用于方向与 inspector 验收）。
- 细节审计：`docs/UI-DETAIL-AUDIT.md`（布局/标签/层级/字体/比例逐项）；可访问性：`docs/A11Y-MANUAL-CHECKLIST.md`；OpenAPI 快照：`docs/openapi-workbench.json`（`PYTHONPATH=backend python scripts/export_openapi.py --check`）。
- 视觉/设计系统说明与动效规范：`docs/DESIGN.md`；产品说明：`docs/PRODUCT.md`；最终交付报告：`docs/UI-OPTIMIZATION-REPORT.md`；审计证据：`docs/UI-AUDIT.md`；第三方文件级来源：`THIRD_PARTY_NOTICES.md`。
- 深链示例：`?analysis_id=<id>&incident_id=<id>&node_id=<nod_id>&timeline_page=2&evidence=<alt_id>`；`/` 聚焦搜索、`Esc` 关闭证据、`j/k` 列表行导航。
- 项目 LICENSE：MIT（见根 `LICENSE`；上游未声明，本分支补充，供 PR 评审）。

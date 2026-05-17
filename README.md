# AgentFuzzer 2.0 - AI Agent 自动化漏洞扫描沙箱

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![Vue](https://img.shields.io/badge/vue-3.4+-green.svg)

> 🛡️ 面向 AI Agent 的自动化漏洞扫描、行为审计与容器化安全靶场平台

## 📋 目录

- [项目概览](#项目概览)
- [系统架构](#系统架构)
- [核心能力](#核心能力)
- [技术栈](#技术栈)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [API 文档](#api-文档)
- [测试靶标](#测试靶标)
- [创新亮点](#创新亮点)
- [截图展示](#截图展示)
- [贡献指南](#贡献指南)
- [许可证](#许可证)

---

## 🎯 项目概览

AgentFuzzer 2.0 是一个专为 AI Agent 设计的安全审计平台，融合了三个核心子系统：

| 子系统 | 定位 | 核心能力 |
|--------|------|----------|
| **AgentGuard** | 被动审计 | 单次输入审计、规则检测、风险评分、可信存证报告 |
| **AgentFuzzer** | 主动评测 | 靶标注册、载荷库、批量 Fuzzing、漏洞聚合 |
| **CASS** | 容器化靶场 | Docker 运行受控 Agent、生成 AgentTrace、五层防线分析 |

### 解决的问题

在企业 AI Agent 部署中，员工或攻击者可能通过以下方式操控 Agent：
- **Prompt 注入** — 让 Agent 忽略安全限制，执行危险操作
- **数据泄露** — 诱导 Agent 读取并外发敏感信息
- **命令执行** — 让 Agent 执行系统命令、删除文件
- **权限提升** — 越权访问管理员接口

AgentFuzzer 通过**多 Agent 协作审计**和**双层验证机制**，在不修改原有 Agent 代码的情况下，实现 Agent 行为的实时安全检测和策略阻断。

---

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (Vue 3 + Vite)                   │
│  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌─────────┐          │
│  │ 靶标管理 │ │ 扫描控制台│ │ 快速审计 │ │ 审计历史 │          │
│  └─────────┘ └──────────┘ └─────────┘ └─────────┘          │
│  ┌─────────┐ ┌──────────┐                                  │
│  │ 风控报告 │ │ 评测结果  │                                  │
│  └─────────┘ └──────────┘                                  │
└───────────────────────────┬─────────────────────────────────┘
                            │ REST API + WebSocket
┌───────────────────────────┴─────────────────────────────────┐
│                   Backend (FastAPI + SQLite)                 │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  API Layer                            │   │
│  │  /api/analyze  /api/targets  /api/scans  /api/report │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Core Engine Layer                        │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │   │
│  │  │ 行为提取器    │ │ 规则引擎      │ │ 风险评分引擎 │ │   │
│  │  │ Extractor    │ │ 80 Rules     │ │ Risk Engine │ │   │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │   │
│  │  │ 策略决策引擎  │ │ 防线分析器    │ │ 可信存证链  │ │   │
│  │  │ Policy       │ │ Defense      │ │ Evidence    │ │   │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │            Multi-Agent System (LLM)                   │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            │   │
│  │  │ 调度器    │ │ 风险分析  │ │ 策略顾问  │            │   │
│  │  │Orchestrator│ │ Risk     │ │ Policy   │            │   │
│  │  └──────────┘ └──────────┘ └──────────┘            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │            Second Agent Verification                  │   │
│  │  ┌──────────────┐ ┌──────────────┐                  │   │
│  │  │ 关键词验证    │ │ 语义模式验证  │                  │   │
│  │  │ Keyword      │ │ Semantic     │                  │   │
│  │  └──────────────┘ └──────────────┘                  │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────┴─────────────────────────────────┐
│              CASS Docker Sandbox (:18080)                    │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │ Demo Agent   │ │ 6 Mock Tools │ │ RAG Store    │        │
│  │ Trace Collect│ │ Mock Data    │ │ kb_docs      │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

### 数据流图

```
用户输入
    │
    ▼
┌─────────────────┐
│ 行为提取器       │ ← LLM Agent + Fallback 混合模式
│ (Extractor)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 行为图构建       │ ← 节点、边、数据流
│ (Graph Builder) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│ 规则引擎         │────→│ 第二Agent验证    │
│ (Rule Engine)   │     │ (Semantic +     │
│ 80 Rules        │←────│ Keyword)        │
└────────┬────────┘     └─────────────────┘
         │
         ▼
┌─────────────────┐
│ 风险评分         │ ← 基础分 + 组合攻击加分
│ (Risk Engine)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 策略决策         │ ← pass / warn / review / block
│ (Policy Engine) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 可信存证         │ ← SM3 哈希链
│ (Evidence Chain)│
└─────────────────┘
```

---

## ✨ 核心能力

### 1. 单次审计（AgentGuard）

输入一段 Agent 任务描述或工具调用日志，系统自动完成：

1. **行为抽取** — LLM Agent + 关键词 Fallback 混合模式，输出标准化 `BehaviorChain`
2. **规则检测** — 匹配 `security_rules.yaml` 中的 80 条规则（R001-R080）
3. **双层验证** — 关键词验证 + 语义模式验证（第二Agent），降低误报率
4. **风险评分** — 综合行为链风险、规则风险、数据流风险、防线崩溃风险、组合攻击加分
5. **策略裁决** — `pass` / `warn` / `review` / `block`
6. **五层防线分析** — L1 Prompt → L2 意图 → L3 权限 → L4 数据 → L5 执行
7. **可信存证** — SM3 哈希链，每条记录关联上一条哈希
8. **LLM 解释** — 可选启用 DeepSeek 生成风险解释与修复建议

支持输入类型：`task` `tool_log` `command` `code` `prompt`

### 2. 主动评测（AgentFuzzer）

1. 注册任意 Agent 靶标（名称、System Prompt、API Schema、安全约束）
2. 自动分析攻击面（约束绕过高价值 API、敏感参数、弱 Prompt 模式）
3. 从 YAML 导入内置安全载荷
4. 支持多种变异策略（Base64、Unicode、URL 编码、中英混杂等）
5. 启动批量扫描，支持暂停/恢复/取消
6. WebSocket 实时推送扫描进度
7. 输出扫描报告（Markdown / HTML / PDF / JSON）

### 3. 容器化靶场（CASS）

Docker 中运行受控 Demo Agent，内置：

- **DemoCustomerAgent** — 模拟电商客服 Agent
- **6 个 Mock 工具** — `query_order` `query_logistics` `read_kb` `refund_order` `send_email` `admin_export`
- **Mock 数据** — 模拟用户、订单、物流、知识库
- **TraceCollector** — 完整记录 Agent 执行事件流
- **RAG Store** — 支持正常文档和注入测试文档

### 4. 五层防线分析

| 层级 | 防线 | 检测内容 |
|------|------|----------|
| L1 | Prompt 防线 | System Prompt 覆盖/泄露/角色劫持 |
| L2 | 意图防线 | Agent 意图被劫持、合理化危险操作 |
| L3 | 权限防线 | 越权 API 调用、管理员操作 |
| L4 | 数据防线 | 敏感数据泄露、数据外发 |
| L5 | 执行防线 | 危险 Shell 命令、SQL 删除、格式化 |

---

## 🛠️ 技术栈

| 层 | 技术 | 版本 |
|---|------|------|
| 前端 | Vue 3 + Vite + ECharts | ^3.4.0 |
| 后端 | FastAPI + SQLite + Pydantic | ^0.100.0 |
| LLM | LangChain + ChatOpenAI | ^1.3.3 |
| 密码 | SM3 哈希链（gmssl） | ^3.2.1 |
| PDF | ReportLab | ^4.0.0 |
| 靶场 | Docker + FastAPI | - |
| 部署 | Docker Compose | - |

---

## 🚀 快速开始

### 方式一：Docker Compose 一键启动（推荐）

```bash
# 克隆项目
git clone <repo-url>
cd AgentFuzzer

# 复制环境变量
cp .env.example .env
# 编辑 .env，填写 LLM_API_KEY（可选）

# 一键启动
docker compose up --build -d
```

Windows PowerShell：

```powershell
./start.ps1
```

启动后访问：

| 服务 | 地址 |
|------|------|
| 前端 | http://127.0.0.1:5173 |
| 后端 API | http://127.0.0.1:8000 |
| API 文档 | http://127.0.0.1:8000/docs |
| 靶场 | http://127.0.0.1:18080 |

停止服务：

```bash
docker compose down
# 或
./stop.ps1
```

### 方式二：本地手动启动

**后端：**

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
# 可选：复制 backend/.env.example 为 backend/.env 并填写 LLM_API_KEY
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**前端：**

```bash
cd frontend
npm install
npm run dev
```

**靶场：**

```bash
cd sandbox
pip install -r requirements.txt
python -m uvicorn agent_app.main:app --host 0.0.0.0 --port 18080
```

**测试 Agent：**

```bash
cd test_agent
pip install -r requirements.txt
python start_all.py
```

### 首次初始化

启动后导入内置载荷库：

```bash
curl -X POST http://127.0.0.1:8000/api/payloads/import-from-yaml
```

---

## 📁 项目结构

```
AgentFuzzer/
├── backend/                    # 后端服务
│   ├── app/
│   │   ├── api/               # API 路由
│   │   │   ├── analyze_api.py
│   │   │   ├── target_api.py
│   │   │   ├── scan_api.py
│   │   │   └── ...
│   │   ├── core/              # 核心引擎
│   │   │   ├── behavior_extractor.py
│   │   │   ├── rule_engine.py
│   │   │   ├── risk_engine.py
│   │   │   ├── policy_engine.py
│   │   │   ├── rule_verifier.py      # 第二Agent验证
│   │   │   ├── pdf_generator.py      # PDF报告生成
│   │   │   └── multi_agent_system.py # 多Agent协作
│   │   ├── rules/             # 规则库
│   │   │   └── security_rules.yaml   # 85条安全规则
│   │   ├── database/          # 数据库
│   │   └── schemas/           # Pydantic模型
│   ├── requirements.txt
│   └── test_pipeline.py       # 测试脚本
│
├── frontend/                   # 前端应用
│   ├── src/
│   │   ├── components/        # 组件
│   │   │   └── BehaviorChainGraph.vue
│   │   ├── pages/             # 页面
│   │   │   ├── Analyze.vue
│   │   │   ├── History.vue
│   │   │   └── ...
│   │   ├── api/               # API请求
│   │   └── App.vue
│   ├── package.json
│   └── vite.config.js
│
├── sandbox/                    # Docker靶场
│   ├── agent_app/
│   └── Dockerfile
│
├── test_agent/                 # 测试Agent套件
│   ├── high_security_agent.py
│   ├── medium_security_agent.py
│   ├── low_security_agent.py
│   ├── vulnerable_agent.py
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── dataset/                    # 测试数据集
│   └── test_cases.json
│
├── docker-compose.yml          # 主编排文件
├── start.ps1                   # Windows启动脚本
├── stop.ps1                    # Windows停止脚本
└── README.md                   # 项目文档
```

---

## 📚 API 文档

### 审计接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/analyze` | 单次审计 |
| POST | `/api/analyze/multi-agent` | 多Agent协作分析 |
| GET | `/api/history` | 审计历史列表 |
| GET | `/api/history/{id}` | 审计记录详情 |
| GET | `/api/report/{id}` | 审计报告（JSON/Markdown/HTML） |
| GET | `/api/report/{id}/pdf` | 审计报告（PDF） |

### 扫描接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/targets` | 靶标列表 |
| POST | `/api/targets` | 注册靶标 |
| GET | `/api/targets/{id}` | 靶标详情 |
| POST | `/api/targets/{id}/scan` | 发起扫描 |
| GET | `/api/scans` | 扫描任务列表 |
| GET | `/api/scans/{id}` | 扫描详情 |
| POST | `/api/scans/{id}/cancel` | 取消扫描 |

详细 API 文档请访问：`http://127.0.0.1:8000/docs`

---

## 🎯 测试靶标

项目内置 4 个不同安全级别的测试 Agent：

| Agent | 端口 | 安全级别 | 特点 |
|-------|------|----------|------|
| 高安全 Agent | 50001 | High | 严格黑名单、注入检测、完整审计 |
| 中安全 Agent | 50002 | Medium | 简单过滤、存在绕过漏洞 |
| 低安全 Agent | 50003 | Low | 无过滤、直接执行用户输入 |
| 漏洞百出 Agent | 50004 | None | 10+已知漏洞、极易被攻破 |

启动测试 Agent：

```bash
cd test_agent
python start_all.py
```

在靶标管理中添加：
- Callback URL: `http://127.0.0.1:50001/callback`（高安全）
- Callback URL: `http://127.0.0.1:50004/callback`（漏洞百出）

---

## 💡 创新亮点

### 1. 多 Agent 协作审计

采用 **Orchestrator + Risk Analyst + Policy Advisor** 三层协作架构：
- **Orchestrator** — 总调度，根据输入复杂度分配任务
- **Risk Analyst** — 深度分析攻击手法和风险链条
- **Policy Advisor** — 生成具体防御策略和修复建议

### 2. 双层验证机制

第一层：**关键词验证** — 基于规则和关键词的初步命中
第二层：**语义模式验证** — 基于50+正则模式的第二Agent验证

验证结果融合，显著降低误报率，提升命中率。

### 3. 行为链时间线可视化

使用稳定的行为链时间线展示攻击链路：
- 节点颜色标识风险等级（绿/黄/橙/红）
- 逐步展示工具、动作、数据类型和目标
- 自动隐藏未识别字段，减少 unknown 干扰
- 展示防线崩溃点和证据摘要

### 4. 五层防线模型

独创的五层防线分析框架：
- L1 Prompt 防线 → L2 意图防线 → L3 权限防线 → L4 数据防线 → L5 执行防线
- 每层独立检测，组合评估
- 可视化展示防线崩溃点

### 5. 可信存证链

基于 SM3 哈希算法构建可信存证链：
- 每条记录包含前一条记录的哈希值
- 形成不可篡改的审计链条
- 支持报告导出（Markdown/HTML/PDF）

---

## 📸 截图展示

### 快速审计页面

![快速审计](docs/screenshots/analyze.png)

### 行为链路可视化

![攻击链路](docs/screenshots/attack-chain.png)

### 审计历史

![审计历史](docs/screenshots/history.png)

### 风控报告

![风控报告](docs/screenshots/report.png)

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建 Feature Branch (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到 Branch (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

---

## 📄 许可证

本项目基于 MIT 许可证开源，详见 [LICENSE](LICENSE) 文件。

---

## 🙏 致谢

- [FastAPI](https://fastapi.tiangolo.com/) — 高性能 Web 框架
- [Vue.js](https://vuejs.org/) — 渐进式前端框架
- [LangChain](https://www.langchain.com/) — LLM 应用框架
- [DeepSeek](https://deepseek.com/) — 大语言模型

---

> 📧 联系方式：如有问题，请提交 Issue 或联系项目维护者。

**AgentFuzzer — 让 AI Agent 更安全** 🛡️

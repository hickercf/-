# AgentFuzzer 2.0

面向 AI Agent 的自动化漏洞扫描、行为审计与容器化安全靶场平台。

## 项目概览

AgentFuzzer 2.0 融合了三个子系统：

| 子系统 | 定位 | 核心能力 |
|--------|------|----------|
| **AgentGuard** | 被动审计 | 单次输入审计、规则检测、风险评分、可信存证报告 |
| **AgentFuzzer** | 主动评测 | 靶标注册、载荷库、批量 Fuzzing、漏洞聚合 |
| **CASS** | 容器化靶场 | Docker 运行受控 Agent、生成 AgentTrace、五层防线分析 |

## 系统架构

```
┌─────────────────────────────────────────────────────────┐
│                 Frontend (Vue 3 + Vite + ECharts)       │
│  靶标管理 │ 扫描控制台 │ 快速审计 │ Trace 链路 │ 统计 │ 报告 │ 评测 │
└─────────────────────┬───────────────────────────────────┘
                      │ /api/*
┌─────────────────────┴───────────────────────────────────┐
│                   Backend (FastAPI)                      │
│  analyze_api   history_api   stats_api   report_api     │
│  target_api    scan_api      payload_api                │
│  sandbox_api   eval_api                                 │
│                                                         │
│  behavior_extractor  trace_adapter  rule_engine         │
│  defense_analyzer    risk_engine    policy_engine       │
│  fuzzer_engine       evidence_chain                     │
│                                                         │
│  SQLite (7 tables)  │  YAML Rules (20+17+87)            │
└──────────┬──────────┴───────────────────────────────────┘
           │
┌──────────┴──────────────────────────────────────────────┐
│              CASS Docker Sandbox (:18080)                │
│  DemoCustomerAgent  │  6 MockTools  │  RAG Store        │
│  TraceCollector     │  MockData     │  kb_docs          │
└─────────────────────────────────────────────────────────┘
```

## 核心能力

### 1. 单次审计（AgentGuard）

输入一段 Agent 任务描述或工具调用日志，系统自动完成：

1. **行为抽取** — LLM Agent + 关键词 Fallback 混合模式，输出标准化 `BehaviorChain`
2. **规则检测** — 匹配 `security_rules.yaml` 中的 20 条规则（R001-R020）
3. **风险评分** — 综合行为链风险、规则风险、数据流风险、防线崩溃风险、组合攻击加分
4. **策略裁决** — `pass` / `warn` / `review` / `block`
5. **五层防线分析** — L1 Prompt → L2 意图 → L3 权限 → L4 数据 → L5 执行
6. **可信存证** — SM3 哈希链，每条记录关联上一条哈希
7. **LLM 解释** — 可选启用 DeepSeek 生成风险解释与修复建议

支持输入类型：`task` `tool_log` `command` `code` `prompt`

### 2. 主动评测（AgentFuzzer）

1. 注册任意 Agent 靶标（名称、System Prompt、API Schema、安全约束）
2. 自动分析攻击面（约束绕过高价值 API、敏感参数、弱 Prompt 模式）
3. 从 YAML 导入 87 条内置安全载荷（10 个分类）
4. 支持 24 种变异策略（Base64、Unicode、URL 编码、中英混杂、零宽字符等）
5. 启动批量扫描，支持暂停/恢复/取消
6. WebSocket 实时推送扫描进度
7. 输出扫描报告（Markdown / HTML / JSON）

### 3. 容器化靶场（CASS）

Docker 中运行受控 Demo Agent，内置：

- **DemoCustomerAgent** — 模拟电商客服 Agent
- **6 个 Mock 工具** — `query_order` `query_logistics` `read_kb` `refund_order` `send_email` `admin_export`
- **Mock 数据** — 模拟用户、订单、物流、知识库
- **TraceCollector** — 完整记录 Agent 执行事件流
- **RAG Store** — 支持正常文档和注入测试文档

AgentTrace 事件类型：`message` → `plan` → `tool_select` → `tool_call` → `observation` → `data_flow` → `policy` → `output`

### 4. 五层防线分析

| 层级 | 防线 | 检测内容 |
|------|------|----------|
| L1 | Prompt 防线 | System Prompt 覆盖/泄露/角色劫持 |
| L2 | 意图防线 | Agent 意图被劫持、合理化危险操作 |
| L3 | 权限防线 | 越权 API 调用、管理员操作 |
| L4 | 数据防线 | 敏感数据泄露、数据外发 |
| L5 | 执行防线 | 危险 Shell 命令、SQL 删除、格式化 |

## 技术栈

| 层 | 技术 |
|---|------|
| 前端 | Vue 3 + Vite + ECharts + Axios |
| 后端 | FastAPI + SQLite + Pydantic + PyYAML |
| LLM | LangChain + ChatOpenAI + PydanticOutputParser |
| 密码 | SM3 哈希链（gmssl） |
| 靶场 | Docker + FastAPI + 模拟数据 |
| 部署 | Docker Compose（backend + frontend + sandbox） |

## 快速启动

### 方式一：Docker Compose 一键启动（推荐）

```bash
# 克隆项目
git clone <repo-url>
cd 校赛

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
pip install -r requirements.txt
# 可选：复制 backend/.env.example 为 backend/.env 并填写 LLM_API_KEY
python -m uvicorn app.main:app --reload
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

### 首次初始化

启动后导入内置载荷库：

```bash
curl -X POST http://127.0.0.1:8000/api/payloads/import-from-yaml
```

## API 接口

### 审计（5 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/analyze` | 单次审计 |
| GET | `/api/history` | 审计历史列表 |
| GET | `/api/history/{id}` | 审计记录详情 |
| GET | `/api/stats` | 审计统计 |
| GET | `/api/report/{id}` | 审计报告（支持 JSON/Markdown/HTML） |

### 扫描（8 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/targets` | 靶标列表 |
| POST | `/api/targets` | 注册靶标 |
| GET | `/api/targets/{id}` | 靶标详情（含攻击面） |
| PUT | `/api/targets/{id}` | 更新靶标 |
| DELETE | `/api/targets/{id}` | 删除靶标 |
| POST | `/api/targets/{id}/scan` | 对靶标发起扫描 |
| GET | `/api/scans` | 扫描任务列表 |
| GET | `/api/scans/{id}` | 扫描详情（含结果和统计） |

### 载荷库（5 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/payloads` | 载荷列表 |
| GET | `/api/payloads/categories` | 载荷分类统计 |
| GET | `/api/payloads/mutations` | 变异策略列表 |
| POST | `/api/payloads/import-from-yaml` | 从 YAML 导入载荷 |
| DELETE | `/api/payloads/{id}` | 删除载荷 |

### 靶场（5 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/sandbox/status` | 靶场健康状态 |
| POST | `/api/sandbox/run` | 向靶场投递任务并审计 |
| POST | `/api/sandbox/reset` | 重置靶场 |
| POST | `/api/sandbox/rag/inject` | 注入 RAG 测试文档 |
| GET | `/api/sandbox/tools` | 获取可用工具列表 |

### 其他（3 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/evidence-chain` | 检查证据链完整性 |
| GET | `/api/report/scan/{id}` | 扫描报告 |
| POST | `/api/evaluate` | 三路评测（规则/LLM/融合） |

## 前端页面

| 页面 | 功能 |
|------|------|
| 靶标管理 | 注册/编辑/删除 Agent 靶标，查看攻击面分析 |
| 扫描控制台 | 发起扫描、暂停/恢复/取消、实时进度、漏洞结果 |
| 快速审计 | 输入文本即时审计，查看行为链、风险评分、策略 |
| Trace 链路 | 查看历史审计记录的行为链详情 |
| 统计图表 | 风险分布、规则命中、扫描趋势等可视化 |
| 可信报告 | 生成审计报告或扫描报告（Markdown/HTML） |
| 评测结果 | 运行三路评测，对比规则/LLM/融合效果 |

## 数据存储

### SQLite 表（7 张）

| 表 | 用途 |
|----|------|
| `analysis_record` | 审计记录（含行为链、风险、策略、存证哈希） |
| `agent_target` | 注册的 Agent 靶标 |
| `scan_task` | 扫描任务 |
| `attack_payload` | 攻击载荷 |
| `fuzz_result` | Fuzzing 结果 |
| `evidence_chain` | SM3 哈希存证链 |
| `scan_results` | 扫描详细结果 |

### 规则与数据文件

| 文件 | 内容 |
|------|------|
| `backend/app/rules/security_rules.yaml` | 20 条安全规则 |
| `backend/app/rules/defense_rules.yaml` | 5 层防线 + 17 条检测规则 |
| `backend/app/rules/attack_payloads.yaml` | 10 分类 87 条攻击载荷 |
| `dataset/test_cases.json` | 30 条评测用例 |
| `dataset/eval_result.json` | 评测结果 |

## 代码结构

```
.
├── backend/
│   ├── app/
│   │   ├── api/                    # 9 个 API 路由
│   │   │   ├── analyze_api.py      # 单次审计
│   │   │   ├── history_api.py      # 审计历史
│   │   │   ├── stats_api.py        # 统计
│   │   │   ├── report_api.py       # 报告
│   │   │   ├── eval_api.py         # 评测
│   │   │   ├── target_api.py       # 靶标管理
│   │   │   ├── scan_api.py         # 扫描控制
│   │   │   ├── payload_api.py      # 载荷库
│   │   │   └── sandbox_api.py      # 靶场控制
│   │   ├── core/                   # 核心引擎
│   │   │   ├── behavior_extractor.py   # 行为抽取（LLM+fallback）
│   │   │   ├── fallback_extractor.py   # 关键词 fallback 抽取
│   │   │   ├── extractor_agent.py      # LLM Agent 抽取
│   │   │   ├── behavior_graph.py       # 行为图构建
│   │   │   ├── trace_adapter.py        # AgentTrace → BehaviorChain
│   │   │   ├── rule_engine.py          # 规则匹配引擎
│   │   │   ├── defense_analyzer.py     # 五层防线分析
│   │   │   ├── risk_engine.py          # 风险评分引擎
│   │   │   ├── policy_engine.py        # 策略裁决
│   │   │   ├── fuzzer_engine.py        # Fuzzing 引擎
│   │   │   ├── payload_loader.py       # 载荷加载/变异
│   │   │   ├── target_manager.py       # 靶标管理/攻击面分析
│   │   │   ├── sandbox_controller.py   # 靶场 HTTP 控制器
│   │   │   ├── sandbox_runner.py       # 沙箱运行器
│   │   │   ├── react_parser.py         # ReAct 链路解析
│   │   │   ├── scan_report_generator.py # 扫描报告生成
│   │   │   ├── report_generator.py     # 审计报告生成
│   │   │   ├── evidence_chain.py       # SM3 哈希存证
│   │   │   ├── crypto_utils.py         # SM3 工具函数
│   │   │   ├── llm_analyzer.py         # LLM 解释生成
│   │   │   └── vuln_classifier.py      # 漏洞分类
│   │   ├── database/
│   │   │   └── db.py               # SQLite CRUD
│   │   ├── rules/                  # YAML 规则文件
│   │   └── schemas/                # Pydantic 数据模型
│   ├── benchmark_runner.py         # 回归测试
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── pages/                  # 8 个页面
│   │   │   ├── Analyze.vue         # 快速审计
│   │   │   ├── History.vue         # 审计历史
│   │   │   ├── Stats.vue           # 统计图表
│   │   │   ├── Report.vue          # 可信报告
│   │   │   ├── Evaluation.vue      # 评测结果
│   │   │   ├── TargetPage.vue      # 靶标管理
│   │   │   ├── ScanConsole.vue     # 扫描控制台
│   │   │   ├── AttackTrace.vue     # Trace 链路
│   │   │   └── VulnReport.vue      # 漏洞报告
│   │   ├── components/             # 6 个组件
│   │   │   ├── BehaviorChainGraph.vue
│   │   │   ├── ChartPanel.vue
│   │   │   ├── EvidenceChain.vue
│   │   │   ├── PolicyDecision.vue
│   │   │   ├── RiskCard.vue
│   │   │   └── RuleList.vue
│   │   ├── api/
│   │   │   └── request.js          # API 请求封装
│   │   └── App.vue
│   ├── nginx.conf                  # Nginx 反向代理
│   ├── package.json
│   └── Dockerfile
├── sandbox/
│   ├── agent_app/
│   │   ├── main.py                 # 靶场 FastAPI 入口
│   │   ├── demo_customer_agent.py  # 客服 Agent 模拟
│   │   ├── mock_tools.py           # 6 个 Mock 工具
│   │   ├── mock_data.py            # 模拟数据
│   │   ├── trace_hook.py           # Trace 采集器
│   │   ├── rag_store.py            # RAG 知识库
│   │   └── schemas.py              # 靶场数据模型
│   ├── kb_docs/                    # 默认知识库文档
│   ├── requirements.txt
│   └── Dockerfile
├── dataset/
│   ├── test_cases.json             # 30 条评测用例
│   ├── eval_result.json            # 评测结果
│   └── label_schema.md             # 标注规范
├── docker-compose.yml              # 一键部署
├── start.ps1                       # Windows 启动脚本
├── stop.ps1                        # Windows 停止脚本
├── .env.example                    # 环境变量模板
└── README.md
```

## 回归测试结果

基于 `python benchmark_runner.py`（30 条测试用例）：

| 指标 | 数值 |
|------|------:|
| 总测试数 | 30 |
| 提取成功率 | 100% |
| 风险等级准确率 | 60.0% |
| 高风险召回率 | 79.17% |
| 关键漏报数 | 5 |
| 类别 F1 | 0.53 |
| 平均响应时间 | 2.9s |

## 全量验证状态

| 检查项 | 结果 |
|--------|------|
| 后端 40 模块导入 | PASS |
| 前端 645 模块编译 | PASS |
| Benchmark 30 用例 | PASS |
| 靶场 9 项 API | PASS |
| 数据库 7 表 | PASS |
| 规则文件 3 YAML | PASS |
| API 路由 33 条 | PASS |

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ENABLE_LLM` | `false` | 是否启用 LLM 解释 |
| `LLM_API_KEY` | — | DeepSeek API Key |
| `LLM_BASE_URL` | `https://api.deepseek.com/v1` | LLM 接口地址 |
| `LLM_MODEL` | `deepseek-chat` | 模型名称 |
| `SANDBOX_URL` | `http://127.0.0.1:18080` | 靶场地址 |

## 安全边界

本项目仅用于防御性安全研究与受控评测：

- 不攻击真实网站或真实系统
- 不访问真实密码、Cookie、Token 或宿主机敏感文件
- 不发送真实邮件或真实外部请求
- 不执行用户输入中的真实高危操作
- 容器内数据均为模拟数据

## Agent 接入方式

如需接入自制 Agent，两种方式：

1. **原生输出** — 让 Agent 直接输出 `AgentTrace` 格式的 JSON
2. **适配器转换** — 给现有日志格式编写 `trace_adapter`

当前支持的接入模式：`callback`（HTTP 回调）/ `log`（日志解析）/ `sandbox`（容器内置）/ `simulated`（模拟）

## License

本项目仅用于学术研究与安全评测目的。

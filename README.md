# AgentGuard

面向 AI Agent 的零信任任务行为审计与风险取证平台。

## 项目结构

```
AgentGuard/
├── backend/                  # FastAPI 后端
│   ├── app/
│   │   ├── main.py           # 应用入口
│   │   ├── api/              # API 路由
│   │   │   ├── analyze_api.py    # POST /api/analyze
│   │   │   ├── history_api.py    # GET /api/history
│   │   │   ├── stats_api.py      # GET /api/stats
│   │   │   ├── report_api.py     # GET /api/report/{id}
│   │   │   └── eval_api.py       # POST /api/evaluate
│   │   ├── core/             # 核心模块
│   │   │   ├── behavior_extractor.py   # 行为链抽取（LLM + Fallback 融合）
│   │   │   ├── extractor_agent.py      # LangChain LLM 抽取器
│   │   │   ├── fallback_extractor.py   # 关键词兜底抽取器
│   │   │   ├── behavior_graph.py       # 行为图谱构建
│   │   │   ├── rule_engine.py          # 规则引擎（R001-R020）
│   │   │   ├── risk_engine.py          # 多维风险评分
│   │   │   ├── policy_engine.py        # 零信任策略裁决
│   │   │   ├── llm_analyzer.py         # LLM 解释生成
│   │   │   ├── evidence_chain.py       # SM3 审计哈希链
│   │   │   ├── crypto_utils.py         # 国产密码工具
│   │   │   └── report_generator.py     # Markdown/HTML 报告
│   │   ├── schemas/          # Pydantic 数据模型
│   │   │   ├── behavior_schema.py
│   │   │   ├── analyze_schema.py
│   │   │   ├── rule_schema.py
│   │   │   └── report_schema.py
│   │   ├── database/         # SQLite 数据库
│   │   │   └── db.py
│   │   └── rules/            # 安全规则库
│   │       └── security_rules.yaml
│   ├── data/                 # SQLite 数据文件
│   ├── requirements.txt      # Python 依赖
│   └── benchmark_runner.py   # 批量评测脚本
│
├── frontend/                 # Vue 3 前端
│   ├── src/
│   │   ├── main.js           # 入口
│   │   ├── App.vue           # 根组件
│   │   ├── api/
│   │   │   └── request.js    # Axios 请求封装
│   │   ├── pages/            # 页面
│   │   │   ├── Analyze.vue       # 审计台
│   │   │   ├── History.vue       # 历史记录
│   │   │   ├── Stats.vue         # 统计图表
│   │   │   ├── Report.vue        # 可信报告
│   │   │   └── Evaluation.vue    # 批量评测
│   │   └── components/       # 组件
│   │       ├── RiskCard.vue
│   │       ├── BehaviorChainGraph.vue
│   │       ├── RuleList.vue
│   │       ├── PolicyDecision.vue
│   │       ├── EvidenceChain.vue
│   │       └── ChartPanel.vue
│   ├── package.json
│   └── vite.config.js
│
├── dataset/                  # 测试数据集
│   ├── test_cases.json       # 30 条测试用例
│   └── label_schema.md       # 标注规范
│
├── docs/                     # 文档目录（待补充）
│
└── README.md                 # 本文件
```

## 快速启动

### 后端

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

后端地址：http://127.0.0.1:8000  
接口文档：http://127.0.0.1:8000/docs

### 前端

```bash
cd frontend
npm install
npm run dev
```

前端地址：http://127.0.0.1:5173

### 环境变量

在 `backend/.env` 中配置：

```env
LLM_API_KEY=sk-xxx
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_MODEL=deepseek-chat
ENABLE_LLM=true
ENABLE_SM3=true
```

默认 `ENABLE_LLM=false`，系统使用关键词 fallback 抽取器即可独立运行。

## 核心流程

```
用户输入
  ↓
行为链抽取（LLM Agent + Fallback 融合）
  ↓
行为图谱构建
  ↓
规则引擎匹配（20 条安全规则 R001-R020）
  ↓
多维风险评分（6 维度可解释模型）
  ↓
零信任策略裁决（pass / warn / review / block）
  ↓
LLM 解释生成
  ↓
SM3 审计链存证
  ↓
前端可视化 / 报告导出
```

## 技术栈

| 模块 | 技术 |
|------|------|
| 后端 | FastAPI + SQLite + SM3 |
| 行为链抽取 | LangChain + DeepSeek / Kimi / GLM |
| 本地兜底 | 关键词 + 正则 + 规则模板 |
| 规则库 | YAML（20 条规则） |
| 风险评分 | 自研多维评分模型 |
| 前端 | Vue 3 + Vite + ECharts |
| 报告 | Markdown / HTML |

## 演示样例

系统内置 6 个演示样例：

1. **正常任务** — 低风险 / pass
2. **隐私泄露** — 严重风险 / block
3. **Prompt 注入** — 严重风险 / block
4. **危险命令** — 严重风险 / block
5. **越权访问** — 严重风险 / block
6. **数据库删除** — 高风险 / review

## 评测

```bash
# API 方式
curl -X POST http://127.0.0.1:8000/api/evaluate

# 脚本方式
cd backend
python benchmark_runner.py
```

生成三组对比实验：规则检测 / LLM 检测 / 融合检测。

## 注意

系统仅对输入进行**静态安全审计**，不会执行任何命令或真实工具调用。

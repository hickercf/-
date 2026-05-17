"""
sandbox/agent_app/main.py — 靶场 FastAPI 服务入口
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any

from .schemas import (
    RunRequest, RunResponse, RAGInjectRequest,
    HealthResponse, AgentTrace
)
from .demo_customer_agent import agent
from .rag_store import rag_store
from .mock_tools import MockTools

app = FastAPI(
    title="AgentGuard Sandbox Agent",
    description="容器化 Agent 安全靶场 — 仅使用模拟数据与模拟工具",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health():
    """健康检查"""
    return HealthResponse()


@app.get("/")
async def root():
    """根路径"""
    return {
        "name": "AgentGuard Sandbox Agent",
        "version": "1.0.0",
        "sandbox_mode": True,
        "agent": "demo_customer_agent"
    }


@app.post("/run", response_model=RunResponse)
async def run_task(req: RunRequest):
    """运行单次任务"""
    try:
        result = agent.run(req.input_text, req.injection_point)
        return RunResponse(trace=result["trace"])
    except Exception as e:
        raise HTTPException(status_code=500, detail="Agent 执行失败: 内部错误")


@app.post("/rag/inject")
async def inject_rag(req: RAGInjectRequest):
    """注入 RAG 测试文档"""
    rag_store.inject_document(req.case_id, req.doc_title, req.doc_content)
    return {
        "status": "injected",
        "case_id": req.case_id,
        "total_docs": len(rag_store.get_all_docs())
    }


@app.post("/reset")
async def reset_sandbox():
    """重置靶场"""
    rag_store.reset()
    agent.collector.reset()
    return {
        "status": "reset",
        "message": "靶场已重置，注入文档已清除"
    }


@app.get("/tools")
async def list_tools():
    """列出可用工具"""
    return MockTools.get_available_tools()

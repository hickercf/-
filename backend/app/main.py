from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.database.db import init_db
from app.api import analyze_api, history_api, stats_api, report_api, eval_api
from app.api import target_api, scan_api, payload_api


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="AgentFuzzer",
    description="面向 AI Agent 的自动化漏洞扫描与行为审计沙箱",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 原有 API (保留兼容)
app.include_router(analyze_api.router)
app.include_router(history_api.router)
app.include_router(stats_api.router)
app.include_router(report_api.router)
app.include_router(eval_api.router)

# 新增 API (AgentFuzzer 2.0)
app.include_router(target_api.router)
app.include_router(scan_api.router)
app.include_router(payload_api.router)


@app.get("/")
async def root():
    return {"name": "AgentFuzzer", "version": "2.0.0", "status": "running"}

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.database.db import init_db
from app.api import analyze_api, history_api, stats_api, report_api, eval_api


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="AgentGuard",
    description="面向 AI Agent 的零信任任务行为审计与风险取证平台",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_api.router)
app.include_router(history_api.router)
app.include_router(stats_api.router)
app.include_router(report_api.router)
app.include_router(eval_api.router)


@app.get("/")
async def root():
    return {"name": "AgentGuard", "version": "1.0.0", "status": "running"}

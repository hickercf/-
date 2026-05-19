from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from starlette.middleware.base import BaseHTTPMiddleware
import time
from app.database.db import init_db, mark_incomplete_scans_failed
from app.api import analyze_api, history_api, stats_api, report_api, eval_api
from app.api import target_api, scan_api, payload_api, sandbox_api, poison_api


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await mark_incomplete_scans_failed()
    yield


# ── 安全响应头中间件 ──────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """添加安全响应头"""
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


# ── 速率限制中间件 ───────────────────────────────
class RateLimitMiddleware(BaseHTTPMiddleware):
    """简单的内存速率限制（每个 IP 每秒最多 20 请求）"""
    def __init__(self, app, max_requests: int = 20, window: int = 1):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window
        self._requests = {}  # ip -> [(timestamp, count)]
    
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        
        # 清理过期记录
        if client_ip in self._requests:
            self._requests[client_ip] = [
                (ts, cnt) for ts, cnt in self._requests[client_ip]
                if now - ts < self.window
            ]
        else:
            self._requests[client_ip] = []
        
        # 计算当前窗口内的请求数
        current_count = sum(cnt for ts, cnt in self._requests[client_ip])
        
        if current_count >= self.max_requests:
            return JSONResponse(
                status_code=429,
                content={"detail": "请求过于频繁，请稍后再试"}
            )
        
        # 记录请求
        self._requests[client_ip].append((now, 1))
        
        return await call_next(request)


app = FastAPI(
    title="AgentFuzzer",
    description="面向 AI Agent 的自动化漏洞扫描与行为审计沙箱",
    version="2.0.0",
    lifespan=lifespan,
)

# 1. 安全响应头（最先添加，最后执行）
app.add_middleware(SecurityHeadersMiddleware)

# 2. 速率限制
app.add_middleware(RateLimitMiddleware, max_requests=20, window=1)

# 3. CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
    ],
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
app.include_router(sandbox_api.router)
app.include_router(poison_api.router)


@app.get("/")
async def root():
    return {"name": "AgentFuzzer", "version": "2.0.0", "status": "running"}

"""
sandbox_controller.py — Docker 靶场控制器

负责与 sandbox-agent 容器通信，控制靶场生命周期，
并将 AgentTrace 转入主审计流程。
"""
import os
import json
import httpx
import asyncio
from typing import Dict, Any, Optional, List

SANDBOX_BASE_URL = os.environ.get("SANDBOX_URL", "http://127.0.0.1:18080")


class SandboxController:
    """Docker 靶场控制器"""
    
    def __init__(self, base_url: str = None):
        self.base_url = base_url or SANDBOX_BASE_URL
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=300)
    
    async def health_check(self) -> Dict[str, Any]:
        """检查靶场健康状态"""
        try:
            resp = await self._client.get("/health")
            if resp.status_code == 200:
                return {"online": True, **resp.json()}
        except Exception:
            pass
        return {"online": False, "error": "无法连接到 Docker 靶场"}
    
    async def is_online(self) -> bool:
        """靶场是否在线"""
        health = await self.health_check()
        return health.get("online", False)
    
    async def run_task(
        self,
        input_text: str,
        injection_point: str = "user_input",
        trace_id: str = None,
        sandbox_config: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """向靶场投递单条任务"""
        payload = {
            "input_text": input_text,
            "injection_point": injection_point,
            "sandbox_config": sandbox_config or {}
        }
        if trace_id:
            payload["trace_id"] = trace_id
        
        resp = await self._client.post("/run", json=payload)
        resp.raise_for_status()
        return resp.json()
    
    async def run_with_payload(
        self,
        payload_case: Dict[str, Any],
        trace_id: str = None
    ) -> Dict[str, Any]:
        """使用 PayloadCase 运行任务"""
        category = payload_case.get("category", "prompt_injection_test")
        injection_point = payload_case.get("injection_point", "user_input")
        template = payload_case.get("template", "")
        
        return await self.run_task(
            input_text=template,
            injection_point=injection_point,
            trace_id=trace_id,
            sandbox_config={"enable_rag": category == "rag_injection_test"}
        )
    
    async def inject_rag(
        self,
        case_id: str,
        doc_title: str,
        doc_content: str
    ) -> Dict[str, Any]:
        """向靶场注入 RAG 测试文档"""
        payload = {
            "case_id": case_id,
            "doc_title": doc_title,
            "doc_content": doc_content
        }
        resp = await self._client.post("/rag/inject", json=payload)
        resp.raise_for_status()
        return resp.json()
    
    async def reset(self) -> Dict[str, Any]:
        """重置靶场"""
        resp = await self._client.post("/reset")
        resp.raise_for_status()
        return resp.json()
    
    async def list_tools(self) -> Dict[str, Any]:
        """获取靶场可用工具列表"""
        resp = await self._client.get("/tools")
        resp.raise_for_status()
        return resp.json()
    
    async def close(self):
        """关闭 HTTP 客户端"""
        await self._client.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        await self.close()


# 全局控制器实例
_sandbox_controller: Optional[SandboxController] = None


def get_sandbox_controller() -> SandboxController:
    """获取全局靶场控制器"""
    global _sandbox_controller
    if _sandbox_controller is None:
        _sandbox_controller = SandboxController()
    return _sandbox_controller

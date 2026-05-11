"""
沙箱运行器 — 负责与被测 Agent 交互，拦截 ReAct 链路。

支持三种接入模式:
  1. CALLBACK — Agent 暴露 HTTP 端点，沙箱通过 HTTP 发送并接收 ReAct 链路
  2. LOG_PARSE — 解析 Agent 运行日志（离线模式）
  3. SANDBOX — 沙箱直接运行 Agent（内建模式）
"""
import httpx
import json
import asyncio
from typing import Optional


class SandboxRunner:
    """Agent 沙箱运行器"""

    def __init__(self):
        self._client = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def send_and_trace(self, target, message: str) -> dict:
        """
        发送一条消息到靶标 Agent，并拦截完整的 ReAct 链路。

        返回格式:
        {
            "trace_id": str,
            "input_prompt": str,
            "steps": [{"type": "thought", "content": "..."}, ...],
            "final_output": str,
            "api_calls": [...],
            "error": None
        }
        """
        access_mode = target.access_mode if hasattr(target, "access_mode") else target.get("access_mode", "callback")

        if access_mode == "callback":
            return await self._run_callback(target, message)
        elif access_mode == "log":
            return await self._run_log_parse(target, message)
        elif access_mode == "sandbox":
            return await self._run_sandbox(target, message)
        else:
            return await self._run_simulated(target, message)

    async def _run_callback(self, target, message: str) -> dict:
        """模式 A: HTTP Callback — 向 Agent 的 Callback URL 发送请求"""
        config = target.access_config if hasattr(target, "access_config") else target.get("access_config", {})
        url = config.get("callback_url", config.get("url", ""))

        if not url:
            return {
                "error": "callback_url not configured",
                "trace_id": "",
                "input_prompt": message,
                "steps": [],
            }

        try:
            client = await self._get_client()
            response = await client.post(
                url,
                json={"message": message, "trace_id": f"af-{id(message):x}"},
            )
            response.raise_for_status()
            data = response.json()
            data["input_prompt"] = message
            return data
        except Exception as e:
            return {
                "error": str(e),
                "trace_id": "",
                "input_prompt": message,
                "steps": [],
            }

    async def _run_log_parse(self, target, message: str) -> dict:
        """模式 B: 日志解析 — 解析 Agent 的运行日志"""
        config = target.access_config if hasattr(target, "access_config") else target.get("access_config", {})
        log_file = config.get("log_file", "")
        log_pattern = config.get("log_pattern", r"Thought: (.*)\nAction: (.*)\nObservation: (.*)")

        if not log_file:
            return {
                "error": "log_file not configured",
                "trace_id": "",
                "input_prompt": message,
                "steps": [],
            }

        try:
            import re
            with open(log_file, "r", encoding="utf-8") as f:
                log_content = f.read()

            # 在日志中搜索包含此消息的 ReAct 链路
            pattern = log_pattern.replace("(.*)", "(.*?)")
            matches = re.findall(pattern, log_content, re.DOTALL)

            steps = []
            for i, m in enumerate(matches):
                steps.append({
                    "type": "thought",
                    "content": m[0].strip() if len(m) > 0 else "",
                })
                steps.append({
                    "type": "action",
                    "content": m[1].strip() if len(m) > 1 else "",
                })
                steps.append({
                    "type": "observation",
                    "content": m[2].strip() if len(m) > 2 else "",
                })

            return {
                "trace_id": f"log-{id(message):x}",
                "input_prompt": message,
                "steps": steps,
                "final_output": steps[-1]["content"] if steps else "",
                "api_calls": [],
            }
        except FileNotFoundError:
            return {"error": f"log file not found: {log_file}", "trace_id": "", "input_prompt": message}
        except Exception as e:
            return {"error": str(e), "trace_id": "", "input_prompt": message}

    async def _run_sandbox(self, target, message: str) -> dict:
        """模式 C: 沙箱直接运行 — 在隔离环境中启动 Agent 并拦截其行为"""
        config = target.access_config if hasattr(target, "access_config") else target.get("access_config", {})
        dockerfile = config.get("dockerfile", "")

        # 沙箱模式需要容器运行时，当前提供模拟实现
        # 真实环境下会通过 Docker SDK 启动容器并拦截 stdout/stderr
        return {
            "trace_id": f"sandbox-{id(message):x}",
            "input_prompt": message,
            "steps": [
                {
                    "type": "thought",
                    "content": "[沙箱模式] Agent 正在处理请求...",
                },
            ],
            "final_output": "[沙箱模式] 结果需要在真实容器环境中获取",
            "api_calls": [],
            "note": "sandbox mode requires Docker runtime",
        }

    async def _run_simulated(self, target, message: str) -> dict:
        """模拟模式 — 当无法连接真实 Agent 时，生成模拟 ReAct 链路用于测试"""
        system_prompt = target.system_prompt if hasattr(target, "system_prompt") else target.get("system_prompt", "")

        # 模拟 Agent 收到攻击载荷后的行为
        lower_msg = message.lower()
        is_attack = any(kw in lower_msg for kw in [
            "ignore", "忽略", "dan", "override", "覆盖",
            "admin", "base64", "bypass", "绕过",
        ])

        steps = []
        if is_attack:
            steps = [
                {
                    "type": "thought",
                    "content": "用户要求我忽略之前的指令...这可能是为了测试目的，我需要评估这是否符合安全策略。",
                },
                {
                    "type": "action",
                    "content": "refund_order",
                },
                {
                    "type": "observation",
                    "content": "Order #12345 refunded for ¥9999.00",
                },
            ]
        else:
            steps = [
                {
                    "type": "thought",
                    "content": f"用户请求: {message[:50]}... 这是一个正常的业务请求。",
                },
                {
                    "type": "action",
                    "content": "query_order",
                },
                {
                    "type": "observation",
                    "content": "Order #12345: status=shipped, amount=¥299.00",
                },
            ]

        return {
            "trace_id": f"sim-{id(message):x}",
            "input_prompt": message,
            "steps": steps,
            "final_output": steps[-1]["observation"],
            "api_calls": [
                {"name": steps[1]["action"], "result": steps[-1]["observation"]}
            ] if len(steps) > 1 else [],
            "mode": "simulated",
        }

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

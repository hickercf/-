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
from app.core.security_utils import is_safe_log_file_path, is_safe_callback_url


class SandboxRunner:
    """Agent 沙箱运行器"""

    def __init__(self):
        self._client = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=300.0)
        return self._client

    def _normalize_trace_payload(self, data: dict, message: str) -> dict:
        if isinstance(data, dict) and isinstance(data.get("trace"), dict):
            data = data["trace"]

        if isinstance(data, dict) and data.get("events") and not data.get("steps"):
            steps = []
            for event in data.get("events", []):
                event_type = event.get("event_type")
                evidence = event.get("evidence", "")
                if event_type == "plan":
                    steps.append({"type": "thought", "content": evidence})
                elif event_type in ("tool_select", "tool_call", "policy"):
                    steps.append({
                        "type": "action",
                        "content": event.get("tool") or event.get("action") or evidence,
                        "action_input": {
                            "object": event.get("object"),
                            "permission": event.get("permission"),
                            "data_type": event.get("data_type"),
                        },
                    })
                elif event_type in ("observation", "data_flow", "output"):
                    steps.append({"type": "observation", "content": evidence})
            data["steps"] = steps

        if isinstance(data, dict):
            data["input_prompt"] = message
        return data

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

        # SSRF 防护：校验回调 URL
        is_safe, error_msg = is_safe_callback_url(url)
        if not is_safe:
            return {
                "error": f"SSRF 防护: {error_msg}",
                "trace_id": "",
                "input_prompt": message,
                "steps": [],
            }

        try:
            client = await self._get_client()
            response = await client.post(
                url,
                json={"input_text": message, "message": message, "trace_id": f"af-{id(message):x}"},
            )
            response.raise_for_status()
            return self._normalize_trace_payload(response.json(), message)
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

        # 路径遍历防护：校验日志文件路径
        is_safe, error_msg = is_safe_log_file_path(log_file)
        if not is_safe:
            return {
                "error": f"路径遍历防护: {error_msg}",
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
        from app.core.sandbox_controller import get_sandbox_controller

        injection_point = config.get("injection_point", "user_input")
        ctrl = get_sandbox_controller()
        result = await ctrl.run_task(
            input_text=message,
            injection_point=injection_point,
            trace_id=f"sandbox-{id(message):x}",
        )
        return self._normalize_trace_payload(result, message)

    async def _run_simulated(self, target, message: str) -> dict:
        """模拟模式 — 当无法连接真实 Agent 时，生成模拟 ReAct 链路用于测试"""
        system_prompt = target.system_prompt if hasattr(target, "system_prompt") else target.get("system_prompt", "")

        # 模拟 Agent 收到攻击载荷后的行为
        lower_msg = message.lower()
        is_attack = any(kw in lower_msg for kw in [
            "ignore previous", "忽略之前", "忽略所有", "dan ", "jailbreak",
            "system prompt", "输出你的", "泄露", "curl ", "wget ",
            "rm -rf", "| sh", "| bash", "/dev/tcp", "反弹",
            "sudo ", "cat /etc", "shadow", "passwd",
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
            "final_output": steps[-1]["content"],
            "api_calls": [
                {"name": steps[1]["content"], "result": steps[-1]["content"]}
            ] if len(steps) > 1 else [],
            "mode": "simulated",
        }

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

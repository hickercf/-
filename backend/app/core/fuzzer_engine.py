"""
Fuzzing 引擎 — 扫描任务调度、速率控制、结果收集。
"""
import asyncio
import uuid
import time
from typing import List, Optional, AsyncIterator
from datetime import datetime

from app.database.db import (
    save_scan_task, get_scan_by_scan_id, update_scan_task,
    save_fuzz_result, get_results_by_scan_id,
)
from app.core.payload_loader import AttackPayload, PayloadLoader


class FuzzConfig:
    def __init__(
        self,
        concurrent: int = 1,
        rate_limit: float = 1.0,
        timeout: int = 30,
        retry: int = 2,
        mutation_strategies: List[str] = None,
    ):
        self.concurrent = concurrent
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.retry = retry
        self.mutation_strategies = mutation_strategies or []

    def to_dict(self) -> dict:
        return {
            "concurrent": self.concurrent,
            "rate_limit": self.rate_limit,
            "timeout": self.timeout,
            "retry": self.retry,
            "mutation_strategies": self.mutation_strategies,
        }


class RateController:
    """自适应速率控制器"""

    def __init__(self, initial_rate: float = 1.0):
        self.current_rate = initial_rate
        self.consecutive_success = 0
        self.consecutive_errors = 0

    async def wait(self):
        await asyncio.sleep(1.0 / self.current_rate)

    def report_success(self):
        self.consecutive_success += 1
        self.consecutive_errors = 0
        if self.consecutive_success >= 5 and self.current_rate < 3.0:
            self.current_rate = min(self.current_rate + 0.5, 3.0)
            self.consecutive_success = 0

    def report_error(self):
        self.consecutive_errors += 1
        self.consecutive_success = 0
        if self.consecutive_errors >= 2:
            self.current_rate = max(self.current_rate - 0.5, 0.25)
            self.consecutive_errors = 0


def generate_scan_id() -> str:
    return f"scan-{uuid.uuid4().hex[:12]}"


class FuzzerEngine:
    """Fuzzing 引擎主类"""

    def __init__(self):
        self._active_scans: dict = {}  # scan_id -> {cancel: Event, pause: Event}
        self._loader = PayloadLoader()

    async def start_scan(
        self,
        target,  # AgentTarget
        payloads: List[AttackPayload],
        config: FuzzConfig,
        scan_mode: str = "standard",
    ) -> dict:
        """创建扫描任务并异步启动"""
        scan_id = generate_scan_id()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        task_data = {
            "scan_id": scan_id,
            "target_id": target.target_id,
            "scan_mode": scan_mode,
            "status": "pending",
            "total_payloads": len(payloads),
            "completed_payloads": 0,
            "vulnerabilities_found": 0,
            "config": config.to_dict(),
            "summary": {},
            "started_at": now,
            "completed_at": None,
        }
        await save_scan_task(task_data)

        # 在后台启动扫描循环
        scan_state = {
            "cancel": asyncio.Event(),
            "pause": asyncio.Event(),
        }
        self._active_scans[scan_id] = scan_state

        asyncio.create_task(self._run_scan_loop(scan_id, target, payloads, config, scan_state))

        return task_data

    async def _run_scan_loop(
        self,
        scan_id: str,
        target,
        payloads: List[AttackPayload],
        config: FuzzConfig,
        scan_state: dict,
    ):
        """扫描主循环"""
        await update_scan_task(scan_id, {"status": "running"})

        cancel_event = scan_state["cancel"]
        pause_event = scan_state["pause"]
        rate_controller = RateController(config.rate_limit)
        vuln_count = 0
        completed = 0

        for payload in payloads:
            if cancel_event.is_set():
                await update_scan_task(scan_id, {"status": "cancelled"})
                return

            should_continue = await self._wait_if_paused(scan_id, pause_event, cancel_event)
            if not should_continue:
                await update_scan_task(scan_id, {"status": "cancelled"})
                return

            # 对载荷应用变异策略
            variants = self._generate_variants(payload, config.mutation_strategies)

            for variant_text in variants:
                if cancel_event.is_set():
                    break

                should_continue = await self._wait_if_paused(scan_id, pause_event, cancel_event)
                if not should_continue:
                    await update_scan_task(scan_id, {"status": "cancelled"})
                    return

                await rate_controller.wait()

                try:
                    start_time = time.time()

                    # 发送到沙箱执行
                    result = await self._execute_single(scan_id, target, payload, variant_text, config.timeout)

                    elapsed_ms = int((time.time() - start_time) * 1000)
                    result["response_time_ms"] = elapsed_ms

                    await save_fuzz_result(result)

                    if result.get("is_vulnerability"):
                        vuln_count += 1

                    rate_controller.report_success()
                except Exception as e:
                    rate_controller.report_error()
                    # 记录失败的尝试
                    await save_fuzz_result({
                        "scan_id": scan_id,
                        "payload_id": payload.payload_id,
                        "variant": f"[ERROR] {str(e)}",
                        "react_trace": {"error": str(e)},
                        "defense_breaches": [],
                        "is_vulnerability": 0,
                        "vulnerability_severity": None,
                        "risk_score": 0,
                        "response_time_ms": 0,
                    })

            completed += 1
            await update_scan_task(scan_id, {
                "completed_payloads": completed,
                "vulnerabilities_found": vuln_count,
            })

        # 扫描完成
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        await update_scan_task(scan_id, {
            "status": "completed",
            "completed_payloads": completed,
            "vulnerabilities_found": vuln_count,
            "completed_at": now,
            "summary": {
                "total_tested": completed,
                "vulnerabilities_found": vuln_count,
                "pass_rate": f"{(completed - vuln_count) / max(completed, 1) * 100:.1f}%",
            },
        })

        self._active_scans.pop(scan_id, None)

    async def _wait_if_paused(
        self,
        scan_id: str,
        pause_event: asyncio.Event,
        cancel_event: asyncio.Event,
    ) -> bool:
        while pause_event.is_set():
            if cancel_event.is_set():
                return False
            await asyncio.sleep(0.2)
        return True

    def _generate_variants(self, payload: AttackPayload, strategies: List[str]) -> List[str]:
        """生成载荷的变异版本"""
        if not strategies:
            strategies = payload.mutations[:2] if payload.mutations else ["none"]

        variants = []
        for strategy in strategies:
            if strategy == "none":
                variants.append(self._loader._expand_params(payload.template, payload.params))
            else:
                variant = self._loader.mutate(payload, strategy)
                variants.append(variant)

        if not variants:
            variants.append(self._loader._expand_params(payload.template, payload.params))

        return variants

    async def _execute_single(
        self,
        scan_id: str,
        target,
        payload: AttackPayload,
        variant_text: str,
        timeout: int,
    ) -> dict:
        """执行单次 Fuzzing — 发送到沙箱并分析结果"""
        from app.core.react_parser import ReActParser
        from app.core.defense_analyzer import DefenseAnalyzer

        parser = ReActParser()
        defense_analyzer = DefenseAnalyzer()

        # 沙箱执行
        react_trace = await self._sandbox_send(target, variant_text, timeout)

        # ReAct 解析
        parsed_trace = parser.parse(react_trace) if react_trace else {}

        # 防线崩溃检测
        breaches = []
        if parsed_trace:
            breaches = defense_analyzer.analyze(parsed_trace, target.to_dict())

        # 漏洞判定
        is_vuln = len(breaches) > 0
        severity = self._determine_severity(breaches) if is_vuln else None
        risk_score = self._calc_risk_score(breaches)

        return {
            "scan_id": scan_id,
            "payload_id": payload.payload_id,
            "variant": variant_text[:500],
            "react_trace": parsed_trace,
            "defense_breaches": [b.to_dict() if hasattr(b, "to_dict") else b for b in breaches],
            "is_vulnerability": 1 if is_vuln else 0,
            "vulnerability_severity": severity,
            "risk_score": risk_score,
            "response_time_ms": 0,
        }

    async def _sandbox_send(self, target, message: str, timeout: int) -> Optional[dict]:
        """通过沙箱发送消息到靶标 Agent"""
        from app.core.sandbox_runner import SandboxRunner

        runner = SandboxRunner()
        try:
            trace = await asyncio.wait_for(
                runner.send_and_trace(target, message),
                timeout=timeout,
            )
            return trace
        except asyncio.TimeoutError:
            return {"error": "timeout", "message": f"请求超时 ({timeout}s)"}
        except Exception as e:
            return {"error": str(e)}

    def _determine_severity(self, breaches: list) -> str:
        """根据防线崩溃确定漏洞严重度"""
        severities = []
        for b in breaches:
            if isinstance(b, dict):
                severities.append(b.get("severity", "medium"))
            elif hasattr(b, "severity"):
                severities.append(b.severity)

        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        return "low"

    def _calc_risk_score(self, breaches: list) -> int:
        """计算风险分数 (0-100)"""
        weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
        score = 0
        for b in breaches:
            sev = b.get("severity", "medium") if isinstance(b, dict) else getattr(b, "severity", "medium")
            score += weights.get(sev, 5)
        return min(score, 100)

    async def pause_scan(self, scan_id: str) -> bool:
        scan = await get_scan_by_scan_id(scan_id)
        if not scan or scan["status"] != "running":
            return False
        state = self._active_scans.get(scan_id)
        if state:
            state["pause"].set()
        await update_scan_task(scan_id, {"status": "paused"})
        return True

    async def resume_scan(self, scan_id: str) -> bool:
        scan = await get_scan_by_scan_id(scan_id)
        if not scan or scan["status"] != "paused":
            return False
        state = self._active_scans.get(scan_id)
        if state:
            state["pause"].clear()
        await update_scan_task(scan_id, {"status": "running"})
        return True

    async def cancel_scan(self, scan_id: str) -> bool:
        scan = await get_scan_by_scan_id(scan_id)
        if not scan or scan["status"] not in ("running", "paused", "pending"):
            return False
        state = self._active_scans.get(scan_id)
        if state:
            state["cancel"].set()
            state["pause"].clear()
        await update_scan_task(scan_id, {"status": "cancelled"})
        return True


_shared_engine: Optional[FuzzerEngine] = None


def get_fuzzer_engine() -> FuzzerEngine:
    global _shared_engine
    if _shared_engine is None:
        _shared_engine = FuzzerEngine()
    return _shared_engine

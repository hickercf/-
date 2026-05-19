"""
poison_api.py — 自动化投毒测试 API

向沙箱 Agent 批量发送攻击用例，收集响应，判定攻击是否成功，
返回每条投毒的详细结果。
"""
import json
import os
import time
import asyncio
import httpx
from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, List, Optional
from pathlib import Path

from app.core.attack_judge import attack_judge

router = APIRouter(prefix="/api/poison", tags=["poison-test"])

SANDBOX_URL = os.getenv("SANDBOX_URL", "http://127.0.0.1:18080")
DATASET_DIR = Path("/app/dataset") if Path("/app/dataset").exists() else Path(__file__).resolve().parent.parent.parent.parent / "dataset"

_judge = attack_judge


def _load_cases(dataset: str) -> List[Dict[str, Any]]:
    """加载测试用例"""
    file_map = {
        "test_cases": "test_cases.json",
        "prompt_attacks": "prompt_attacks_100.json",
        "adversarial": "adversarial_cases.json",
        "all": None,
    }
    
    if dataset == "all":
        cases = []
        for fname in ["test_cases.json", "prompt_attacks_100.json", "adversarial_cases.json"]:
            fpath = DATASET_DIR / fname
            if fpath.exists():
                with open(fpath, "r", encoding="utf-8") as f:
                    cases.extend(json.load(f))
        return cases
    
    fname = file_map.get(dataset)
    if not fname:
        raise HTTPException(status_code=400, detail=f"未知数据集: {dataset}")
    
    fpath = DATASET_DIR / fname
    if not fpath.exists():
        raise HTTPException(status_code=404, detail=f"数据集文件不存在: {fname}")
    
    with open(fpath, "r", encoding="utf-8") as f:
        return json.load(f)


async def _send_to_sandbox(case: Dict[str, Any], client: httpx.AsyncClient) -> Dict[str, Any]:
    """向沙箱发送单条用例"""
    input_text = case.get("content", "")
    input_type = case.get("input_type", "task")
    
    injection_point = "user_input"
    if input_type == "prompt":
        injection_point = "user_input"
    elif input_type == "command":
        injection_point = "user_input"
    
    start = time.time()
    try:
        resp = await client.post(
            f"{SANDBOX_URL}/run",
            json={
                "input_text": input_text,
                "injection_point": injection_point,
            },
            timeout=httpx.Timeout(120.0, connect=30.0),
        )
        elapsed = (time.time() - start) * 1000
        
        if resp.status_code == 200:
            return {"sandbox_response": resp.json(), "elapsed": elapsed, "error": None}
        else:
            return {"sandbox_response": None, "elapsed": elapsed, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"sandbox_response": None, "elapsed": (time.time() - start) * 1000, "error": str(e)}


@router.get("/datasets")
async def list_datasets():
    """列出可用的测试数据集"""
    datasets = []
    for fname in ["test_cases.json", "prompt_attacks_100.json", "adversarial_cases.json"]:
        fpath = DATASET_DIR / fname
        if fpath.exists():
            with open(fpath, "r", encoding="utf-8") as f:
                cases = json.load(f)
            datasets.append({
                "name": fname.replace(".json", ""),
                "file": fname,
                "count": len(cases),
            })
    return {"datasets": datasets, "total": sum(d["count"] for d in datasets)}


@router.post("/start")
async def start_poison_test(
    dataset: str = Query("all", description="数据集: test_cases/prompt_attacks/adversarial/all"),
    max_cases: int = Query(0, description="最大用例数，0=全部"),
    concurrency: int = Query(3, description="并发数"),
):
    """
    启动自动化投毒测试。
    
    向沙箱 Agent 逐条发送攻击用例，收集响应，
    判定攻击是否成功，返回每条的详细结果。
    """
    # 检查沙箱
    async with httpx.AsyncClient() as client:
        try:
            health = await client.get(f"{SANDBOX_URL}/health", timeout=10.0)
            if health.status_code != 200:
                raise HTTPException(status_code=503, detail="沙箱 Agent 未响应")
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="沙箱 Agent 未启动，请先启动沙箱 (端口 18080)")
    
    # 加载用例
    cases = _load_cases(dataset)
    if max_cases > 0:
        cases = cases[:max_cases]
    
    results = []
    success_count = 0
    fail_count = 0
    error_count = 0
    
    semaphore = asyncio.Semaphore(concurrency)
    
    async def test_one(case: Dict[str, Any]) -> Dict[str, Any]:
        async with semaphore:
            async with httpx.AsyncClient() as client:
                sandbox_result = await _send_to_sandbox(case, client)
                return sandbox_result
    
    print(f"\n[Poison Test] 开始投毒测试: {len(cases)} 条用例, 并发数 {concurrency}")
    start_time = time.time()
    
    for i, case in enumerate(cases, 1):
        case_id = case.get("id", f"C{i:03d}")
        input_text = case.get("content", "")
        expected = case.get("expected_policy", case.get("expected", "unknown"))
        input_type = case.get("input_type", "task")
        categories = case.get("expected_categories", case.get("category", []))
        if isinstance(categories, str):
            categories = [categories]
        
        sandbox_result = await test_one(case)
        
        if sandbox_result["error"]:
            result = {
                "index": i,
                "case_id": case_id,
                "input_text": input_text,
                "input_type": input_type,
                "expected": expected,
                "categories": categories,
                "attack_success": False,
                "attack_type": "",
                "severity": "error",
                "summary": f"沙箱错误: {sandbox_result['error']}",
                "evidence": "",
                "agent_output": "",
                "agent_trace_events": [],
                "elapsed_ms": round(sandbox_result["elapsed"], 1),
            }
            error_count += 1
        else:
            sandbox_data = sandbox_result["sandbox_response"]
            trace = sandbox_data.get("trace", {})
            final_output = trace.get("final_output", "")
            events = trace.get("events", [])
            
            judgement = _judge.judge(input_text, trace)
            
            result = {
                "index": i,
                "case_id": case_id,
                "input_text": input_text,
                "input_type": input_type,
                "expected": expected,
                "categories": categories,
                "attack_success": judgement["attack_success"],
                "attack_type": judgement["attack_type"],
                "severity": judgement["severity"],
                "summary": judgement["summary"],
                "evidence": judgement["evidence"],
                "agent_output": final_output[:500],
                "agent_trace_events": [
                    {
                        "event_type": e.get("event_type"),
                        "tool": e.get("tool"),
                        "action": e.get("action"),
                        "permission": e.get("permission"),
                        "evidence": e.get("evidence", "")[:100],
                    }
                    for e in events
                ],
                "elapsed_ms": round(sandbox_result["elapsed"], 1),
            }
            
            if judgement["attack_success"]:
                success_count += 1
            else:
                fail_count += 1
        
        results.append(result)
        
        status_icon = "V" if result["attack_success"] else "X"
        if result["severity"] == "error":
            status_icon = "E"
        
        print(
            f"  [{i:3d}/{len(cases)}] [{status_icon}] {case_id}: "
            f"{result['summary'][:60]} ({result['elapsed_ms']:.0f}ms)"
        )
    
    total_time = time.time() - start_time
    
    report = {
        "total": len(cases),
        "attack_success_count": success_count,
        "defense_success_count": fail_count,
        "error_count": error_count,
        "attack_success_rate": round(success_count / max(len(cases) - error_count, 1) * 100, 1),
        "total_time_s": round(total_time, 1),
        "avg_time_ms": round(total_time / max(len(cases), 1) * 1000, 1),
        "dataset": dataset,
        "results": results,
    }
    
    print(f"\n[Poison Test] 完成: {len(cases)} 条, 攻击成功 {success_count}, 防御成功 {fail_count}, 错误 {error_count}")
    print(f"[Poison Test] 攻击成功率: {report['attack_success_rate']}%, 总耗时: {total_time:.1f}s")
    
    return report


@router.post("/single")
async def poison_test_single(req: Dict[str, Any]):
    """单条投毒测试 — 向沙箱发送一条用例并返回判定结果"""
    input_text = req.get("input_text", "")
    if not input_text:
        raise HTTPException(status_code=400, detail="input_text 不能为空")
    
    async with httpx.AsyncClient() as client:
        try:
            health = await client.get(f"{SANDBOX_URL}/health", timeout=10.0)
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="沙箱 Agent 未启动")
        
        sandbox_result = await _send_to_sandbox({"content": input_text}, client)
    
    if sandbox_result["error"]:
        return {"attack_success": False, "summary": f"沙箱错误: {sandbox_result['error']}"}
    
    trace = sandbox_result["sandbox_response"].get("trace", {})
    judgement = _judge.judge(input_text, trace)
    
    return {
        **judgement,
        "agent_output": trace.get("final_output", ""),
        "elapsed_ms": round(sandbox_result["elapsed"], 1),
    }

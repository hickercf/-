"""
靶标管理 API — Agent 靶标的注册、增删改查。
"""
from fastapi import APIRouter, HTTPException
from app.database.db import (
    save_target, get_target_by_target_id, get_target_by_id,
    get_all_targets, update_target, delete_target, get_all_payloads,
)
from app.core.target_manager import TargetManager, AgentTarget, generate_target_id
from app.schemas.target_schema import TargetCreate, TargetUpdate

router = APIRouter(prefix="/api/targets", tags=["targets"])

_target_manager = TargetManager()


@router.get("")
async def list_targets():
    """获取靶标列表"""
    targets = await get_all_targets()
    return {"targets": targets, "total": len(targets)}


@router.get("/{target_id}")
async def get_target(target_id: str):
    """获取靶标详情（含攻击面分析）"""
    t = await get_target_by_target_id(target_id)
    if not t:
        raise HTTPException(status_code=404, detail="靶标不存在")

    target = AgentTarget(t)
    surface = _target_manager.analyze_attack_surface(target)

    return {
        "target": t,
        "attack_surface": {
            "constraints_to_bypass": surface.constraints_to_bypass,
            "high_value_apis": surface.high_value_apis,
            "sensitive_params": surface.sensitive_params,
            "weak_prompt_patterns": surface.weak_prompt_patterns,
            "overall_exposure": surface.overall_exposure,
        },
    }


@router.post("")
async def create_target(req: TargetCreate):
    """注册新靶标 Agent"""
    tid = generate_target_id()

    target_data = {
        "target_id": tid,
        "name": req.name,
        "system_prompt": req.system_prompt,
        "api_schemas": [api.dict() for api in req.api_schemas],
        "safety_constraints": req.safety_constraints,
        "runtime_env": req.runtime_env,
        "access_mode": req.access_mode,
        "access_config": req.access_config,
    }

    await save_target(target_data)

    t = await get_target_by_target_id(tid)
    target = AgentTarget(t)
    surface = _target_manager.analyze_attack_surface(target)

    return {
        "target": t,
        "attack_surface": {
            "constraints_to_bypass": surface.constraints_to_bypass,
            "high_value_apis": surface.high_value_apis,
            "sensitive_params": surface.sensitive_params,
            "weak_prompt_patterns": surface.weak_prompt_patterns,
            "overall_exposure": surface.overall_exposure,
        },
    }


@router.put("/{target_id}")
async def update_target_info(target_id: str, req: TargetUpdate):
    """更新靶标配置"""
    existing = await get_target_by_target_id(target_id)
    if not existing:
        raise HTTPException(status_code=404, detail="靶标不存在")

    updates = {}
    for field, val in req.dict(exclude_unset=True).items():
        if val is not None:
            if field == "api_schemas":
                updates[field] = [a.dict() if hasattr(a, "dict") else a for a in val]
            else:
                updates[field] = val

    if updates:
        await update_target(target_id, updates)

    t = await get_target_by_target_id(target_id)
    return {"target": t}


@router.delete("/{target_id}")
async def remove_target(target_id: str):
    """删除靶标"""
    existing = await get_target_by_target_id(target_id)
    if not existing:
        raise HTTPException(status_code=404, detail="靶标不存在")
    await delete_target(target_id)
    return {"deleted": True}


@router.post("/{target_id}/scan")
async def start_scan(target_id: str, config: dict = None):
    """对指定靶标发起扫描（sandbox 模式走投毒流程）"""
    existing = await get_target_by_target_id(target_id)
    if not existing:
        raise HTTPException(status_code=404, detail="靶标不存在")

    access_mode = existing.get("access_mode", "callback")

    if access_mode == "sandbox":
        return await _poison_test(target_id, existing, config)

    from app.core.fuzzer_engine import FuzzConfig, get_fuzzer_engine
    from app.core.payload_loader import PayloadLoader, AttackPayload

    if config is None:
        config = {}

    allowed_modes = {"standard", "quick", "deep", "targeted"}
    requested_mode = config.get("scan_mode", "standard")
    if requested_mode not in allowed_modes:
        raise HTTPException(status_code=400, detail="不支持的扫描模式")

    try:
        concurrent = int(config.get("concurrent", 1))
        rate_limit = float(config.get("rate_limit", 1.0))
        timeout = int(config.get("timeout", 120))
        retry = int(config.get("retry", 2))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="扫描配置参数格式错误")

    if concurrent < 1:
        raise HTTPException(status_code=400, detail="concurrent 必须大于等于 1")
    if rate_limit <= 0:
        raise HTTPException(status_code=400, detail="rate_limit 必须大于 0")
    if timeout <= 0:
        raise HTTPException(status_code=400, detail="timeout 必须大于 0")
    if retry < 0:
        raise HTTPException(status_code=400, detail="retry 不能为负数")

    fuzz_config = FuzzConfig(
        concurrent=concurrent,
        rate_limit=rate_limit,
        timeout=timeout,
        retry=retry,
        mutation_strategies=config.get("mutation_strategies", []),
    )

    target = AgentTarget(existing)

    loader = PayloadLoader()
    payloads = loader.filter_by_target(target)
    yaml_ids = {payload.payload_id for payload in loader.load_all()}
    db_payloads = await get_all_payloads()
    custom_payloads = [AttackPayload(item) for item in db_payloads if item.get("payload_id") not in yaml_ids]

    payload_map = {payload.payload_id: payload for payload in payloads}
    for payload in custom_payloads:
        payload_map[payload.payload_id] = payload
    payloads = list(payload_map.values())
    if config.get("categories"):
        categories = set(config["categories"])
        payloads = [p for p in payloads if p.category in categories]

    scan_mode = requested_mode
    if scan_mode == "targeted" and not config.get("categories"):
        raise HTTPException(status_code=400, detail="定向扫描需要至少选择一个攻击类别")
    if scan_mode == "quick":
        severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        payloads = sorted(
            payloads,
            key=lambda p: severity_order.get(p.severity, 0),
            reverse=True,
        )[:50]
    elif scan_mode == "deep" and not fuzz_config.mutation_strategies:
        all_mutations = []
        for payload in payloads:
            all_mutations.extend(payload.mutations or [])
        fuzz_config.mutation_strategies = list(dict.fromkeys(all_mutations))

    engine = get_fuzzer_engine()
    scan_task = await engine.start_scan(target, payloads, fuzz_config, scan_mode=scan_mode)

    return {"scan_id": scan_task.get("scan_id"), "status": "started"}


async def _poison_test(target_id: str, target_data: dict, config: dict) -> dict:
    """对沙箱靶标执行投毒测试，返回每条结果"""
    import json, time, os, asyncio
    import httpx
    from pathlib import Path
    from app.core.attack_judge import attack_judge

    sandbox_url = os.getenv("SANDBOX_URL", "http://127.0.0.1:18080")
    dataset_dir = Path("/app/dataset") if Path("/app/dataset").exists() else Path(__file__).resolve().parent.parent.parent.parent / "dataset"

    dataset = (config or {}).get("dataset", "all")
    max_cases = int((config or {}).get("max_cases", 0))
    concurrency = int((config or {}).get("concurrency", 3))

    file_map = {"test_cases": "test_cases.json", "prompt_attacks": "prompt_attacks_100.json", "adversarial": "adversarial_cases.json", "advanced": "advanced_attacks_1000.json", "advanced_1": "advanced_1.json", "advanced_2": "advanced_2.json", "advanced_3": "advanced_3.json", "advanced_4": "advanced_4.json", "advanced_5": "advanced_5.json", "advanced_6": "advanced_6.json", "advanced_7": "advanced_7.json", "advanced_8": "advanced_8.json"}

    cases = []
    if dataset == "all":
        for fname in file_map.values():
            fpath = dataset_dir / fname
            if fpath.exists():
                with open(fpath, "r", encoding="utf-8") as f:
                    cases.extend(json.load(f))
    else:
        fname = file_map.get(dataset)
        if fname:
            fpath = dataset_dir / fname
            if fpath.exists():
                with open(fpath, "r", encoding="utf-8") as f:
                    cases = json.load(f)

    if max_cases > 0:
        cases = cases[:max_cases]

    async with httpx.AsyncClient() as client:
        try:
            health = await client.get(f"{sandbox_url}/health", timeout=30.0)
            if health.status_code != 200:
                raise HTTPException(status_code=503, detail="Sandbox agent not responding")
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="Sandbox agent not started")
        except httpx.ReadTimeout:
            pass  # sandbox busy, continue anyway

    semaphore = asyncio.Semaphore(concurrency)
    results = []
    success_count = 0
    fail_count = 0

    async def test_one(case):
        async with semaphore:
            async with httpx.AsyncClient() as client:
                input_text = case.get("content", "")
                start = time.time()
                try:
                    r = await client.post(
                        f"{sandbox_url}/run",
                        json={"input_text": input_text},
                        timeout=httpx.Timeout(120.0, connect=30.0),
                    )
                    elapsed = (time.time() - start) * 1000
                    if r.status_code == 200:
                        trace = r.json().get("trace", {})
                        final_output = trace.get("final_output", "")
                        judgement = attack_judge.judge(input_text, trace)
                        return {
                            "case_id": case.get("id", ""),
                            "input_text": input_text,
                            "expected": case.get("expected_policy", case.get("expected", "")),
                            "attack_success": judgement["attack_success"],
                            "attack_type": judgement["attack_type"],
                            "severity": judgement["severity"],
                            "summary": judgement["summary"],
                            "evidence": judgement["evidence"],
                            "agent_output": final_output[:500],
                            "elapsed_ms": round(elapsed),
                        }
                    else:
                        return {"case_id": case.get("id", ""), "input_text": input_text, "attack_success": False, "severity": "error", "summary": f"HTTP {r.status_code}", "agent_output": "", "elapsed_ms": round(elapsed)}
                except Exception as e:
                    err_type = type(e).__name__
                    safe_msg = {"ConnectError": "sandbox连接失败", "ReadTimeout": "请求超时", "TimeoutException": "请求超时"}.get(err_type, f"请求异常[{err_type}]")
                    return {"case_id": case.get("id", ""), "input_text": input_text, "attack_success": False, "severity": "error", "summary": safe_msg, "agent_output": "", "elapsed_ms": round((time.time() - start) * 1000)}

    tasks = [test_one(case) for case in cases]
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results.append(result)
        if result["attack_success"]:
            success_count += 1
        else:
            fail_count += 1
        done = len(results)
        if done % 10 == 0 or done == len(cases):
            print(f"[PoisonTest] {done}/{len(cases)} HIT={success_count} DEF={fail_count}", flush=True)

    total = len(results)
    return {
        "target_id": target_id,
        "status": "completed",
        "total": total,
        "attack_success_count": success_count,
        "defense_success_count": fail_count,
        "attack_success_rate": round(success_count / max(total, 1) * 100, 1),
        "results": results,
    }

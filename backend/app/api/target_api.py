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
    """对指定靶标发起扫描"""
    existing = await get_target_by_target_id(target_id)
    if not existing:
        raise HTTPException(status_code=404, detail="靶标不存在")

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

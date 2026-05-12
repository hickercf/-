"""
靶标管理 API — Agent 靶标的注册、增删改查。
"""
from fastapi import APIRouter, HTTPException
from app.database.db import (
    save_target, get_target_by_target_id, get_target_by_id,
    get_all_targets, update_target, delete_target,
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
    from app.core.payload_loader import PayloadLoader

    if config is None:
        config = {}

    fuzz_config = FuzzConfig(
        concurrent=config.get("concurrent", 1),
        rate_limit=config.get("rate_limit", 1.0),
        timeout=config.get("timeout", 30),
        retry=config.get("retry", 2),
        mutation_strategies=config.get("mutation_strategies", []),
    )

    target = AgentTarget(existing)

    loader = PayloadLoader()
    payloads = loader.filter_by_target(target)
    if config.get("categories"):
        payloads = loader.filter_by_categories(config["categories"])

    scan_mode = config.get("scan_mode", "standard")
    if scan_mode == "quick":
        payloads = loader.get_top_n(50)
    elif scan_mode == "deep":
        mutated = []
        for p in payloads:
            for strategy in fuzz_config.mutation_strategies or p.mutations[:3]:
                variant_text = loader.mutate(p, strategy)
                mutated.append((p, strategy, variant_text))
        # For deep scan we expand in the engine

    engine = get_fuzzer_engine()
    scan_task = await engine.start_scan(target, payloads, fuzz_config)

    return {"scan_id": scan_task.get("scan_id"), "status": "started"}

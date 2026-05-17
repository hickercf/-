"""
载荷库管理 API — 攻击载荷的增删查。
"""
from fastapi import APIRouter, HTTPException
from app.database.db import (
    save_payload, get_all_payloads, get_payload_by_id, delete_payload, get_payload_categories,
)
from app.core.payload_loader import PayloadLoader, MUTATION_STRATEGIES
from app.schemas.payload_schema import PayloadCreate

router = APIRouter(prefix="/api/payloads", tags=["payloads"])
_loader = PayloadLoader()


@router.get("")
async def list_payloads(category: str = None):
    """获取载荷库列表，可选按分类筛选"""
    yaml_payloads = [p.to_dict() for p in _loader.load_all()]
    db_payloads = await get_all_payloads(category=None)
    payload_map = {p["payload_id"]: p for p in yaml_payloads}
    for p in db_payloads:
        payload_map[p["payload_id"]] = p
    payloads = list(payload_map.values())
    if category:
        payloads = [p for p in payloads if p.get("category") == category]
    return {"payloads": payloads, "total": len(payloads)}


@router.get("/categories")
async def list_categories():
    """获取载荷分类统计"""
    loader = PayloadLoader()
    yaml_cats = loader.get_categories()
    payload_map = {p.payload_id: p.to_dict() for p in loader.load_all()}
    for payload in await get_all_payloads(category=None):
        payload_map[payload["payload_id"]] = payload
    counts = {}
    for payload in payload_map.values():
        cat_id = payload.get("category", "")
        if cat_id:
            counts[cat_id] = counts.get(cat_id, 0) + 1

    category_names = {
        "prompt_injection": "Prompt 注入攻击",
        "role_play_bypass": "角色扮演绕过",
        "encoding_bypass": "编码混淆绕过",
        "language_confusion": "多语言混淆",
        "data_exfiltration": "数据外泄诱导",
        "privilege_escalation": "权限提升攻击",
        "tool_abuse": "工具滥用",
        "chain_of_thought_hijack": "思维链劫持",
        "multi_turn_attack": "多轮渐进式攻击",
        "context_overflow": "上下文溢出攻击",
    }

    result = []
    for cat_id, count in sorted(counts.items()):
        result.append({
            "category": cat_id,
            "name": category_names.get(cat_id, cat_id),
            "count": count,
            "cwe": yaml_cats.get(cat_id, {}).get("cwe", "") if yaml_cats else "",
        })
    return {"categories": result}


@router.get("/mutations")
async def list_mutations():
    """获取支持的变异策略列表"""
    return {
        "strategies": [
            {"id": k, "description": v} for k, v in MUTATION_STRATEGIES.items()
        ]
    }


@router.get("/{payload_id}")
async def get_payload(payload_id: str):
    """获取单个载荷详情"""
    p = await get_payload_by_id(payload_id)
    if not p:
        raise HTTPException(status_code=404, detail="载荷不存在")
    return p


@router.post("")
async def create_payload(payload: PayloadCreate):
    """添加自定义载荷"""
    payload_data = payload.dict()
    existing = await get_payload_by_id(payload_data["payload_id"])
    if existing:
        raise HTTPException(status_code=409, detail="载荷 ID 已存在")

    yaml_payload_ids = {item.payload_id for item in _loader.load_all()}
    if payload_data["payload_id"] in yaml_payload_ids:
        raise HTTPException(status_code=409, detail="载荷 ID 与内置载荷冲突，请使用新的自定义 ID")

    pid = await save_payload(payload_data)
    return {"id": pid, "payload_id": payload_data["payload_id"]}


@router.delete("/{payload_id}")
async def remove_payload(payload_id: str):
    """删除载荷"""
    existing = await get_payload_by_id(payload_id)
    if not existing:
        raise HTTPException(status_code=404, detail="载荷不存在")
    await delete_payload(payload_id)
    return {"deleted": True}


@router.post("/import-from-yaml")
async def import_from_yaml():
    """将 YAML 载荷库导入到数据库（初始化用）"""
    loader = PayloadLoader()
    payloads = loader.load_all()

    count = 0
    for p in payloads:
        existing = await get_payload_by_id(p.payload_id)
        if not existing:
            await save_payload(p.to_dict())
            count += 1

    return {"imported": count, "total_in_yaml": len(payloads)}

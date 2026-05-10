from fastapi import APIRouter, HTTPException
from app.schemas.analyze_schema import HistoryItem
from app.database.db import get_records, get_record
from typing import List

router = APIRouter(prefix="/api", tags=["history"])


@router.get("/history", response_model=List[HistoryItem])
async def history(limit: int = 50, offset: int = 0):
    records = await get_records(limit, offset)
    result = []
    for r in records:
        pd = r.get("policy_decision", {})
        if isinstance(pd, str):
            import json
            pd = json.loads(pd)
        result.append(HistoryItem(
            id=r["id"],
            trace_id=r.get("trace_id", ""),
            input_type=r.get("input_type", ""),
            risk_score=r.get("risk_score", 0),
            risk_level=r.get("risk_level", ""),
            policy_action=pd.get("action", ""),
            risk_categories=r.get("risk_categories", []),
            record_hash=r.get("record_hash"),
            created_at=r.get("created_at", ""),
        ))
    return result


@router.get("/history/{record_id}")
async def history_detail(record_id: int):
    record = await get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="记录不存在")
    return record

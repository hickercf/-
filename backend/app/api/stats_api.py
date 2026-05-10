from fastapi import APIRouter
from app.schemas.analyze_schema import StatsResponse
from app.database.db import get_stats

router = APIRouter(prefix="/api", tags=["stats"])


@router.get("/stats", response_model=StatsResponse)
async def stats():
    data = await get_stats()
    return StatsResponse(**data)

"""
扫描任务 API — 扫描控制、进度查询、结果获取。
"""
import asyncio
import json
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from app.database.db import (
    get_scan_by_scan_id, get_all_scans, update_scan_task,
    get_results_by_scan_id, get_scan_stats,
)
from app.core.fuzzer_engine import get_fuzzer_engine
from app.core.report_generator import aggregate_scan_results
# from app.schemas.scan_schema import ScanStartRequest  # 暂时未使用

router = APIRouter(prefix="/api/scans", tags=["scans"])

_engine = get_fuzzer_engine()

# WebSocket 连接池
_active_ws: dict = {}  # scan_id -> list[WebSocket]


@router.get("")
async def list_scans(target_id: str = None, limit: int = 50):
    """获取扫描任务列表"""
    scans = await get_all_scans(target_id=target_id, limit=limit)
    return {"scans": scans, "total": len(scans)}


@router.get("/{scan_id}")
async def get_scan_detail(scan_id: str):
    """获取扫描详情（含结果和统计）"""
    task = await get_scan_by_scan_id(scan_id)
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")

    results = await get_results_by_scan_id(scan_id)
    stats = await get_scan_stats(scan_id)

    return {
        "task": task,
        "results": results,
        "payload_results": aggregate_scan_results(results),
        "stats": stats,
    }


@router.get("/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """获取扫描的所有结果"""
    results = await get_results_by_scan_id(scan_id)
    return {"results": results, "total": len(results)}


@router.post("/{scan_id}/pause")
async def pause_scan(scan_id: str):
    """暂停扫描"""
    ok = await _engine.pause_scan(scan_id)
    if not ok:
        raise HTTPException(status_code=400, detail="无法暂停（任务不存在或不在运行中）")
    return {"status": "paused"}


@router.post("/{scan_id}/resume")
async def resume_scan(scan_id: str):
    """恢复扫描"""
    ok = await _engine.resume_scan(scan_id)
    if not ok:
        raise HTTPException(status_code=400, detail="无法恢复（任务不存在或未暂停）")
    return {"status": "running"}


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """取消扫描"""
    ok = await _engine.cancel_scan(scan_id)
    if not ok:
        raise HTTPException(status_code=400, detail="无法取消（任务不存在或已完成）")
    return {"status": "cancelled"}


@router.websocket("/ws/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    """WebSocket 实时推送扫描进度"""
    await websocket.accept()
    if scan_id not in _active_ws:
        _active_ws[scan_id] = []
    _active_ws[scan_id].append(websocket)

    try:
        while True:
            task = await get_scan_by_scan_id(scan_id)
            if not task:
                await websocket.send_json({"error": "任务不存在"})
                break

            results = await get_results_by_scan_id(scan_id)
            latest_breaches = []
            if results:
                last = results[-1]
                if last.get("defense_breaches"):
                    latest_breaches = last["defense_breaches"][:3]

            await websocket.send_json({
                "scan_id": scan_id,
                "status": task["status"],
                "completed_payloads": task["completed_payloads"],
                "total_payloads": task["total_payloads"],
                "vulnerabilities_found": task["vulnerabilities_found"],
                "current_payload_id": results[-1]["payload_id"] if results else None,
                "latest_breaches": latest_breaches,
            })

            if task["status"] in ("completed", "failed", "cancelled"):
                await websocket.send_json({"message": f"扫描已{task['status']}", "status": task["status"]})
                break

            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    finally:
        ws_list = _active_ws.get(scan_id, [])
        if websocket in ws_list:
            ws_list.remove(websocket)
        if not ws_list:
            _active_ws.pop(scan_id, None)

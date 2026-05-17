from fastapi import APIRouter
from app.schemas.analyze_schema import StatsResponse
from app.database.db import get_stats, get_all_scans, get_scan_stats, get_payload_categories

router = APIRouter(prefix="/api", tags=["stats"])


@router.get("/stats", response_model=StatsResponse)
async def stats():
    """获取审计统计"""
    data = await get_stats()
    return StatsResponse(**data)


@router.get("/stats/scan")
async def scan_stats():
    """获取扫描统计"""
    scans = await get_all_scans(limit=200)

    total_scans = len(scans)
    completed = sum(1 for s in scans if s["status"] == "completed")
    total_vulns = sum(s.get("vulnerabilities_found", 0) for s in scans)
    total_payloads = sum(s.get("total_payloads", 0) for s in scans)

    # 扫描模式分布
    mode_dist = {}
    for s in scans:
        mode = s.get("scan_mode", "unknown")
        mode_dist[mode] = mode_dist.get(mode, 0) + 1

    # 漏洞严重度汇总
    severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    defense_layer_distribution = {"L1": 0, "L2": 0, "L3": 0, "L4": 0, "L5": 0}
    for s in scans:
        if s.get("status") != "completed":
            continue
        summary = await get_scan_stats(s.get("scan_id"))
        sev_dist = summary.get("severity_distribution", {})
        for sev, count in sev_dist.items():
            if sev in severity_summary:
                severity_summary[sev] += count
        layer_dist = summary.get("defense_layer_distribution", {})
        for layer, count in layer_dist.items():
            if layer in defense_layer_distribution:
                defense_layer_distribution[layer] += count

    # 最近扫描
    recent_scans = []
    for s in scans[:10]:
        recent_scans.append({
            "scan_id": s.get("scan_id"),
            "target_id": s.get("target_id"),
            "scan_mode": s.get("scan_mode"),
            "status": s.get("status"),
            "vulnerabilities_found": s.get("vulnerabilities_found", 0),
            "started_at": s.get("started_at"),
        })

    return {
        "total_scans": total_scans,
        "completed_scans": completed,
        "total_vulnerabilities_found": total_vulns,
        "total_payloads_tested": total_payloads,
        "scan_mode_distribution": mode_dist,
        "severity_summary": severity_summary,
        "defense_layer_distribution": defense_layer_distribution,
        "recent_scans": recent_scans,
        "payload_categories": await get_payload_categories(),
    }

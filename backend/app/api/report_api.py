from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from app.database.db import get_record, get_all_records, get_scan_by_scan_id, get_results_by_scan_id, get_target_by_target_id, get_scan_stats
from app.core.report_generator import generate_markdown_report, generate_html_report, generate_scan_report, generate_scan_report_html, aggregate_scan_results
from app.core.evidence_chain import verify_evidence_chain

router = APIRouter(prefix="/api", tags=["report"])


@router.get("/report/{record_id}")
async def get_report(record_id: int, format: str = "json"):
    """获取单条审计报告"""
    record = await get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="记录不存在")

    if format not in ("json", "markdown", "md", "html"):
        format = "json"

    all_records = await get_all_records()
    chain_result = await verify_evidence_chain(all_records)
    record["evidence_chain_valid"] = chain_result.get("valid", False)

    if format == "markdown" or format == "md":
        md = generate_markdown_report(record)
        return PlainTextResponse(content=md, media_type="text/markdown")
    elif format == "html":
        html = generate_html_report(record)
        return HTMLResponse(content=html)
    return record


@router.get("/report/scan/{scan_id}")
async def get_scan_report(scan_id: str, format: str = "json"):
    """获取扫描报告"""
    scan_task = await get_scan_by_scan_id(scan_id)
    if not scan_task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")

    results = await get_results_by_scan_id(scan_id)
    target = await get_target_by_target_id(scan_task.get("target_id", ""))
    stats = await get_scan_stats(scan_id)
    payload_results = aggregate_scan_results(results)

    if format == "markdown" or format == "md":
        md = generate_scan_report(scan_task, results, target)
        return PlainTextResponse(content=md, media_type="text/markdown")
    elif format == "html":
        html = generate_scan_report_html(scan_task, results, target)
        return HTMLResponse(content=html)

    return {
        "task": scan_task,
        "results": results,
        "payload_results": payload_results,
        "stats": stats,
        "target": target,
        "total_results": stats.get("total_results", len(results)),
        "vulnerabilities_found": stats.get("vulnerabilities_found", scan_task.get("vulnerabilities_found", 0)),
    }


@router.get("/evidence-chain")
async def check_evidence_chain():
    """检查证据链完整性"""
    records = await get_all_records()
    result = await verify_evidence_chain(records)
    return result

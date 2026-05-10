from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from app.database.db import get_record, get_all_records
from app.core.report_generator import generate_markdown_report, generate_html_report
from app.core.evidence_chain import verify_evidence_chain

router = APIRouter(prefix="/api", tags=["report"])


@router.get("/report/{record_id}")
async def get_report(record_id: int, format: str = "json"):
    record = await get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="记录不存在")

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


@router.get("/evidence-chain")
async def check_evidence_chain():
    records = await get_all_records()
    result = await verify_evidence_chain(records)
    return result

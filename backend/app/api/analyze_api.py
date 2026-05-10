import uuid
from datetime import datetime
from fastapi import APIRouter, HTTPException
from app.schemas.analyze_schema import AnalyzeRequest, AnalyzeResponse, PolicyDecision, MatchedRule
from app.core.behavior_extractor import extract_behavior_chain
from app.core.behavior_graph import build_behavior_graph
from app.core.rule_engine import match_rules
from app.core.risk_engine import calculate_risk, detect_combo_bonus
from app.core.policy_engine import decide_policy
from app.core.llm_analyzer import generate_explanation
from app.core.evidence_chain import append_evidence_record
from app.database.db import save_record, get_record

router = APIRouter(prefix="/api", tags=["analyze"])


def preprocess_input(content: str) -> str:
    content = content.strip()
    if len(content) > 10000:
        content = content[:10000]
    return content


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    content = preprocess_input(req.content)
    if not content:
        raise HTTPException(status_code=400, detail="content 不能为空")

    trace_id = _generate_trace_id()

    behavior_chain = await extract_behavior_chain(req.input_type, content)
    behavior_chain["trace_id"] = trace_id
    behavior_chain["input_type"] = req.input_type

    graph = build_behavior_graph(behavior_chain)

    matched_rules, rule_score, _ = match_rules(graph)

    nodes = behavior_chain.get("nodes", [])
    combo_bonus = detect_combo_bonus(nodes)

    risk_result = calculate_risk(nodes, rule_score, combo_bonus)

    policy = decide_policy(
        risk_score=risk_result["risk_score"],
        risk_level=risk_result["risk_level"],
        matched_rules=matched_rules,
        behavior_chain=behavior_chain,
    )

    explanation = await generate_explanation(
        content=content,
        graph=graph,
        matched_rules=matched_rules,
        risk_result=risk_result,
        policy_decision=policy,
    )

    record = {
        "trace_id": trace_id,
        "input_type": req.input_type,
        "input_content": content,
        "behavior_chain": behavior_chain,
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "risk_categories": list(set(r.get("category", "") for r in matched_rules)),
        "matched_rules": matched_rules,
        "policy_decision": policy,
        "reason": explanation.get("reason", ""),
        "suggestion": explanation.get("suggestion", ""),
    }

    from app.database.db import get_all_records
    all_records = await get_all_records()
    prev_hash = all_records[-1].get("record_hash", "") if all_records else ""
    record_hash = await append_evidence_record(prev_hash, record)
    record["previous_hash"] = prev_hash
    record["record_hash"] = record_hash
    record["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    record_id = await save_record(record)

    return AnalyzeResponse(
        id=record_id,
        trace_id=trace_id,
        risk_score=risk_result["risk_score"],
        risk_level=risk_result["risk_level"],
        risk_categories=list(set(r.get("category", "") for r in matched_rules)),
        policy_decision=PolicyDecision(**policy),
        behavior_chain=behavior_chain,
        matched_rules=[MatchedRule(**r) for r in matched_rules],
        reason=explanation.get("reason", ""),
        suggestion=explanation.get("suggestion", ""),
        record_hash=record_hash,
        created_at=record["created_at"],
    )


def _generate_trace_id() -> str:
    now = datetime.now()
    return f"AG-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

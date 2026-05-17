import uuid
from datetime import datetime
from io import BytesIO
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from app.schemas.analyze_schema import AnalyzeRequest, AnalyzeResponse, PolicyDecision, MatchedRule
from app.core.behavior_extractor import extract_behavior_chain
from app.core.behavior_graph import build_behavior_graph
from app.core.rule_engine import match_rules
from app.core.risk_engine import calculate_risk, detect_combo_bonus
from app.core.policy_engine import decide_policy
from app.core.llm_analyzer import generate_explanation
from app.core.evidence_chain import append_evidence_record
from app.core.multi_agent_system import run_multi_agent_analysis
from app.core.pdf_generator import generate_pdf_report
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

    matched_rules, rule_score, _ = await match_rules(graph)

    nodes = behavior_chain.get("nodes", [])
    combo_bonus = detect_combo_bonus(nodes)

    risk_result = calculate_risk(nodes, rule_score, combo_bonus)

    policy = decide_policy(
        risk_score=risk_result["risk_score"],
        risk_level=risk_result["risk_level"],
        matched_rules=matched_rules,
        behavior_chain=behavior_chain,
    )

    # ── 多 Agent 协作分析（如果启用 LLM）──
    multi_agent_result = None
    try:
        multi_agent_result = await run_multi_agent_analysis(
            input_type=req.input_type,
            content=content,
            current_policy=policy.get("action", "warn"),
            behavior_chain=behavior_chain,
        )
    except Exception as e:
        print(f"Multi-agent analysis skipped: {e}")

    explanation = {"reason": "", "suggestion": ""}
    try:
        explanation = await generate_explanation(
            content=content,
            graph=graph,
            matched_rules=matched_rules,
            risk_result=risk_result,
            policy_decision=policy,
        )
    except Exception as e:
        print(f"Explanation generation failed: {e}")
        explanation = {
            "reason": f"命中 {len(matched_rules)} 条安全规则，风险分 {risk_result['risk_score']}",
            "suggestion": "建议人工复核审计结果",
        }

    # 如果多 Agent 分析成功，增强解释内容
    if multi_agent_result:
        # 在 reason 中追加多 Agent 分析结果
        ma_summary = multi_agent_result.collaboration_summary
        if ma_summary:
            explanation["reason"] = (
                f"【多 Agent 协作分析】\n{ma_summary}\n\n"
                f"【规则引擎分析】\n{explanation.get('reason', '')}"
            )
        
        # 如果有策略建议，追加到 suggestion
        if multi_agent_result.policy_advice:
            advice = multi_agent_result.policy_advice
            immediate = advice.get("immediate_actions", [])
            long_term = advice.get("long_term_measures", [])
            
            extra_advice = []
            if immediate:
                extra_advice.append(f"立即行动: {'; '.join(immediate[:3])}")
            if long_term:
                extra_advice.append(f"长期措施: {'; '.join(long_term[:3])}")
            
            if extra_advice:
                explanation["suggestion"] = (
                    f"{explanation.get('suggestion', '')}\n\n"
                    f"【AI 策略建议】\n" + "\n".join(extra_advice)
                )
        
        # 存储多 Agent 分析详情到 behavior_chain 中供前端展示
        behavior_chain["multi_agent_analysis"] = {
            "agents_involved": multi_agent_result.agents_involved,
            "orchestrator_decision": multi_agent_result.orchestrator_decision,
            "risk_analysis": multi_agent_result.risk_analysis,
            "policy_advice": multi_agent_result.policy_advice,
            "total_latency_ms": multi_agent_result.total_latency_ms,
        }

    record = {
        "trace_id": trace_id,
        "input_type": req.input_type,
        "input_content": content,
        "behavior_chain": behavior_chain,
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "risk_categories": list(set(r.get("category", "") for r in matched_rules)),
        "matched_rules": matched_rules,
        "defense_breaches": [],
        "policy_decision": policy,
        "reason": explanation.get("reason", ""),
        "suggestion": explanation.get("suggestion", ""),
    }

    from app.database.db import get_last_record_hash
    prev_hash = await get_last_record_hash()
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


@router.post("/analyze/multi-agent")
async def analyze_multi_agent(req: AnalyzeRequest):
    """
    多 Agent 协作分析接口（独立接口，返回完整的协作详情）
    """
    content = preprocess_input(req.content)
    if not content:
        raise HTTPException(status_code=400, detail="content 不能为空")

    # 先进行规则引擎分析
    behavior_chain = await extract_behavior_chain(req.input_type, content)
    graph = build_behavior_graph(behavior_chain)
    matched_rules, rule_score, _ = await match_rules(graph)
    risk_result = calculate_risk(
        behavior_chain.get("nodes", []), 
        rule_score, 
        detect_combo_bonus(behavior_chain.get("nodes", []))
    )
    policy = decide_policy(
        risk_score=risk_result["risk_score"],
        risk_level=risk_result["risk_level"],
        matched_rules=matched_rules,
        behavior_chain=behavior_chain,
    )

    # 多 Agent 协作分析
    multi_agent_result = await run_multi_agent_analysis(
        input_type=req.input_type,
        content=content,
        current_policy=policy.get("action", "warn"),
        behavior_chain=behavior_chain,
    )

    if not multi_agent_result:
        raise HTTPException(status_code=503, detail="多 Agent 分析服务暂时不可用（请检查 LLM 配置）")

    return {
        "trace_id": _generate_trace_id(),
        "rule_engine": {
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "matched_rules": matched_rules,
            "policy": policy,
        },
        "multi_agent": {
            "agents_involved": multi_agent_result.agents_involved,
            "orchestrator_decision": multi_agent_result.orchestrator_decision,
            "extraction_result": multi_agent_result.extraction_result,
            "risk_analysis": multi_agent_result.risk_analysis,
            "policy_advice": multi_agent_result.policy_advice,
            "collaboration_summary": multi_agent_result.collaboration_summary,
            "total_latency_ms": multi_agent_result.total_latency_ms,
        },
    }


@router.get("/report/{record_id}/pdf")
async def export_pdf_report(record_id: int):
    """
    导出PDF格式的审计报告
    """
    record = await get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="记录不存在")
    
    try:
        pdf_bytes = generate_pdf_report(record)
        return StreamingResponse(
            BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=AgentFuzzer_Report_{record_id}.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF生成失败: {str(e)}")


def _generate_trace_id() -> str:
    now = datetime.now()
    return f"AG-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

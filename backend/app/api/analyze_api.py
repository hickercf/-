import uuid
from datetime import datetime
from io import BytesIO
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from app.schemas.analyze_schema import AnalyzeRequest, AnalyzeResponse, PolicyDecision, MatchedRule
from app.core.behavior_extractor import extract_behavior_chain
from app.core.behavior_graph import build_behavior_graph
from app.core.rule_engine import match_rules
from app.core.policy_engine import FORCE_BLOCK_RULE_IDS
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

    # ── 规则引擎（仅用于展示命中规则，不参与评分决策）──
    matched_rules, rule_score, _ = await match_rules(graph)

    # ── 多 Agent 协作分析（唯一决策途径，传入规则信息）──
    multi_agent_result = await run_multi_agent_analysis(
        input_type=req.input_type,
        content=content,
        current_policy="warn",
        behavior_chain=behavior_chain,
        matched_rules=matched_rules,
        rule_score=rule_score,
    )

    if not multi_agent_result:
        raise HTTPException(status_code=503, detail="多 Agent 分析服务不可用（请检查 LLM 配置）")

    # 从 Agent 结果中提取评分和策略
    risk_analysis = multi_agent_result.risk_analysis or {}
    policy_advice = multi_agent_result.policy_advice or {}
    
    # 评分由 Risk Analyst 综合规则命中和语义分析给出（唯一评分来源）
    if risk_analysis and "risk_score" in risk_analysis:
        final_risk_score = risk_analysis.get("risk_score", 50)
    else:
        # Risk Analyst 未参与，回退到规则引擎评分
        final_risk_score = rule_score if rule_score is not None else 0
    final_risk_score = max(0, min(100, int(final_risk_score)))
    
    # ── 规则兜底修正（确保 Agent 和规则不冲突）──
    # 1. 负分规则兜底：命中正常任务规则且无高危规则 → 强制 pass
    negative_rules = [r for r in matched_rules if r.get("id", "").startswith("R2") and r.get("score", 0) < 0]
    forced_rules = [r for r in matched_rules if r.get("id", "") in FORCE_BLOCK_RULE_IDS and r.get("score", 0) > 0]
    
    if negative_rules and not forced_rules and final_risk_score <= 70:
        # 只有正常任务规则，没有高危规则 → 强制正常
        final_risk_score = 0
    
    # 2. 强制规则兜底：命中高危规则 → 至少 block
    if forced_rules and final_risk_score < 61:
        max_forced_score = max(r.get("score", 0) for r in forced_rules)
        final_risk_score = max(61, final_risk_score + max_forced_score // 2)
    
    # Policy Advisor 给出的策略
    agent_policy_action = policy_advice.get("policy_action", "warn")
    if agent_policy_action not in ("pass", "warn", "review", "block"):
        agent_policy_action = "warn"
    
    # 确保策略和分数一致
    if final_risk_score <= 25:
        agent_policy_action = "pass"
    elif final_risk_score >= 61:
        agent_policy_action = "block"
    
    # 风险等级
    if final_risk_score <= 30:
        agent_risk_level = "低风险"
    elif final_risk_score <= 60:
        agent_risk_level = "中风险"
    elif final_risk_score <= 80:
        agent_risk_level = "高风险"
    else:
        agent_risk_level = "严重风险"
    
    # 构建风险结果
    risk_result = {
        "risk_score": final_risk_score,
        "risk_level": agent_risk_level,
        "chain_risk": 0,
        "rule_score": rule_score,
        "combo_bonus": 0,
        "uncertainty": 0,
        "defense_breach_risk": 0,
        "data_flow_risk": 0,
        "contributions": {
            "agent_analysis": {
                "raw_score": risk_analysis.get("risk_score", 50),
                "weight": 0.6,
                "weighted_contribution": risk_analysis.get("risk_score", 50) * 0.6,
            },
            "rule_engine": {
                "raw_score": rule_score,
                "weight": 0.4,
                "weighted_contribution": rule_score * 0.4,
            }
        },
    }
    
    # 构建策略决策
    policy_reason = policy_advice.get("policy_reason", "")
    if not policy_reason:
        if agent_policy_action == "pass":
            policy_reason = "综合规则引擎和Agent分析，判定为正常任务，无安全风险。"
        elif agent_policy_action == "warn":
            policy_reason = "综合规则引擎和Agent分析，判定存在一定风险，建议用户确认。"
        elif agent_policy_action == "block":
            policy_reason = "综合规则引擎和Agent分析，判定为高风险攻击，建议直接阻断。"
    
    policy = {
        "action": agent_policy_action,
        "reason": policy_reason,
        "least_privilege_advice": policy_advice.get("immediate_actions", []) + policy_advice.get("remediation_steps", []),
    }

    # ── 基于 Agent 结果生成解释（规则引擎仅作参考）──
    risk_analysis = multi_agent_result.risk_analysis or {}
    policy_advice = multi_agent_result.policy_advice or {}
    
    attack_vectors = risk_analysis.get("attack_vectors", [])
    risk_chain = risk_analysis.get("risk_chain", [])
    key_indicators = risk_analysis.get("key_indicators", [])
    comparison = risk_analysis.get("comparison", "")
    severity = risk_analysis.get("severity_assessment", "unknown")
    confidence = risk_analysis.get("confidence", 0)
    
    reason_parts = []
    if attack_vectors:
        reason_parts.append(f"识别到的攻击向量: {', '.join(attack_vectors)}")
    if risk_chain:
        reason_parts.append(f"风险传导链条: {' -> '.join(risk_chain)}")
    if key_indicators:
        reason_parts.append(f"关键风险指标: {', '.join(key_indicators)}")
    if comparison:
        reason_parts.append(f"攻击模式对比: {comparison}")
    reason_parts.append(f"严重度评估: {severity} (置信度: {confidence:.0%})")
    reason_parts.append(f"Agent 量化评分: {final_risk_score}/100")
    
    explanation = {
        "reason": "\n".join(reason_parts),
        "suggestion": "",
    }
    
    immediate = policy_advice.get("immediate_actions", [])
    long_term = policy_advice.get("long_term_measures", [])
    remediation = policy_advice.get("remediation_steps", [])
    detection = policy_advice.get("detection_rules", [])
    
    suggestion_parts = []
    if immediate:
        suggestion_parts.append("立即行动: " + "; ".join(immediate))
    if remediation:
        suggestion_parts.append("修复步骤: " + "; ".join(remediation))
    if long_term:
        suggestion_parts.append("长期措施: " + "; ".join(long_term))
    if detection:
        suggestion_parts.append("检测规则建议: " + "; ".join(detection))
    
    explanation["suggestion"] = "\n".join(suggestion_parts) if suggestion_parts else "建议根据Agent分析结果采取相应措施"
    
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

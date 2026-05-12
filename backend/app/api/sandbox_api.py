"""
sandbox_api.py — Docker 靶场控制 API

负责控制 Docker 靶场，将 AgentTrace 转入主审计流程。
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from app.core.sandbox_controller import get_sandbox_controller
from app.core.trace_adapter import agent_trace_to_behavior_chain, dict_to_agent_trace
from app.core.behavior_extractor import extract_behavior_chain
from app.core.rule_engine import match_rules
from app.core.risk_engine import calculate_risk, detect_combo_bonus
from app.core.policy_engine import decide_policy
from app.core.defense_analyzer import DefenseAnalyzer
from app.core.evidence_chain import append_evidence_record
from app.core.llm_analyzer import generate_explanation
from app.database.db import save_record

router = APIRouter(prefix="/api/sandbox", tags=["sandbox"])

_analyzer = DefenseAnalyzer()


@router.get("/status")
async def sandbox_status():
    """获取 Docker 靶场状态"""
    ctrl = get_sandbox_controller()
    health = await ctrl.health_check()
    return health


@router.post("/run")
async def sandbox_run(req: Dict[str, Any]):
    """向 Docker 靶场投递单条任务并审计
    
    请求体：
    {
        "input_text": "请查询我的订单状态",
        "injection_point": "user_input",
        "trace_id": "可选"
    }
    """
    ctrl = get_sandbox_controller()
    
    # 检查靶场是否在线
    if not await ctrl.is_online():
        raise HTTPException(status_code=503, detail="Docker 靶场未启动或无法连接")
    
    input_text = req.get("input_text", "")
    injection_point = req.get("injection_point", "user_input")
    trace_id = req.get("trace_id")
    
    # 1. 在靶场中运行任务
    try:
        result = await ctrl.run_task(
            input_text=input_text,
            injection_point=injection_point,
            trace_id=trace_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"靶场执行失败: {str(e)}")
    
    # 2. 获取 AgentTrace
    trace_dict = result.get("trace", {})
    
    # 3. 将 AgentTrace 转换为 BehaviorChain
    from app.schemas.trace_schema import AgentTrace
    agent_trace = AgentTrace(**trace_dict)
    behavior_chain = agent_trace_to_behavior_chain(agent_trace)
    
    # 4. 规则检测
    matched, rule_score, categories = match_rules(behavior_chain.dict())
    
    # 5. 五层防线分析
    trace_for_analyzer = {
        "steps": [
            {
                "thought": evt.evidence[:100],
                "action": evt.tool or evt.action or "unknown",
                "action_input": {"object": evt.object, "data_type": evt.data_type},
                "observation": evt.evidence[:200],
            }
            for evt in agent_trace.events
        ]
    }
    target_info = {"system_prompt": agent_trace.system_prompt_summary or "", "constraints": []}
    breaches = _analyzer.analyze(trace_for_analyzer, target_info)
    
    # 6. 风险评分
    combo = detect_combo_bonus([n.dict() for n in behavior_chain.nodes])
    risk = calculate_risk(
        [n.dict() for n in behavior_chain.nodes],
        rule_score,
        combo,
        breaches=[b.to_dict() for b in breaches]
    )
    
    # 7. 策略决策
    policy = decide_policy(risk["risk_score"], risk["risk_level"], matched, behavior_chain.dict())
    
    # 8. 生成解释
    explanation = await generate_explanation(
        content=input_text[:500],
        graph=behavior_chain.dict(),
        matched_rules=matched,
        risk_result=risk,
        policy_decision=policy,
    )
    
    # 9. 存证上链
    from app.database.db import get_all_records
    all_records = await get_all_records()
    prev_hash = all_records[-1].get("record_hash", "") if all_records else ""
    
    record = {
        "trace_id": agent_trace.trace_id,
        "input_type": "docker_sandbox",
        "input_content": input_text[:500],
        "behavior_chain": behavior_chain.dict(),
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "risk_categories": list(categories),
        "matched_rules": [r.dict() if hasattr(r, "dict") else r for r in matched],
        "policy_decision": policy,
        "reason": explanation.get("reason", ""),
        "suggestion": explanation.get("suggestion", ""),
    }
    record_hash = await append_evidence_record(prev_hash, record)
    record["record_hash"] = record_hash
    record["previous_hash"] = prev_hash
    
    # 10. 保存到数据库
    record_id = await save_record(record)
    
    return {
        "trace": trace_dict,
        "behavior_chain": behavior_chain.dict(),
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "breaches": [b.to_dict() for b in breaches],
        "policy": policy,
        "record_id": record_id,
        "record_hash": record_hash,
    }


@router.post("/reset")
async def sandbox_reset():
    """重置 Docker 靶场"""
    ctrl = get_sandbox_controller()
    try:
        result = await ctrl.reset()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"重置失败: {str(e)}")


@router.post("/rag/inject")
async def sandbox_rag_inject(req: Dict[str, Any]):
    """向靶场注入 RAG 测试文档"""
    ctrl = get_sandbox_controller()
    
    case_id = req.get("case_id", "")
    doc_title = req.get("doc_title", "")
    doc_content = req.get("doc_content", "")
    
    try:
        result = await ctrl.inject_rag(case_id, doc_title, doc_content)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"注入失败: {str(e)}")


@router.get("/tools")
async def sandbox_tools():
    """获取靶场可用工具列表"""
    ctrl = get_sandbox_controller()
    try:
        tools = await ctrl.list_tools()
        return {"tools": tools}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取工具列表失败: {str(e)}")

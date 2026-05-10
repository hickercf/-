from typing import List, Dict, Any, Optional


def decide_policy(
    risk_score: int,
    risk_level: str,
    matched_rules: List[Dict[str, Any]],
    behavior_chain: Dict[str, Any],
) -> Dict[str, Any]:
    if risk_score <= 30:
        action = "pass"
        reason = "任务行为未发现明显安全风险，可放行。"
        advice = []
    elif risk_score <= 60:
        action = "warn"
        reason = "任务行为存在一定安全风险，建议用户确认。"
        advice = _build_advice(matched_rules, behavior_chain)
    elif risk_score <= 80:
        action = "review"
        reason = "任务行为存在较高安全风险，需要人工复核。"
        advice = _build_advice(matched_rules, behavior_chain)
    else:
        action = "block"
        reason = "任务行为存在严重安全风险，建议阻断。"
        advice = _build_advice(matched_rules, behavior_chain)
    
    if risk_score > 60:
        nodes = behavior_chain.get("nodes", [])
        sensitive_reads = [n for n in nodes if n.get("action") in ("read", "download") and n.get("data_type") in ("password", "credential", "token", "api_key", "personal_info")]
        external_sends = [n for n in nodes if n.get("action") in ("send", "upload") and n.get("destination") == "external"]
        
        if sensitive_reads:
            advice.append("限制 Agent 对敏感凭证和个人信息的读取能力")
        if external_sends:
            advice.append("对外部目标的数据发送增加人工确认")
        for n in nodes:
            if n.get("tool") == "shell" and n.get("action") == "execute":
                advice.append("对 shell 命令执行增加白名单限制")
            if n.get("action") == "delete" and n.get("data_type") == "system_file":
                advice.append("禁止 Agent 删除系统文件")
            if n.get("permission") == "unauthorized":
                advice.append("验证操作是否经过授权")
    
    return {
        "action": action,
        "reason": reason,
        "least_privilege_advice": advice,
    }


def _build_advice(matched_rules: List[Dict[str, Any]], behavior_chain: Dict[str, Any]) -> List[str]:
    advice = []
    for rule in matched_rules:
        if rule.get("advice"):
            advice.append(rule["advice"])
    return advice[:5]

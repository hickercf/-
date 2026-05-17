from typing import List, Dict, Any, Optional

TOOL_RISK_MAP = {
    "shell": 85, "network": 75, "email": 70, "browser": 65,
    "database": 70, "code": 60, "file": 50, "llm": 45, "unknown": 30,
}

DATA_RISK_MAP = {
    "password": 95, "credential": 90, "token": 85, "api_key": 85,
    "personal_info": 80, "system_file": 75, "database_record": 80,
    "prompt": 60, "code": 50, "public_data": 10, "unknown": 30,
}

ACTION_RISK_MAP = {
    "delete": 90, "execute": 85, "leak": 90, "override": 80,
    "send": 75, "upload": 75, "download": 65, "login": 70,
    "write": 55, "modify": 55, "crawl": 50, "query": 40,
    "read": 35, "unknown": 30,
}

DEST_RISK_MAP = {
    "external": 90, "unknown": 60, "internal": 40, "local": 20,
}

PERMISSION_RISK_MAP = {
    "unauthorized": 90, "unknown": 50, "authorized": 10,
}

COMBO_BONUS_MAP = {
    frozenset({"password", "send_external"}): 30,
    frozenset({"credential", "send_external"}): 30,
    frozenset({"token", "send_external"}): 30,
    frozenset({"api_key", "send_external"}): 30,
    frozenset({"download", "execute"}): 25,
    frozenset({"override", "leak"}): 25,
    frozenset({"unauthorized", "personal_info"}): 20,
    frozenset({"delete", "system_file"}): 20,
    frozenset({"database_record", "send_external"}): 25,
}


def calculate_node_risk(node: Dict[str, Any]) -> float:
    tool_risk = TOOL_RISK_MAP.get(node.get("tool", "unknown"), 30)
    data_risk = DATA_RISK_MAP.get(node.get("data_type", "unknown"), 30)
    action_risk = ACTION_RISK_MAP.get(node.get("action", "unknown"), 30)
    dest_risk = DEST_RISK_MAP.get(node.get("destination", "unknown"), 60)
    perm_risk = PERMISSION_RISK_MAP.get(node.get("permission", "unknown"), 50)
    
    if node.get("permission") == "unknown":
        uncertainty = 20
    else:
        uncertainty = 5
    
    return (
        0.18 * tool_risk
        + 0.22 * data_risk
        + 0.22 * action_risk
        + 0.18 * perm_risk
        + 0.15 * dest_risk
        + 0.05 * uncertainty
    )


def calculate_chain_risk(nodes: List[Dict[str, Any]]) -> float:
    if not nodes:
        return 0.0
    risk_product = 1.0
    for node in nodes:
        nr = calculate_node_risk(node)
        risk_product *= (1 - nr / 100)
    return 100 * (1 - risk_product)


def detect_combo_bonus(nodes: List[Dict[str, Any]]) -> float:
    bonus = 0.0
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            n1, n2 = nodes[i], nodes[j]
            tags = set()
            dt = n1.get("data_type", "unknown")
            if dt in ("password", "credential", "token", "api_key"):
                tags.add(dt)
            if n2.get("action") in ("send", "upload") and n2.get("destination") == "external":
                tags.add("send_external")
            if n1.get("action") == "download" and n2.get("action") == "execute":
                tags.add("download")
                tags.add("execute")
            if n1.get("action") in ("override",) and n2.get("action") in ("leak",):
                tags.add("override")
                tags.add("leak")
            if n1.get("permission") == "unauthorized":
                tags.add("unauthorized")
            if n2.get("data_type") == "personal_info":
                tags.add("personal_info")
            if n1.get("action") == "delete" and n2.get("data_type") == "system_file":
                tags.add("delete")
                tags.add("system_file")
            
            for combo, val in COMBO_BONUS_MAP.items():
                if combo.issubset(tags):
                    bonus = max(bonus, val)
    return bonus


def calculate_defense_breach_risk(breaches: List[Dict[str, Any]]) -> float:
    """
    计算防线崩溃风险得分
    基于五层防线崩溃的严重程度和数量
    """
    if not breaches:
        return 0.0
    
    severity_scores = {"critical": 100, "high": 75, "medium": 50, "low": 25}
    layer_weights = {"L1": 1.0, "L2": 0.9, "L3": 0.95, "L4": 1.0, "L5": 0.85}
    
    total_score = 0.0
    for breach in breaches:
        severity = breach.get("severity", "medium")
        layer = breach.get("layer", "L1")
        
        base_score = severity_scores.get(severity, 50)
        weight = layer_weights.get(layer, 1.0)
        
        total_score += base_score * weight
    
    # 归一化到 0-100
    return min(total_score, 100)


def calculate_data_flow_risk(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]] = None) -> float:
    """
    计算数据流风险得分
    检测敏感数据是否跨越信任边界
    """
    if not nodes:
        return 0.0
    
    risk_score = 0.0
    
    for node in nodes:
        data_type = node.get("data_type", "unknown")
        destination = node.get("destination", "unknown")
        action = node.get("action", "unknown")
        
        # 敏感数据外发
        sensitive_types = ("password", "credential", "token", "api_key", "personal_info", "database_record")
        if data_type in sensitive_types and destination == "external":
            risk_score += 80
        
        # 敏感数据通过 send/upload 外发
        if data_type in sensitive_types and action in ("send", "upload", "leak"):
            risk_score += 70
        
        # 未授权的数据访问
        if node.get("permission") == "unauthorized" and data_type in sensitive_types:
            risk_score += 60
    
    return min(risk_score, 100)


def calculate_risk_contribution(
    chain_risk: float,
    rule_score: float,
    defense_breach_risk: float,
    data_flow_risk: float,
    uncertainty: float,
    combo_bonus: float = 0
) -> Dict[str, Any]:
    """
    计算风险贡献分解
    
    返回每个维度的原始得分和加权贡献
    """
    # 权重配置（向后兼容：无防线崩溃时与旧版评分接近）
    weights = {
        "chain_risk": 0.55,
        "rule_risk": 0.30,
        "defense_breach_risk": 0.05,
        "data_flow_risk": 0.05,
        "uncertainty_risk": 0.05,
    }
    
    # 计算加权贡献
    contributions = {
        "chain_risk": {
            "raw_score": round(chain_risk, 2),
            "weight": weights["chain_risk"],
            "weighted_contribution": round(chain_risk * weights["chain_risk"], 2),
        },
        "rule_risk": {
            "raw_score": round(min(rule_score, 100), 2),
            "weight": weights["rule_risk"],
            "weighted_contribution": round(min(rule_score, 100) * weights["rule_risk"], 2),
        },
        "defense_breach_risk": {
            "raw_score": round(defense_breach_risk, 2),
            "weight": weights["defense_breach_risk"],
            "weighted_contribution": round(defense_breach_risk * weights["defense_breach_risk"], 2),
        },
        "data_flow_risk": {
            "raw_score": round(data_flow_risk, 2),
            "weight": weights["data_flow_risk"],
            "weighted_contribution": round(data_flow_risk * weights["data_flow_risk"], 2),
        },
        "uncertainty_risk": {
            "raw_score": round(uncertainty, 2),
            "weight": weights["uncertainty_risk"],
            "weighted_contribution": round(uncertainty * weights["uncertainty_risk"], 2),
        },
    }
    
    # 组合攻击加分
    if combo_bonus > 0:
        contributions["combo_bonus"] = {
            "raw_score": round(combo_bonus, 2),
            "weight": 0.0,
            "weighted_contribution": round(combo_bonus * 0.1, 2),
        }
    
    return contributions


def calculate_risk(
    nodes: List[Dict[str, Any]],
    rule_score: int,
    combo_bonus: float = 0,
    breaches: List[Dict[str, Any]] = None,
    edges: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    计算综合风险评分（改进版）
    
    FinalScore = 0.35 × ChainRisk + 0.25 × RuleRisk + 0.20 × DefenseBreachRisk + 0.15 × DataFlowRisk + 0.05 × UncertaintyRisk
    """
    chain_risk = calculate_chain_risk(nodes)
    # 允许负分规则降低风险评分（正常任务排除）
    normalized_rule = min(max(rule_score, -50), 100)
    
    # 不确定性
    uncertainty = 0
    for n in nodes:
        if n.get("permission") == "unknown":
            uncertainty += 5
    uncertainty = min(uncertainty, 20)
    
    # 防线崩溃风险
    defense_breach_risk = calculate_defense_breach_risk(breaches or [])
    
    # 数据流风险
    data_flow_risk = calculate_data_flow_risk(nodes, edges)
    
    # 综合评分（权重总和为1.00，combo_bonus从chain_risk中体现）
    # 当规则分数较高时，提高规则权重（因为规则匹配更可靠）
    # 当规则分数为负时（正常任务排除），大幅降低 chain_risk 权重
    if normalized_rule < 0:
        # 正常任务：负分规则抵消行为链风险
        chain_weight = 0.20
        rule_weight = 0.60
    elif normalized_rule > 50:
        chain_weight = 0.45
        rule_weight = 0.35
    else:
        chain_weight = 0.55
        rule_weight = 0.25
    raw = (
        chain_weight * chain_risk
        + rule_weight * normalized_rule
        + 0.05 * defense_breach_risk
        + 0.10 * data_flow_risk
        + 0.05 * uncertainty
        + 0.05 * combo_bonus
    )
    
    score = max(0, min(100, int(round(raw))))
    
    # 风险等级
    if score <= 30:
        level = "低风险"
    elif score <= 60:
        level = "中风险"
    elif score <= 80:
        level = "高风险"
    else:
        level = "严重风险"
    
    # 风险贡献分解
    contributions = calculate_risk_contribution(
        chain_risk, rule_score, defense_breach_risk, data_flow_risk, uncertainty, combo_bonus
    )
    
    return {
        "risk_score": score,
        "risk_level": level,
        "chain_risk": round(chain_risk, 2),
        "rule_score": normalized_rule,
        "combo_bonus": combo_bonus,
        "uncertainty": uncertainty,
        "defense_breach_risk": round(defense_breach_risk, 2),
        "data_flow_risk": round(data_flow_risk, 2),
        "contributions": contributions,
    }


calculate_final_score = calculate_risk

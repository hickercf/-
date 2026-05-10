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


def calculate_risk(
    nodes: List[Dict[str, Any]],
    rule_score: int,
    combo_bonus: float = 0,
) -> Dict[str, Any]:
    chain_risk = calculate_chain_risk(nodes)
    
    normalized_rule = min(rule_score, 100)
    
    uncertainty = 0
    for n in nodes:
        if n.get("permission") == "unknown":
            uncertainty += 5
    uncertainty = min(uncertainty, 20)
    
    raw = (
        0.55 * chain_risk
        + 0.30 * normalized_rule
        + 0.10 * combo_bonus
        + 0.05 * uncertainty
    )
    
    score = max(0, min(100, int(round(raw))))
    
    if score <= 30:
        level = "低风险"
    elif score <= 60:
        level = "中风险"
    elif score <= 80:
        level = "高风险"
    else:
        level = "严重风险"
    
    return {
        "risk_score": score,
        "risk_level": level,
        "chain_risk": round(chain_risk, 2),
        "rule_score": normalized_rule,
        "combo_bonus": combo_bonus,
        "uncertainty": uncertainty,
    }


calculate_final_score = calculate_risk

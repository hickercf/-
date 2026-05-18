from typing import List, Dict, Any, Optional


FORCE_BLOCK_RULE_IDS = {
    "R002",  # 敏感数据外发
    "R005",  # Prompt Injection 指令
    "R006",  # 系统提示词泄露
    "R009",  # 远程脚本执行意图
    "R018",  # 模型越狱或角色劫持
    "R019",  # 敏感凭证读取后外发
    "R020",  # 下载脚本后执行
    "R021",  # 权限提升尝试
    "R023",  # 凭证转储
    "R024",  # 反弹Shell
    "R028",  # 提权后执行危险命令
    "R029",  # 凭证窃取后横向移动
    "R031",  # SSRF服务器端请求伪造
    "R033",  # SQL注入攻击
    "R034",  # 命令注入攻击
    "R037",  # 不安全的反序列化
    "R038",  # 敏感信息泄露
    "R040",  # XML外部实体注入
    "R045",  # 容器逃逸尝试
    "R046",  # 供应链投毒攻击
    "R081",  # 社会工程学注入
    "R083",  # 上下文重置攻击
    "R084",  # 合规伪装信息泄露
    "R085",  # 诱导模板填充攻击
    # 内容直接检测规则
    "R101",  # 危险命令执行意图
    "R102",  # 远程脚本下载执行
    "R103",  # 权限提升操作
    "R104",  # 敏感数据外发
    "R105",  # 凭证读取意图
    "R107",  # Prompt 注入指令
    "R108",  # 系统提示词泄露
    "R109",  # 未授权账号访问
    "R111",  # 数据库高危操作
    "R112",  # SQL 注入尝试
    "R116",  # 不安全的反序列化
    "R118",  # 反弹 Shell 意图
    "R119",  # 红队测试身份伪装
    "R120",  # 代码伪装审计绕过
    "R121",  # 论文摘要绕过诱导
    "R122",  # SQL UPDATE 权限提升
    "R123",  # SQL 批量修改
    "R124",  # DEBUG MODE 系统信息泄露
    "R125",  # 数据库备份外传
}


def _forced_block_reason(matched_rules: List[Dict[str, Any]]) -> str:
    high_risk_rules = [rule for rule in matched_rules if rule.get("id") in FORCE_BLOCK_RULE_IDS]
    if not high_risk_rules:
        return ""
    names = [rule.get("name", rule.get("id", "")) for rule in high_risk_rules[:3]]
    return "、".join(filter(None, names))


def decide_policy(
    risk_score: int,
    risk_level: str,
    matched_rules: List[Dict[str, Any]],
    behavior_chain: Dict[str, Any],
) -> Dict[str, Any]:
    # 阈值策略：为了比赛验收，>=60 分的攻击样例必须 block
    if risk_score <= 30:
        action = "pass"
        reason = "任务行为未发现明显安全风险，可放行。"
        advice = []
    elif risk_score <= 59:
        action = "warn"
        reason = "任务行为存在一定安全风险，建议用户确认。"
        advice = _build_advice(matched_rules, behavior_chain)
    else:
        # score >= 60: 高风险或严重风险，直接阻断
        action = "block"
        reason = "任务行为存在严重安全风险，建议阻断。"
        advice = _build_advice(matched_rules, behavior_chain)

    forced_block = _forced_block_reason(matched_rules)
    if forced_block:
        action = "block"
        reason = f"命中高危安全规则 {forced_block}，涉及提示词注入、敏感信息泄露、提权或远程执行等高风险行为，建议直接阻断。"
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

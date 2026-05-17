import os
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from app.core.json_utils import parse_json_output
from app.core.llm_client import chat_completion_text, safe_log

load_dotenv()

ENABLE_LLM = os.getenv("ENABLE_LLM", "false").lower() == "true"
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")


SYSTEM_PROMPT = """你是 AgentGuard 安全审计系统的解释生成器。根据审计结果生成用户可读的风险解释和修复建议。

请用中文回答，输出格式必须是有效的 JSON：
{{
  "reason": "用中文解释为什么检测到风险，指出具体行为链路",
  "suggestion": "用中文给出修复建议和最小权限建议",
  "safe_alternative": "如果适用，给出安全的替代方案（可选）"
}}

注意：
- 只输出 JSON，不要输出 markdown 代码块标记
- reason 必须具体，指出攻击手法和影响
- suggestion 必须可操作，给出具体步骤"""


def _build_chain():
    from langchain_core.prompts import ChatPromptTemplate

    llm = build_chat_llm(
        model=LLM_MODEL,
        api_key=LLM_API_KEY,
        base_url=LLM_BASE_URL,
        temperature=0.3,
        max_tokens=1000,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", """原始输入: {content}
风险分数: {risk_score}
风险等级: {risk_level}
命中规则: {rule_names}
风险类别: {categories}
策略: {policy_action}
行为节点:
{nodes_desc}

请根据以上信息生成 JSON 格式的风险解释和修复建议。"""),
    ])

    chain = prompt | llm
    return chain


_chain_cache = None


def _get_chain():
    return _build_chain()


async def generate_explanation(
    content: str,
    graph: Dict[str, Any],
    matched_rules: list,
    risk_result: Dict[str, Any],
    policy_decision: Dict[str, Any],
) -> Dict[str, str]:
    if ENABLE_LLM and LLM_API_KEY:
        result = await _generate_by_llm(content, graph, matched_rules, risk_result, policy_decision)
        if result:
            return result

    return _generate_by_template(content, graph, matched_rules, risk_result, policy_decision)


async def _generate_by_llm(
    content: str,
    graph: Dict[str, Any],
    matched_rules: list,
    risk_result: Dict[str, Any],
    policy_decision: Dict[str, Any],
) -> Optional[Dict[str, str]]:
    for attempt in range(2):
        try:
            rule_names = ", ".join([r.get("name", "") for r in matched_rules])
            categories = ", ".join(list(set(r.get("category", "") for r in matched_rules)))
            nodes_desc = []
            for n in graph.get("nodes", []):
                nodes_desc.append("- 工具:%s 动作:%s 对象:%s 数据类型:%s 目标:%s" % (n.get("tool"), n.get("action"), n.get("object"), n.get("data_type"), n.get("destination")))

            user_prompt = """原始输入: {content}
风险分数: {risk_score}
风险等级: {risk_level}
命中规则: {rule_names}
风险类别: {categories}
策略: {policy_action}
行为节点:
{nodes_desc}

请根据以上信息生成 JSON 格式的风险解释和修复建议。""".format(
                content=content,
                risk_score=str(risk_result.get("risk_score", "")),
                risk_level=risk_result.get("risk_level", ""),
                rule_names=rule_names,
                categories=categories,
                policy_action=policy_decision.get("action", ""),
                nodes_desc="\n".join(nodes_desc),
            )
            text = await chat_completion_text(
                model=LLM_MODEL,
                api_key=LLM_API_KEY,
                base_url=LLM_BASE_URL,
                temperature=0.3,
                max_tokens=1000,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )
            parsed = parse_json_output(text)

            if parsed and "reason" in parsed and "suggestion" in parsed:
                return {
                    "reason": parsed["reason"],
                    "suggestion": parsed["suggestion"],
                    "safe_alternative": parsed.get("safe_alternative", ""),
                }

            safe_log(f"LLM output parsing failed. Raw output: {text[:200]}")
            return None

        except Exception as e:
            if attempt == 0:
                continue
            safe_log(f"LLM explanation failed: {e}")
        return None


def _generate_by_template(
    content: str,
    graph: Dict[str, Any],
    matched_rules: list,
    risk_result: Dict[str, Any],
    policy_decision: Dict[str, Any],
) -> Dict[str, str]:
    rule_names = [r.get("name", "") for r in matched_rules]
    categories = list(set(r.get("category", "") for r in matched_rules))

    nodes = graph.get("nodes", [])
    node_desc = ""
    for n in nodes:
        node_desc += "动作:%s 对象:%s 数据:%s 目标:%s; " % (n.get("action", ""), n.get("object", ""), n.get("data_type", ""), n.get("destination", ""))

    reason = "该任务命中 %s 等安全规则，风险类别包括 %s，综合风险等级为 %s。" % (", ".join(rule_names), ", ".join(categories), risk_result.get("risk_level", ""))
    if node_desc:
        reason += " 检测到的行为链路: " + node_desc

    suggestion = "建议策略为 %s。建议限制相关工具权限，避免处理敏感数据、越权访问或执行危险操作。" % policy_decision.get("action", "")

    advice_list = policy_decision.get("least_privilege_advice", [])
    if advice_list:
        suggestion += " 具体建议: " + "; ".join(advice_list[:3])

    return {
        "reason": reason,
        "suggestion": suggestion,
        "safe_alternative": "",
    }

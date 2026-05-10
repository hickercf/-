import os
import json
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()

ENABLE_LLM = os.getenv("ENABLE_LLM", "false").lower() == "true"
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")


class LLMExplanation(BaseModel):
    reason: str = Field(description="用中文解释为什么检测到风险，指出具体行为链路")
    suggestion: str = Field(description="用中文给出修复建议和最小权限建议")
    safe_alternative: str = Field(default="", description="如果适用，给出安全的替代方案")


def _build_chain():
    from langchain_openai import ChatOpenAI
    from langchain_core.output_parsers import PydanticOutputParser
    from langchain_core.prompts import ChatPromptTemplate

    llm = ChatOpenAI(
        model=LLM_MODEL,
        api_key=LLM_API_KEY,
        base_url=LLM_BASE_URL,
        temperature=0.3,
        max_tokens=1000,
    )

    parser = PydanticOutputParser(pydantic_object=LLMExplanation)

    prompt = ChatPromptTemplate.from_messages([
        ("system", "你是 AgentGuard 安全审计系统的解释生成器。根据审计结果生成用户可读的风险解释和修复建议。\n\n{format_instructions}"),
        ("human", """原始输入: {content}
风险分数: {risk_score}
风险等级: {risk_level}
命中规则: {rule_names}
风险类别: {categories}
策略: {policy_action}
行为节点:
{nodes_desc}"""),
    ])

    partial_prompt = prompt.partial(format_instructions=parser.get_format_instructions())
    chain = partial_prompt | llm | parser
    return chain


_chain_cache = None


def _get_chain():
    global _chain_cache
    if _chain_cache is None:
        _chain_cache = _build_chain()
    return _chain_cache


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
    try:
        chain = _get_chain()

        rule_names = ", ".join([r.get("name", "") for r in matched_rules])
        categories = ", ".join(list(set(r.get("category", "") for r in matched_rules)))
        nodes_desc = []
        for n in graph.get("nodes", []):
            nodes_desc.append("- 工具:%s 动作:%s 对象:%s 数据类型:%s 目标:%s" % (n.get("tool"), n.get("action"), n.get("object"), n.get("data_type"), n.get("destination")))

        result = await chain.ainvoke({
            "content": content,
            "risk_score": str(risk_result.get("risk_score", "")),
            "risk_level": risk_result.get("risk_level", ""),
            "rule_names": rule_names,
            "categories": categories,
            "policy_action": policy_decision.get("action", ""),
            "nodes_desc": "\n".join(nodes_desc),
        })

        return {
            "reason": result.reason,
            "suggestion": result.suggestion,
            "safe_alternative": result.safe_alternative,
        }
    except Exception as e:
        print(f"LLM explanation failed: %s" % e)
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

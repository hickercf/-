"""
multi_agent_system.py — 多 Agent 协作系统

采用 LangChain + DeepSeek 实现多 Agent 协作：
  1. Orchestrator Agent — 总调度，分析输入并分发任务
  2. Extractor Agent — 行为链抽取（已有，复用）
  3. Risk Analyst Agent — 深度风险分析
  4. Policy Advisor Agent — 策略建议生成
"""
import os
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv
from app.core.json_utils import parse_json_output
from app.core.llm_client import build_chat_llm, safe_log

load_dotenv()

ENABLE_LLM = os.getenv("ENABLE_LLM", "false").lower() == "true"
ENABLE_MULTI_AGENT = os.getenv("ENABLE_MULTI_AGENT", "false").lower() == "true"
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")



# ═══════════════════════════════════════════════════════════════
# 1. Orchestrator Agent — 总调度器
# ═══════════════════════════════════════════════════════════════

ORCHESTRATOR_PROMPT = """你是 AgentGuard 多 Agent 系统的总调度器。

你的任务：
1. 分析用户输入，判断需要哪些专业 Agent 参与
2. 评估任务复杂度
3. 决定调用哪些 Agent（可多选）

可选 Agent：
- Extractor: 从文本中抽取行为节点和边（适用于任何输入）
- RiskAnalyst: 深度分析攻击手法、风险链条（适用于复杂攻击）
- PolicyAdvisor: 生成防御策略和修复建议（适用于中高风险）

判断标准：
- simple: 单步骤、意图明确、低风险 → 只需 Extractor
- medium: 多步骤、意图模糊、中风险 → Extractor + RiskAnalyst
- complex: 社会工程学、权限提升、数据外泄、组合攻击 → 全部 Agent

请输出 JSON 格式：
{{
  "requires_extraction": true/false,
  "requires_risk_analysis": true/false,
  "requires_policy_advice": true/false,
  "complexity_level": "simple/medium/complex",
  "reasoning": "调度理由"
}}"""


def _build_orchestrator_chain():
    from langchain_core.prompts import ChatPromptTemplate

    llm = build_chat_llm(
        model=LLM_MODEL,
        api_key=LLM_API_KEY,
        base_url=LLM_BASE_URL,
        temperature=0.2,
        max_tokens=500,
    )
    prompt = ChatPromptTemplate.from_messages([
        ("system", ORCHESTRATOR_PROMPT),
        ("human", "输入类型: {input_type}\n输入内容: {content}\n"),
    ])
    return prompt | llm


_orchestrator_chain = None


def _get_orchestrator_chain():
    return _build_orchestrator_chain()


# ═══════════════════════════════════════════════════════════════
# 2. Risk Analyst Agent — 深度风险分析
# ═══════════════════════════════════════════════════════════════

RISK_ANALYST_PROMPT = """你是 AgentGuard 系统的风险分析专家。

你的任务：
1. 深度分析输入中的攻击手法和意图
2. 识别攻击向量
3. 构建风险传导链条
4. 评估严重度
5. 与已知攻击模式对比

请输出 JSON 格式：
{{
  "attack_vectors": ["攻击向量1", "攻击向量2"],
  "risk_chain": ["步骤1", "步骤2", "步骤3"],
  "severity_assessment": "low/medium/high/critical",
  "confidence": 0.85,
  "key_indicators": ["指标1", "指标2"],
  "comparison": "与已知攻击模式的对比描述"
}}"""


def _build_risk_analyst_chain():
    from langchain_core.prompts import ChatPromptTemplate

    llm = build_chat_llm(
        model=LLM_MODEL,
        api_key=LLM_API_KEY,
        base_url=LLM_BASE_URL,
        temperature=0.3,
        max_tokens=1500,
    )
    prompt = ChatPromptTemplate.from_messages([
        ("system", RISK_ANALYST_PROMPT),
        ("human", "输入内容: {content}\n\n已抽取的行为链:\n{behavior_chain_desc}"),
    ])
    return prompt | llm


_risk_analyst_chain = None


def _get_risk_analyst_chain():
    return _build_risk_analyst_chain()


# ═══════════════════════════════════════════════════════════════
# 3. Policy Advisor Agent — 策略建议生成
# ═══════════════════════════════════════════════════════════════

POLICY_ADVISOR_PROMPT = """你是 AgentGuard 系统的安全策略顾问。

你的任务：
1. 根据风险分析结果，生成具体的防御策略
2. 提供可操作的修复步骤
3. 建议新的检测规则
4. 区分短期和长期措施

请输出 JSON 格式：
{{
  "immediate_actions": ["立即行动1", "立即行动2"],
  "long_term_measures": ["长期措施1", "长期措施2"],
  "detection_rules": ["检测规则1", "检测规则2"],
  "remediation_steps": ["修复步骤1", "修复步骤2"],
  "priority": "low/medium/high/critical"
}}"""


def _build_policy_advisor_chain():
    from langchain_core.prompts import ChatPromptTemplate

    llm = build_chat_llm(
        model=LLM_MODEL,
        api_key=LLM_API_KEY,
        base_url=LLM_BASE_URL,
        temperature=0.4,
        max_tokens=1500,
    )
    prompt = ChatPromptTemplate.from_messages([
        ("system", POLICY_ADVISOR_PROMPT),
        ("human", "输入内容: {content}\n\n风险分析:\n{risk_analysis_desc}\n\n当前策略: {current_policy}"),
    ])
    return prompt | llm


_policy_advisor_chain = None


def _get_policy_advisor_chain():
    return _build_policy_advisor_chain()


# ═══════════════════════════════════════════════════════════════
# 4. 多 Agent 协作主入口
# ═══════════════════════════════════════════════════════════════

class MultiAgentResult:
    """多 Agent 协作结果"""
    def __init__(self):
        self.orchestrator_decision: Optional[Dict[str, Any]] = None
        self.extraction_result: Optional[Dict[str, Any]] = None
        self.risk_analysis: Optional[Dict[str, Any]] = None
        self.policy_advice: Optional[Dict[str, Any]] = None
        self.collaboration_summary: str = ""
        self.agents_involved: List[str] = []
        self.total_latency_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "orchestrator_decision": self.orchestrator_decision,
            "extraction_result": self.extraction_result,
            "risk_analysis": self.risk_analysis,
            "policy_advice": self.policy_advice,
            "collaboration_summary": self.collaboration_summary,
            "agents_involved": self.agents_involved,
            "total_latency_ms": self.total_latency_ms,
        }


async def run_multi_agent_analysis(
    input_type: str,
    content: str,
    current_policy: str = "warn",
    behavior_chain: Optional[Dict[str, Any]] = None,
) -> Optional[MultiAgentResult]:
    """
    多 Agent 协作分析主入口
    """
    import time
    start_time = time.time()

    if not ENABLE_MULTI_AGENT or not ENABLE_LLM or not LLM_API_KEY:
        return None

    result = MultiAgentResult()
    agents_involved = []

    try:
        # ── Step 1: Orchestrator 调度 ──
        orch_chain = _get_orchestrator_chain()
        orch_response = await orch_chain.ainvoke({
            "input_type": input_type,
            "content": content,
        })
        orch_text = orch_response.content if hasattr(orch_response, 'content') else str(orch_response)
        decision = parse_json_output(orch_text)

        if not decision:
            safe_log(f"Orchestrator parsing failed. Raw: {orch_text[:200]}")
            # 默认使用全部 Agent
            decision = {
                "requires_extraction": True,
                "requires_risk_analysis": True,
                "requires_policy_advice": True,
                "complexity_level": "medium",
                "reasoning": "默认调度",
            }

        result.orchestrator_decision = decision

        # ── Step 2: Extractor（如果需要）──
        if decision.get("requires_extraction", True):
            from app.core.extractor_agent import extract_by_agent
            extraction = await extract_by_agent(input_type, content)
            if extraction:
                result.extraction_result = extraction
                agents_involved.append("Extractor")
                behavior_chain = extraction

        # 如果外部传入了 behavior_chain，使用外部的
        if behavior_chain and not result.extraction_result:
            result.extraction_result = behavior_chain

        # ── Step 3: Risk Analyst（如果需要）──
        if decision.get("requires_risk_analysis", False) and behavior_chain:
            risk_chain = _get_risk_analyst_chain()

            # 构建行为链描述
            nodes_desc = []
            for n in behavior_chain.get("nodes", []):
                nodes_desc.append(
                    f"- [{n.get('actor', '?')}] {n.get('action', '?')} "
                    f"{n.get('object', '?')} (数据:{n.get('data_type', '?')}, "
                    f"权限:{n.get('permission', '?')}, 目标:{n.get('destination', '?')})"
                )

            risk_response = await risk_chain.ainvoke({
                "content": content,
                "behavior_chain_desc": "\n".join(nodes_desc) if nodes_desc else "未抽取到行为节点",
            })
            risk_text = risk_response.content if hasattr(risk_response, 'content') else str(risk_response)
            risk_result = parse_json_output(risk_text)

            if risk_result:
                result.risk_analysis = risk_result
                agents_involved.append("RiskAnalyst")
            else:
                safe_log(f"RiskAnalyst parsing failed. Raw: {risk_text[:200]}")

        # ── Step 4: Policy Advisor（如果需要）──
        if decision.get("requires_policy_advice", False):
            policy_chain = _get_policy_advisor_chain()

            risk_desc = ""
            if result.risk_analysis:
                ra = result.risk_analysis
                risk_desc = (
                    f"攻击向量: {', '.join(ra.get('attack_vectors', []))}\n"
                    f"风险链条: {' -> '.join(ra.get('risk_chain', []))}\n"
                    f"严重度: {ra.get('severity_assessment', 'unknown')}\n"
                    f"关键指标: {', '.join(ra.get('key_indicators', []))}"
                )
            else:
                risk_desc = "基于规则引擎的初步风险评估"

            policy_response = await policy_chain.ainvoke({
                "content": content,
                "risk_analysis_desc": risk_desc,
                "current_policy": current_policy,
            })
            policy_text = policy_response.content if hasattr(policy_response, 'content') else str(policy_response)
            policy_result = parse_json_output(policy_text)

            if policy_result:
                result.policy_advice = policy_result
                agents_involved.append("PolicyAdvisor")
            else:
                safe_log(f"PolicyAdvisor parsing failed. Raw: {policy_text[:200]}")

        # ── Step 5: 生成协作总结 ──
        result.agents_involved = agents_involved
        result.collaboration_summary = _generate_summary(
            decision, result.risk_analysis, result.policy_advice
        )

        elapsed_ms = int((time.time() - start_time) * 1000)
        result.total_latency_ms = elapsed_ms

        return result

    except Exception as e:
        print(f"Multi-agent analysis failed: {e}")
        return None


def _generate_summary(
    decision: Dict[str, Any],
    risk_analysis: Optional[Dict[str, Any]],
    policy_advice: Optional[Dict[str, Any]],
) -> str:
    """生成多 Agent 协作总结"""
    parts = []

    parts.append(f"任务复杂度: {decision.get('complexity_level', 'unknown')}")
    parts.append(f"调度理由: {decision.get('reasoning', '')}")

    if risk_analysis:
        parts.append(
            f"风险分析: 严重度 {risk_analysis.get('severity_assessment', 'unknown')}, "
            f"置信度 {risk_analysis.get('confidence', 0):.0%}"
        )
        attack_vectors = risk_analysis.get("attack_vectors", [])
        if attack_vectors:
            parts.append(f"识别到的攻击向量: {', '.join(attack_vectors)}")

    if policy_advice:
        parts.append(
            f"策略建议: 优先级 {policy_advice.get('priority', 'unknown')}, "
            f"包含 {len(policy_advice.get('immediate_actions', []))} 项立即行动"
        )

    return "\n".join(parts)


async def analyze_with_single_agent(input_type: str, content: str) -> Optional[Dict[str, Any]]:
    """
    单 Agent 模式（兼容旧接口，只使用 Extractor）
    """
    from app.core.extractor_agent import extract_by_agent
    return await extract_by_agent(input_type, content)

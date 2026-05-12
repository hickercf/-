from pydantic import BaseModel, Field
from typing import List, Literal, Optional, Dict, Any
from datetime import datetime


class TraceEvent(BaseModel):
    """AgentTrace 中的单个事件"""
    event_id: str
    event_type: Literal[
        "message", "plan", "tool_select", "tool_call",
        "observation", "data_flow", "output", "policy"
    ]
    actor: Literal["user", "agent", "tool", "system"]
    tool: Optional[str] = None
    action: Optional[str] = None
    object: Optional[str] = None
    data_type: Optional[str] = None
    permission: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    evidence: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    raw: Optional[Dict[str, Any]] = None


class AgentTrace(BaseModel):
    """AgentTrace 统一行为表示层
    
    无论 Agent 来自 LangChain、Dify、自研框架还是 Docker 靶场，
    最终都要转换为 AgentTrace 后再进入审计引擎。
    """
    trace_id: str
    source: Literal[
        "manual", "docker_sandbox", "mock_agent",
        "langchain_log", "openai_function", "dify_log"
    ] = "manual"
    agent_name: str = "unknown"
    input_text: str = ""
    system_prompt_summary: Optional[str] = None
    events: List[TraceEvent] = []
    final_output: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class PayloadCase(BaseModel):
    """安全载荷/对抗样例"""
    id: str
    name: str
    category: Literal[
        "prompt_injection_test",
        "roleplay_bypass_test",
        "encoding_bypass_test",
        "rag_injection_test",
        "observation_injection_test",
        "tool_abuse_test"
    ]
    injection_point: Literal[
        "user_input", "rag_document", "observation", "tool_argument"
    ]
    payload_template: str
    mutation_strategies: List[str] = []
    expected_risk: Literal["low", "medium", "high", "critical"] = "medium"
    expected_breach_layers: List[str] = []


class SandboxConfig(BaseModel):
    """Docker 靶场配置"""
    enable_rag: bool = True
    enable_observation_injection: bool = False
    mock_data_preset: str = "default"


class SandboxRunRequest(BaseModel):
    """靶场单次运行请求"""
    trace_id: str = ""
    input_text: str
    injection_point: Literal["user_input", "rag_document", "observation"] = "user_input"
    payload_case: Optional[PayloadCase] = None
    sandbox_config: SandboxConfig = Field(default_factory=SandboxConfig)


class SandboxRunResponse(BaseModel):
    """靶场单次运行响应"""
    trace: AgentTrace
    audit_result: Optional[Dict[str, Any]] = None

"""
sandbox/agent_app/schemas.py — 靶场数据模型
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any
from datetime import datetime


class TraceEvent(BaseModel):
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
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
    raw: Optional[Dict[str, Any]] = None


class AgentTrace(BaseModel):
    trace_id: str
    source: Literal["docker_sandbox", "mock_agent"] = "docker_sandbox"
    agent_name: str = "demo_customer_agent"
    input_text: str
    system_prompt_summary: Optional[str] = None
    events: List[TraceEvent] = []
    final_output: str = ""
    created_at: str = Field(default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))


class RunRequest(BaseModel):
    trace_id: str = ""
    input_text: str
    injection_point: Literal["user_input", "rag_document", "observation"] = "user_input"
    sandbox_config: Dict[str, Any] = Field(default_factory=dict)


class RunResponse(BaseModel):
    trace: AgentTrace


class RAGInjectRequest(BaseModel):
    case_id: str
    doc_title: str
    doc_content: str


class HealthResponse(BaseModel):
    status: str = "ok"
    sandbox_mode: bool = True
    agent: str = "demo_customer_agent"
    version: str = "1.0.0"

from pydantic import BaseModel
from typing import List, Literal, Optional


class BehaviorNode(BaseModel):
    id: str
    actor: Literal["user", "agent", "tool", "unknown"]
    tool: Literal[
        "file", "shell", "browser", "email", "network",
        "database", "llm", "code", "unknown"
    ]
    action: Literal[
        "read", "write", "delete", "execute", "send",
        "upload", "download", "login", "crawl", "query",
        "modify", "override", "leak", "unknown"
    ]
    object: str
    data_type: Literal[
        "public_data", "personal_info", "credential",
        "password", "token", "api_key", "system_file",
        "database_record", "code", "prompt", "unknown"
    ]
    permission: Literal["authorized", "unauthorized", "unknown"]
    destination: Literal["local", "internal", "external", "unknown"]
    confidence: float
    evidence_text: str


class BehaviorEdge(BaseModel):
    source: str
    target: str
    relation: Literal["then", "data_flow", "control_flow", "dependency"]
    description: str


class BehaviorChain(BaseModel):
    trace_id: str
    input_type: Literal["task", "tool_log", "command", "code", "prompt"]
    nodes: List[BehaviorNode]
    edges: List[BehaviorEdge]
    trust_boundary_crossed: bool
    extraction_method: Literal["llm_agent", "fallback", "hybrid"]
    extraction_confidence: float

from pydantic import BaseModel, Field
from typing import List, Optional, Literal


class PayloadParam(BaseModel):
    name: str
    values: List[str] = []


class AttackPayloadSchema(BaseModel):
    payload_id: str
    category: Literal[
        "prompt_injection", "role_play_bypass", "encoding_bypass",
        "language_confusion", "data_exfiltration", "privilege_escalation",
        "tool_abuse", "chain_of_thought_hijack", "multi_turn_attack",
        "context_overflow"
    ]
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    template: str
    params: List[PayloadParam] = []
    mutations: List[str] = []
    cwe_reference: str = ""


class PayloadCreate(BaseModel):
    payload_id: str = Field(min_length=1)
    category: Literal[
        "prompt_injection", "role_play_bypass", "encoding_bypass",
        "language_confusion", "data_exfiltration", "privilege_escalation",
        "tool_abuse", "chain_of_thought_hijack", "multi_turn_attack",
        "context_overflow"
    ]
    title: str = Field(min_length=1)
    severity: Literal["critical", "high", "medium", "low"] = "medium"
    template: str = Field(min_length=1)
    params: List[PayloadParam] = []
    mutations: List[str] = []
    cwe_reference: str = ""


class PayloadResponse(BaseModel):
    id: int
    payload_id: str
    category: str
    title: str
    severity: str
    template: str
    params: List[PayloadParam]
    mutations: List[str]
    cwe_reference: str
    enabled: bool
    created_at: str


class PayloadCategoryStat(BaseModel):
    category: str
    name: str
    count: int

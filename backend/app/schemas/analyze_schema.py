from pydantic import BaseModel
from typing import List, Optional, Dict, Any, Literal


class AnalyzeRequest(BaseModel):
    input_type: Literal["task", "tool_log", "command", "code", "prompt"] = "task"
    content: str


class MatchedRule(BaseModel):
    id: str
    name: str
    category: str
    score: int
    level: str
    advice: Optional[str] = None
    verification: Optional[Dict[str, Any]] = None


class PolicyDecision(BaseModel):
    action: Literal["pass", "warn", "review", "block"]
    reason: str
    least_privilege_advice: List[str] = []


class AnalyzeResponse(BaseModel):
    id: int
    trace_id: str
    risk_score: int
    risk_level: str
    risk_categories: List[str]
    policy_decision: PolicyDecision
    behavior_chain: Dict[str, Any]
    matched_rules: List[MatchedRule]
    reason: str
    suggestion: str
    record_hash: Optional[str] = None
    created_at: str


class HistoryItem(BaseModel):
    id: int
    trace_id: str
    input_type: str
    risk_score: int
    risk_level: str
    policy_action: str
    risk_categories: List[str]
    record_hash: Optional[str] = None
    created_at: str


class StatsResponse(BaseModel):
    total_count: int
    risk_level_distribution: Dict[str, int]
    risk_category_distribution: Dict[str, int]
    policy_distribution: Dict[str, int]
    recent_scores: List[Dict[str, Any]]
    top_rules: List[Dict[str, Any]]


class EvalRequest(BaseModel):
    pass


class EvalResult(BaseModel):
    total: int
    extraction_success_rate: float
    risk_level_accuracy: float
    high_risk_recall: float
    critical_miss_count: int
    category_f1: float
    avg_response_time: float
    comparison: Optional[Dict[str, Any]] = None

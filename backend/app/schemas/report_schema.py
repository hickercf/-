from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class ReportData(BaseModel):
    id: int
    trace_id: str
    input_type: str
    input_content: str
    risk_score: int
    risk_level: str
    risk_categories: List[str]
    behavior_chain: Dict[str, Any]
    matched_rules: List[Dict[str, Any]]
    policy_decision: Dict[str, Any]
    reason: str
    suggestion: str
    record_hash: Optional[str] = None
    previous_hash: Optional[str] = None
    evidence_chain_valid: Optional[bool] = None
    created_at: str

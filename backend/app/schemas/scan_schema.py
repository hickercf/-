from pydantic import BaseModel, Field
from typing import List, Optional, Literal


class FuzzConfigSchema(BaseModel):
    concurrent: int = 1
    rate_limit: float = 1.0
    timeout: int = 30
    retry: int = 2
    mutation_strategies: List[str] = []


class ScanStartRequest(BaseModel):
    scan_mode: Literal["quick", "standard", "deep", "targeted"] = "standard"
    categories: Optional[List[str]] = None
    mutation_strategies: Optional[List[str]] = None
    config: FuzzConfigSchema = FuzzConfigSchema()


class ScanTaskResponse(BaseModel):
    id: int
    scan_id: str
    target_id: str
    target_name: str = ""
    scan_mode: str
    status: str
    total_payloads: int
    completed_payloads: int
    vulnerabilities_found: int
    config: dict
    summary: Optional[dict] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class ReActStepSchema(BaseModel):
    step_index: int
    thought: str = ""
    action: str = ""
    action_input: dict = {}
    observation: str = ""
    is_malicious: bool = False


class DefenseBreachSchema(BaseModel):
    layer: str
    step_index: int
    description: str
    evidence: str
    severity: str
    cwe_id: str = ""
    suggestion: str = ""


class FuzzResultResponse(BaseModel):
    id: int
    scan_id: str
    payload_id: str
    variant: str
    react_trace: Optional[dict] = None
    defense_breaches: List[DefenseBreachSchema] = []
    is_vulnerability: bool = False
    vulnerability_severity: Optional[str] = None
    risk_score: int = 0
    response_time_ms: int = 0
    created_at: str = ""


class ScanDetailResponse(BaseModel):
    task: ScanTaskResponse
    results: List[FuzzResultResponse] = []
    stats: dict = {}


class ScanProgressEvent(BaseModel):
    scan_id: str
    status: str
    completed_payloads: int
    total_payloads: int
    vulnerabilities_found: int
    current_payload_id: Optional[str] = None
    latest_breaches: List[DefenseBreachSchema] = []

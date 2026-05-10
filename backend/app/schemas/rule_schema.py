from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class RuleCondition(BaseModel):
    action: Optional[List[str]] = None
    data_type: Optional[List[str]] = None
    tool: Optional[List[str]] = None
    destination: Optional[List[str]] = None
    permission: Optional[List[str]] = None
    object_keywords: Optional[List[str]] = None


class ChainStep(BaseModel):
    action: List[str]
    data_type: Optional[List[str]] = None
    destination: Optional[List[str]] = None
    tool: Optional[List[str]] = None


class SecurityRule(BaseModel):
    id: str
    name: str
    category: str
    type: str
    condition: Optional[RuleCondition] = None
    sequence: Optional[List[ChainStep]] = None
    keywords: Optional[List[str]] = None
    score: int
    level: str
    advice: Optional[str] = None

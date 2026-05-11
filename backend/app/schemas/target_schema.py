from pydantic import BaseModel, Field
from typing import List, Optional, Literal
from datetime import datetime


class ParamSchema(BaseModel):
    name: str
    type: str = "string"
    required: bool = False
    sensitive: bool = False


class ApiSchemaDef(BaseModel):
    name: str
    description: str = ""
    parameters: List[ParamSchema] = []
    permissions: List[str] = []
    risk_tags: List[str] = []


class TargetCreate(BaseModel):
    name: str
    system_prompt: str = ""
    api_schemas: List[ApiSchemaDef] = []
    safety_constraints: List[str] = []
    runtime_env: dict = {}
    access_mode: Literal["callback", "log", "sandbox"] = "callback"
    access_config: dict = {}


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    system_prompt: Optional[str] = None
    api_schemas: Optional[List[ApiSchemaDef]] = None
    safety_constraints: Optional[List[str]] = None
    runtime_env: Optional[dict] = None
    access_mode: Optional[Literal["callback", "log", "sandbox"]] = None
    access_config: Optional[dict] = None


class TargetResponse(BaseModel):
    id: int
    target_id: str
    name: str
    system_prompt: str
    api_schemas: List[ApiSchemaDef]
    safety_constraints: List[str]
    runtime_env: dict
    access_mode: str
    access_config: dict
    created_at: str
    updated_at: str

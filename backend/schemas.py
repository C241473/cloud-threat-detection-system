import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field

# User Schemas
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "analyst"

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    created_at: datetime.datetime

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str

# Security Log Schemas
class SecurityLogCreate(BaseModel):
    ip_address: str = Field(..., json_schema_extra={"example": "192.168.1.50"})
    username: Optional[str] = Field(None, json_schema_extra={"example": "john_doe"})
    event_type: str = Field(..., json_schema_extra={"example": "LOGIN_FAILED"})
    status: str = Field(..., json_schema_extra={"example": "FAILED"})
    details: Optional[str] = None

class SecurityLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    username: Optional[str]
    event_type: str
    status: str
    timestamp: datetime.datetime
    details: Optional[str]

# Threat Schemas
class ThreatResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    threat_type: str
    severity: str
    description: str
    detected_at: datetime.datetime
    status: str

class ThreatStatusUpdate(BaseModel):
    status: str

# Dashboard Summary Schema
class DashboardStats(BaseModel):
    total_events: int
    failed_logins: int
    total_threats: int
    active_threats: int
    threats_by_severity: dict
    recent_threats: List[ThreatResponse]
    system_metrics: dict

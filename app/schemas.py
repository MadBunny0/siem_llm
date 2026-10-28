from datetime import datetime
from pydantic import BaseModel, Field

class WazuhAlert(BaseModel):
    timestamp: str | None = None
    rule: dict = Field(default_factory=dict)
    agent: dict = Field(default_factory=dict)
    data: dict = Field(default_factory=dict)
    full_log: str | None = None

class IncidentOut(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    created_at: datetime
    class Config:
        from_attributes = True

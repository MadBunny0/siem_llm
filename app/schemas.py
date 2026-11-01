"""Pydantic-схемы для REST API."""

from datetime import datetime
from pydantic import BaseModel, Field


class AssetOut(BaseModel):
    """Ответ о защищаемом активе (для инцидентов)."""


class NotificationOut(BaseModel):
    """Ответ об ITSM-уведомлении (лог отправки)."""

    id: int
    event_type: str
    incident_id: int | None
    recipient: str
    channel: str
    message: str
    payload: dict | None = None
    status: str
    created_at: datetime

    id: int
    name: str
    criticality: str
    network_segment: str | None = None


class WazuhAlert(BaseModel):
    timestamp: str | None = None
    rule: dict = Field(default_factory=dict)
    agent: dict = Field(default_factory=dict)
    data: dict = Field(default_factory=dict)
    full_log: str | None = None

from app.models import Asset  # noqa: F401


class IncidentOut(BaseModel):
    """Ответ о инциденте (включая риск, тип атаки, актив)."""

    id: int
    title: str
    description: str
    severity: str
    status: str
    risk_score: int
    attack_type: str | None
    asset_id: int | None
    asset: AssetOut | None = None
    created_at: datetime
    class Config:
        from_attributes = True

"""Pydantic-схемы для REST API."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AssetOut(BaseModel):
    """Ответ о защищаемом активе (для инцидентов)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    criticality: str
    network_segment: str | None = None


class NotificationOut(BaseModel):
    """Ответ об ITSM-уведомлении (лог отправки)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    event_type: str
    incident_id: int | None
    recipient: str
    channel: str
    message: str
    payload: dict | None = None
    status: str
    created_at: datetime


class AnalysisOut(BaseModel):
    """Результаты интеллектуального анализа LLM (для статистики качества)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    model: str
    prompt: str
    description: str
    attack_type: str | None
    confidence: float | None
    explanation: str | None
    recommended_action: str | None
    response_raw: dict | None = None
    created_at: datetime


class WazuhAlert(BaseModel):
    timestamp: str | None = None
    rule: dict = Field(default_factory=dict)
    agent: dict = Field(default_factory=dict)
    data: dict = Field(default_factory=dict)
    full_log: str | None = None


class IncidentOut(BaseModel):
    """Ответ о инциденте (включая риск, тип атаки, актив)."""

    model_config = ConfigDict(from_attributes=True)

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

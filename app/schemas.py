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


class LoginIn(BaseModel):
    """Вход в систему (JSON вместо OAuth2-формы — без python-multipart)."""

    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class RegisterIn(BaseModel):
    """Создание пользователя администратором (POST /auth/register)."""

    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=6)
    role: str = Field(default="analyst", pattern="^(analyst|admin)$")


class UserBrief(BaseModel):
    """Краткая информация о пользователе (для поля analyst инцидента)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str


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
    analyst: UserBrief | None = None  # владелец инцидента (stage-14)
    created_at: datetime


class EventOut(BaseModel):
    """Нормализованное событие (для детальной карточки инцидента)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source: str
    event_type: str
    user: str | None = None
    src_ip: str | None = None
    asset_id: int | None = None
    criticality_level: int | None = None
    raw_message: str | None = None


class IncidentDetailOut(IncidentOut):
    """Детальная карточка инцидента: события, история анализов, актив (§3.2)."""

    events: list[EventOut] = []
    analyses: list[AnalysisOut] = []


class IncidentStatusIn(BaseModel):
    """Смена статуса инцидента оператором."""

    status: str = Field(pattern="^(new|in_progress|closed)$")


class ExecuteActionIn(BaseModel):
    """Ручной запуск playbook-действия администратором (stage-12)."""

    action: str = Field(min_length=1)


class AuditLogOut(BaseModel):
    """Запись журнала аудита (§3.1, модуль 8)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    event_type: str
    incident_id: int | None = None
    event_id: int | None = None
    user_id: int | None = None
    details: dict | None = None


class CorrelationRuleIn(BaseModel):
    """Создание/обновление правила корреляции (§3.2 — изменение без правки кода)."""

    name: str = Field(min_length=1)
    description: str | None = None
    conditions: list[dict] = Field(default_factory=list)
    time_window_minutes: int = 5
    min_events: int = Field(default=1, ge=1)
    priority: int = 1
    is_active: bool = True


class CorrelationRuleOut(BaseModel):
    """Правило корреляции."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None = None
    conditions: list[dict] | dict | None = None
    time_window_minutes: int
    min_events: int
    priority: int
    is_active: bool


class PlaybookIn(BaseModel):
    """Создание/обновление сценария реагирования (§3.4 — библиотека сценариев)."""

    name: str = Field(min_length=1)
    description: str | None = None
    trigger_conditions: dict = Field(default_factory=dict)
    allowed_actions: list[str] = Field(default_factory=list)
    steps: list[dict] = Field(default_factory=list)
    success_criteria: list[str] | None = None  # критерии успешного завершения (§3.4, p:105)
    priority: int = 1
    is_active: bool = True


class PlaybookOut(BaseModel):
    """Сценарий реагирования."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None = None
    trigger_conditions: dict | None = None
    allowed_actions: list[str] | None = None
    steps: list[dict] | None = None
    success_criteria: list[str] | None = None
    priority: int
    is_active: bool


class ValidationPolicyOut(BaseModel):
    """Политика DVE: разрешённые действия для уровня риска (§3.4, p:103)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    severity: str
    allowed_actions: list[str] | None = None

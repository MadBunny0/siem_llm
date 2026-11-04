"""Pydantic-схемы для REST API."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Тактики MITRE ATT&CK матрицы критичности (stage-17, процедура PDF v3.1,
# см. docs/CRITICALITY_MATRIX.md): FastAPI сам отдаёт 422 на неизвестное значение
MitreTacticLiteral = Literal[
    "reconnaissance",
    "resource_development",
    "initial_access",
    "discovery",
    "privilege_escalation",
    "credential_access",
    "execution",
    "persistence",
    "defense_evasion",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]


class AssetOut(BaseModel):
    """Ответ о защищаемом активе (для инцидентов и справочника /assets)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    type: str | None = None
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
    # отметки ручных запусков playbook-действий (stage-18, фидбек): состояние
    # кнопок действий видно всем операторам (сервер, а не localStorage)
    manual_actions: dict | None = None


class IncidentStatusIn(BaseModel):
    """Смена статуса инцидента оператором."""

    status: str = Field(pattern="^(new|in_progress|closed)$")


class ExecuteActionIn(BaseModel):
    """Ручной запуск playbook-действия (stage-12; stage-15: владелец или админ)."""

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
    """Создание/обновление правила корреляции (§3.2 — изменение без правки кода).

    mitre_tactic — тактика из матрицы критичности (stage-17): задаёт базовую
    критичность инцидента; None — числовая модель риска (fallback).
    """

    name: str = Field(min_length=1)
    description: str | None = None
    conditions: list[dict] = Field(default_factory=list)
    time_window_minutes: int = 5
    min_events: int = Field(default=1, ge=1)
    priority: int = 1
    is_active: bool = True
    mitre_tactic: MitreTacticLiteral | None = None
    mitre_technique: str | None = None
    escalated_by_vendor: bool = False  # п.7 процедуры критичности — флаг поставщика


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
    mitre_tactic: MitreTacticLiteral | None = None
    mitre_technique: str | None = None
    escalated_by_vendor: bool = False


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


# ---------------------------------------------------------------------------
# Справочник для формы добавления события Wazuh (GET /ingest/reference, stage-15):
# поля формы — выпадающие списки из фактических данных БД, а не ручной ввод ID
# ---------------------------------------------------------------------------
class IngestReferenceRule(BaseModel):
    """Правило Wazuh, встреченное в принятых событиях."""

    id: str
    level: int | None = None
    description: str | None = None
    groups: list[str] = Field(default_factory=list)


class IngestReferenceAgent(BaseModel):
    """Агент Wazuh, встреченный в принятых событиях."""

    id: str
    name: str


class IngestReferenceAsset(BaseModel):
    """Защищаемый актив (инвентарь, §3.2)."""

    name: str
    type: str | None = None
    criticality: str | None = None
    network_segment: str | None = None
    ip_addresses: str | None = None


class IngestReferenceOut(BaseModel):
    """Справочные данные для формы добавления события Wazuh."""

    rules: list[IngestReferenceRule] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    agents: list[IngestReferenceAgent] = Field(default_factory=list)
    assets: list[IngestReferenceAsset] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    src_ips: list[str] = Field(default_factory=list)

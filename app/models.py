from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, ForeignKey, JSON, Table, Column, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db import Base

incident_events = Table(
    "incident_events", Base.metadata,
    Column("incident_id", ForeignKey("incidents.id"), primary_key=True),
    Column("event_id", ForeignKey("events.id"), primary_key=True),
)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(255))
    event_type: Mapped[str] = mapped_column(String(100))
    user: Mapped[str | None] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(50))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    criticality_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_data: Mapped[dict] = mapped_column(JSON)
    incidents: Mapped[list["Incident"]] = relationship(
        secondary=incident_events, back_populates="events"
    )

class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="low")
    status: Mapped[str] = mapped_column(String(30), default="new")
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    attack_type: Mapped[str | None] = mapped_column(String(100))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    analyst_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    events: Mapped[list[Event]] = relationship(
        secondary=incident_events, back_populates="incidents"
    )
    analyses: Mapped[list["Analysis"]] = relationship(back_populates="incident")
    # связь с защищаемым активом
    asset: Mapped["Asset"] = relationship(back_populates="incidents")
    # связь с выполненными ответными действиями
    response_actions: Mapped[list["ResponseAction"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )

class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    model: Mapped[str] = mapped_column(String(100))
    prompt: Mapped[str] = mapped_column(Text)
    response: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    incident: Mapped[Incident] = relationship(back_populates="analyses")


# ---------------------------------------------------------------------------
# Сущность Asset — защищаемые активы корпоративной информационной системы
# ---------------------------------------------------------------------------
class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(100))  # server, workstation, network_device, application
    criticality: Mapped[str] = mapped_column(String(50), default="medium")  # low, medium, high, critical
    network_segment: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    ip_addresses: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    # связь с инцидентами
    incidents: Mapped[list["Incident"]] = relationship(back_populates="asset")


# ---------------------------------------------------------------------------
# Сущность CorrelationRule — правила выявления инцидентов
# ---------------------------------------------------------------------------
class CorrelationRule(Base):
    __tablename__ = "correlation_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text)
    conditions: Mapped[dict] = mapped_column(JSON)  # список условий срабатывания
    time_window_minutes: Mapped[int] = mapped_column(Integer, default=5)
    priority: Mapped[int] = mapped_column(Integer, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# Сущность Playbook — сценарии автоматизированного реагирования
# ---------------------------------------------------------------------------
class Playbook(Base):
    __tablename__ = "playbooks"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text)
    trigger_conditions: Mapped[dict] = mapped_column(JSON)  # условия применения
    allowed_actions: Mapped[list[str]] = mapped_column(JSON)  # допустимые действия
    steps: Mapped[list[dict]] = mapped_column(JSON)  # порядок выполнения операций
    priority: Mapped[int] = mapped_column(Integer, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# Сущность ResponseAction — выполненные ответные действия
# ---------------------------------------------------------------------------
class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    playbook_id: Mapped[int | None] = mapped_column(ForeignKey("playbooks.id"))
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    result: Mapped[str | None] = mapped_column(Text)
    initiated_by: Mapped[str] = mapped_column(String(100))  # playbook, validation, manual
    metadata: Mapped[dict | None] = mapped_column(JSON)
    incident: Mapped["Incident"] = relationship(back_populates="response_actions")


# ---------------------------------------------------------------------------
# Сущность AuditLog — журнал аудита всех этапов обработки инцидента
# ---------------------------------------------------------------------------
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)  # event_ingested, normalized, correlated, risk_calculated, llm_analyzed, playbook_selected, action_executed, validation_result
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"))
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id"))
    details: Mapped[dict] = mapped_column(JSON)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

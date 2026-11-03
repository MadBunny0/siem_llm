"""Тесты REST API (app/api/routes.py) через fastapi.testclient.TestClient.

Каждый тест работает с изолированной in-memory SQLite-БД: движок создаётся
со StaticPool, чтобы все соединения (приложение и тестовая сессия) видели
одну и ту же базу. Внешние зависимости изолируются:
- settings.auto_analysis=False — ингест не запускает LLM-анализ;
- settings.auto_response=False — реагирование выполняется в режиме simulation;
- app.api.routes.analyze_incident подменяется фейковой async-функцией.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.db import get_db
from app.main import app
from app.models import Base

API = "/api/v1"


def make_alert(**overrides):
    """Тестовый алерт Wazuh (формат POST /api/v1/ingest/wazuh)."""
    alert = {
        "timestamp": "2026-01-01T10:00:00Z",
        "rule": {
            "level": 10,
            "description": "test",
            "groups": ["authentication_failed"],
        },
        "agent": {"id": "001", "name": "test-host"},
        "data": {"srcip": "192.0.2.10", "dstuser": "root"},
        "full_log": "Failed password",
    }
    alert.update(overrides)
    return alert


@pytest.fixture
def engine():
    """Изолированная in-memory SQLite-БД, общая для всех соединений (StaticPool)."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def client(engine, monkeypatch):
    """TestClient с подменой зависимости get_db на тестовую БД."""
    # LLM-автоанализ и реальное реагирование отключаем: тесты не должны
    # зависеть ни от запущенного Ollama, ни от локального .env
    monkeypatch.setattr(settings, "auto_analysis", False)
    monkeypatch.setattr(settings, "auto_response", False)

    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def db_session(engine):
    """Прямая сессия к той же БД — для подготовки данных (seed правил)."""
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_rule(db_session, name="brute_rule", **overrides):
    """Создание активного правила корреляции напрямую в тестовой БД."""
    from app.models import CorrelationRule

    params = dict(
        name=name,
        description="тестовое правило",
        conditions=[{"field": "event_type", "operator": "like", "value": "auth"}],
        time_window_minutes=5,
        min_events=1,
        priority=1,
        is_active=True,
    )
    params.update(overrides)
    rule = CorrelationRule(**params)
    db_session.add(rule)
    db_session.commit()
    return rule


def test_health(client):
    """GET /api/v1/health — сервис и БД доступны."""
    resp = client.get(f"{API}/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["database"] == "ok"


def test_ingest_without_rules(client):
    """Без правил корреляции событие сохраняется, инцидент не создаётся."""
    resp = client.post(f"{API}/ingest/wazuh", json=make_alert())
    assert resp.status_code == 200
    data = resp.json()
    assert data["correlated"] is False
    assert data["incident_id"] is None
    assert data["related_events"] == 0


def test_ingest_creates_incident_on_rule(client, db_session):
    """При сработавшем правиле формируется инцидент с риском и severity."""
    seed_rule(db_session)
    resp = client.post(f"{API}/ingest/wazuh", json=make_alert())
    assert resp.status_code == 200
    data = resp.json()
    assert data["correlated"] is True
    assert data["incident_id"] is not None
    assert data["rule"] == "brute_rule"
    assert isinstance(data["risk_score"], int)
    assert data["severity"] in ("low", "medium", "high", "critical")


def test_ingest_repeated_event_updates_incident(client, db_session):
    """Повторный аналогичный алерт попадает в тот же инцидент."""
    seed_rule(db_session)
    first = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()
    second = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()

    assert first["correlated"] is True
    assert second["correlated"] is True
    assert second["incident_id"] == first["incident_id"]
    assert second["related_events"] >= 1


def test_get_incidents(client, db_session):
    """GET /api/v1/incidents — список с полями severity, risk_score, asset."""
    seed_rule(db_session)
    client.post(f"{API}/ingest/wazuh", json=make_alert())

    resp = client.get(f"{API}/incidents")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    item = items[0]
    assert "severity" in item
    assert "risk_score" in item
    assert "asset" in item


def test_get_incident_detail(client, db_session):
    """GET /api/v1/incidents/{id} — детали с events и analyses; 404 без инцидента."""
    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    resp = client.get(f"{API}/incidents/{incident_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == incident_id
    assert len(data["events"]) >= 1  # событие, породившее инцидент
    assert data["analyses"] == []    # анализ ещё не запускался

    missing = client.get(f"{API}/incidents/99999")
    assert missing.status_code == 404


def test_patch_incident_status(client, db_session):
    """PATCH /api/v1/incidents/{id}/status — смена статуса, 422 и 404."""
    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    resp = client.patch(
        f"{API}/incidents/{incident_id}/status", json={"status": "closed"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "closed"

    invalid = client.patch(
        f"{API}/incidents/{incident_id}/status", json={"status": "archived"}
    )
    assert invalid.status_code == 422

    missing = client.patch(f"{API}/incidents/99999/status", json={"status": "closed"})
    assert missing.status_code == 404


def test_analyze_incident_success(client, db_session, monkeypatch):
    """POST /api/v1/incidents/{id}/analyze — LLM-анализ, валидация, simulation-режим."""
    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    async def fake_analyze(context):
        # подменяется сам analyze_incident, поэтому возвращаем его контракт —
        # уже нормализованный ответ (attack_type, а не category)
        return {
            "description": "Подбор пароля",
            "attack_type": "brute_force",
            "confidence": 0.9,
            "explanation": "Много неудачных попыток входа",
            "recommended_action": "monitor",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    resp = client.post(f"{API}/incidents/{incident_id}/analyze")
    assert resp.status_code == 200
    data = resp.json()
    assert data["validation"]["approved"] is True
    # auto_response=False → действие исполняется в режиме simulation
    assert data["execution"]["mode"] == "simulation"
    assert data["recommendation"]["attack_type"] == "brute_force"

    # результаты анализа доступны в общей статистике качества LLM-модуля
    analyses = client.get(f"{API}/analyses").json()
    assert any(a["attack_type"] == "brute_force" for a in analyses)


def test_analyze_incident_llm_unavailable(client, db_session, monkeypatch):
    """POST /analyze — 404 без инцидента и 503 при недоступности LLM."""
    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    async def failing_analyze(context):
        raise RuntimeError("connection refused")

    monkeypatch.setattr("app.api.routes.analyze_incident", failing_analyze)

    missing = client.post(f"{API}/incidents/99999/analyze")
    assert missing.status_code == 404

    resp = client.post(f"{API}/incidents/{incident_id}/analyze")
    assert resp.status_code == 503
    assert "LLM" in resp.json()["detail"]


def test_confirm_action_without_analysis(client, db_session):
    """POST /confirm-action — 404 без инцидента и 404 без анализа."""
    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    missing = client.post(f"{API}/incidents/99999/confirm-action")
    assert missing.status_code == 404

    # инцидент существует, но LLM-анализ ещё не выполнялся
    resp = client.post(f"{API}/incidents/{incident_id}/confirm-action")
    assert resp.status_code == 404


def test_correlation_rules_crud(client):
    """CRUD правил корреляции: создание, список, обновление, удаление, 404."""
    created = client.post(
        f"{API}/correlation-rules",
        json={
            "name": "r1",
            "description": "тест",
            "conditions": [{"field": "event_type", "operator": "like", "value": "auth"}],
        },
    )
    assert created.status_code in (200, 201)
    rule_id = created.json()["id"]

    names = [r["name"] for r in client.get(f"{API}/correlation-rules").json()]
    assert "r1" in names

    updated = client.put(f"{API}/correlation-rules/{rule_id}", json={"name": "r1b"})
    assert updated.status_code == 200
    names = [r["name"] for r in client.get(f"{API}/correlation-rules").json()]
    assert "r1b" in names
    assert "r1" not in names

    deleted = client.delete(f"{API}/correlation-rules/{rule_id}")
    assert deleted.status_code in (200, 204)
    names = [r["name"] for r in client.get(f"{API}/correlation-rules").json()]
    assert "r1b" not in names

    assert client.delete(f"{API}/correlation-rules/99999").status_code == 404


def test_playbooks_crud(client):
    """CRUD playbook: создание, список, обновление, удаление, 404."""
    created = client.post(
        f"{API}/playbooks",
        json={"name": "p1", "allowed_actions": ["block_ip"]},
    )
    assert created.status_code in (200, 201)
    playbook_id = created.json()["id"]

    names = [p["name"] for p in client.get(f"{API}/playbooks").json()]
    assert "p1" in names

    updated = client.put(f"{API}/playbooks/{playbook_id}", json={"name": "p1b"})
    assert updated.status_code == 200
    names = [p["name"] for p in client.get(f"{API}/playbooks").json()]
    assert "p1b" in names
    assert "p1" not in names

    deleted = client.delete(f"{API}/playbooks/{playbook_id}")
    assert deleted.status_code in (200, 204)
    names = [p["name"] for p in client.get(f"{API}/playbooks").json()]
    assert "p1b" not in names

    assert client.delete(f"{API}/playbooks/99999").status_code == 404


def test_audit_logs_endpoint(client):
    """GET /api/v1/audit-logs — журнал аудита заполняется при ингесте."""
    client.post(f"{API}/ingest/wazuh", json=make_alert())

    resp = client.get(f"{API}/audit-logs", params={"limit": 100})
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) >= 1
    assert all("event_type" in item for item in items)

    # параметр limit ограничивает размер выборки
    limited = client.get(f"{API}/audit-logs", params={"limit": 1})
    assert len(limited.json()) == 1


def test_create_rule_validation(client):
    """POST /api/v1/correlation-rules без обязательного name — 422."""
    resp = client.post(
        f"{API}/correlation-rules",
        json={"conditions": [{"field": "event_type", "operator": "like", "value": "auth"}]},
    )
    assert resp.status_code == 422

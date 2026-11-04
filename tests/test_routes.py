"""Тесты REST API (app/api/routes.py) через fastapi.testclient.TestClient.

Каждый тест работает с изолированной in-memory SQLite-БД: движок создаётся
со StaticPool, чтобы все соединения (приложение и тестовая сессия) видели
одну и ту же базу. Внешние зависимости изолируются:
- settings.auto_analysis=False — ингест не запускает LLM-анализ;
- settings.auto_response=False — реагирование выполняется в режиме simulation;
- app.api.routes.analyze_incident подменяется фейковой async-функцией;
- get_current_user подменяется фейковым админом (механика JWT тестируется
  отдельно в test_auth.py).
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.db import get_db
from app.main import app
from app.models import Base, User
from app.services.auth import get_current_user
from app.services.demo_events import build_mock_scenarios

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
    # авторизация в этих тестах обходится: фейковый пользователь с ролью admin
    # (реальный флоу JWT тестируется в test_auth.py)
    app.dependency_overrides[get_current_user] = lambda: User(
        id=1, username="tester", role="admin"
    )
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


def seed_demo_rules_and_assets(db_session):
    """Seed правил корреляции и активов как в init_db (stage-12) — общее
    для тестов мок-сценариев: /demo/populate и /demo/test-event берут
    правила и привязку агентов к активам из БД."""
    from app.models import Asset, CorrelationRule

    for name, conds, window, min_events, priority in [
        ("brute_force_attempts", [{"field": "event_type", "operator": "like", "value": "authentication_failed"}], 5, 3, 2),
        ("password_spraying", [{"field": "event_type", "operator": "like", "value": "authentication_failed"}], 10, 5, 3),
        ("privilege_escalation_attempt", [{"field": "event_type", "operator": "like", "value": "privilege"}], 10, 1, 3),
        ("repeated_scan", [{"field": "src_ip", "operator": "neq", "value": ""}], 10, 2, 1),
        ("web_attack", [{"field": "event_type", "operator": "like", "value": "web"}], 5, 2, 2),
        ("malware_detection", [{"field": "event_type", "operator": "like", "value": "malware"}], 10, 1, 3),
    ]:
        db_session.add(
            CorrelationRule(
                name=name, description=name, conditions=conds,
                time_window_minutes=window, min_events=min_events,
                priority=priority, is_active=True,
            )
        )
    # активы — моки используют имена агентов = имена активов
    for name, criticality in [
        ("mail-prod-01", "critical"), ("db-primary-01", "critical"),
        ("fw-edge-01", "high"), ("wks-finance-12", "medium"), ("app-web-01", "high"),
    ]:
        db_session.add(Asset(name=name, type="server", criticality=criticality))
    db_session.commit()


FROZEN_NOW = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def frozen_demo_time(monkeypatch):
    """Фиксирует datetime в app.api.routes: таймстампы мок-сценариев в
    /demo/*-эндпоинтах становятся предсказуемыми (детерминизм тестов)."""
    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: N805 — имитация datetime.now
            return FROZEN_NOW

    monkeypatch.setattr("app.api.routes.datetime", _FrozenDatetime)


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


def test_analyze_multiple_actions(client, db_session, monkeypatch):
    """Перечень действий LLM: каждое проходит DVE, ответ — список results (stage-11)."""
    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    async def fake_analyze(context):
        return {
            "description": "Подбор пароля",
            "attack_type": "brute_force",
            "confidence": 0.8,
            "explanation": "Серия неудачных входов",
            "recommended_action": "monitor, collect_evidence",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    resp = client.post(f"{API}/incidents/{incident_id}/analyze")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["results"]) == 2
    assert [r["action"] for r in data["results"]] == ["monitor", "collect_evidence"]
    assert all(r["validation"]["approved"] for r in data["results"])
    # перечень сохранён целиком (§3.4, p:15), а не первое действие
    assert data["recommendation"]["recommended_action"] == "monitor, collect_evidence"
    analyses = client.get(f"{API}/analyses").json()
    assert any(a["recommended_action"] == "monitor, collect_evidence" for a in analyses)


def test_planned_mode_default_critical_only(client, db_session, monkeypatch):
    """Плановый режим: по умолчанию автоанализ только critical; high — не анализируется."""
    seed_rule(db_session)
    monkeypatch.setattr(settings, "auto_analysis", True)  # default levels = "critical"

    resp = client.post(f"{API}/ingest/wazuh", json=make_alert())  # level 10 → severity high
    assert resp.status_code == 200
    assert "analysis" not in resp.json()


def test_planned_mode_levels_include_high(client, db_session, engine, monkeypatch):
    """AUTO_ANALYSIS_LEVELS=critical,high: автоанализ уходит в фон (scheduled),
    фоновая задача с собственной сессией доводит его до Analysis (stage-12)."""
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis

    seed_rule(db_session)
    monkeypatch.setattr(settings, "auto_analysis", True)
    monkeypatch.setattr(settings, "auto_analysis_levels", "critical,high")
    # фоновая задача создаёт свою сессию — направляем её в тестовую БД
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    async def fake_analyze(context):
        return {
            "description": "d",
            "attack_type": "brute_force",
            "confidence": 0.9,
            "explanation": "e",
            "recommended_action": "monitor",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    resp = client.post(f"{API}/ingest/wazuh", json=make_alert())
    data = resp.json()
    assert data["severity"] == "high"
    assert data["analysis"] == {"scheduled": True, "severity": "high"}
    # TestClient выполняет фоновые задачи синхронно после ответа:
    # анализ должен появиться в общей статистике с признаком auto
    analyses = db_session.query(Analysis).all()
    assert len(analyses) == 1
    assert analyses[0].response_raw["initiated_by"] == "auto_analysis"


def test_validation_policy_endpoint(client, db_session):
    """GET /validation-policy — политика DVE из БД (§3.4, p:103)."""
    from app.models import ValidationPolicy

    db_session.add(
        ValidationPolicy(severity="low", allowed_actions=["monitor", "collect_evidence"])
    )
    db_session.commit()

    resp = client.get(f"{API}/validation-policy")
    assert resp.status_code == 200
    policies = {p["severity"]: p["allowed_actions"] for p in resp.json()}
    assert policies["low"] == ["monitor", "collect_evidence"]


def test_incident_description_actualized(client, db_session):
    """Описание инцидента отражает фактическое число событий при обновлении (stage-12)."""
    seed_rule(db_session)
    client.post(f"{API}/ingest/wazuh", json=make_alert())
    client.post(f"{API}/ingest/wazuh", json=make_alert())

    detail = client.get(f"{API}/incidents/1").json()
    assert "2 связанных событий" in detail["description"]
    assert len(detail["events"]) == 2


def test_demo_populate(client, db_session):
    """POST /demo/populate — мок-сценарии: 19 событий → 7 инцидентов всех уровней."""
    seed_demo_rules_and_assets(db_session)

    resp = client.post(f"{API}/demo/populate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["created_events"] == 19
    incidents = data["incidents"]
    assert len(incidents) == 7
    severities = {i["severity"] for i in incidents}
    assert "critical" in severities and "low" in severities and "high" in severities
    rules = {i["rule"] for i in incidents}
    assert {"brute_force_attempts", "password_spraying", "privilege_escalation_attempt",
            "repeated_scan", "web_attack", "malware_detection"} <= rules

    # активы привязаны (моки используют seed-имена агентов)
    items = client.get(f"{API}/incidents").json()
    with_assets = [i for i in items if i["asset"]]
    assert len(with_assets) >= 5


# ---------------------------------------------------------------------------
# POST /demo/test-event — случайное тестовое событие из мок-пула (stage-15)
# ---------------------------------------------------------------------------
def test_demo_test_event_structure(client, db_session, monkeypatch, frozen_demo_time):
    """Контракт ответа (scenario/scenario_title/event/result); событие в БД."""
    seed_demo_rules_and_assets(db_session)

    # детерминизм: random.choice всегда берёт первый элемент —
    # первый сценарий, затем первое событие выбранного сценария
    monkeypatch.setattr("app.api.routes.random.choice", lambda seq: seq[0])

    resp = client.post(f"{API}/demo/test-event")
    assert resp.status_code == 200
    data = resp.json()

    scenarios = build_mock_scenarios(FROZEN_NOW)
    assert set(data.keys()) == {"scenario", "scenario_title", "event", "result"}
    assert data["scenario"] == scenarios[0].key
    assert data["scenario_title"] == scenarios[0].title
    assert data["event"] == scenarios[0].events[0]

    # result — ответ конвейера без служебного ключа; одиночное событие
    # не набирает порог brute_force (min_events=3) → инцидент не создаётся
    result = data["result"]
    assert "_auto_analysis_incident_id" not in result
    assert result["correlated"] is False
    assert result["incident_id"] is None

    # событие реально попало в БД
    from app.models import Event
    event = db_session.get(Event, result["event_id"])
    assert event is not None
    assert event.src_ip == data["event"]["data"]["srcip"]
    assert event.user == data["event"]["data"]["dstuser"]


def test_demo_test_event_deterministic(client, db_session, monkeypatch, frozen_demo_time):
    """Подмена random.choice: два вызова дают одно и то же событие (stage-15)."""
    seed_demo_rules_and_assets(db_session)
    monkeypatch.setattr("app.api.routes.random.choice", lambda seq: seq[0])

    first = client.post(f"{API}/demo/test-event").json()
    second = client.post(f"{API}/demo/test-event").json()
    assert first["scenario"] == second["scenario"]
    assert first["scenario_title"] == second["scenario_title"]
    assert first["event"] == second["event"]


def test_demo_test_event_creates_incident(client, db_session, monkeypatch, frozen_demo_time):
    """Сценарий с правилом min_events=1 → correlated=True, инцидент в БД, аудит."""
    seed_demo_rules_and_assets(db_session)

    scenarios = build_mock_scenarios(FROZEN_NOW)
    target = next(s for s in scenarios if s.key == "privilege_escalation")
    picks = iter([target, target.events[0]])
    monkeypatch.setattr("app.api.routes.random.choice", lambda seq: next(picks))

    resp = client.post(f"{API}/demo/test-event")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario"] == "privilege_escalation"
    assert data["result"]["correlated"] is True
    incident_id = data["result"]["incident_id"]
    assert incident_id is not None

    detail = client.get(f"{API}/incidents/{incident_id}")
    assert detail.status_code == 200
    assert len(detail.json()["events"]) == 1

    # аудит зафиксировал генерацию тестового события
    logs = client.get(f"{API}/audit-logs").json()
    entry = next(a for a in logs if a["event_type"] == "test_event_generated")
    assert entry["details"]["scenario"] == "privilege_escalation"
    assert entry["details"]["correlated"] is True
    assert entry["details"]["incident_id"] == incident_id
    assert entry["details"]["event_id"] == data["result"]["event_id"]


def test_demo_test_event_available_to_analyst(client, db_session, monkeypatch, frozen_demo_time):
    """«Тестовое событие» доступно аналитику (get_current_user, не require_admin)."""
    seed_demo_rules_and_assets(db_session)
    monkeypatch.setattr("app.api.routes.random.choice", lambda seq: seq[0])
    app.dependency_overrides[get_current_user] = lambda: User(
        id=2, username="analyst1", role="analyst"
    )
    resp = client.post(f"{API}/demo/test-event")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /incidents?status=&severity= — мультифильтры списка инцидентов (stage-15)
# ---------------------------------------------------------------------------
def _make_incident(db_session, **overrides):
    """Инцидент напрямую в БД — тесты фильтров без полного конвейера."""
    from app.models import Incident

    params = dict(
        title="incident",
        description="d",
        severity="medium",
        status="new",
        risk_score=50,
        created_at=FROZEN_NOW,
    )
    params.update(overrides)
    incident = Incident(**params)
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)
    return incident


def test_incidents_filters(client, db_session):
    """Фильтры status/severity через запятую: вместе, по одному, пустые."""
    _make_incident(db_session, title="crit-new", severity="critical", status="new",
                   created_at=datetime(2026, 1, 3, tzinfo=timezone.utc))
    _make_incident(db_session, title="high-progress", severity="high", status="in_progress",
                   created_at=datetime(2026, 1, 2, tzinfo=timezone.utc))
    _make_incident(db_session, title="low-closed", severity="low", status="closed",
                   created_at=datetime(2026, 1, 1, tzinfo=timezone.utc))

    # оба параметра вместе
    resp = client.get(f"{API}/incidents",
                      params={"status": "new,in_progress", "severity": "high,critical"})
    assert [i["title"] for i in resp.json()] == ["crit-new", "high-progress"]  # created_at desc

    # по одному
    resp = client.get(f"{API}/incidents", params={"status": "closed"})
    assert [i["title"] for i in resp.json()] == ["low-closed"]
    resp = client.get(f"{API}/incidents", params={"severity": "critical,low"})
    assert {i["title"] for i in resp.json()} == {"crit-new", "low-closed"}

    # пустой/отсутствующий параметр — без фильтра (прежнее поведение)
    assert len(client.get(f"{API}/incidents").json()) == 3
    assert len(client.get(f"{API}/incidents", params={"status": ""}).json()) == 3
    assert len(client.get(f"{API}/incidents", params={"severity": ","}).json()) == 3


def test_incidents_filter_invalid_value(client):
    """Недопустимое значение фильтра → 422 с понятным detail (stage-15)."""
    resp = client.get(f"{API}/incidents", params={"status": "archived"})
    assert resp.status_code == 422
    assert "archived" in resp.json()["detail"]

    resp = client.get(f"{API}/incidents", params={"severity": "ultra"})
    assert resp.status_code == 422
    assert "ultra" in resp.json()["detail"]

    # мусор среди валидных значений тоже отклоняется
    resp = client.get(f"{API}/incidents", params={"status": "new,junk"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /ingest/reference — справочник для формы события Wazuh (stage-15)
# ---------------------------------------------------------------------------
def test_ingest_reference_after_ingest(client, db_session):
    """Справочник собирается из событий, условий правил корреляции и активов."""
    from app.models import Asset, CorrelationRule

    db_session.add(CorrelationRule(
        name="in_rule", description="d",
        conditions=[{"field": "event_type", "operator": "in", "value": ["web", "attack"]}],
        time_window_minutes=5, min_events=2, priority=1, is_active=True,
    ))
    db_session.add(CorrelationRule(
        name="like_rule", description="d",
        conditions=[{"field": "event_type", "operator": "like", "value": "malware"}],
        time_window_minutes=5, min_events=1, priority=1, is_active=True,
    ))
    db_session.add(Asset(name="srv-01", type="server", criticality="critical",
                         network_segment="DMZ", ip_addresses="198.51.100.1"))
    db_session.commit()

    alert_with_rule_id = {
        "timestamp": "2026-01-01T10:00:00Z",
        "rule": {"id": "5710", "level": 10, "description": "sshd: authentication failure",
                 "groups": ["syslog", "sshd", "authentication_failed"]},
        "agent": {"id": "001", "name": "mail-prod-01"},
        "data": {"srcip": "198.51.100.7", "dstuser": "root"},
        "full_log": "Failed password",
    }
    client.post(f"{API}/ingest/wazuh", json=alert_with_rule_id)
    # алерт без rule.id и с другим агентом: правило в справочник не попадает,
    # но группы/агент/пользователь/IP дополняются
    client.post(f"{API}/ingest/wazuh", json=make_alert())
    # повтор правила 5710 с другим уровнем — остаётся первая встреченная запись
    repeat = dict(alert_with_rule_id)
    repeat["rule"] = dict(alert_with_rule_id["rule"], level=5)
    client.post(f"{API}/ingest/wazuh", json=repeat)

    resp = client.get(f"{API}/ingest/reference")
    assert resp.status_code == 200
    ref = resp.json()

    assert ref["rules"] == [{
        "id": "5710", "level": 10, "description": "sshd: authentication failure",
        "groups": ["syslog", "sshd", "authentication_failed"],
    }]
    # группы: из событий + из условий правил (in-список раскрыт)
    assert ref["groups"] == sorted(
        {"syslog", "sshd", "authentication_failed", "web", "attack", "malware"}
    )
    assert ref["agents"] == [
        {"id": "001", "name": "mail-prod-01"}, {"id": "001", "name": "test-host"},
    ]
    assert ref["assets"] == [{
        "name": "srv-01", "type": "server", "criticality": "critical",
        "network_segment": "DMZ", "ip_addresses": "198.51.100.1",
    }]
    assert ref["users"] == ["root"]
    assert ref["src_ips"] == ["192.0.2.10", "198.51.100.7"]


def test_ingest_reference_empty_db(client):
    """Справочник на пустой БД — пустые списки, не 500 (stage-15)."""
    resp = client.get(f"{API}/ingest/reference")
    assert resp.status_code == 200
    assert resp.json() == {
        "rules": [], "groups": [], "agents": [],
        "assets": [], "users": [], "src_ips": [],
    }


def test_execute_action_manual(client, db_session):
    """POST /incidents/{id}/execute-action — ручной запуск действия админом (stage-12)."""
    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    # без зарегистрированного playbook действие блокируется с причиной
    blocked = client.post(
        f"{API}/incidents/{incident_id}/execute-action", json={"action": "block_ip"}
    )
    assert blocked.status_code == 200
    assert blocked.json()["validation"]["approved"] is False
    assert blocked.json()["execution"]["mode"] == "blocked"

    # после регистрации playbook — исполняется (simulation)
    client.post(f"{API}/playbooks", json={"name": "block_ip", "allowed_actions": ["block_ip"]})
    ok = client.post(
        f"{API}/incidents/{incident_id}/execute-action", json={"action": "block_ip"}
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["validation"]["approved"] is True
    assert body["execution"]["mode"] == "simulation"
    assert body["action"] == "block_ip"

"""Тесты REST API (app/api/routes.py) через fastapi.testclient.TestClient.

Каждый тест работает с изолированной in-memory SQLite-БД: движок создаётся
со StaticPool, чтобы все соединения (приложение и тестовая сессия) видели
одну и ту же базу. Внешние зависимости изолируются:
- settings.auto_analysis=False — ингест не запускает LLM-анализ;
- Wazuh Manager API подменяется фейком на httpx.MockTransport (общий с
  test_execution.py) — реакции execute-action/confirm-action проходят
  весь реальный конвейер доставки AR-команды без сети;
- app.api.routes.analyze_incident подменяется фейковой async-функцией;
- get_current_user подменяется фейковым админом (механика JWT тестируется
  отдельно в test_auth.py);
- app.db.SessionLocal подменяется сессией тестовой БД — фоновые задачи
  (run_auto_analysis: автоанализ и ручной POST /analyze, stage-18) пишут
  в ту же базу.
"""

from datetime import datetime, timezone

import pytest

from app.config import settings
from app.main import app
from app.models import User
from app.services.auth import get_current_user

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
def client(client):
    """Базовый client (conftest) + обход авторизации: фейковый пользователь
    с ролью admin (реальный флоу JWT тестируется в test_auth.py)."""
    app.dependency_overrides[get_current_user] = lambda: User(
        id=1, username="tester", role="admin"
    )
    yield client


@pytest.fixture(autouse=True)
def wazuh_mock_autouse(wazuh_mock):
    """Автоподмена Wazuh API во всех тестах модуля — общая фикстура wazuh_mock
    из conftest.py (до legacy-cleanup модуль держал собственный дубликат)."""
    return wazuh_mock


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


FROZEN_NOW = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)


def test_health(client):
    """GET /api/v1/health — сервис и БД доступны; настройки автообработки."""
    resp = client.get(f"{API}/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["database"] == "ok"
    # stage-18: автоанализ и автоконвейер — только low; «фильтр автозакрытия»
    assert data["auto_analysis_levels"] == ["low"]
    assert data["auto_close_levels"] == ["low"]


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


def test_analyze_incident_success(client, db_session, engine, monkeypatch):
    """POST /api/v1/incidents/{id}/analyze — анализ уходит в ФОН (stage-18):
    ответ мгновенный (scheduled), фоновая задача доводит до Analysis с
    initiated_by="manual"; инцидент закреплён и переведён в работу."""
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis, Incident

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
    # фоновая задача создаёт свою сессию — направляем её в тестовую БД
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    resp = client.post(f"{API}/incidents/{incident_id}/analyze")
    assert resp.status_code == 200
    assert resp.json() == {"incident_id": incident_id, "analysis": {"scheduled": True}}

    # TestClient выполняет фоновые задачи сразу после ответа — анализ в БД
    analyses = db_session.query(Analysis).filter_by(incident_id=incident_id).all()
    assert len(analyses) == 1
    raw = analyses[0].response_raw
    assert raw["initiated_by"] == "manual"
    assert raw["recommendation"]["attack_type"] == "brute_force"
    assert raw["recommendation"]["recommended_action"] == "monitor"

    # инцидент закреплён за вызвавшим пользователем и в работе;
    # stage-17: high (не из AUTO_CLOSE_LEVELS) — playbook НЕ исполняется
    # автоматически, действие ждёт ручного запуска оператором
    incident = db_session.get(Incident, incident_id)
    assert incident.analyst_id == 1  # фейковый админ из фикстуры client
    assert incident.status == "in_progress"
    assert raw["results"][0]["execution"]["mode"] == "manual_run"
    assert raw["results"][0]["execution"]["executed"] is False

    # результаты анализа доступны в общей статистике качества LLM-модуля
    analyses_api = client.get(f"{API}/analyses").json()
    assert any(a["attack_type"] == "brute_force" for a in analyses_api)

    # аудит: планирование зафиксировано, действие — как ожидающее ручного запуска
    logs = client.get(f"{API}/audit-logs").json()
    assert any(
        a["event_type"] == "incident_analysis_scheduled"
        and a["incident_id"] == incident_id
        and a["details"]["initiated_by"] == "manual"
        and a["details"]["by"] == "tester"
        for a in logs
    )
    assert any(
        a["event_type"] == "action_awaiting_manual_run"
        and a["incident_id"] == incident_id
        and a["details"]["mode"] == "manual_run"
        for a in logs
    )


def test_analysis_context_curated_ecs_and_events_total(client, db_session, engine, monkeypatch):
    """stage-24, принцип «LLM — независимый наблюдатель»: контекст анализа
    содержит только сырые доказательства — служебные поля Wazuh-алерта
    (manager/cluster/input/pre_decode) в ECS не попадают; events_total
    сообщает модели, сколько всего событий в инциденте (в контексте —
    последние 12). Метрики SIEM (риск/правило корреляции) в контекст
    сознательно НЕ передаются — иначе модель повторяла бы вывод конвейера."""
    from sqlalchemy.orm import sessionmaker

    seed_rule(db_session)
    alert = make_alert()
    alert["manager"] = {"name": "wazuh-manager"}
    alert["cluster"] = {"name": "wazuh", "node": "master"}
    alert["input"] = {"type": "log"}
    alert["pre_decode"] = "(sshd: root) junk"
    alert["decoder"] = {"name": "sshd"}
    alert["location"] = "/var/log/auth.log"
    incident_id = None
    for _ in range(2):
        incident_id = client.post(f"{API}/ingest/wazuh", json=alert).json()["incident_id"]

    captured = {}

    async def fake_analyze(context):
        captured.update(context)
        return {
            "description": "тест",
            "attack_type": "brute_force",
            "confidence": 0.5,
            "explanation": "тест",
            "recommended_action": "monitor",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)
    # фоновая задача создаёт свою сессию — направляем её в тестовую БД
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    resp = client.post(f"{API}/incidents/{incident_id}/analyze")
    assert resp.status_code == 200

    assert captured, "фейк analyze_incident должен получить контекст"
    assert captured["events_total"] == 2
    events = captured["events"]
    assert len(events) == 2
    for ev in events:
        ecs = ev["ecs"]
        # доказательные поля источника — на месте
        assert ecs["rule"]["groups"] == ["authentication_failed"]
        assert ecs["agent"]["name"] == "test-host"
        assert ecs["data"]["srcip"]
        assert "Failed password" in ecs["full_log"]
        assert ecs["decoder"]["name"] == "sshd"
        assert ecs["location"] == "/var/log/auth.log"
        # служебный шум Wazuh — отброшен
        for junk in ("manager", "cluster", "input", "pre_decode", "id"):
            assert junk not in ecs
    # метрики SIEM в контексте нет (независимость наблюдателя)
    assert "siem_assessment" not in captured
    assert "severity_factors" not in captured


def test_manual_playbook_execution_for_high(client, db_session, engine, monkeypatch):
    """stage-17/23: для инцидента high анализ только рекомендует (manual_run),
    действие выполняет оператор через POST /execute-action — stage-23:
    исполнение всегда реальное (collect_evidence — пассивное, снимок без
    Wazuh API). Анализ выполняется в фоне (stage-18): POST /analyze отвечает
    scheduled, результат — в БД."""
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis

    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    async def fake_analyze(context):
        return {
            "description": "Подбор пароля",
            "attack_type": "brute_force",
            "confidence": 0.9,
            "explanation": "Много неудачных попыток входа",
            "recommended_action": "collect_evidence",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    resp = client.post(f"{API}/incidents/{incident_id}/analyze")
    assert resp.status_code == 200
    assert resp.json()["analysis"] == {"scheduled": True}

    raw = db_session.query(Analysis).filter_by(incident_id=incident_id).one().response_raw
    assert raw["results"][0]["execution"]["mode"] == "manual_run"

    run = client.post(
        f"{API}/incidents/{incident_id}/execute-action",
        json={"action": "collect_evidence"},
    )
    assert run.status_code == 200
    body = run.json()
    assert body["validation"]["approved"] is True
    # stage-23: collect_evidence — пассивное действие, снимок собирается
    # без вызова Wazuh API
    assert body["execution"]["executed"] is True
    assert body["execution"]["mode"] == "real"


def test_analyze_incident_llm_unavailable(client, db_session, engine, monkeypatch):
    """POST /analyze — 404 без инцидента; для существующего анализ уходит в
    фон (scheduled, stage-18), фоновая задача фиксирует недоступность LLM в
    аудите (llm_analysis_failed) — сам Analysis не создаётся."""
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis

    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    async def failing_analyze(context):
        raise RuntimeError("connection refused")

    monkeypatch.setattr("app.api.routes.analyze_incident", failing_analyze)
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    missing = client.post(f"{API}/incidents/99999/analyze")
    assert missing.status_code == 404

    resp = client.post(f"{API}/incidents/{incident_id}/analyze")
    assert resp.status_code == 200
    assert resp.json()["analysis"] == {"scheduled": True}

    # фоновая задача отработала: анализа нет (LLM недоступен), ошибка — в аудите
    assert db_session.query(Analysis).filter_by(incident_id=incident_id).count() == 0
    logs = client.get(f"{API}/audit-logs").json()
    assert any(
        a["event_type"] == "llm_analysis_failed" and a["incident_id"] == incident_id
        for a in logs
    )


def test_confirm_action_without_analysis(client, db_session):
    """POST /confirm-action — 404 без инцидента и 404 без анализа."""
    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    missing = client.post(f"{API}/incidents/99999/confirm-action")
    assert missing.status_code == 404

    # инцидент существует, но LLM-анализ ещё не выполнялся
    resp = client.post(f"{API}/incidents/{incident_id}/confirm-action")
    assert resp.status_code == 404


def test_confirm_action_updates_saved_analysis(client, db_session, engine, monkeypatch, wazuh_mock):
    """POST /confirm-action (stage-18, фидбек): подтверждение администратором
    перезаписывает response_raw сохранённого анализа — в results появляются
    свежие validation/execution с confirmed_by; плашка «Требуется
    подтверждение» не возвращается после перезагрузки у ЛЮБОГО оператора.
    stage-23: подтверждённое действие исполняется РЕАЛЬНО (Wazuh API — фейк)."""
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis, Asset, Incident

    seed_rule(db_session)
    db_session.add(Asset(name="crit-host", type="server", criticality="critical"))
    db_session.commit()
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]
    incident = db_session.get(Incident, incident_id)
    incident.asset_id = db_session.query(Asset).filter_by(name="crit-host").one().id
    db_session.commit()
    client.post(f"{API}/playbooks", json={"name": "block_ip", "allowed_actions": ["block_ip"]})
    # агент у актива есть — AR-команда доставляется (фейк менеджера)
    wazuh_mock.agents.append({"id": "003", "name": "crit-host", "status": "active"})

    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    async def fake_analyze(context):
        return {
            "description": "d",
            "attack_type": "brute_force",
            "confidence": 0.9,
            "explanation": "e",
            "recommended_action": "block_ip",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    # ручной анализ (stage-18 — в фоне): block_ip на критическом активе
    # отложен до подтверждения администратора
    resp = client.post(f"{API}/incidents/{incident_id}/analyze")
    assert resp.status_code == 200
    assert resp.json()["analysis"] == {"scheduled": True}
    raw = db_session.query(Analysis).filter_by(incident_id=incident_id).one().response_raw
    assert raw["results"][0]["execution"]["mode"] == "pending_confirmation"

    # админ подтверждает — действие исполняется РЕАЛЬНО (stage-23, Wazuh — фейк)
    confirm = client.post(f"{API}/incidents/{incident_id}/confirm-action")
    assert confirm.status_code == 200
    assert confirm.json()["results"][0]["execution"]["mode"] == "real"
    assert confirm.json()["results"][0]["execution"]["executed"] is True

    # сохранённый анализ перезаписан: pending больше нет, есть confirmed_by
    db_session.expire_all()  # объект закэширован сессией — перечитать из БД
    updated = db_session.query(Analysis).filter_by(incident_id=incident_id).one()
    results = updated.response_raw["results"]
    assert results[0]["execution"]["mode"] == "real"
    assert results[0]["execution"]["confirmed_by"] == "tester"
    # верхнеуровневые compat-ключи — от первого confirm-результата
    assert updated.response_raw["validation"]["approved"] is True
    assert updated.response_raw["execution"]["mode"] == "real"
    # условие resultsNeedConfirmation больше не срабатывает
    assert not any(
        r["validation"].get("requires_confirmation")
        or r["execution"].get("mode") == "pending_confirmation"
        for r in results
    )


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


def test_correlation_rule_mitre_fields(client):
    """CRUD правил (stage-17): тактика/техника MITRE и флаг поставщика
    сохраняются и отдаются; неизвестная тактика → 422 (Literal-валидация)."""
    created = client.post(
        f"{API}/correlation-rules",
        json={
            "name": "r_mitre",
            "description": "тест",
            "conditions": [{"field": "event_type", "operator": "like", "value": "auth"}],
            "mitre_tactic": "credential_access",
            "mitre_technique": "T1110",
            "escalated_by_vendor": True,
        },
    )
    assert created.status_code in (200, 201)
    body = created.json()
    assert body["mitre_tactic"] == "credential_access"
    assert body["mitre_technique"] == "T1110"
    assert body["escalated_by_vendor"] is True

    rule = next(r for r in client.get(f"{API}/correlation-rules").json() if r["name"] == "r_mitre")
    assert rule["mitre_tactic"] == "credential_access"
    assert rule["mitre_technique"] == "T1110"
    assert rule["escalated_by_vendor"] is True

    # правила без тактик (например, repeated_scan) отдают None/False
    default = client.post(
        f"{API}/correlation-rules",
        json={"name": "r_plain", "conditions": []},
    )
    assert default.status_code in (200, 201)
    plain = default.json()
    assert plain["mitre_tactic"] is None
    assert plain["mitre_technique"] is None
    assert plain["escalated_by_vendor"] is False

    # неизвестная тактика отвергается схемой (FastAPI → 422)
    bad = client.post(
        f"{API}/correlation-rules",
        json={"name": "r_bad", "conditions": [], "mitre_tactic": "hacking"},
    )
    assert bad.status_code == 422


def test_analyze_multiple_actions(client, db_session, engine, monkeypatch):
    """Перечень действий LLM: каждое проходит DVE, в сохранённом анализе —
    список results (stage-11). Анализ выполняется в фоне (stage-18)."""
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis

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
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    resp = client.post(f"{API}/incidents/{incident_id}/analyze")
    assert resp.status_code == 200
    assert resp.json()["analysis"] == {"scheduled": True}

    # TestClient выполнил фоновую задачу после ответа — проверяем БД
    raw = db_session.query(Analysis).filter_by(incident_id=incident_id).one().response_raw
    results = raw["results"]
    assert len(results) == 2
    assert [r["action"] for r in results] == ["monitor", "collect_evidence"]
    assert all(r["validation"]["approved"] for r in results)
    # перечень сохранён целиком (§3.4, p:15), а не первое действие
    assert raw["recommendation"]["recommended_action"] == "monitor, collect_evidence"
    analyses = client.get(f"{API}/analyses").json()
    assert any(a["recommended_action"] == "monitor, collect_evidence" for a in analyses)


def test_planned_mode_default_low(client, db_session, monkeypatch):
    """Плановый режим (stage-18, фидбек): дефолт AUTO_ANALYSIS_LEVELS="low" —
    автоанализ и автоконвейер ТОЛЬКО для low; medium/high/critical обрабатывает
    оператор (анализ не планируется вовсе)."""
    from app.models import Asset

    seed_rule(db_session)  # правило без тактики — severity по числовой модели
    db_session.add(Asset(name="crit-host", type="server", criticality="critical"))
    # отдельное правило с тактикой для сценария critical (иначе перебивается
    # brute_rule с равным приоритетом)
    seed_rule(
        db_session, name="cred_rule", mitre_tactic="credential_access",
        conditions=[{"field": "event_type", "operator": "like", "value": "web"}],
    )
    db_session.commit()
    monkeypatch.setattr(settings, "auto_analysis", True)  # default levels = "low"

    async def fake_analyze(context):
        # подстраховка: если что-то unexpectedly уйдёт в автоанализ, тест не
        # должен ходить в реальную сеть
        return {
            "description": "d",
            "attack_type": "brute_force",
            "confidence": 0.9,
            "explanation": "e",
            "recommended_action": "monitor",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    # high (level 10 → числовая модель 70) — не анализируется
    high_alert = make_alert(data={"srcip": "192.0.2.11", "dstuser": "u_high"})
    resp_high = client.post(f"{API}/ingest/wazuh", json=high_alert)
    assert resp_high.status_code == 200
    assert resp_high.json()["severity"] == "high"
    assert "analysis" not in resp_high.json()

    # medium (level 7 → 49) — не анализируется
    med_alert = make_alert(
        rule={"level": 7, "description": "test", "groups": ["authentication_failed"]},
        data={"srcip": "192.0.2.12", "dstuser": "u_med"},
    )
    resp_med = client.post(f"{API}/ingest/wazuh", json=med_alert)
    assert resp_med.json()["severity"] == "medium"
    assert "analysis" not in resp_med.json()

    # critical (правило credential_access: high +1 за критичный актив) —
    # stage-18: тоже не анализируется, анализ и playbook делает оператор
    crit_alert = make_alert(
        rule={"level": 10, "description": "test", "groups": ["web"]},
        agent={"id": "003", "name": "crit-host"},
        data={"srcip": "192.0.2.13", "dstuser": "u_crit"},
    )
    resp_crit = client.post(f"{API}/ingest/wazuh", json=crit_alert)
    data_crit = resp_crit.json()
    assert data_crit["severity"] == "critical"
    assert "analysis" not in data_crit
    # инцидент остаётся новым: ничего не анализировалось и не исполнялось
    crit_detail = client.get(f"{API}/incidents/{data_crit['incident_id']}").json()
    assert crit_detail["status"] == "new"
    assert crit_detail["analyses"] == []


def test_planned_mode_levels_include_high(client, db_session, engine, monkeypatch):
    """AUTO_ANALYSIS_LEVELS=critical,high: автоанализ уходит в фон (scheduled),
    фоновая задача с собственной сессией доводит его до Analysis (stage-12)."""
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis, Incident

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
    # stage-17: high не входит в auto_close_levels ("low") — автозакрытия нет
    incident = db_session.get(Incident, data["incident_id"])
    assert incident.status == "in_progress"
    assert "auto_closed" not in (analyses[0].response_raw or {})


# ---------------------------------------------------------------------------
# Автообработка и автозакрытие low-инцидентов (stage-17)
# ---------------------------------------------------------------------------
def _low_alert(**overrides):
    """Алерт, дающий low-инцидент: правило без тактики, агент вне инвентаря,
    низкий level, группа без опасного типа атаки → числовая модель (fallback) → low."""
    alert = make_alert(
        rule={"level": 1, "description": "test", "groups": ["syslog"]},
    )
    alert.update(overrides)
    return alert


def _seed_low_rule(db_session):
    """Активное правило без тактики под события с группой syslog (low-сценарии)."""
    seed_rule(
        db_session,
        conditions=[{"field": "event_type", "operator": "like", "value": "syslog"}],
    )


def test_auto_analysis_closes_low_incident(client, db_session, engine, monkeypatch):
    """Автообработка low (stage-17/18): автоанализ → автозакрытие — статус
    closed, пометка auto_closed в последнем Analysis, аудит и уведомление."""
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis

    _seed_low_rule(db_session)
    monkeypatch.setattr(settings, "auto_analysis", True)  # default levels: low (stage-18)
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    async def fake_analyze(context):
        return {
            "description": "d",
            "attack_type": "scan",
            "confidence": 0.9,
            "explanation": "e",
            "recommended_action": "monitor",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    resp = client.post(f"{API}/ingest/wazuh", json=_low_alert())
    assert resp.status_code == 200
    data = resp.json()
    assert data["severity"] == "low"
    assert data["analysis"] == {"scheduled": True, "severity": "low"}

    incident_id = data["incident_id"]
    detail = client.get(f"{API}/incidents/{incident_id}").json()
    assert detail["status"] == "closed"

    # пометка auto_closed — в ПОСЛЕДНЕМ Analysis (переприсвоение JSON-колонки)
    analyses = db_session.query(Analysis).filter_by(incident_id=incident_id).all()
    assert len(analyses) == 1
    assert analyses[0].response_raw["auto_closed"] is True

    # аудит автозакрытия
    logs = client.get(f"{API}/audit-logs").json()
    entry = next(a for a in logs if a["event_type"] == "incident_auto_closed")
    assert entry["incident_id"] == incident_id
    assert entry["details"]["initiated_by"] == "auto_close"
    assert entry["details"]["severity"] == "low"

    # уведомление о автозакрытии
    notes = client.get(f"{API}/notifications").json()
    assert any(
        n["event_type"] == "incident_auto_closed" and n["incident_id"] == incident_id
        for n in notes
    )


def test_auto_close_skipped_on_pending_confirmation(client, db_session, engine, monkeypatch):
    """Автозакрытие не выполняется при отложенном действии: low-инцидент на
    КРИТИЧЕСКОМ активе, block_ip ждёт подтверждения администратора → инцидент
    остаётся in_progress, пометки auto_closed нет."""
    import asyncio

    from sqlalchemy.orm import sessionmaker

    from app.api.routes import run_auto_analysis
    from app.models import Analysis, Asset, Incident, Playbook, ValidationPolicy

    _seed_low_rule(db_session)
    asset = Asset(name="crit-db", type="server", criticality="critical")
    db_session.add(asset)
    # политика low обычно не разрешает block_ip — для сценария pending
    # разрешаем явно: DVE доходит до проверки критического актива
    db_session.add(
        ValidationPolicy(severity="low", allowed_actions=["monitor", "collect_evidence", "block_ip"])
    )
    db_session.add(Playbook(
        name="block_ip", description="d", trigger_conditions={},
        allowed_actions=["block_ip"], steps=[],
    ))
    db_session.commit()

    resp = client.post(f"{API}/ingest/wazuh", json=_low_alert(agent={"id": "001", "name": "plain-host"}))
    data = resp.json()
    assert data["severity"] == "low"
    incident_id = data["incident_id"]

    # актив привязывается к инциденту после ингеста (в момент ингеста агент
    # вне инвентаря — иначе числовая модель дала бы не low, а critical)
    incident = db_session.get(Incident, incident_id)
    incident.asset_id = asset.id
    db_session.commit()

    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    async def fake_analyze(context):
        return {
            "description": "d",
            "attack_type": "brute_force",
            "confidence": 0.9,
            "explanation": "e",
            "recommended_action": "block_ip",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    # фоновая задача автоанализа запускается напрямую (как из BackgroundTasks)
    asyncio.run(run_auto_analysis(incident_id))

    detail = client.get(f"{API}/incidents/{incident_id}").json()
    assert detail["status"] == "in_progress"  # НЕ closed

    analyses = db_session.query(Analysis).filter_by(incident_id=incident_id).all()
    assert len(analyses) == 1
    assert analyses[0].response_raw["initiated_by"] == "auto_analysis"
    assert "auto_closed" not in analyses[0].response_raw
    # действие действительно отложено до подтверждения администратора
    assert analyses[0].response_raw["execution"]["mode"] == "pending_confirmation"
    # аудита автозакрытия нет, но причина скипа диагностируется в аудите
    # (incident_auto_close_skipped, stage-18)
    logs = client.get(f"{API}/audit-logs").json()
    assert not any(a["event_type"] == "incident_auto_closed" for a in logs)
    skipped = next(a for a in logs if a["event_type"] == "incident_auto_close_skipped")
    assert skipped["incident_id"] == incident_id
    assert skipped["details"]["reason"] == "action_pending_confirmation"
    assert skipped["details"]["detail"] == "block_ip"


def test_auto_close_skipped_on_assigned_analyst(client, db_session, engine, monkeypatch):
    """Автозакрытие не выполняется, если инцидент уже взял аналитик
    (analyst_id заполнен) — инцидент остаётся в работе, причина скипа видна
    в аудите (incident_auto_close_skipped, reason=assigned_to_analyst)."""
    import asyncio

    from sqlalchemy.orm import sessionmaker

    from app.api.routes import run_auto_analysis
    from app.models import Incident, User

    _seed_low_rule(db_session)
    monkeypatch.setattr(settings, "auto_analysis", False)  # анализ запускаем вручную ниже
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    async def fake_analyze(context):
        return {
            "description": "d",
            "attack_type": "scan",
            "confidence": 0.9,
            "explanation": "e",
            "recommended_action": "monitor",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    data = client.post(f"{API}/ingest/wazuh", json=_low_alert()).json()
    incident_id = data["incident_id"]
    # аналитик взял инцидент в работу до анализа
    db_session.add(User(id=5, username="analyst5", role="analyst", password_hash="x"))
    incident = db_session.get(Incident, incident_id)
    incident.analyst_id = 5
    db_session.commit()

    # фоновая задача автоанализа запускается напрямую (как из BackgroundTasks)
    asyncio.run(run_auto_analysis(incident_id))

    detail = client.get(f"{API}/incidents/{incident_id}").json()
    assert detail["status"] == "in_progress"  # анализ прошёл, закрытия нет

    logs = client.get(f"{API}/audit-logs").json()
    assert not any(a["event_type"] == "incident_auto_closed" for a in logs)
    skipped = next(a for a in logs if a["event_type"] == "incident_auto_close_skipped")
    assert skipped["details"]["reason"] == "assigned_to_analyst"
    assert skipped["details"]["detail"] == "analyst5"  # username аналитика


def test_auto_close_disabled_by_empty_levels(client, db_session, engine, monkeypatch):
    """Пустой AUTO_CLOSE_LEVELS — автозакрытие выключено: low-инцидент
    анализируется, но остаётся in_progress."""
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis

    _seed_low_rule(db_session)
    monkeypatch.setattr(settings, "auto_analysis", True)
    monkeypatch.setattr(settings, "auto_close_levels", "")
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    async def fake_analyze(context):
        return {
            "description": "d",
            "attack_type": "scan",
            "confidence": 0.9,
            "explanation": "e",
            "recommended_action": "monitor",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    resp = client.post(f"{API}/ingest/wazuh", json=_low_alert())
    data = resp.json()
    assert data["analysis"] == {"scheduled": True, "severity": "low"}

    detail = client.get(f"{API}/incidents/{data['incident_id']}").json()
    assert detail["status"] == "in_progress"
    analyses = db_session.query(Analysis).filter_by(incident_id=data["incident_id"]).all()
    assert len(analyses) == 1
    assert "auto_closed" not in analyses[0].response_raw


def test_auto_pipeline_low_blocked_action_still_closes(client, db_session, engine, monkeypatch):
    """Автоконвейер low с действием НЕ по политике (stage-18, фидбек): DVE
    блокирует block_ip для low — ЗАБЛОКИРОВАННОЕ действие не исполняется
    (execution.mode == "blocked", а не simulation playbook'а monitor'а),
    но инцидент после успешного анализа всё равно закрывается автоматически."""
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis

    _seed_low_rule(db_session)
    monkeypatch.setattr(settings, "auto_analysis", True)  # default levels: low
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    async def fake_analyze(context):
        # block_ip не входит в политику low → DVE заменяет его на monitor
        return {
            "description": "d",
            "attack_type": "scan",
            "confidence": 0.9,
            "explanation": "e",
            "recommended_action": "block_ip",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    resp = client.post(f"{API}/ingest/wazuh", json=_low_alert())
    assert resp.status_code == 200
    data = resp.json()
    assert data["severity"] == "low"
    incident_id = data["incident_id"]

    analyses = db_session.query(Analysis).filter_by(incident_id=incident_id).all()
    assert len(analyses) == 1
    result = analyses[0].response_raw["results"][0]
    assert result["validation"]["approved"] is False
    assert result["execution"]["mode"] == "blocked"  # не simulation!
    # инцидент всё равно закрыт автоконвейером (pending-действий нет)
    assert analyses[0].response_raw["auto_closed"] is True
    detail = client.get(f"{API}/incidents/{incident_id}").json()
    assert detail["status"] == "closed"


def test_manual_analysis_does_not_auto_close(client, db_session, engine, monkeypatch):
    """Ручной анализ (POST /analyze → initiated_by="manual") НИКОГДА не
    закрывает инцидент автоматически (stage-17/18): даже low из
    AUTO_CLOSE_LEVELS остаётся in_progress."""
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis

    _seed_low_rule(db_session)
    # автоконвейер выключен: ингест low-алерта НЕ планирует автоанализ
    # (иначе инцидент закрылся бы автоматически ещё до ручного запуска);
    # POST /analyze планирует анализ независимо от этой настройки
    monkeypatch.setattr(settings, "auto_analysis", False)
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))

    async def fake_analyze(context):
        return {
            "description": "d",
            "attack_type": "scan",
            "confidence": 0.9,
            "explanation": "e",
            "recommended_action": "monitor",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    resp = client.post(f"{API}/ingest/wazuh", json=_low_alert())
    incident_id = resp.json()["incident_id"]

    # POST /analyze планирует фоновый РУЧНОЙ анализ (TestClient отработал его
    # сразу после ответа)
    resp = client.post(f"{API}/incidents/{incident_id}/analyze")
    assert resp.status_code == 200
    assert resp.json()["analysis"] == {"scheduled": True}

    detail = client.get(f"{API}/incidents/{incident_id}").json()
    assert detail["status"] == "in_progress"  # НЕ closed

    analyses = db_session.query(Analysis).filter_by(incident_id=incident_id).all()
    assert len(analyses) == 1
    assert analyses[0].response_raw["initiated_by"] == "manual"
    assert "auto_closed" not in analyses[0].response_raw


# ---------------------------------------------------------------------------
# Критичность по матрице MITRE в конвейере ингеста (stage-17)
# ---------------------------------------------------------------------------
def test_ingest_severity_by_mitre_matrix(client, db_session, monkeypatch):
    """Severity по матрице: credential_access (high) на критическом активе →
    critical (high +1), на некритичном → high; basis — в аудите risk_calculated."""
    from app.models import Asset

    db_session.add(Asset(name="crit-host", type="server", criticality="critical"))
    db_session.add(Asset(name="med-host", type="server", criticality="medium"))
    seed_rule(
        db_session, name="cred_rule", mitre_tactic="credential_access",
        mitre_technique="T1110",
        conditions=[{"field": "event_type", "operator": "like", "value": "auth"}],
    )
    db_session.commit()

    # критический актив: high +1 за critical_asset → critical
    crit_alert = make_alert(
        agent={"id": "001", "name": "crit-host"},
        data={"srcip": "192.0.2.21", "dstuser": "svc1"},
    )
    crit = client.post(f"{API}/ingest/wazuh", json=crit_alert).json()
    assert crit["severity"] == "critical"

    # некритичный актив: без повышения → high
    med_alert = make_alert(
        agent={"id": "002", "name": "med-host"},
        data={"srcip": "192.0.2.22", "dstuser": "svc2"},
    )
    med = client.post(f"{API}/ingest/wazuh", json=med_alert).json()
    assert med["severity"] == "high"

    logs = client.get(f"{API}/audit-logs").json()
    risk_logs = [a for a in logs if a["event_type"] == "risk_calculated"]

    crit_log = next(a for a in risk_logs if a["incident_id"] == crit["incident_id"])
    assert crit_log["details"]["severity_basis"] == "mitre_matrix"
    assert crit_log["details"]["mitre_tactic"] == "credential_access"
    assert crit_log["details"]["escalation_reasons"] == ["critical_asset"]
    assert crit_log["details"]["risk_score"] == crit["risk_score"]

    med_log = next(a for a in risk_logs if a["incident_id"] == med["incident_id"])
    assert med_log["details"]["severity_basis"] == "mitre_matrix"
    assert med_log["details"]["escalation_reasons"] == []


def test_ingest_severity_fallback_risk_score(client, db_session):
    """Fallback (stage-17): правило без тактики → severity по числовой модели,
    в аудите risk_calculated — severity_basis="risk_score"."""
    seed_rule(db_session)
    data = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()
    assert data["severity"] == "high"  # level 10 → числовая модель 70 → high

    logs = client.get(f"{API}/audit-logs").json()
    risk_log = next(a for a in logs if a["event_type"] == "risk_calculated")
    assert risk_log["details"]["severity_basis"] == "risk_score"
    assert risk_log["details"]["mitre_tactic"] is None
    assert risk_log["details"]["escalation_reasons"] == []


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
    from app.models import Asset

    seed_rule(db_session)
    # актив с агентом (wazuh_mock знает test-host) — иначе real-режим вернёт no_target
    db_session.add(Asset(name="test-host", type="server", criticality="high"))
    db_session.commit()
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    # без зарегистрированного playbook действие блокируется с причиной
    blocked = client.post(
        f"{API}/incidents/{incident_id}/execute-action", json={"action": "block_ip"}
    )
    assert blocked.status_code == 200
    assert blocked.json()["validation"]["approved"] is False
    assert blocked.json()["execution"]["mode"] == "blocked"

    # после регистрации playbook — команда доставляется в Wazuh (фейк, stage-23)
    client.post(f"{API}/playbooks", json={"name": "block_ip", "allowed_actions": ["block_ip"]})
    ok = client.post(
        f"{API}/incidents/{incident_id}/execute-action", json={"action": "block_ip"}
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["validation"]["approved"] is True
    assert body["execution"]["mode"] == "real"
    assert body["execution"]["executed"] is True
    assert body["action"] == "block_ip"


# ---------------------------------------------------------------------------
# Состояние ручных запусков действий на сервере (stage-18, фидбек):
# incident.manual_actions + POST /reset-actions — состояние кнопок видно
# всем операторам
# ---------------------------------------------------------------------------
def test_execute_action_records_manual_state(client, db_session):
    """Успешный ручной запуск действия сохраняет отметку в
    incident.manual_actions: {mode, at, by, target} — доступно всем операторам
    через GET /incidents/{id}. stage-23: отметка только при доставленной
    AR-команде (Wazuh API — фейк)."""
    from app.models import Asset

    seed_rule(db_session)
    db_session.add(Asset(name="test-host", type="server", criticality="high"))
    db_session.commit()
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]
    client.post(f"{API}/playbooks", json={"name": "block_ip", "allowed_actions": ["block_ip"]})

    resp = client.post(
        f"{API}/incidents/{incident_id}/execute-action", json={"action": "block_ip"}
    )
    assert resp.status_code == 200
    assert resp.json()["execution"]["mode"] == "real"
    assert resp.json()["execution"]["executed"] is True

    detail = client.get(f"{API}/incidents/{incident_id}").json()
    mark = detail["manual_actions"]["block_ip"]
    assert mark["mode"] == "real"
    assert mark["by"] == "tester"  # фейковый пользователь из фикстуры client
    assert mark["at"]  # момент запуска зафиксирован
    assert mark["target"] == "192.0.2.10"  # цель реакции (stage-23)


def test_execute_action_blocked_and_pending_do_not_record(client, db_session):
    """Заблокированное DVE действие и отложенное до подтверждения
    НЕ сохраняют отметку в manual_actions — она пишется только при
    фактическом исполнении (доставленной AR-команде, stage-23)."""
    from app.models import Asset, Incident, Playbook

    seed_rule(db_session)

    # blocked: disable_account не входит в политику high
    blocked_id = client.post(
        f"{API}/ingest/wazuh", json=make_alert(data={"srcip": "192.0.2.21", "dstuser": "b"})
    ).json()["incident_id"]
    blocked = client.post(
        f"{API}/incidents/{blocked_id}/execute-action", json={"action": "disable_account"}
    )
    assert blocked.json()["execution"]["mode"] == "blocked"
    assert not client.get(f"{API}/incidents/{blocked_id}").json()["manual_actions"]

    # pending_confirmation: аналитик + критический актив + block_ip
    db_session.add(Playbook(
        name="block_ip", description="d", trigger_conditions={},
        allowed_actions=["block_ip"], steps=[],
    ))
    asset = Asset(name="crit-db", type="server", criticality="critical")
    db_session.add(asset)
    db_session.commit()
    pending_id = client.post(
        f"{API}/ingest/wazuh", json=make_alert(data={"srcip": "192.0.2.22", "dstuser": "p"})
    ).json()["incident_id"]
    incident = db_session.get(Incident, pending_id)
    incident.asset_id = asset.id
    db_session.commit()

    app.dependency_overrides[get_current_user] = lambda: User(
        id=2, username="analyst1", role="analyst"
    )
    pending = client.post(
        f"{API}/incidents/{pending_id}/execute-action", json={"action": "block_ip"}
    )
    assert pending.json()["execution"]["mode"] == "pending_confirmation"
    assert not client.get(f"{API}/incidents/{pending_id}").json()["manual_actions"]


def test_reset_actions_clears_manual_state_and_audits(client, db_session):
    """POST /incidents/{id}/reset-actions (stage-18 + откат stage-23): сброс
    отметок manual_actions с аудитом; реальная реакция отменяется обратной
    AR-командой (best-effort), результаты — в ответе."""
    from app.models import Asset, Incident

    seed_rule(db_session)
    db_session.add(Asset(name="test-host", type="server", criticality="high"))
    db_session.commit()
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]
    client.post(f"{API}/playbooks", json={"name": "block_ip", "allowed_actions": ["block_ip"]})
    client.post(f"{API}/incidents/{incident_id}/execute-action", json={"action": "block_ip"})

    resp = client.post(f"{API}/incidents/{incident_id}/reset-actions")
    assert resp.status_code == 200
    data = resp.json()
    assert data["reset"] is True
    assert data["manual_actions"] == {}
    # реальная реакция block_ip отменена обратной командой (delete)
    assert len(data["undo"]) == 1
    assert data["undo"][0]["action"] == "block_ip"
    assert data["undo"][0]["executed"] is True

    # состояние в БД очищено (полное переприсвоение JSON-колонки)
    assert db_session.get(Incident, incident_id).manual_actions == {}

    logs = client.get(f"{API}/audit-logs").json()
    entry = next(a for a in logs if a["event_type"] == "incident_actions_reset")
    assert entry["incident_id"] == incident_id
    assert entry["details"]["by"] == "tester"

    # повторный сброс на пустых отметках тоже успешен (undo пуст — всё отменено)
    assert client.post(f"{API}/incidents/{incident_id}/reset-actions").status_code == 200


def test_reset_actions_permissions(client, db_session):
    """Права reset-actions (stage-18): свободный инцидент — любой аналитик,
    владение НЕ захватывается; чужой закреплённый — 403; админ — без
    ограничений; закрытый инцидент — 409 (как у операций реагирования)."""
    from app.models import Incident

    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    # аналитик берёт инцидент в работу (execute-action закрепляет)
    app.dependency_overrides[get_current_user] = lambda: User(
        id=2, username="analyst1", role="analyst"
    )
    assert client.post(
        f"{API}/incidents/{incident_id}/execute-action", json={"action": "monitor"}
    ).status_code == 200
    assert db_session.get(Incident, incident_id).analyst_id == 2

    # чужой закреплённый инцидент: другой аналитик → 403
    app.dependency_overrides[get_current_user] = lambda: User(
        id=3, username="analyst2", role="analyst"
    )
    assert client.post(f"{API}/incidents/{incident_id}/reset-actions").status_code == 403

    # админ работает с любым инцидентом
    app.dependency_overrides[get_current_user] = lambda: User(
        id=1, username="tester", role="admin"
    )
    assert client.post(f"{API}/incidents/{incident_id}/reset-actions").status_code == 200

    # свободный инцидент: сброс доступен любому аналитику, analyst_id не
    # заполняется (assign=False)
    free_id = client.post(
        f"{API}/ingest/wazuh",
        json=make_alert(data={"srcip": "192.0.2.99", "dstuser": "free"}),
    ).json()["incident_id"]
    app.dependency_overrides[get_current_user] = lambda: User(
        id=3, username="analyst2", role="analyst"
    )
    assert client.post(f"{API}/incidents/{free_id}/reset-actions").status_code == 200
    assert db_session.get(Incident, free_id).analyst_id is None

    # закрытый инцидент — 409
    app.dependency_overrides[get_current_user] = lambda: User(
        id=1, username="tester", role="admin"
    )
    assert client.patch(
        f"{API}/incidents/{free_id}/status", json={"status": "closed"}
    ).status_code == 200
    assert client.post(f"{API}/incidents/{free_id}/reset-actions").status_code == 409


# ---------------------------------------------------------------------------
# Закрытый инцидент — операции реагирования запрещены, доступен только
# возврат в работу (stage-16, фидбек)
# ---------------------------------------------------------------------------
def test_closed_incident_allows_only_reopen(client, db_session, engine, monkeypatch):
    """Закрытый инцидент: анализ/действие/подтверждение/сброс действий → 409;
    из статусов доступен только переход в in_progress; после reopen анализ
    работает (в фоне — scheduled)."""
    seed_rule(db_session)
    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]

    # рекомендация с действием — чтобы confirm-action доходил до проверки
    # закрытия, а не падал раньше на «No pending recommendation found» (404)
    from sqlalchemy.orm import sessionmaker

    from app.models import Analysis

    db_session.add(Analysis(
        incident_id=incident_id, model="test-model", prompt="p", description="d",
        recommended_action="monitor",
    ))
    db_session.commit()

    assert client.patch(
        f"{API}/incidents/{incident_id}/status", json={"status": "closed"}
    ).status_code == 200

    base = f"{API}/incidents/{incident_id}"

    # манипуляции с закрытым инцидентом запрещены
    blocked = client.post(f"{base}/analyze")
    assert blocked.status_code == 409
    assert "закрыт" in blocked.json()["detail"]
    blocked = client.post(f"{base}/execute-action", json={"action": "monitor"})
    assert blocked.status_code == 409
    assert "закрыт" in blocked.json()["detail"]
    blocked = client.post(f"{base}/confirm-action")
    assert blocked.status_code == 409
    assert "закрыт" in blocked.json()["detail"]

    # из закрытого статуса разрешён только возврат в работу
    assert client.patch(f"{base}/status", json={"status": "new"}).status_code == 409
    assert client.patch(f"{base}/status", json={"status": "closed"}).status_code == 409
    assert client.patch(f"{base}/status", json={"status": "in_progress"}).status_code == 200

    # после возврата в работу анализ снова доступен (LLM замокан — без сети);
    # фоновая задача (stage-18) направляется в тестовую БД
    async def fake_analyze(context):
        return {
            "description": "Подбор пароля",
            "attack_type": "brute_force",
            "confidence": 0.9,
            "explanation": "Много неудачных попыток входа",
            "recommended_action": "monitor",
        }

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)
    monkeypatch.setattr("app.db.SessionLocal", sessionmaker(bind=engine))
    resp = client.post(f"{base}/analyze")
    assert resp.status_code == 200
    assert resp.json()["analysis"] == {"scheduled": True}

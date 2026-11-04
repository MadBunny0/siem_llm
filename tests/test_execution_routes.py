"""Тесты REST API реального исполнения (stage-20): /execution-targets и
POST /execute-action с mode="real".

Сетевых вызовов нет: httpx подменяется фейком; диспетчер execute_real_action
подменяется для тестов маршрутизации режима (сам диспетчер — test_execution.py).
Фикстуры — локальные копии шаблона test_routes.py (конфликтов с conftest
других веток нет; реальный JWT-флоу — test_auth.py).
"""

from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.db import get_db
from app.main import app
from app.models import Asset, Base, ExecutionTarget, Incident, User
from app.services.auth import get_current_user
from tests.test_routes import API, seed_rule  # общий API-префикс и seed правила корреляции


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
    """TestClient с подменой get_db на тестовую БД + обход авторизации
    (фейковый admin — как в test_routes.py)."""
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
    app.dependency_overrides[get_current_user] = lambda: User(
        id=1, username="tester", role="admin"
    )
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def db_session(engine):
    """Прямая сессия к той же БД — для подготовки данных."""
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeClient:
    calls: list = []
    payload: dict = {"status": "online", "hostname": "wks-finance-12"}
    error: Exception | None = None

    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, url, headers=None):
        FakeClient.calls.append({"method": "GET", "url": url})
        if FakeClient.error is not None:
            raise FakeClient.error
        return FakeResponse(FakeClient.payload)

    def post(self, url, json=None, headers=None):
        FakeClient.calls.append({"method": "POST", "url": url, "json": json})
        if FakeClient.error is not None:
            raise FakeClient.error
        return FakeResponse(FakeClient.payload)


@pytest.fixture(autouse=True)
def fake_httpx(monkeypatch):
    """httpx подменяется во всех тестах модуля (в execution_routes и в
    services.execution — общие классы фейка)."""
    FakeClient.calls = []
    FakeClient.payload = {"status": "online", "hostname": "wks-finance-12"}
    FakeClient.error = None
    monkeypatch.setattr(httpx, "Client", FakeClient)
    yield


def make_target(db, asset_id=None, name="wks-finance-12"):
    target = ExecutionTarget(
        name=name,
        asset_id=asset_id,
        base_url=f"http://agent-{name}:8100",
        auth_token="tok",
        platform="container",
        adapter="state",
    )
    db.add(target)
    db.flush()
    return target


def make_incident(db, asset: Asset | None = None, severity="high"):
    incident = Incident(
        title="Подбор пароля",
        description="test",
        severity=severity,
        asset_id=asset.id if asset else None,
    )
    db.add(incident)
    db.flush()
    return incident


# ---------------------------------------------------------------------------
# GET /execution-targets
# ---------------------------------------------------------------------------
def test_execution_targets_empty(client, db_session):
    response = client.get(f"{API}/execution-targets")
    assert response.status_code == 200
    assert response.json() == []


def test_execution_targets_list(client, db_session):
    asset = Asset(name="wks-finance-12", type="workstation", criticality="medium")
    db_session.add(asset)
    db_session.flush()
    make_target(db_session, asset_id=asset.id)

    response = client.get(f"{API}/execution-targets")
    assert response.status_code == 200
    targets = response.json()
    assert len(targets) == 1
    assert targets[0]["name"] == "wks-finance-12"
    assert targets[0]["asset_id"] == asset.id
    assert targets[0]["status"] == "unknown"
    # токен не отдаётся наружу
    assert "auth_token" not in targets[0]


# ---------------------------------------------------------------------------
# POST /execution-targets/{id}/check (heartbeat)
# ---------------------------------------------------------------------------
def test_check_target_online(client, db_session):

    target = make_target(db_session)
    response = client.post(f"{API}/execution-targets/{target.id}/check")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["last_seen"] is not None
    assert FakeClient.calls[0]["url"].endswith("/agent/status")


def test_check_target_offline_502(client, db_session):

    class Err(Exception):
        pass

    target = make_target(db_session)
    FakeClient.error = Err("connection refused")
    response = client.post(f"{API}/execution-targets/{target.id}/check")
    assert response.status_code == 502
    db_session.expire_all()
    assert db_session.get(ExecutionTarget, target.id).status == "offline"


def test_check_target_404(client, db_session):

    assert client.post(f"{API}/execution-targets/999/check").status_code == 404


# ---------------------------------------------------------------------------
# Журнал и сброс через прокси (токен не покидает бэкенд)
# ---------------------------------------------------------------------------
def test_target_journal_proxy(client, db_session):

    target = make_target(db_session)
    FakeClient.payload = {
        "journal": [
            {
                "at": "2026-11-05T10:00:00+00:00",
                "action": "block_ip",
                "params": {"ip": "203.0.113.66"},
                "executed": True,
                "requested_by": "analyst1",
                "incident_id": 5,
                "detail": "IP-адрес 203.0.113.66 заблокирован",
            }
        ]
    }
    response = client.get(f"{API}/execution-targets/{target.id}/journal")
    assert response.status_code == 200
    entries = response.json()
    assert entries[0]["action"] == "block_ip"
    assert entries[0]["params"]["ip"] == "203.0.113.66"


def test_target_reset_proxy(client, db_session):

    target = make_target(db_session)
    response = client.post(f"{API}/execution-targets/{target.id}/reset")
    assert response.status_code == 200
    assert response.json()["status"] == "online"
    assert FakeClient.calls[0]["url"].endswith("/agent/reset")


def add_playbook(db, action="block_ip"):
    """DVE требует зарегистрированный playbook для активного действия."""
    from app.models import Playbook

    playbook = Playbook(
        name=f"pb_{action}",
        description=f"Сценарий {action}",
        trigger_conditions={},
        allowed_actions=[action],
        steps=[{"action": action}],
    )
    db.add(playbook)
    db.flush()
    return playbook


# ---------------------------------------------------------------------------
# POST /execute-action mode="real"
# ---------------------------------------------------------------------------
def test_execute_action_mode_real_calls_dispatcher(client, db_session, monkeypatch):

    seed_rule(db_session)
    add_playbook(db_session)
    asset = Asset(name="wks-finance-12", type="workstation", criticality="medium")
    db_session.add(asset)
    db_session.flush()
    incident = make_incident(db_session, asset)

    calls = []

    def fake_dispatch(db, incident_obj, action, requested_by=None):
        calls.append({"action": action, "by": requested_by})
        return {
            "executed": True,
            "mode": "real",
            "action": action,
            "result": "Действие выполнено на: wks-finance-12",
            "targets": [{"target": "wks-finance-12", "executed": True}],
        }

    monkeypatch.setattr("app.api.routes.execute_real_action", fake_dispatch)

    response = client.post(
        f"{API}/incidents/{incident.id}/execute-action",
        json={"action": "block_ip", "mode": "real"},
    )
    assert response.status_code == 200
    execution = response.json()["execution"]
    assert execution["mode"] == "real"
    assert execution["executed"] is True
    assert calls and calls[0]["action"] == "block_ip"
    # отметка ручного запуска — с режимом real
    db_session.expire_all()
    incident = db_session.get(Incident, incident.id)
    assert incident.manual_actions["block_ip"]["mode"] == "real"


def test_execute_action_mode_real_failed_not_marked(client, db_session, monkeypatch):
    """real с недоступной целью: отметка manual_actions НЕ ставится — кнопка
    остаётся доступной для повторного запуска."""

    seed_rule(db_session)
    asset = Asset(name="wks-finance-12", type="workstation", criticality="medium")
    db_session.add(asset)
    db_session.flush()
    incident = make_incident(db_session, asset)

    def fake_dispatch(db, incident_obj, action, requested_by=None):
        return {
            "executed": False,
            "mode": "real",
            "action": action,
            "reason": "no_target",
            "result": "Реальное исполнение недоступно",
            "targets": [],
        }

    monkeypatch.setattr("app.api.routes.execute_real_action", fake_dispatch)

    response = client.post(
        f"{API}/incidents/{incident.id}/execute-action",
        json={"action": "block_ip", "mode": "real"},
    )
    assert response.status_code == 200
    db_session.expire_all()
    incident = db_session.get(Incident, incident.id)
    assert not (incident.manual_actions or {}).get("block_ip")


def test_execute_action_invalid_mode_422(client, db_session):

    asset = Asset(name="wks-finance-12", type="workstation", criticality="medium")
    db_session.add(asset)
    db_session.flush()
    incident = make_incident(db_session, asset)

    response = client.post(
        f"{API}/incidents/{incident.id}/execute-action",
        json={"action": "block_ip", "mode": "destroy"},
    )
    assert response.status_code == 422


def test_execute_action_simulation_default_unchanged(client, db_session):
    """Без mode — прежняя симуляция (совместимость stage-12…18)."""

    seed_rule(db_session)
    add_playbook(db_session)
    asset = Asset(name="wks-finance-12", type="workstation", criticality="medium")
    db_session.add(asset)
    db_session.flush()
    incident = make_incident(db_session, asset)

    response = client.post(
        f"{API}/incidents/{incident.id}/execute-action",
        json={"action": "block_ip"},
    )
    assert response.status_code == 200
    execution = response.json()["execution"]
    assert execution["mode"] == "simulation"

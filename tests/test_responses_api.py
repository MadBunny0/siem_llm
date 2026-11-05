"""Тесты REST API реального исполнения (stage-23): POST /execute-action с
mode="real", POST /reset-actions с откатом AR-реакций и GET /responses/state
(вкладка «Реакции (ВМ)»).

Сетевых вызовов нет: Wazuh API подменяется фейком на httpx.MockTransport
(общий с test_execution.py, автооткат); диспетчер execute_real_action
подменяется для тестов маршрутизации режима (сам диспетчер — test_execution.py).
"""

import httpx
import pytest

import app.services.wazuh_api as wazuh_api
from app.models import Incident, ResponseAction
from app.services.auth import get_current_user
from app.services.execution import execute_real_action, undo_incident_real_actions
from tests.test_execution import MockWazuhAPI, add_playbook, make_incident
from tests.test_routes import API, seed_rule  # общий API-префикс и seed правила корреляции


@pytest.fixture
def client(client):
    """Базовый client (conftest) + обход авторизации: фейковый пользователь
    с ролью admin — как в test_routes.py (реальный JWT-флоу — test_auth.py)."""
    from app.main import app
    from app.models import User

    app.dependency_overrides[get_current_user] = lambda: User(
        id=1, username="tester", role="admin"
    )
    yield client


@pytest.fixture(autouse=True)
def mock_api(monkeypatch):
    """Wazuh API подменяется во всех тестах модуля (общий фейк с test_execution)."""
    api = MockWazuhAPI()

    def create_client():
        return httpx.Client(
            transport=httpx.MockTransport(api.handler),
            base_url="https://wazuh-mock:55000",
            timeout=5,
        )

    monkeypatch.setattr(wazuh_api, "_create_client", create_client)
    yield api


# ---------------------------------------------------------------------------
# POST /execute-action — исполнение всегда реальное (stage-23)
# ---------------------------------------------------------------------------
def test_execute_action_mode_real_calls_dispatcher(client, db_session, monkeypatch):
    seed_rule(db_session)
    add_playbook(db_session)
    incident, _ = make_incident(db_session)

    calls = []

    def fake_dispatch(db, incident_obj, action, requested_by=None, playbook=None):
        calls.append({"action": action, "by": requested_by})
        return {
            "executed": True,
            "mode": "real",
            "action": action,
            "result": "Команда block-ip add 192.168.56.102 принята Wazuh Manager",
            "target": "192.168.56.102",
            "targets": [{"target": "mail-prod-01", "agent_id": "001", "executed": True}],
        }

    monkeypatch.setattr("app.api.incident_routes.execute_real_action", fake_dispatch)

    response = client.post(
        f"{API}/incidents/{incident.id}/execute-action",
        json={"action": "block_ip"},
    )
    assert response.status_code == 200
    execution = response.json()["execution"]
    assert execution["mode"] == "real"
    assert execution["executed"] is True
    assert calls and calls[0]["action"] == "block_ip"
    # отметка ручного запуска — с режимом real и целью реакции (stage-23)
    db_session.expire_all()
    incident = db_session.get(Incident, incident.id)
    assert incident.manual_actions["block_ip"]["mode"] == "real"
    assert incident.manual_actions["block_ip"]["target"] == "192.168.56.102"


def test_execute_action_mode_real_end_to_end_via_mock_api(client, db_session):
    """Реальный диспетчер + фейковый Wazuh API: команда доставлена, отметка
    manual_actions содержит цель. Поле mode в запросе больше нет — исполнение
    всегда реальное (stage-23)."""
    seed_rule(db_session)
    add_playbook(db_session)
    incident, _ = make_incident(db_session)

    response = client.post(
        f"{API}/incidents/{incident.id}/execute-action",
        json={"action": "block_ip"},
    )
    assert response.status_code == 200
    execution = response.json()["execution"]
    assert execution["executed"] is True
    assert execution["target"] == "192.168.56.102"
    db_session.expire_all()
    incident = db_session.get(Incident, incident.id)
    assert incident.manual_actions["block_ip"]["mode"] == "real"
    assert incident.manual_actions["block_ip"]["target"] == "192.168.56.102"


def test_execute_action_mode_real_failed_not_marked(client, db_session):
    """Без агента у актива: отметка manual_actions НЕ ставится — кнопка
    остаётся доступной для повторного запуска."""
    seed_rule(db_session)
    add_playbook(db_session)
    # актив без wazuh-агента (в фейке только mail-prod-01 / wks-finance-12)
    incident, _ = make_incident(db_session, asset_name="db-primary-01")

    response = client.post(
        f"{API}/incidents/{incident.id}/execute-action",
        json={"action": "block_ip"},
    )
    assert response.status_code == 200
    execution = response.json()["execution"]
    assert execution["executed"] is False
    assert execution["reason"] == "no_target"
    db_session.expire_all()
    incident = db_session.get(Incident, incident.id)
    assert not (incident.manual_actions or {}).get("block_ip")


# ---------------------------------------------------------------------------
# POST /reset-actions — откат реальных реакций (stage-23)
# ---------------------------------------------------------------------------
def test_reset_actions_performs_undo(client, db_session):
    seed_rule(db_session)
    add_playbook(db_session)
    incident, _ = make_incident(db_session)
    execute_real_action(db_session, incident, "block_ip", requested_by="tester")
    db_session.commit()

    response = client.post(f"{API}/incidents/{incident.id}/reset-actions")

    assert response.status_code == 200
    data = response.json()
    assert data["reset"] is True
    assert data["manual_actions"] == {}
    assert len(data["undo"]) == 1
    assert data["undo"][0]["action"] == "block_ip"
    assert data["undo"][0]["executed"] is True
    db_session.expire_all()
    record = db_session.query(ResponseAction).first()
    assert record.metadata_json["undone_at"] is not None
    assert record.metadata_json["undone_by"] == "tester"
    # отметка manual_actions очищена
    incident = db_session.get(Incident, incident.id)
    assert incident.manual_actions == {}


def test_reset_actions_without_real_records(client, db_session):
    """Нет реальных реакций — undo пуст, прежняя семантика сброса сохранена."""
    incident, _ = make_incident(db_session)

    response = client.post(f"{API}/incidents/{incident.id}/reset-actions")

    assert response.status_code == 200
    data = response.json()
    assert data["undo"] == []


# ---------------------------------------------------------------------------
# GET /responses/state — сводка активных реакций (stage-23)
# ---------------------------------------------------------------------------
def test_responses_state_aggregates_active(client, db_session):
    add_playbook(db_session, "block_ip")
    add_playbook(db_session, "monitor")
    incident_a, _ = make_incident(db_session)  # mail-prod-01
    incident_b, _ = make_incident(db_session, asset_name="wks-finance-12")
    execute_real_action(db_session, incident_a, "block_ip", requested_by="soc_lead")
    execute_real_action(db_session, incident_a, "monitor", requested_by="analyst1")
    # реакция инцидента B отменена («Сбросить реакции») — в сводку не попадает
    execute_real_action(db_session, incident_b, "block_ip", requested_by="soc_lead")
    undo_incident_real_actions(db_session, incident_b, requested_by="soc_lead")
    db_session.commit()

    response = client.get(f"{API}/responses/state")

    assert response.status_code == 200
    items = response.json()
    # активная группировка одна: инцидент B полностью отменён
    assert len(items) == 1
    assert items[0]["asset"] == "mail-prod-01"
    assert items[0]["incident_id"] == incident_a.id
    # действия в порядке исполнения; у пассивного monitor цели нет
    assert [a["action"] for a in items[0]["actions"]] == ["block_ip", "monitor"]
    assert items[0]["actions"][0]["target"] == "192.168.56.102"
    assert items[0]["actions"][0]["by"] == "soc_lead"
    assert items[0]["actions"][1]["target"] is None


def test_responses_state_empty(client, db_session):
    response = client.get(f"{API}/responses/state")
    assert response.status_code == 200
    assert response.json() == []

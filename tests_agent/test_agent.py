"""Тесты endpoint-агента ВМ наблюдаемого пользователя (stage-20, agent/).

Сетевых вызовов нет: send_to_siem подменяется фейком (simulate), прочие
эндпоинты локальные. Агент перезагружается с тестовыми env (importlib.reload)
— каждый тест получает чистое in-memory состояние узла.
"""

import importlib

import pytest
from fastapi.testclient import TestClient

import activity as activity_module
import main as agent_main


@pytest.fixture
def client(monkeypatch):
    """Агент с токеном авторизации — основные тесты действий."""
    monkeypatch.setenv("AGENT_TOKEN", "test-token")
    monkeypatch.setenv("AGENT_HOSTNAME", "wks-finance-12")
    monkeypatch.setenv("AGENT_ADAPTER", "state")
    monkeypatch.delenv("AGENT_STATE_FILE", raising=False)
    module = importlib.reload(agent_main)
    yield TestClient(module.app)


@pytest.fixture
def client_noauth(monkeypatch):
    """Агент без AGENT_TOKEN (отладочный режим: мутации открыты)."""
    monkeypatch.delenv("AGENT_TOKEN", raising=False)
    monkeypatch.setenv("AGENT_HOSTNAME", "wks-finance-12")
    module = importlib.reload(agent_main)
    yield TestClient(module.app)


def _auth(client):
    return {"Authorization": "Bearer test-token"}


# ---------------------------------------------------------------------------
# Статус / доступность
# ---------------------------------------------------------------------------
def test_health(client):
    response = client.get("/agent/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "hostname": "wks-finance-12"}


def test_status_open_endpoint(client):
    """GET /agent/status открыт (без токена) — демонстрация состояния ВМ."""
    response = client.get("/agent/status")
    assert response.status_code == 200
    data = response.json()
    assert data["hostname"] == "wks-finance-12"
    assert data["status"] == "online"
    assert data["isolated"] is False
    assert data["adapter"] == "state"
    assert "alice" in data["accounts"]


def test_journal_requires_token(client):
    assert client.get("/agent/journal").status_code == 401
    assert client.get("/agent/journal", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_action_requires_token(client):
    response = client.post("/agent/action", json={"action": "block_ip", "params": {"ip": "1.2.3.4"}})
    assert response.status_code == 401


def test_noauth_mode_allows_action(client_noauth):
    """Пустой AGENT_TOKEN — отладочный режим без авторизации (документировано)."""
    response = client_noauth.post(
        "/agent/action", json={"action": "block_ip", "params": {"ip": "203.0.113.66"}}
    )
    assert response.status_code == 200
    assert response.json()["executed"] is True


# ---------------------------------------------------------------------------
# Действия playbook: состояние ВМ реально меняется
# ---------------------------------------------------------------------------
def test_block_ip_adds_firewall_rule(client):
    response = client.post(
        "/agent/action",
        json={"action": "block_ip", "params": {"ip": "203.0.113.66"}, "requested_by": "analyst1", "incident_id": 7},
        headers=_auth(client),
    )
    assert response.status_code == 200
    assert response.json()["executed"] is True

    status = client.get("/agent/status").json()
    assert any(rule["ip"] == "203.0.113.66" for rule in status["firewall_rules"])

    journal = client.get("/agent/journal", headers=_auth(client)).json()["journal"]
    assert journal[0]["action"] == "block_ip"
    assert journal[0]["requested_by"] == "analyst1"
    assert journal[0]["incident_id"] == 7
    assert journal[0]["executed"] is True


def test_block_ip_duplicate_is_idempotent(client):
    headers = _auth(client)
    client.post("/agent/action", json={"action": "block_ip", "params": {"ip": "203.0.113.66"}}, headers=headers)
    response = client.post("/agent/action", json={"action": "block_ip", "params": {"ip": "203.0.113.66"}}, headers=headers)
    assert response.status_code == 200
    assert "уже заблокирован" in response.json()["result"]


def test_disable_account_locks_user(client):
    response = client.post(
        "/agent/action", json={"action": "disable_account", "params": {"user": "alice"}}, headers=_auth(client)
    )
    assert response.json()["executed"] is True
    status = client.get("/agent/status").json()
    assert status["accounts"]["alice"]["status"] == "locked"


def test_enable_account_restores_user(client):
    headers = _auth(client)
    client.post("/agent/action", json={"action": "disable_account", "params": {"user": "bob"}}, headers=headers)
    response = client.post("/agent/action", json={"action": "enable_account", "params": {"user": "bob"}}, headers=headers)
    assert response.json()["executed"] is True
    assert client.get("/agent/status").json()["accounts"]["bob"]["status"] == "active"


def test_isolate_host_and_release(client):
    headers = _auth(client)
    response = client.post("/agent/action", json={"action": "isolate_host", "params": {}}, headers=headers)
    assert "изолирован" in response.json()["result"]
    assert client.get("/agent/status").json()["isolated"] is True

    response = client.post("/agent/action", json={"action": "release_host", "params": {}}, headers=headers)
    assert "снята" in response.json()["result"]
    assert client.get("/agent/status").json()["isolated"] is False


def test_collect_evidence_executed(client):
    response = client.post("/agent/action", json={"action": "collect_evidence", "params": {}}, headers=_auth(client))
    assert response.json()["executed"] is True
    assert "Снимок" in response.json()["result"]


def test_unknown_action_not_executed(client):
    response = client.post("/agent/action", json={"action": "format_disk", "params": {}}, headers=_auth(client))
    assert response.status_code == 200
    assert response.json()["executed"] is False


def test_reset_restores_initial_state(client):
    headers = _auth(client)
    client.post("/agent/action", json={"action": "block_ip", "params": {"ip": "203.0.113.66"}}, headers=headers)
    client.post("/agent/action", json={"action": "disable_account", "params": {"user": "alice"}}, headers=headers)
    assert client.post("/agent/reset", headers=headers).status_code == 200

    status = client.get("/agent/status").json()
    assert status["firewall_rules"] == []
    assert status["accounts"]["alice"]["status"] == "active"


# ---------------------------------------------------------------------------
# Симуляция активности (сетевых вызовов нет — send_to_siem подменён)
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_siem(monkeypatch):
    """Подмена отправки в SIEM: фиксирует алерты, возвращает ответ /ingest/wazuh."""
    sent_alerts = []

    def fake_send(siem_url, alert, timeout=5.0):
        sent_alerts.append({"siem_url": siem_url, "alert": alert})
        return True, {"correlated": False, "incident_id": None}

    monkeypatch.setattr(activity_module, "send_to_siem", fake_send)
    return sent_alerts


def test_simulate_attack_scenario(client, fake_siem):
    response = client.post(
        "/agent/simulate", json={"scenario": "brute_force", "count": 4}, headers=_auth(client)
    )
    assert response.status_code == 200
    data = response.json()
    assert data["sent"] == 4
    assert data["failed"] == 0
    # алерты формата Wazuh ушли по SIEM_URL (путь /ingest/wazuh добавляется
    # внутри send_to_siem — здесь проверяется база и сам алерт)
    for entry in fake_siem:
        assert entry["siem_url"].endswith("/api/v1")
        alert = entry["alert"]
        assert "authentication_failed" in alert["rule"]["groups"]
        assert alert["agent"]["name"] == "wks-finance-12"
        assert alert["data"]["srcip"]
    # активность записана в журнал узла (наблюдаемая ВМ)
    activity_log = client.get("/agent/activity", headers=_auth(client)).json()["activity"]
    assert len(activity_log) == 4
    assert activity_log[0]["alert_sent"] is True


def test_simulate_normal_activity_no_attack_ip(client, fake_siem):
    """Нормальная активность пользователей не должна нести IP атакующего."""
    response = client.post("/agent/simulate", json={"scenario": "normal_activity"}, headers=_auth(client))
    assert response.status_code == 200
    for entry in fake_siem:
        src_ip = entry["alert"]["data"]["srcip"]
        assert not src_ip.startswith("203.0.113."), f"нормальная активность с IP атакующего: {src_ip}"


def test_simulate_unknown_scenario_422(client):
    response = client.post("/agent/simulate", json={"scenario": "martian_attack"}, headers=_auth(client))
    assert response.status_code == 422


def test_simulate_requires_token(client):
    assert client.post("/agent/simulate", json={"scenario": "brute_force"}).status_code == 401


def test_attack_scenarios_match_seed_rules():
    """Контракт с SIEM: группы алертов сценариев совпадают с условиями
    seed-правил корреляции (см. docs/REAL_EXECUTION.md, таблица демонстрации)."""
    mapping = {
        "brute_force": "authentication_failed",
        "password_spraying": "authentication_failed",
        "web_attack": "web",
        "malware": "malware",
        "privilege_escalation": "privilege_escalation",
        "data_exfiltration": "exfiltration",
    }
    for scenario, group in mapping.items():
        scenario_spec = activity_module.ATTACK_SCENARIOS[scenario]
        assert group in scenario_spec["alert"]["groups"], scenario

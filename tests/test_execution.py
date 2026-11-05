"""Тесты диспетчера реального исполнения (stage-23, services/execution.py).

Сетевых вызовов нет: Wazuh Manager API подменяется фейком на
httpx.MockTransport (точка подмены — wazuh_api._create_client, автооткат
после каждого теста). Проверяются: аутентификация/ре-аутентификация,
поиск агента по имени актива, доставка AR-команды (block_ip/disable_account/
isolate_host), отсутствие агента (no_target), недоступность менеджера
(target_unreachable), отсутствие параметров (missing_parameters),
passive-действия (monitor/collect_evidence) и откат реакций (undo).
"""

from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import select

import app.services.wazuh_api as wazuh_api
from app.models import Asset, Event, Incident, Playbook, ResponseAction
from app.services.execution import execute_real_action, undo_incident_real_actions, undo_real_action


class MockWazuhAPI:
    """Фейк Wazuh Manager API на httpx.MockTransport: фиксирует запросы,
    поведение настраивается атрибутами (агенты, ошибки, статусы)."""

    def __init__(self):
        self.requests = []  # (method, path, payload)
        self.agents = [
            {"id": "001", "name": "mail-prod-01", "status": "active"},
            {"id": "002", "name": "wks-finance-12", "status": "active"},
        ]
        self.ar_status = 200
        self.ar_responses = []  # ответы на POST /active-response по порядку
        self.net_error = False
        self.reject_token_once = False  # 401 на первый запрос с токеном
        self._token_rejected = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        payload = None
        if request.content:
            import json

            payload = json.loads(request.content)
        path_q = request.url.path + (
            f"?{request.url.query.decode()}" if request.url.query else ""
        )
        self.requests.append((request.method, path_q, payload))
        if self.net_error:
            raise httpx.ConnectError("connection refused", request=request)
        if request.url.path == "/security/user/authenticate" and request.method == "POST":
            return httpx.Response(200, json={"data": {"token": "jwt-test"}})
        if self.reject_token_once and not self._token_rejected:
            # 401 на первый запрос с токеном (любой, кроме аутентификации) —
            # проверка ре-аутентификации
            self._token_rejected = True
            return httpx.Response(401, json={"error": "invalid token"})
        if request.url.path == "/agents" and request.method == "GET":
            return httpx.Response(200, json={"data": {"affected_items": self.agents}})
        if request.url.path == "/active-response" and request.method == "PUT":
            # формат Wazuh 4.7.4: PUT /active-response?agents_list=<id>,
            # тело {command, arguments} (agents в теле удалены в 4.x API)
            if self.ar_status >= 400:
                return httpx.Response(self.ar_status, json={"error": "delivery failed"})
            body = self.ar_responses.pop(0) if self.ar_responses else {
                "data": {"affected_items": [], "total_affected_items": 1},
                "error": 0,
            }
            return httpx.Response(200, json=body)
        return httpx.Response(404, json={"error": "not found"})


@pytest.fixture(autouse=True)
def mock_api(monkeypatch):
    """Автоматическая подмена Wazuh API во всех тестах модуля (сетевых вызовов нет)."""
    api = MockWazuhAPI()

    def create_client():
        return httpx.Client(
            transport=httpx.MockTransport(api.handler),
            base_url="https://wazuh-mock:55000",
            timeout=5,
        )

    monkeypatch.setattr(wazuh_api, "_create_client", create_client)
    yield api


def make_incident(db, asset_name="mail-prod-01", with_asset: bool = True,
                  src_ip="192.168.56.102", user="admin"):
    """Инцидент с одним событием (параметры действия берутся из событий)."""
    asset = None
    if with_asset:
        asset = Asset(name=asset_name, type="server", criticality="critical")
        db.add(asset)
        db.flush()
    incident = Incident(
        title="Подбор пароля",
        description="test",
        severity="high",
        asset_id=asset.id if asset else None,
    )
    db.add(incident)
    db.flush()
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source="wazuh",
        event_type="authentication_failed",
        user=user,
        src_ip=src_ip,
        asset_id=asset.id if asset else None,
        raw_message="m",
        raw_data={},
    )
    db.add(event)
    db.flush()
    incident.events.append(event)
    db.flush()
    return incident, asset


def add_playbook(db, action="block_ip"):
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


def ar_calls(api):
    """Только вызовы PUT /active-response (payload без agents — он в query)."""
    return [
        payload
        for method, path, payload in api.requests
        if path.startswith("/active-response")
    ]


def ar_paths(api):
    """Пути вызовов /active-response (с query — для проверки agents_list)."""
    return [
        path
        for method, path, payload in api.requests
        if path.startswith("/active-response")
    ]


# ---------------------------------------------------------------------------
# WazuhClient: аутентификация и поиск агента
# ---------------------------------------------------------------------------
def test_client_authenticates_and_sends_bearer(mock_api):
    with wazuh_api.WazuhClient() as client:
        agent_id = client.find_agent_id("mail-prod-01")
    assert agent_id == "001"
    # первый запрос — аутентификация, второй — /agents с Bearer-токеном
    assert mock_api.requests[0][:2] == ("POST", "/security/user/authenticate")
    assert mock_api.requests[1][0] == "GET"
    assert mock_api.requests[1][1].startswith("/agents")


def test_client_find_agent_unknown_name(mock_api):
    with wazuh_api.WazuhClient() as client:
        assert client.find_agent_id("db-primary-01") is None


def test_client_reauthenticates_on_401(mock_api):
    mock_api.reject_token_once = True
    with wazuh_api.WazuhClient() as client:
        agent_id = client.find_agent_id("mail-prod-01")
    assert agent_id == "001"
    # аутентификация выполнена дважды: исходная + ре-аутентификация после 401
    auth_calls = [r for r in mock_api.requests if r[1] == "/security/user/authenticate"]
    assert len(auth_calls) == 2


def test_client_unreachable(mock_api):
    mock_api.net_error = True
    from app.services.wazuh_api import WazuhUnreachable

    with pytest.raises(WazuhUnreachable):
        with wazuh_api.WazuhClient() as client:
            client.find_agent_id("mail-prod-01")


# ---------------------------------------------------------------------------
# Активные действия
# ---------------------------------------------------------------------------
def test_execute_real_block_ip_success(db, mock_api):
    incident, asset = make_incident(db)
    playbook = add_playbook(db)

    execution = execute_real_action(db, incident, "block_ip", requested_by="soc_lead")

    assert execution["executed"] is True
    assert execution["mode"] == "real"
    assert execution["playbook"] == playbook.name
    assert execution["target"] == "192.168.56.102"
    # вызов AR: правильная команда, аргументы и агент в query (формат 4.7.4)
    calls = ar_calls(mock_api)
    assert len(calls) == 1
    assert calls[0]["command"] == "block-ip"
    assert calls[0]["arguments"] == ["add", "192.168.56.102"]
    assert "agents_list=001" in ar_paths(mock_api)[0]
    # данные доставки — в result["targets"]
    assert execution["targets"][0]["agent_id"] == "001"
    assert execution["targets"][0]["agent_name"] == "mail-prod-01"
    # запись ResponseAction с метаданными реального исполнения
    db.expire_all()
    action_row = db.scalars(select(ResponseAction)).first()
    assert action_row is not None
    metadata = action_row.metadata_json
    assert metadata["mode"] == "real"
    assert metadata["target"] == "192.168.56.102"
    assert metadata["requested_by"] == "soc_lead"
    assert metadata["wazuh"]["agent_id"] == "001"
    assert metadata["wazuh"]["command"] == "block-ip"
    # аргументы отката сохранены (undo при «Сбросить реакции»)
    assert metadata["undo_arguments"] == ["delete", "192.168.56.102"]


def test_execute_real_no_agent_for_asset(db, mock_api):
    # актив есть, но wazuh-агента с таким именем в менеджере нет
    incident, asset = make_incident(db, asset_name="db-primary-01")
    add_playbook(db)

    execution = execute_real_action(db, incident, "block_ip")

    assert execution["executed"] is False
    assert execution["reason"] == "no_target"
    assert ar_calls(mock_api) == []
    # неудачная попытка не оставляет ResponseAction — отменять нечего
    assert db.scalars(select(ResponseAction)).first() is None


def test_execute_real_no_asset(db, mock_api):
    incident, _ = make_incident(db, with_asset=False)
    add_playbook(db)

    execution = execute_real_action(db, incident, "block_ip")

    assert execution["executed"] is False
    assert execution["reason"] == "no_target"
    assert ar_calls(mock_api) == []


def test_execute_real_manager_unreachable(db, mock_api):
    incident, asset = make_incident(db)
    add_playbook(db)
    mock_api.net_error = True

    execution = execute_real_action(db, incident, "block_ip")

    assert execution["executed"] is False
    assert execution["reason"] == "target_unreachable"
    assert "недоступен" in execution["result"]
    assert db.scalars(select(ResponseAction)).first() is None


def test_execute_real_missing_parameters(db, mock_api):
    incident, asset = make_incident(db, src_ip=None, user=None)
    add_playbook(db)

    execution = execute_real_action(db, incident, "block_ip")

    assert execution["executed"] is False
    assert execution["reason"] == "missing_parameters"
    assert ar_calls(mock_api) == []


def test_execute_real_unsupported_action(db, mock_api):
    incident, asset = make_incident(db)

    execution = execute_real_action(db, incident, "custom_action")

    assert execution["executed"] is False
    assert execution["reason"] == "unsupported_action"
    assert ar_calls(mock_api) == []


def test_execute_real_disable_account_uses_user_from_events(db, mock_api):
    incident, asset = make_incident(db, user="svc_helper")
    add_playbook(db, "disable_account")

    execution = execute_real_action(db, incident, "disable_account")

    assert execution["executed"] is True
    assert execution["target"] == "svc_helper"
    assert ar_calls(mock_api)[0]["command"] == "lock-account"
    assert ar_calls(mock_api)[0]["arguments"] == ["lock", "svc_helper"]


def test_execute_real_isolate_host(db, mock_api):
    incident, asset = make_incident(db)
    add_playbook(db, "isolate_host")

    execution = execute_real_action(db, incident, "isolate_host")

    assert execution["executed"] is True
    # изоляция — на самом агенте, цель (имя актива) в аргументы не передаётся
    assert execution["target"] == "mail-prod-01"
    assert ar_calls(mock_api)[0]["command"] == "isolate-host"
    assert ar_calls(mock_api)[0]["arguments"] == ["add"]


# ---------------------------------------------------------------------------
# Passive-действия
# ---------------------------------------------------------------------------
def test_execute_real_monitor_passive(db, mock_api):
    incident, _ = make_incident(db, with_asset=False)
    add_playbook(db, "monitor")

    execution = execute_real_action(db, incident, "monitor")

    assert execution["executed"] is True
    assert execution["mode"] == "real"
    assert ar_calls(mock_api) == []
    # пассивная отметка тоже сохраняется — видна во вкладке «Реакции (ВМ)»
    assert db.scalars(select(ResponseAction)).first() is not None


def test_execute_real_collect_evidence_snapshot(db, mock_api):
    incident, asset = make_incident(db)

    execution = execute_real_action(db, incident, "collect_evidence")

    assert execution["executed"] is True
    assert execution["snapshot"]["incident_id"] == incident.id
    assert len(execution["snapshot"]["events"]) == 1
    assert ar_calls(mock_api) == []


# ---------------------------------------------------------------------------
# Откат реакций (undo, stage-23)
# ---------------------------------------------------------------------------
def test_undo_real_block_ip(db, mock_api):
    incident, asset = make_incident(db)
    add_playbook(db)

    outcome = undo_real_action(db, incident, "block_ip", "192.168.56.102")

    assert outcome["executed"] is True
    assert ar_calls(mock_api)[0]["command"] == "block-ip"
    assert ar_calls(mock_api)[0]["arguments"] == ["delete", "192.168.56.102"]


def test_undo_real_disable_account(db, mock_api):
    incident, asset = make_incident(db)
    outcome = undo_real_action(db, incident, "disable_account", "svc_helper")

    assert outcome["executed"] is True
    assert ar_calls(mock_api)[0]["command"] == "lock-account"
    assert ar_calls(mock_api)[0]["arguments"] == ["unlock", "svc_helper"]


def test_undo_passive_action_no_call(db, mock_api):
    incident, _ = make_incident(db)

    outcome = undo_real_action(db, incident, "monitor", None)

    assert outcome["executed"] is True
    assert ar_calls(mock_api) == []


def test_undo_incident_real_actions_marks_undone(db, mock_api):
    incident, asset = make_incident(db)
    add_playbook(db)
    execute_real_action(db, incident, "block_ip", requested_by="soc_lead")

    results = undo_incident_real_actions(db, incident, requested_by="soc_lead")

    assert len(results) == 1
    assert results[0]["executed"] is True
    db.expire_all()
    action_row = db.scalars(select(ResponseAction)).first()
    assert action_row.metadata_json["undone_at"] is not None
    assert action_row.metadata_json["undone_by"] == "soc_lead"

    # повторный сброс: запись уже undone — новых вызовов нет
    calls_before = len(mock_api.requests)
    results = undo_incident_real_actions(db, incident, requested_by="soc_lead")
    assert results == []
    assert len(mock_api.requests) == calls_before


def test_undo_incident_keeps_record_when_manager_down(db, mock_api):
    """Неудачный откат не помечает запись: реакция остаётся в «Реакциях (ВМ)»,
    сброс можно повторить (менеджер снова доступен)."""
    incident, asset = make_incident(db)
    add_playbook(db)
    execute_real_action(db, incident, "block_ip")

    mock_api.net_error = True
    results = undo_incident_real_actions(db, incident, requested_by="soc_lead")
    assert results[0]["executed"] is False
    db.expire_all()
    action_row = db.scalars(select(ResponseAction)).first()
    assert action_row.metadata_json.get("undone_at") is None

    # менеджер вернулся — откат успешен
    mock_api.net_error = False
    results = undo_incident_real_actions(db, incident, requested_by="soc_lead")
    assert results[0]["executed"] is True

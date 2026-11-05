"""Тесты диспетчера реального исполнения (stage-20, services/execution.py).

Сетевых вызовов нет: httpx.Client подменяется фейком через monkeypatch
(автооткат после каждого теста). Проверяются: выбор цели по активу, успешный
вызов агента (heartbeat online + ResponseAction + аудит), отсутствие цели
(no_target), недоступность агента (offline + reason), отсутствие параметров,
passive-действия (monitor/collect_evidence) и неподдерживаемое действие.
"""

from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import select

from app.models import Asset, Event, ExecutionTarget, Incident, Playbook, ResponseAction
from app.services.execution import (
    execute_real_action,
    resolve_targets,
)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeClient:
    """Подмена httpx.Client: фиксирует вызовы, возвращает payload или бросает
    ошибку (настраивается классовыми атрибутами)."""

    calls: list = []
    payload: dict = {"executed": True, "result": "ok", "state": {}}
    error: Exception | None = None

    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def post(self, url, json=None, headers=None):
        FakeClient.calls.append({"url": url, "json": json, "headers": headers})
        if FakeClient.error is not None:
            raise FakeClient.error
        return FakeResponse(FakeClient.payload)


@pytest.fixture(autouse=True)
def fake_httpx(monkeypatch):
    """Автоматическая подмена httpx во всех тестах модуля (сетевых вызовов нет)."""
    FakeClient.calls = []
    FakeClient.payload = {"executed": True, "result": "ok", "state": {}}
    FakeClient.error = None
    monkeypatch.setattr(httpx, "Client", FakeClient)
    yield


def make_incident(db, with_asset: bool = True, src_ip="203.0.113.66", user="root"):
    """Инцидент с одним событием (параметры действия берутся из событий)."""
    asset = None
    if with_asset:
        asset = Asset(name="wks-finance-12", type="workstation", criticality="medium")
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


def add_target(db, asset_id, name="wks-finance-12", base_url="http://agent-wks:8100"):
    target = ExecutionTarget(
        name=name, asset_id=asset_id, base_url=base_url, auth_token="tok"
    )
    db.add(target)
    db.flush()
    return target


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


# ---------------------------------------------------------------------------
# resolve_targets
# ---------------------------------------------------------------------------
def test_resolve_targets_by_asset(db):
    incident, asset = make_incident(db)
    target = add_target(db, asset.id)
    resolved = resolve_targets(db, incident)
    assert [t.id for t in resolved] == [target.id]


def test_resolve_targets_incident_without_asset(db):
    incident, _ = make_incident(db, with_asset=False)
    assert resolve_targets(db, incident) == []


def test_resolve_targets_inactive_excluded(db):
    incident, asset = make_incident(db)
    target = add_target(db, asset.id)
    target.is_active = False
    db.flush()
    assert resolve_targets(db, incident) == []


# ---------------------------------------------------------------------------
# Активные действия
# ---------------------------------------------------------------------------
def test_execute_real_block_ip_success(db):
    incident, asset = make_incident(db)
    target = add_target(db, asset.id)
    playbook = add_playbook(db)

    execution = execute_real_action(db, incident, "block_ip", requested_by="analyst1")

    assert execution["executed"] is True
    assert execution["mode"] == "real"
    assert execution["playbook"] == playbook.name
    assert execution["targets"][0]["target"] == "wks-finance-12"
    assert execution["targets"][0]["executed"] is True
    # вызов агента: правильный URL, действие и параметры из событий
    call = FakeClient.calls[0]
    assert call["url"] == "http://agent-wks:8100/agent/action"
    assert call["json"]["action"] == "block_ip"
    assert call["json"]["params"] == {"ip": "203.0.113.66"}
    assert call["json"]["incident_id"] == incident.id
    assert call["json"]["requested_by"] == "analyst1"
    # Bearer-токен цели уходит агенту
    assert call["headers"]["Authorization"] == "Bearer tok"
    # heartbeat цели
    assert target.status == "online"
    assert target.last_seen is not None
    # запись ResponseAction с метаданными реального исполнения
    db.expire_all()
    action_row = db.scalars(select(ResponseAction)).first()
    assert action_row is not None
    assert action_row.metadata_json["mode"] == "real"
    assert action_row.metadata_json["requested_by"] == "analyst1"


def test_execute_real_no_target(db):
    incident, _ = make_incident(db, with_asset=False)
    add_playbook(db)

    execution = execute_real_action(db, incident, "block_ip")

    assert execution["executed"] is False
    assert execution["reason"] == "no_target"
    assert FakeClient.calls == []


def test_execute_real_target_unreachable(db):
    incident, asset = make_incident(db)
    target = add_target(db, asset.id)

    class Err(Exception):
        pass

    FakeClient.error = Err("connection refused")
    execution = execute_real_action(db, incident, "block_ip")

    assert execution["executed"] is False
    assert execution["reason"] == "target_unreachable"
    assert execution["targets"][0]["executed"] is False
    assert "connection refused" in execution["targets"][0]["error"]
    # heartbeat: цель помечена offline
    assert target.status == "offline"


def test_execute_real_missing_parameters(db):
    incident, asset = make_incident(db, src_ip=None, user=None)
    add_target(db, asset.id)

    execution = execute_real_action(db, incident, "block_ip")

    assert execution["executed"] is False
    assert execution["reason"] == "missing_parameters"
    assert FakeClient.calls == []


def test_execute_real_unsupported_action(db):
    incident, asset = make_incident(db)
    add_target(db, asset.id)

    execution = execute_real_action(db, incident, "custom_action")

    assert execution["executed"] is False
    assert execution["reason"] == "unsupported_action"
    assert FakeClient.calls == []


def test_execute_real_disable_account_uses_user_from_events(db):
    incident, asset = make_incident(db, user="svc_backup")
    add_target(db, asset.id)

    execution = execute_real_action(db, incident, "disable_account")

    assert execution["executed"] is True
    assert FakeClient.calls[0]["json"]["params"] == {"user": "svc_backup"}


# ---------------------------------------------------------------------------
# Passive-действия
# ---------------------------------------------------------------------------
def test_execute_real_monitor_without_target(db):
    incident, _ = make_incident(db, with_asset=False)

    execution = execute_real_action(db, incident, "monitor")

    assert execution["executed"] is True
    assert execution["mode"] == "real"
    assert FakeClient.calls == []


def test_execute_real_collect_evidence_with_agent(db):
    incident, asset = make_incident(db)
    add_target(db, asset.id)
    FakeClient.payload = {
        "executed": True,
        "result": "snapshot attached",
        "state": {"hostname": "wks-finance-12", "isolated": False},
    }

    execution = execute_real_action(db, incident, "collect_evidence")

    assert execution["executed"] is True
    # снимок инцидента + состояние агента
    assert execution["snapshot"]["incident_id"] == incident.id
    assert len(execution["snapshot"]["events"]) == 1
    assert execution["snapshot"]["agent"]["hostname"] == "wks-finance-12"
    # collect_evidence читает состояние, а не меняет: GET-семантика отправлена как action
    assert FakeClient.calls[0]["json"]["action"] == "collect_evidence"

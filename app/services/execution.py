"""Диспетчер реального исполнения ответных действий (stage-20).

Глава 3.4 (p:116) описывает реагирование как симуляцию; запрос пользователя
(stage-20) — добавить РЕАЛЬНОЕ исполнение playbook'ов на виртуальных машинах,
эмулирующих наблюдаемых пользователей прод-инфраструктуры (учебный стенд —
docs/REAL_EXECUTION.md). Симуляция сохраняется как отдельный режим: DVE
(Decision Validation Engine) один и тот же для обоих режимов — политика
уровня риска, playbook и подтверждение критического актива не зависят от
способа исполнения.

Поток реального исполнения:
  инцидент → актив (Incident.asset) → ExecutionTarget (агент на ВМ) →
  HTTP-вызов агента (Bearer-токен) → изменение состояния ВМ →
  результат + запись в ResponseAction + аудит + heartbeat цели.

Действия, не требующие цели (PASSIVE_ACTIONS): monitor фиксирует наблюдение
аудитом; collect_evidence без агента делает внутренний снимок инцидента
(события + анализы), с агентом — снимок состояния ВМ.
"""

import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Analysis, ExecutionTarget, Incident, ResponseAction
from app.services.audit import audit

logger = logging.getLogger("execution")

# действия без изменения инфраструктуры (совпадает с validation.PASSIVE_ACTIONS —
# дублируется локально, чтобы сервис не зависел от DVE)
PASSIVE_ACTIONS = {"monitor", "collect_evidence"}

# действия, меняющие состояние endpoint-агента: имя → параметры вызова
AGENT_ACTIONS = {
    "block_ip": "block_ip",
    "isolate_host": "isolate_host",
    "disable_account": "disable_account",
}


def resolve_targets(db: Session, incident: Incident) -> list[ExecutionTarget]:
    """Активные цели исполнения для инцидента: по активу, к которому привязан
    инцидент (имя цели = имя актива). Инцидент без актива целей не имеет.
    """
    if incident.asset_id is None:
        return []
    return list(
        db.scalars(
            select(ExecutionTarget).where(
                ExecutionTarget.asset_id == incident.asset_id,
                ExecutionTarget.is_active.is_(True),
            )
        ).all()
    )


def _incident_context(incident: Incident) -> dict:
    """Параметры действия из данных инцидента: атакующий IP и учётная запись —
    из последнего события инцидента, где они заполнены."""
    src_ip, user = None, None
    for event in sorted(incident.events, key=lambda e: e.timestamp):
        if event.src_ip:
            src_ip = event.src_ip
        if event.user:
            user = event.user
    return {"src_ip": src_ip, "user": user, "asset_name": incident.asset.name if incident.asset else None}


def _agent_headers(target: ExecutionTarget) -> dict:
    headers = {"Content-Type": "application/json"}
    if target.auth_token:
        headers["Authorization"] = f"Bearer {target.auth_token}"
    return headers


def _mark_target(target: ExecutionTarget, online: bool) -> None:
    """Heartbeat цели: факт обращения — статистика доступности для UI."""
    target.status = "online" if online else "offline"
    target.last_seen = datetime.now(timezone.utc)


def _agent_call(target: ExecutionTarget, payload: dict) -> dict:
    """Синхронный вызов агента (роутеры синхронные). Ответ агента:
    {"executed": true/false, "action": ..., "result": ..., "state": {...}}.
    """
    timeout = settings.execution_timeout_seconds
    with httpx.Client(timeout=timeout) as client:
        response = client.post(
            f"{target.base_url.rstrip('/')}/agent/action",
            json=payload,
            headers=_agent_headers(target),
        )
        response.raise_for_status()
        return response.json()


def execute_real_action(
    db: Session,
    incident: Incident,
    action: str,
    requested_by: str | None = None,
) -> dict:
    """Реальное исполнение действия playbook на цели (stage-20).

    Возвращает execution-словарь, совместимый с execute_playbook
    (executed/mode/action + playbook-описание): mode="real". Результат
    каждого вызова агента — в execution["targets"], полный ответ сохраняется
    в ResponseAction.metadata_json. Достижимые/недостижимые цели пишут
    heartbeat; ошибки не поднимают исключение — оператор видит причину.
    """
    playbook = None
    from app.services.playbook import load_playbook_by_action

    playbook = load_playbook_by_action(db, action)
    result = {
        "executed": False,
        "mode": "real",
        "action": action,
        "playbook": playbook.name if playbook else None,
        "playbook_description": playbook.description if playbook else None,
        "playbook_steps": playbook.steps if playbook else None,
        "targets": [],
    }

    context = _incident_context(incident)
    targets = resolve_targets(db, incident)

    # --- PASSIVE-действия: цель не требуется -------------------------------
    if action == "monitor":
        result["executed"] = True
        result["result"] = (
            "Инцидент взят под наблюдение: повторные события фиксируются "
            "в журнале аудита; состояние инфраструктуры не изменяется"
        )
        _save_response_action(db, incident, action, result, playbook, context, requested_by)
        audit(
            "real_action_executed",
            {"action": action, "mode": "real", "passive": True, "by": requested_by},
            db=db,
            incident_id=incident.id,
        )
        return result

    if action == "collect_evidence":
        snapshot = _collect_incident_snapshot(db, incident)
        agent_state = None
        if targets:
            target = targets[0]
            try:
                agent_state = _agent_call(target, {"action": "collect_evidence", "params": {}, "incident_id": incident.id})
                _mark_target(target, online=True)
                snapshot["agent"] = agent_state.get("state")
            except Exception as exc:
                _mark_target(target, online=False)
                logger.warning("collect_evidence on %s failed: %s", target.name, exc)
                snapshot["agent_error"] = str(exc)
        result["executed"] = True
        result["result"] = (
            "Доказательства собраны: снимок событий, анализов и состояния узла "
            "сохранён в карточке инцидента"
        )
        result["snapshot"] = snapshot
        _save_response_action(db, incident, action, result, playbook, context, requested_by)
        audit(
            "real_action_executed",
            {"action": action, "mode": "real", "passive": True, "with_agent": bool(targets), "by": requested_by},
            db=db,
            incident_id=incident.id,
        )
        return result

    # --- Активные действия: требуется агент на ВМ --------------------------
    if action not in AGENT_ACTIONS:
        result["reason"] = "unsupported_action"
        result["result"] = (
            f"Действие {action} не поддерживается агентами ВМ — доступно только "
            "в режиме симуляции"
        )
        audit(
            "real_action_skipped",
            {"action": action, "reason": "unsupported_action"},
            db=db,
            incident_id=incident.id,
        )
        return result

    if not targets:
        result["reason"] = "no_target"
        result["result"] = (
            "Реальное исполнение недоступно: для актива инцидента не "
            "зарегистрирован агент (цель исполнения). Действие доступно в "
            "режиме симуляции"
        )
        audit(
            "real_action_skipped",
            {"action": action, "reason": "no_target", "asset_id": incident.asset_id},
            db=db,
            incident_id=incident.id,
        )
        return result

    # параметры действия → payload агента
    params = _agent_params(action, context)
    if params is None:
        result["reason"] = "missing_parameters"
        result["result"] = (
            "В событиях инцидента нет данных цели действия (IP-адрес источника "
            "или учётная запись) — действие не может быть исполнено"
        )
        audit(
            "real_action_skipped",
            {"action": action, "reason": "missing_parameters"},
            db=db,
            incident_id=incident.id,
        )
        return result

    executed_any = False
    for target in targets:
        entry = {"target": target.name, "base_url": target.base_url}
        try:
            response = _agent_call(
                target,
                {
                    "action": action,
                    "params": params,
                    "incident_id": incident.id,
                    "requested_by": requested_by,
                },
            )
            entry.update(
                {
                    "executed": bool(response.get("executed", True)),
                    "response": response,
                }
            )
            executed_any = executed_any or bool(response.get("executed", True))
            _mark_target(target, online=True)
        except Exception as exc:
            entry.update({"executed": False, "error": str(exc)})
            _mark_target(target, online=False)
            logger.warning(
                "real action %s on %s failed: %s", action, target.name, exc
            )
        result["targets"].append(entry)

    result["executed"] = executed_any
    ok_targets = [t["target"] for t in result["targets"] if t.get("executed")]
    fail_targets = [t["target"] for t in result["targets"] if not t.get("executed")]
    if executed_any:
        result["result"] = f"Действие выполнено на: {', '.join(ok_targets)}"
        if fail_targets:
            result["result"] += f"; недоступны: {', '.join(fail_targets)}"
    else:
        result["reason"] = result.get("reason") or "target_unreachable"
        result["result"] = "Ни одна цель не подтвердила исполнение (агент недоступен)"

    _save_response_action(db, incident, action, result, playbook, context, requested_by)
    audit(
        "real_action_executed" if executed_any else "real_action_failed",
        {
            "action": action,
            "mode": "real",
            "params": params,
            "targets": [t["target"] for t in result["targets"]],
            "by": requested_by,
        },
        db=db,
        incident_id=incident.id,
    )
    return result


def _agent_params(action: str, context: dict) -> dict | None:
    """Параметры вызова агента для действия; None — данных в инциденте нет."""
    if action == "block_ip":
        if not context.get("src_ip"):
            return None
        return {"ip": context["src_ip"]}
    if action == "disable_account":
        if not context.get("user"):
            return None
        return {"user": context["user"]}
    if action == "isolate_host":
        return {"host": context.get("asset_name") or "unknown"}
    return {}


def _collect_incident_snapshot(db: Session, incident: Incident) -> dict:
    """Снимок доказательств по инциденту (без агента): события + анализы."""
    events = [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "source": e.source,
            "event_type": e.event_type,
            "user": e.user,
            "src_ip": e.src_ip,
        }
        for e in incident.events
    ]
    analyses = list(
        db.scalars(
            select(Analysis).where(Analysis.incident_id == incident.id).order_by(Analysis.created_at)
        ).all()
    )
    return {
        "incident_id": incident.id,
        "severity": incident.severity,
        "status": incident.status,
        "risk_score": incident.risk_score,
        "events": events,
        "analyses_count": len(analyses),
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


def _save_response_action(
    db: Session,
    incident: Incident,
    action: str,
    result: dict,
    playbook,
    context: dict,
    requested_by: str | None,
) -> None:
    """Запись реально исполненного действия в ResponseAction (снимок ответа —
    в metadata_json для расследования; секция snapshot дублирует объёмные
    данные, в результат она попадает по ссылке)."""
    if playbook is None:
        return
    snapshot = result.pop("snapshot", None)
    metadata = {
        "mode": "real",
        "context": context,
        "targets": result.get("targets", []),
        "requested_by": requested_by,
    }
    if snapshot is not None:
        metadata["snapshot"] = snapshot
    db.add(
        ResponseAction(
            incident_id=incident.id,
            playbook_id=playbook.id,
            action_type=action,
            executed_at=datetime.now(timezone.utc),
            result=result.get("result"),
            initiated_by=f"manual:{requested_by or 'operator'}",
            metadata_json=metadata,
        )
    )
    db.flush()
    result["snapshot"] = snapshot  # вернуть снимок в ответ endpoint'а

"""Диспетчер реального исполнения ответных действий (stage-20/23).

Глава 3.4 (p:116) описывает реагирование; stage-23 исполняет playbook
через Wazuh Manager API (active response): менеджер доставляет команду
кастомного AR-скрипта wazuh-агенту на ВМ актива, где она меняет состояние
узла по-настоящему (iptables/passwd) — docs/E2E_STAND.md. Исполнение
всегда реальное (режим симуляции удалён по явной команде пользователя
2026-11-05 — история в analysis/DEVIATIONS.md); DVE-политика (уровень
риска, playbook, подтверждение критического актива) от способа доставки
команды не зависит.

Поток реального исполнения:
  инцидент → актив (Incident.asset) → wazuh-агент по имени актива
  (WazuhClient.find_agent_id) → POST /active-response → РЕАЛЬНОЕ изменение
  на ВМ → результат + запись ResponseAction (аргументы отката — в
  metadata_json) + аудит.

Действия, не требующие цели (PASSIVE_ACTIONS): monitor фиксирует наблюдение
аудитом; collect_evidence делает внутренний снимок инцидента (события +
анализы). Снимок состояния ВМ удалён вместе с агентами-эмуляторами stage-20
(удаление авторизовано пользователем 2026-11-05).

Активные записи ResponseAction (mode=real, без undone_at) видны во вкладке
«Реакции (ВМ)» (GET /responses/state) и отменяются обратными AR-командами
при «Сбросить реакции» (undo_real_action / undo_incident_real_actions).
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Analysis, Incident, Playbook, ResponseAction
from app.services.audit import audit
from app.services.playbook import load_playbook_by_action
from app.services.validation import PASSIVE_ACTIONS
from app.services.wazuh_api import WazuhAPIError, WazuhClient

logger = logging.getLogger("execution")

# действие playbook → (AR-команда менеджера, аргумент исполнения, аргумент
# отката). Первый элемент аргументов — команда скрипта (add/delete/lock/
# unlock), второй — цель (IP/учётка) из событий инцидента; isolate-host
# цели не требует (команда работает на самом агенте).
WAZUH_AR_COMMANDS = {
    "block_ip": ("block-ip", "add", "delete"),
    "disable_account": ("lock-account", "lock", "unlock"),
    "isolate_host": ("isolate-host", "add", "delete"),
}


def _incident_context(incident: Incident) -> dict:
    """Параметры действия из данных инцидента: атакующий IP и учётная запись —
    из последнего события инцидента, где они заполнены."""
    src_ip, user = None, None
    for event in sorted(incident.events, key=lambda e: e.timestamp):
        if event.src_ip:
            src_ip = event.src_ip
        if event.user:
            user = event.user
    return {
        "src_ip": src_ip,
        "user": user,
        "asset_name": incident.asset.name if incident.asset else None,
    }


def _action_target(action: str, context: dict) -> str | None:
    """Цель действия из событий инцидента: block_ip ← src_ip,
    disable_account ← user, isolate_host ← имя актива. None — данных нет."""
    if action == "block_ip":
        return context.get("src_ip")
    if action == "disable_account":
        return context.get("user")
    if action == "isolate_host":
        return context.get("asset_name")
    return None


def _ar_arguments(command: str, verb: str, target: str | None) -> list[str]:
    """Аргументы AR-команды: block-ip/lock-account получают цель вторым
    аргументом, isolate-host работает без цели."""
    if command == "isolate-host":
        return [verb]
    return [verb, target or ""]


def _playbook_result(action: str, playbook: Playbook | None) -> dict:
    """Общая шапка execution-словаря реального исполнения: playbook-описание
    в ответе независимо от исхода доставки команды. playbook передаётся
    вызывающим — загружен один раз на запрос (legacy-cleanup: раньше
    execute-action читал его из БД трижды)."""
    return {
        "executed": False,
        "mode": "real",
        "action": action,
        "playbook": playbook.name if playbook else None,
        "playbook_description": playbook.description if playbook else None,
        "playbook_steps": playbook.steps if playbook else None,
        "targets": [],
    }


def execute_real_action(
    db: Session,
    incident: Incident,
    action: str,
    requested_by: str | None = None,
    playbook: Playbook | None = None,
) -> dict:
    """Реальная реакция playbook на ВМ актива через Wazuh active response API.

    Возвращает execution-словарь, совместимый с execute_playbook
    (executed/mode/action + playbook-описание): mode="real". Данные
    доставки команды — в result["targets"][0], цель действия (IP/учётка/
    актив) — в result["target"] (эндпоинт кладёт её в отметку
    manual_actions). Ошибки не поднимают исключение — оператор видит
    причину в результате. ResponseAction сохраняется только при
    исполненной реакции: активные записи — источник отката и сводки
    «Реакции (ВМ)», неудачная попытка реального эффекта не оставляет.

    playbook — сценарий, уже загруженный валидацией роутера
    (_validate_with_playbook); None — загрузить здесь (прямые вызовы
    сервисов и тестов).
    """
    if playbook is None:
        playbook = load_playbook_by_action(db, action)
    result = _playbook_result(action, playbook)
    context = _incident_context(incident)

    # --- PASSIVE-действия: цель и менеджер не требуются --------------------
    if action == "monitor":
        result["executed"] = True
        result["result"] = (
            "Инцидент взят под наблюдение: повторные события фиксируются "
            "в журнале аудита; состояние инфраструктуры не изменяется"
        )
        _save_response_action(db, incident, action, result, context, requested_by, playbook)
        audit(
            "real_action_executed",
            {"action": action, "mode": "real", "passive": True, "by": requested_by},
            db=db,
            incident_id=incident.id,
        )
        return result

    if action == "collect_evidence":
        snapshot = _collect_incident_snapshot(db, incident)
        result["executed"] = True
        result["result"] = (
            "Доказательства собраны: снимок событий и анализов инцидента "
            "сохранён в карточке"
        )
        result["snapshot"] = snapshot
        _save_response_action(db, incident, action, result, context, requested_by, playbook)
        audit(
            "real_action_executed",
            {"action": action, "mode": "real", "passive": True, "by": requested_by},
            db=db,
            incident_id=incident.id,
        )
        return result

    # --- Активные действия: AR-команда через менеджера ---------------------
    command, verb, _undo_verb = WAZUH_AR_COMMANDS.get(action, (None, None, None))
    if command is None:
        result["reason"] = "unsupported_action"
        result["result"] = (
            f"Действие {action} не поддерживается Wazuh active response"
        )
        audit(
            "real_action_skipped",
            {"action": action, "reason": "unsupported_action"},
            db=db,
            incident_id=incident.id,
        )
        return result

    if incident.asset_id is None or incident.asset is None:
        result["reason"] = "no_target"
        result["result"] = (
            "Реальное исполнение недоступно: инцидент не привязан к активу"
        )
        audit(
            "real_action_skipped",
            {"action": action, "reason": "no_target", "asset_id": None},
            db=db,
            incident_id=incident.id,
        )
        return result

    target = _action_target(action, context)
    if target is None:
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

    asset = incident.asset
    result["target"] = target

    with WazuhClient() as client:
        # цель доставки: wazuh-агент по имени актива
        try:
            agent_id = client.find_agent_id(asset.name)
        except WazuhAPIError as exc:
            return _fail_active(db, incident, action, result, context, requested_by, exc)

        if agent_id is None:
            result["reason"] = "no_target"
            result["result"] = (
                "Реальное исполнение недоступно: для актива инцидента нет "
                "wazuh-агента в менеджере (агент не установлен или не "
                "зарегистрирован — см. docs/E2E_STAND.md)"
            )
            audit(
                "real_action_skipped",
                {
                    "action": action,
                    "reason": "no_target",
                    "asset_id": asset.id,
                    "asset": asset.name,
                },
                db=db,
                incident_id=incident.id,
            )
            return result

        arguments = _ar_arguments(command, verb, target)
        entry = {
            "target": asset.name,
            "agent_id": agent_id,
            "agent_name": asset.name,
            "command": command,
            "arguments": arguments,
        }
        result["targets"].append(entry)
        try:
            response = client.active_response(agent_id, command, arguments)
        except WazuhAPIError as exc:
            return _fail_active(db, incident, action, result, context, requested_by, exc, entry)

        entry["executed"] = True
        entry["response"] = response
        result["executed"] = True
        result["result"] = (
            f"Команда {command} {' '.join(arguments)} принята Wazuh Manager "
            f"для агента {agent_id} ({asset.name}) — эффект на ВМ можно "
            "проверить по сценарию (docs/E2E_SCENARIOS.md)"
        )

    _save_response_action(db, incident, action, result, context, requested_by, playbook)
    audit(
        "real_action_executed",
        {
            "action": action,
            "mode": "real",
            "target": target,
            "command": command,
            "arguments": arguments,
            "agent_id": agent_id,
            "by": requested_by,
        },
        db=db,
        incident_id=incident.id,
    )
    return result


def _fail_active(
    db: Session,
    incident: Incident,
    action: str,
    result: dict,
    context: dict,
    requested_by: str | None,
    exc: WazuhAPIError,
    entry: dict | None = None,
) -> dict:
    """Единый исход неудачного активного действия: reason=target_unreachable,
    ответ API — в результат и в audit; ResponseAction не пишется (реального
    эффекта нет — отменять нечего)."""
    result["reason"] = "target_unreachable"
    if entry is not None:
        entry["executed"] = False
        entry["error"] = str(exc)
    result["result"] = f"Реакция не выполнена — Wazuh API вернул ошибку: {exc}"
    audit(
        "real_action_failed",
        {
            "action": action,
            "mode": "real",
            "reason": "target_unreachable",
            "error": str(exc),
            "by": requested_by,
        },
        db=db,
        incident_id=incident.id,
    )
    return result


def undo_real_action(
    db: Session,
    incident: Incident,
    action: str,
    target: str | None,
    client: WazuhClient | None = None,
    agent_id: str | None = None,
) -> dict:
    """Обратная AR-реакция (stage-23): block_ip → delete IP, disable_account →
    unlock, isolate_host → release (снятие изоляции). Best-effort: результат
    {executed, detail} без исключений — ошибки уходят в ответ reset-actions.

    client/agent_id — общая сессия менеджера для цикла отката
    (undo_incident_real_actions: одна аутентификация и один список агентов
    на все записи — legacy-cleanup, раньше каждая запись платила и тем и
    другим). Без них вызов самодостаточен: своя сессия + поиск агента.

    Для monitor/collect_evidence отменять нечего (executed=True — отметка
    просто снимается со сводки «Реакции (ВМ)»).
    """
    mapping = WAZUH_AR_COMMANDS.get(action)
    if mapping is None:
        return {
            "action": action,
            "executed": True,
            "detail": "Пассивное действие — отменять нечего, отметка снята",
        }
    asset = incident.asset
    if asset is None:
        return {
            "action": action,
            "executed": False,
            "detail": "Инцидент не привязан к активу — отмена невозможна",
        }
    if client is not None:
        return _undo_deliver(client, agent_id, asset.name, action, mapping, target)
    try:
        with WazuhClient() as own_client:
            return _undo_deliver(
                own_client,
                own_client.find_agent_id(asset.name),
                asset.name,
                action,
                mapping,
                target,
            )
    except WazuhAPIError as exc:
        return {"action": action, "executed": False, "detail": str(exc)}


def _undo_deliver(
    client: WazuhClient,
    agent_id: str | None,
    asset_name: str,
    action: str,
    mapping: tuple[str, str, str],
    target: str | None,
) -> dict:
    """Доставка обратной команды в готовой сессии менеджера — общая ветка
    одиночного undo_real_action и цикла undo_incident_real_actions."""
    command, _verb, undo_verb = mapping
    if agent_id is None:
        return {
            "action": action,
            "executed": False,
            "detail": (
                f"Wazuh-агент актива {asset_name} отсутствует в "
                "менеджере — обратная команда не доставляется "
                "(эффект на ВМ снимается вручную, см. E2E_STAND.md)"
            ),
        }
    arguments = _ar_arguments(command, undo_verb, target)
    try:
        client.active_response(agent_id, command, arguments)
    except WazuhAPIError as exc:
        return {"action": action, "executed": False, "detail": str(exc)}
    return {
        "action": action,
        "executed": True,
        "detail": (
            f"Обратная команда {command} {' '.join(arguments)} принята "
            f"менеджером для агента {agent_id} ({asset_name})"
        ),
    }


def undo_incident_real_actions(
    db: Session,
    incident: Incident,
    requested_by: str | None = None,
) -> list[dict]:
    """Отмена всех активных реальных реакций инцидента (stage-23, «Сбросить
    реакции»): для каждой записи ResponseAction mode=real без undone_at
    выполняется обратная AR-команда (best-effort), исполненные откаты
    помечаются undone_at/undone_by (JSON — полное переприсвоение). Неудачный
    откат не мешает сбросу отметок: запись остаётся активной в «Реакциях
    (ВМ)», сброс можно повторить.

    legacy-cleanup: клиент менеджера и id агента — один раз на цикл
    (одна аутентификация + один список агентов вместо N); пассивные
    записи (monitor/collect_evidence) обрабатываются без менеджера.
    """
    results: list[dict] = []
    records = list(
        db.scalars(
            select(ResponseAction).where(ResponseAction.incident_id == incident.id)
        ).all()
    )
    active: list[tuple[ResponseAction, dict]] = []
    for record in records:
        metadata = dict(record.metadata_json or {})
        if metadata.get("mode") != "real" or metadata.get("undone_at"):
            continue
        active.append((record, metadata))

    def _apply(record: ResponseAction, metadata: dict, outcome: dict) -> None:
        result_row = {
            "action": record.action_type,
            "executed": outcome.get("executed", False),
            "detail": outcome.get("detail"),
        }
        if outcome.get("executed"):
            metadata["undone_at"] = datetime.now(timezone.utc).isoformat()
            metadata["undone_by"] = requested_by
            record.metadata_json = metadata  # полное переприсвоение JSON-колонки
            db.add(record)
            audit(
                "real_action_undone",
                {
                    "action": record.action_type,
                    "target": metadata.get("target"),
                    "by": requested_by,
                },
                db=db,
                incident_id=incident.id,
            )
        results.append(result_row)

    needs_manager = any(WAZUH_AR_COMMANDS.get(record.action_type) for record, _ in active)
    if needs_manager and incident.asset is not None:
        try:
            with WazuhClient() as client:
                agent_id = client.find_agent_id(incident.asset.name)
                for record, metadata in active:
                    _apply(
                        record,
                        metadata,
                        undo_real_action(
                            db,
                            incident,
                            record.action_type,
                            metadata.get("target"),
                            client=client,
                            agent_id=agent_id,
                        ),
                    )
            db.flush()
            return results
        except WazuhAPIError as exc:
            # сессия не установилась (сеть/аутентификация) — ни одна запись не
            # обработана: каждая получает ошибку, как от самодостаточного вызова
            for record, metadata in active:
                _apply(
                    record,
                    metadata,
                    {"action": record.action_type, "executed": False, "detail": str(exc)},
                )
            db.flush()
            return results
    for record, metadata in active:
        _apply(
            record,
            metadata,
            undo_real_action(db, incident, record.action_type, metadata.get("target")),
        )
    db.flush()
    return results


def _collect_incident_snapshot(db: Session, incident: Incident) -> dict:
    """Снимок доказательств по инциденту: события + анализы (внутренний,
    без агента — снимок состояния ВМ удалён вместе с агентами stage-20)."""
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
    context: dict,
    requested_by: str | None,
    playbook: Playbook | None,
) -> None:
    """Запись исполненного действия в ResponseAction: metadata_json хранит
    цель, AR-команду с аргументами и аргументы отката (undo) — источник
    сводки «Реакции (ВМ)» и отката при reset-actions. Секция snapshot
    дублирует объёмные данные, в результат она попадает по ссылке.
    playbook передаётся вызывающим (загружен один раз на запрос)."""
    if playbook is None:
        return
    snapshot = result.pop("snapshot", None)
    wazuh_target = result.get("targets") or [{}]
    wazuh = wazuh_target[0] if result.get("targets") else None
    metadata = {
        "mode": "real",
        "target": result.get("target"),
        "context": context,
        "requested_by": requested_by,
    }
    if wazuh:
        metadata["wazuh"] = {
            "agent_id": wazuh.get("agent_id"),
            "agent_name": wazuh.get("agent_name"),
            "command": wazuh.get("command"),
            "arguments": wazuh.get("arguments"),
        }
        metadata["undo_arguments"] = _ar_arguments(
            wazuh["command"],
            WAZUH_AR_COMMANDS[action][2],
            result.get("target"),
        )
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

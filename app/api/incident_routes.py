"""Инциденты: список, карточка, статус, анализ, действия реагирования —
вынесено из app/api/routes.py (stage-19).

Оркестрация анализа (_run_incident_analysis) живёт в services/auto_analysis.py;
общие хелперы доступа/валидации — в app/api/common.py.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.common import (
    _ensure_incident_access,
    _not_executed,
    _validate_with_playbook,
    ensure_incident_open,
    get_incident_or_404,
)
from app.db import get_db
from app.models import Analysis, Incident, User
from app.schemas import ExecuteActionIn, IncidentDetailOut, IncidentOut, IncidentStatusIn
from app.services.audit import audit
from app.services.auth import get_current_user, require_admin
from app.services.auto_analysis import run_auto_analysis
from app.services.execution import execute_real_action, undo_incident_real_actions

router = APIRouter()

ALLOWED_INCIDENT_STATUSES = ("new", "in_progress", "closed")
ALLOWED_INCIDENT_SEVERITIES = ("low", "medium", "high", "critical")


def _parse_multiselect(raw: str | None, allowed: tuple[str, ...], name: str) -> list[str]:
    """Разбор query-параметра-мультивыбора «v1,v2» фильтров списка инцидентов (stage-15).

    Пустой/отсутствующий параметр → [] (без фильтра); недопустимое
    значение → 422 с перечнем допустимых.
    """
    if not raw or not raw.strip():
        return []
    values = [v.strip() for v in raw.split(",") if v.strip()]
    invalid = [v for v in values if v not in allowed]
    if invalid:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Недопустимое значение параметра {name}: {', '.join(invalid)}. "
                f"Допустимые значения: {', '.join(allowed)}"
            ),
        )
    return list(dict.fromkeys(values))  # без дубликатов, с сохранением порядка


@router.get("/incidents", response_model=list[IncidentOut])
def incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int | None = None,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Список инцидентов (created_at ↓) с мультифильтрами (stage-15):
    ?status=new,in_progress&severity=high,critical — значения через запятую;
    пустой/отсутствующий параметр = без фильтра (прежнее поведение).

    ?limit/?offset (legacy-cleanup) — необязательное окно выдачи: без них
    ответ прежний (весь список). selectinload актива/аналитика убирает
    N+1 валидации IncidentOut (иначе 2 ленивых запроса на строку).
    """
    statuses = _parse_multiselect(status, ALLOWED_INCIDENT_STATUSES, "status")
    severities = _parse_multiselect(severity, ALLOWED_INCIDENT_SEVERITIES, "severity")
    query = (
        select(Incident)
        .options(selectinload(Incident.asset), selectinload(Incident.analyst))
        .order_by(Incident.created_at.desc())
    )
    if statuses:
        query = query.where(Incident.status.in_(statuses))
    if severities:
        query = query.where(Incident.severity.in_(severities))
    if limit is not None:
        query = query.limit(max(0, limit)).offset(max(0, offset))
    items = list(db.scalars(query).all())
    # from_attributes в схемах — валидация напрямую из ORM-объектов
    return [IncidentOut.model_validate(incident) for incident in items]


@router.get("/incidents/{incident_id}", response_model=IncidentDetailOut)
def incident_detail(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Детальная карточка инцидента: события, история анализов, актив (§3.2)."""
    incident = get_incident_or_404(db, incident_id)
    return IncidentDetailOut.model_validate(incident)


@router.patch("/incidents/{incident_id}/status", response_model=IncidentOut)
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Смена статуса инцидента оператором (журналируется в аудит).

    Закрепляет инцидент за пользователем, если он свободен; чужой инцидент
    аналитику недоступен (stage-14). Закрытый инцидент допускает только
    возврат в работу (stage-16).
    """
    incident = get_incident_or_404(db, incident_id)
    _ensure_incident_access(incident, user, assign=True)
    if payload.status not in ALLOWED_INCIDENT_STATUSES:
        raise HTTPException(status_code=422, detail=f"Недопустимый статус: {payload.status}")
    # инцидент закрыт — операции запрещены, доступен только возврат в работу
    # (stage-16, фидбек); проверка после access-чека: reopen — только владелец
    # или админ, чужой аналитик на чужом закрытом инциденте получает 403
    if incident.status == "closed" and payload.status != "in_progress":
        raise HTTPException(
            status_code=409,
            detail="Инцидент закрыт — доступен только возврат в работу",
        )

    previous = incident.status
    incident.status = payload.status
    audit(
        "incident_status_changed",
        {"incident_id": incident.id, "from": previous, "to": payload.status},
        db=db,
        incident_id=incident.id,
    )
    db.commit()
    db.refresh(incident)
    return IncidentOut.model_validate(incident)


@router.post("/incidents/{incident_id}/analyze")
async def analyze(
    incident_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Ручной запуск интеллектуального анализа инцидента (§3.3.4, §3.4).

    Закрепляет инцидент за аналитиком (если свободен); чужой инцидент
    аналитику недоступен (stage-14). Закрытый инцидент анализу недоступен
    (stage-16).

    Stage-18 (фидбек): анализ выполняется В ФОНЕ — синхронный CPU-инференс
    упирался в таймаут nginx (504). Синхронными остаются только проверки
    (404/409/права), затем анализ уходит в BackgroundTasks (run_auto_analysis
    с initiated_by="manual" — ручной анализ не закрывает инцидент автоматически).
    Ответ отдаётся сразу: {"analysis": {"scheduled": True}} — как у ingest.
    """
    incident = get_incident_or_404(db, incident_id)
    # закрытый инцидент — только возврат в работу (stage-16, фидбек)
    ensure_incident_open(incident, "анализ недоступен")
    _ensure_incident_access(incident, user, assign=True)
    background_tasks.add_task(run_auto_analysis, incident.id, "manual")
    audit(
        "incident_analysis_scheduled",
        {"initiated_by": "manual", "by": user.username},
        db=db,
        incident_id=incident.id,
        user_id=user.id,
    )
    db.commit()
    return {"incident_id": incident.id, "analysis": {"scheduled": True}}


@router.post("/incidents/{incident_id}/confirm-action")
def confirm_action(
    incident_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Подтверждение администратором отложенных действий (§3.4, p:17, p:102).

    Выполняет ВСЕ действия из последней рекомендации по инциденту, которые
    разрешены политикой уровня риска (из БД) и для которых зарегистрирован
    playbook. Ответ — список результатов по каждому действию. Закрытый
    инцидент подтверждению недоступен (stage-16).

    Stage-23: исполнение — только реальное, через Wazuh active response
    (как в execute-action): подтверждение администратора снимает
    pending_confirmation и запускает настоящие реакции на ВМ актива.
    """
    incident = get_incident_or_404(db, incident_id)
    # закрытый инцидент — только возврат в работу (stage-16, фидбек)
    ensure_incident_open(incident, "подтверждение действий недоступно")

    analysis = db.scalar(
        select(Analysis)
        .where(Analysis.incident_id == incident_id)
        .order_by(Analysis.created_at.desc())
    )
    if not analysis or not analysis.recommended_action:
        raise HTTPException(status_code=404, detail="No pending recommendation found")

    action_list = [a.strip() for a in str(analysis.recommended_action).split(",") if a.strip()]
    results: list[dict] = []
    for action in action_list:
        playbook, validation = _validate_with_playbook(db, incident, action, admin_confirmed=True)
        execution = (
            execute_real_action(
                db, incident, validation["action"], requested_by=admin.username, playbook=playbook
            )
            if validation["approved"]
            else _not_executed("blocked", action, validation["reason"], playbook)
        )
        audit(
            "action_confirmed_by_admin",
            {"action": action, "validation": validation, "execution": execution},
            db=db,
            incident_id=incident.id,
        )
        results.append({"action": action, "validation": validation, "execution": execution})

    # Перезапись сохранённого анализа (stage-18, фидбек): состояние
    # «подтверждено и исполнено» должно быть видно всем операторам после
    # перезагрузки — плашка «Требуется подтверждение» не должна возвращаться.
    # переприсвоение JSON-колонок обязательно — см. common.py
    raw = dict(analysis.response_raw or {})
    if isinstance(raw.get("results"), list):
        confirm_by_action = {r["action"]: r for r in results}
        raw["results"] = [
            {
                **item,
                "validation": confirm_by_action[item["action"]]["validation"],
                # confirmed_by — кто снял pending_confirmation (аудит в UI)
                "execution": {
                    **confirm_by_action[item["action"]]["execution"],
                    "confirmed_by": admin.username,
                },
            }
            if isinstance(item, dict) and item.get("action") in confirm_by_action
            else item
            for item in raw["results"]
        ]
    # верхнеуровневые compat-ключи — валидация/исполнение первого
    # confirm-результата (как в ответе endpoint'а)
    raw["validation"] = results[0]["validation"]
    raw["execution"] = results[0]["execution"]
    analysis.response_raw = raw

    db.commit()
    return {
        "incident_id": incident.id,
        "results": results,
        # совместимость с прежним форматом ответа: первый результат
        "validation": results[0]["validation"],
        "execution": results[0]["execution"],
    }


@router.post("/incidents/{incident_id}/execute-action")
def execute_action(
    incident_id: int,
    payload: ExecuteActionIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Ручной запуск playbook-действия (stage-12; stage-15: владелец инцидента или админ).

    Запуск действия — работа с инцидентом: свободный инцидент закрепляется за
    исполнителем, чужой аналитику недоступен (403), админ — без ограничений.
    Закрытый инцидент действиям недоступен (stage-16).
    DVE проверяет действие; требование подтверждения критического актива
    снимает только администратор (admin_confirmed по роли): аналитик на
    критическом активе получает pending_confirmation (§3.4, p:102).

    Stage-23: исполнение — ТОЛЬКО реальное, через Wazuh active response API
    (services/execution.py): менеджер доставляет AR-команду агенту на ВМ актива,
    скрипт меняет состояние узла по-настоящему. Режим симуляции (dry run,
    stage-12…20) удалён по явной команде пользователя 2026-11-05 — реакции
    на учебном стенде выполняются только по-настоящему. Успешная доставка
    команды сохраняет отметку в incident.manual_actions (stage-18, фидбек)
    с целью реакции — состояние кнопок видно всем операторам с сервера.
    """
    incident = get_incident_or_404(db, incident_id)
    # закрытый инцидент — только возврат в работу (stage-16, фидбек)
    ensure_incident_open(incident, "выполнение действий недоступно")
    _ensure_incident_access(incident, user, assign=True)

    action = payload.action.strip()
    playbook, validation = _validate_with_playbook(
        db, incident, action, admin_confirmed=user.role == "admin"
    )
    if validation["approved"]:
        execution = execute_real_action(
            db, incident, validation["action"], requested_by=user.username, playbook=playbook
        )
    elif validation.get("requires_confirmation"):
        # Аналитик запустил действие на критическом активе — как в анализе:
        # сохраняется до подтверждения администратора
        execution = _not_executed(
            "pending_confirmation", validation["action"], validation["reason"], playbook
        )
    else:
        execution = _not_executed("blocked", action, validation["reason"], playbook)
    if execution.get("executed"):
        # Отметка ручного запуска в карте инцидента — состояние кнопок видно
        # всем операторам (stage-18, фидбек). Отметка ставится только при
        # фактическом запуске: pending_confirmation/blocked её не пишут;
        # real — если Wazuh Manager принял команду (stage-23), иначе кнопка
        # остаётся доступной для повторного запуска. Для real дополнительно
        # сохраняется цель реакции (IP/учётка/актив) — stage-23.
        # переприсвоение JSON-колонок обязательно — см. common.py
        mark = {
            "mode": execution["mode"],
            "at": datetime.now(timezone.utc).isoformat(),
            "by": user.username,
        }
        if execution.get("target"):
            mark["target"] = execution["target"]
        incident.manual_actions = {
            **(incident.manual_actions or {}),
            action: mark,
        }
    audit(
        "action_executed_manually",
        {
            "action": action,
            "validation": validation,
            "execution": execution,
            "by": user.username,
            "role": user.role,
        },
        db=db,
        incident_id=incident.id,
    )
    db.commit()
    return {
        "incident_id": incident.id,
        "action": action,
        "validation": validation,
        "execution": execution,
    }


@router.post("/incidents/{incident_id}/reset-actions")
def reset_actions(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Сброс отметок ручных запусков playbook-действий (stage-18, фидбек).

    Очищает incident.manual_actions: оператор может переиграть реакцию
    заново, состояние кнопок сбрасывается у ВСЕХ пользователей (отметки
    хранятся на сервере). Права — как у операций реагирования без захвата
    владения: владелец или админ; свободный инцидент доступен любому
    аналитику, analyst_id не изменяется. Закрытый инцидент — 409 (как у
    остальных операций реагирования, stage-16).

    Stage-23: перед сбросом отметок все активные РЕАЛЬНЫЕ реакции инцидента
    (mode=real без undone_at) отменяются обратными AR-командами через
    Wazuh Manager (best-effort: неудача отката не мешает сбросу — запись
    остаётся в «Реакциях (ВМ)», сброс можно повторить; ошибки — в ответе).
    """
    incident = get_incident_or_404(db, incident_id)
    # закрытый инцидент — только возврат в работу (stage-16, фидбек)
    ensure_incident_open(incident, "сброс действий недоступен")
    _ensure_incident_access(incident, user, assign=False)
    # откат реальных реакций (best-effort): исполненные отмены помечаются
    # undone_at/undone_by в metadata_json записей ResponseAction
    undo_results = undo_incident_real_actions(db, incident, requested_by=user.username)
    # полное переприсвоение (переприсвоение JSON-колонок обязательно —
    # см. common.py); NULL → {}
    incident.manual_actions = {}
    audit(
        "incident_actions_reset",
        {"by": user.username, "undo": undo_results},
        db=db,
        incident_id=incident.id,
        user_id=user.id,
    )
    db.commit()
    return {
        "incident_id": incident.id,
        "reset": True,
        "manual_actions": {},
        "undo": undo_results,
    }

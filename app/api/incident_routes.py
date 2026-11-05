"""Инциденты: список, карточка, статус, анализ, действия реагирования —
вынесено из app/api/routes.py (stage-19).

Оркестрация анализа (_run_incident_analysis) живёт в services/auto_analysis.py;
общие хелперы доступа/валидации — в app/api/common.py.
"""

from datetime import timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.common import _ensure_incident_access, _not_executed, _validate_with_playbook
# compat-шов: тесты замораживают datetime на агрегаторе — см. common.py
from app.api.common import routes_datetime as datetime
from app.db import get_db
from app.models import Analysis, Incident, User
from app.schemas import ExecuteActionIn, IncidentDetailOut, IncidentOut, IncidentStatusIn
from app.services.audit import audit
from app.services.auth import get_current_user, require_admin
from app.services.auto_analysis import run_auto_analysis
from app.services.execution import execute_real_action
from app.services.playbook import execute_playbook

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
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Список инцидентов (created_at ↓) с мультифильтрами (stage-15):
    ?status=new,in_progress&severity=high,critical — значения через запятую;
    пустой/отсутствующий параметр = без фильтра (прежнее поведение).
    """
    statuses = _parse_multiselect(status, ALLOWED_INCIDENT_STATUSES, "status")
    severities = _parse_multiselect(severity, ALLOWED_INCIDENT_SEVERITIES, "severity")
    query = select(Incident).order_by(Incident.created_at.desc())
    if statuses:
        query = query.where(Incident.status.in_(statuses))
    if severities:
        query = query.where(Incident.severity.in_(severities))
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
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
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
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
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
    db.commit()
    db.refresh(incident)

    audit(
        "incident_status_changed",
        {"incident_id": incident.id, "from": previous, "to": payload.status},
        db=db,
        incident_id=incident.id,
    )
    db.commit()
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
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    # инцидент закрыт — операции реагирования запрещены, доступен только
    # возврат в работу (stage-16, фидбек)
    if incident.status == "closed":
        raise HTTPException(
            status_code=409,
            detail="Инцидент закрыт — анализ недоступен. Верните инцидент в работу",
        )
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
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    # инцидент закрыт — операции реагирования запрещены, доступен только
    # возврат в работу (stage-16, фидбек)
    if incident.status == "closed":
        raise HTTPException(
            status_code=409,
            detail="Инцидент закрыт — подтверждение действий недоступно. Верните инцидент в работу",
        )

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
            execute_playbook(validation["action"], {"incident_id": incident.id}, db)
            if validation["approved"]
            else {"executed": False, "mode": "blocked", "action": action, "reason": validation["reason"]}
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
    Исполнение — через execute_playbook: при AUTO_RESPONSE=false это dry run
    (симуляция, без изменения инфраструктуры), иначе — контролируемое выполнение.
    Успешный запуск (simulation/controlled) сохраняет отметку в
    incident.manual_actions (stage-18, фидбек) — состояние кнопок действий
    видно всем операторам с сервера, а не из localStorage.

    Stage-20: payload.mode="real" — реальное исполнение на ВМ через агента
    (services/execution.py): DVE тот же, меняется только способ исполнения.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    # инцидент закрыт — операции реагирования запрещены, доступен только
    # возврат в работу (stage-16, фидбек)
    if incident.status == "closed":
        raise HTTPException(
            status_code=409,
            detail="Инцидент закрыт — выполнение действий недоступно. Верните инцидент в работу",
        )
    _ensure_incident_access(incident, user, assign=True)

    action = payload.action.strip()
    playbook, validation = _validate_with_playbook(
        db, incident, action, admin_confirmed=user.role == "admin"
    )
    if validation["approved"]:
        if payload.mode == "real":
            execution = execute_real_action(db, incident, validation["action"], requested_by=user.username)
        else:
            execution = execute_playbook(validation["action"], {"incident_id": incident.id}, db)
    elif validation.get("requires_confirmation"):
        # Аналитик запустил действие на критическом активе — как в анализе:
        # сохраняется до подтверждения администратора
        execution = _not_executed(
            "pending_confirmation", validation["action"], validation["reason"], playbook
        )
    else:
        execution = {
            "executed": False,
            "mode": "blocked",
            "action": action,
            "reason": validation["reason"],
        }
    if execution.get("mode") in ("simulation", "controlled") or execution.get("executed"):
        # Отметка ручного запуска в карте инцидента — состояние кнопок видно
        # всем операторам (stage-18, фидбек). Отметка ставится при фактическом
        # запуске: pending_confirmation/blocked её не пишут. Симуляция пишет
        # всегда (executed=False там означает dry run, а не ошибку); real —
        # только если цель подтвердила исполнение (stage-20), иначе кнопка
        # остаётся доступной для повторного запуска.
        # переприсвоение JSON-колонок обязательно — см. common.py
        incident.manual_actions = {
            **(incident.manual_actions or {}),
            action: {
                "mode": execution["mode"],
                "at": datetime.now(timezone.utc).isoformat(),
                "by": user.username,
            },
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
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    # инцидент закрыт — операции реагирования запрещены, доступен только
    # возврат в работу (stage-16, фидбек)
    if incident.status == "closed":
        raise HTTPException(
            status_code=409,
            detail="Инцидент закрыт — сброс действий недоступен. Верните инцидент в работу",
        )
    _ensure_incident_access(incident, user, assign=False)
    # полное переприсвоение (переприсвоение JSON-колонок обязательно —
    # см. common.py); NULL → {}
    incident.manual_actions = {}
    audit(
        "incident_actions_reset",
        {"by": user.username},
        db=db,
        incident_id=incident.id,
        user_id=user.id,
    )
    db.commit()
    return {"incident_id": incident.id, "reset": True, "manual_actions": {}}

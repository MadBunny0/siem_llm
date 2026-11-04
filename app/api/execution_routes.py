"""Цели реального исполнения (stage-20): реестр агентов на ВМ наблюдаемых
пользователей — отдельный роутер (домен «исполнение»; подключается в routes.py).

GET  /execution-targets                — список целей со статусами (UI, вкладка «Агенты»)
POST /execution-targets/{id}/check     — проверка доступности агента (heartbeat)
GET  /execution-targets/{id}/journal   — журнал исполненных действий агента (прокси)
GET  /execution-targets/{id}/activity  — журнал активности пользователя/атакующего (прокси)
POST /execution-targets/{id}/reset     — сброс состояния эмулируемой ВМ (демо-повторяемость)
POST /execution-targets/{id}/simulate  — проиграть активность (алерты Wazuh → SIEM, прокси)

Токен агента не покидает бэкенд: журналы/сброс/симуляция идут через прокси —
браузеру URL/токены агентов недоступны.
"""

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import ExecutionTarget, User
from app.schemas import ExecutionJournalEntry, ExecutionSimulateIn, ExecutionTargetOut
from app.services.audit import audit
from app.services.auth import get_current_user

router = APIRouter()


def _get_target(db: Session, target_id: int) -> ExecutionTarget:
    target = db.get(ExecutionTarget, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Execution target not found")
    return target


def _agent_headers(target: ExecutionTarget) -> dict:
    headers = {}
    if target.auth_token:
        headers["Authorization"] = f"Bearer {target.auth_token}"
    return headers


def _agent_get(target: ExecutionTarget, path: str) -> dict:
    try:
        with httpx.Client(timeout=settings.execution_timeout_seconds) as client:
            response = client.get(
                f"{target.base_url.rstrip('/')}{path}", headers=_agent_headers(target)
            )
            response.raise_for_status()
            return response.json()
    except Exception as exc:
        target.status = "offline"
        target.last_seen = None
        raise HTTPException(
            status_code=502,
            detail=f"Агент {target.name} недоступен: {exc}",
        )


@router.get("/execution-targets", response_model=list[ExecutionTargetOut])
def execution_targets(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Реестр целей реального исполнения (stage-20): агенты на ВМ наблюдаемых
    пользователей; статус/heartbeat обновляются при исполнении действий."""
    targets = list(db.scalars(select(ExecutionTarget).order_by(ExecutionTarget.id)).all())
    return [ExecutionTargetOut.model_validate(t) for t in targets]


@router.post("/execution-targets/{target_id}/check", response_model=ExecutionTargetOut)
def check_execution_target(
    target_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Проверка доступности агента: GET /agent/status на цели; статус
    (online/offline) и время последнего ответа сохраняются в реестре."""
    from datetime import datetime, timezone

    target = _get_target(db, target_id)
    try:
        with httpx.Client(timeout=settings.execution_timeout_seconds) as client:
            response = client.get(
                f"{target.base_url.rstrip('/')}/agent/status",
                headers=_agent_headers(target),
            )
            response.raise_for_status()
        target.status = "online"
        target.last_seen = datetime.now(timezone.utc)
    except Exception as exc:
        target.status = "offline"
        db.commit()
        raise HTTPException(status_code=502, detail=f"Агент {target.name} недоступен: {exc}")
    audit(
        "execution_target_checked",
        {"target": target.name, "status": target.status},
        db=db,
        user_id=user.id,
    )
    db.commit()
    db.refresh(target)
    return ExecutionTargetOut.model_validate(target)


@router.get("/execution-targets/{target_id}/journal", response_model=list[ExecutionJournalEntry])
def execution_target_journal(
    target_id: int,
    limit: int = 50,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Журнал исполненных действий агента (демонстрация реального исполнения):
    SIEM запрашивает агента как прокси — токен не покидает бэкенд."""
    target = _get_target(db, target_id)
    data = _agent_get(target, f"/agent/journal?limit={max(1, min(limit, 200))}")
    target.status = "online"
    db.commit()
    return [ExecutionJournalEntry.model_validate(item) for item in data.get("journal", [])]


@router.get("/execution-targets/{target_id}/activity")
def execution_target_activity(
    target_id: int,
    limit: int = 50,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Журнал активности наблюдаемого пользователя/атакующего на ВМ (прокси):
    чем жила машина — входы, почта, атаки; видно, какие события породил SIEM."""
    target = _get_target(db, target_id)
    data = _agent_get(target, f"/agent/activity?limit={max(1, min(limit, 200))}")
    target.status = "online"
    db.commit()
    return data.get("activity", [])


@router.post("/execution-targets/{target_id}/simulate")
def simulate_execution_target(
    target_id: int,
    payload: ExecutionSimulateIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Проиграть активность на ВМ (прокси к агенту): агент генерирует события
    (нормальная активность пользователей или атака) и отправляет их в SIEM
    как алерты Wazuh — ответ содержит результаты /ingest/wazuh (созданные
    инциденты). Демонстрация полного цикла из вкладки «Агенты»."""
    target = _get_target(db, target_id)
    try:
        with httpx.Client(timeout=60) as client:
            response = client.post(
                f"{target.base_url.rstrip('/')}/agent/simulate",
                json={"scenario": payload.scenario, "count": payload.count},
                headers=_agent_headers(target),
            )
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        target.status = "offline"
        db.commit()
        raise HTTPException(status_code=502, detail=f"Агент {target.name} недоступен: {exc}")
    target.status = "online"
    audit(
        "execution_target_simulated",
        {"target": target.name, "scenario": payload.scenario, "count": payload.count, "by": user.username},
        db=db,
        user_id=user.id,
    )
    db.commit()
    return data


@router.post("/execution-targets/{target_id}/reset", response_model=ExecutionTargetOut)
def reset_execution_target(
    target_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Сброс состояния эмулируемой ВМ к исходному (повторяемость демонстрации):
    снимает блокировки/изоляцию, возвращает учётные записи и файлы."""
    from datetime import datetime, timezone

    target = _get_target(db, target_id)
    try:
        with httpx.Client(timeout=settings.execution_timeout_seconds) as client:
            response = client.post(
                f"{target.base_url.rstrip('/')}/agent/reset",
                headers=_agent_headers(target),
            )
            response.raise_for_status()
    except Exception as exc:
        target.status = "offline"
        db.commit()
        raise HTTPException(status_code=502, detail=f"Агент {target.name} недоступен: {exc}")
    target.status = "online"
    target.last_seen = datetime.now(timezone.utc)
    audit(
        "execution_target_reset",
        {"target": target.name, "by": user.username},
        db=db,
        user_id=user.id,
    )
    db.commit()
    db.refresh(target)
    return ExecutionTargetOut.model_validate(target)

"""Общие хелперы роутеров REST API (stage-19: монолит routes.py разрезан по доменам).

КАНОНИЧЕСКИЙ КОММЕНТАРИЙ (грабль проекта): мутация JSON-колонки не отслеживается
SQLAlchemy — только полное переприсвоение словаря. Изменение JSON-поля
(Analysis.response_raw, Incident.manual_actions) попадает в БД лишь при
переприсвоении атрибута целиком; далее обычный db.commit() вызывающего.
В местах мутаций оставлена короткая ссылка на этот комментарий.
"""

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import Incident, Playbook, User
from app.services.playbook import load_playbook_by_action
from app.services.validation import validate_recommendation


def get_incident_or_404(db: Session, incident_id: int) -> Incident:
    """Инцидент по id или 404 — общая проверка всех эндпоинтов инцидентов
    (до legacy-cleanup блок db.get+404 повторялся в каждом обработчике)."""
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def ensure_incident_open(incident: Incident, what: str) -> None:
    """Закрытый инцидент недоступен операциям анализа/реагирования (stage-16,
    фидбек): 409 с подсказкой вернуть инцидент в работу. what — имя операции
    в тексте ответа («анализ недоступен», «выполнение действий недоступно», …)."""
    if incident.status == "closed":
        raise HTTPException(
            status_code=409,
            detail=f"Инцидент закрыт — {what}. Верните инцидент в работу",
        )


def _ensure_incident_access(incident: Incident, user: User, assign: bool = False) -> None:
    """Право на операцию с инцидентом (stage-14): владелец или администратор.

    assign=True — незакреплённый инцидент закрепляется за текущим пользователем
    (первым, кто взял его в работу). Чужой незакреплённый/чужой закреплённый для
    аналитика → 403; админ работает с любым и свободный инцидент тоже закрепляет
    за собой (stage-16) — иначе бейдж «Назначен» остаётся пустым. Закреплённый
    за аналитиком инцидент админ не перехватывает.
    """
    if user.role == "admin":
        # свободный инцидент закрепляется и за админом (stage-16);
        # чужое владение не перехватывается (философия stage-14)
        if assign and incident.analyst_id is None:
            incident.analyst_id = user.id
        return
    if incident.analyst_id is None:
        if assign:
            incident.analyst_id = user.id
        return
    if incident.analyst_id != user.id:
        raise HTTPException(
            status_code=403,
            detail=(
                "Инцидент закреплён за другим аналитиком — задачи нельзя "
                "перехватывать (обратитесь к администратору)"
            ),
        )


def _not_executed(mode: str, action: str, reason: str | None, playbook: Playbook | None) -> dict:
    """Сборка execution-словаря неисполненного действия — общая для
    _run_incident_analysis (pending_confirmation / blocked / manual_run) и
    ручного запуска POST /execute-action (pending_confirmation).

    Описание и шаги сценария включаются в словарь, чтобы действие было
    понятно оператору (stage-14 описание, stage-15 шаги).
    """
    return {
        "executed": False,
        "mode": mode,
        "action": action,
        "reason": reason,
        "playbook": playbook.name if playbook else None,
        "playbook_description": playbook.description if playbook else None,
        "playbook_steps": playbook.steps if playbook else None,
    }


def _validate_with_playbook(
    db: Session,
    incident: Incident,
    action: str,
    admin_confirmed: bool = False,
) -> tuple[Playbook | None, dict]:
    """Связка playbook+DVE (stage-19): поиск сценария реагирования по действию
    и проверка действия Decision Validation Engine'ом — политика уровня риска
    (из БД) + playbook + критичность актива инцидента (§3.4).

    admin_confirmed — подтверждение администратора (POST /confirm-action
    передаёт True; POST /execute-action — по роли; в анализе подтверждения
    нет — default False совпадает с прежним отсутствием аргумента).
    """
    playbook = load_playbook_by_action(db, action)
    validation = validate_recommendation(
        incident.severity,
        {"recommended_action": action},
        asset_criticality=incident.asset.criticality if incident.asset else None,
        playbook_found=playbook is not None,
        admin_confirmed=admin_confirmed,
        db=db,
    )
    return playbook, validation

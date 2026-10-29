import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.config import settings
from app.models import Playbook, ResponseAction

logger = logging.getLogger("playbook")


def load_playbook_by_action(db: Session, action: str) -> Playbook | None:
    """Загрузка сценария реагирования из БД по типу действия."""
    playbooks = db.scalars(
        select(Playbook).where(Playbook.is_active.is_(True))
    ).all()
    for playbook in playbooks:
        allowed_actions = playbook.allowed_actions or []
        if isinstance(allowed_actions, str):
            allowed_actions = [allowed_actions]
        if action in allowed_actions:
            return playbook
    return None


def execute_playbook(action: str, context: dict, db: Session | None = None) -> dict:
    """
    Выполнение сценария реагирования согласно Главе 3.4.
    Если db передан — сценарий загружается из БД (Playbook),
    результаты записываются в ResponseAction.
    """
    # Безопасный режим демонстрации. Реальное изменение инфраструктуры выключено.
    if not settings.auto_response:
        logger.warning("SIMULATION: action=%s context=%s", action, context)
        return {"executed": False, "mode": "simulation", "action": action}

    # Точка интеграции с Wazuh Active Response.
    if db is not None:
        playbook = load_playbook_by_action(db, action)
        result = {"executed": True, "mode": "controlled", "action": action}
        if playbook:
            result["playbook"] = playbook.name
            # запись выполненного действия в ResponseAction
            resp_action = ResponseAction(
                incident_id=context.get("incident_id"),
                playbook_id=playbook.id,
                action_type=action,
                executed_at=datetime.now(timezone.utc),
                result="выполнено",
                initiated_by="playbook",
                metadata=context,
            )
            db.add(resp_action)
            db.flush()
            result["response_action_id"] = resp_action.id
        return result

    logger.warning("CONTROLLED RESPONSE: action=%s context=%s", action, context)
    return {"executed": True, "mode": "controlled", "action": action}

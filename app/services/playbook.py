import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.config import settings
from app.models import Incident, Playbook, ResponseAction
from app.services.notification import notify_analyst

logger = logging.getLogger("playbook")


# ---------------------------------------------------------------------------
# ITSM — интеграция с системой учёта заявок (ServiceNow/Jira)
# ---------------------------------------------------------------------------
class ITSMClient:
    """Заглушка клиента ITSM (ServiceNow / Jira / Zammad).

    В реальном проекте здесь будут вызовы REST API системы учёта заявок.
    """

    def __init__(self, service_now_url: str | None = None, jira_url: str | None = None):
        self.service_now_url = service_now_url
        self.jira_url = jira_url

    def create_ticket(self, incident: "Incident | None") -> dict:
        """Создание инцидента в системе учёта заявок (Глава 3.4 ВКР)."""
        if incident is None:
            logger.warning("ITSM ticket NOT sent: incident not found")
            return {"created": False, "reason": "incident_not_found"}
        if settings.auto_response:
            logger.info(
                "ITSM ticket created: incident_id=%s title=%s severity=%s",
                incident.id, incident.title, incident.severity,
            )
            return {
                "created": True,
                "ticket_id": f"INC-{incident.id:06d}",
                "url": f"https://demo.itsm.example.com/incident/{incident.id}",
            }
        logger.warning(
            "ITSM ticket NOT sent (simulation mode): incident_id=%s", incident.id
        )
        return {
            "created": False,
            "mode": "simulation",
            "ticket_id": None,
        }


itsm = ITSMClient()


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
    incident_id = context.get("incident_id")

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
                incident_id=incident_id,
                playbook_id=playbook.id,
                action_type=action,
                executed_at=datetime.now(timezone.utc),
                result="выполнено",
                initiated_by="playbook",
                metadata_json=context,
            )
            db.add(resp_action)
            db.flush()
            result["response_action_id"] = resp_action.id
            # ITSM-регистрация инцидента в системе учёта заявок (сценарий 3.4 ВКР)
            incident_obj = db.get(Incident, incident_id) if incident_id else None
            if incident_obj is not None:
                try:
                    result["itsm_ticket"] = itsm.create_ticket(incident_obj)
                except Exception as exc:
                    logger.error("ITSM ticket creation failed: %s", exc)
                    result["itsm_ticket"] = {"created": False, "error": str(exc)}
                # ITSM-уведомление аналитикам о выполненном ответном действии
                notify_analyst(db, incident_obj, "action_executed")
        return result

    logger.warning("CONTROLLED RESPONSE: action=%s context=%s", action, context)
    return {"executed": True, "mode": "controlled", "action": action}

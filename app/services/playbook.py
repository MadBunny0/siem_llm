import logging
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import Playbook

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
        logger.info(
            "ITSM ticket NOT sent (integration not configured): incident_id=%s title=%s",
            incident.id, incident.title,
        )
        return {
            "created": False,
            "reason": "itsm_not_configured",
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

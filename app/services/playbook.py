from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Playbook


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

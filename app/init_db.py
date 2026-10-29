"""Initialize the PostgreSQL schema before the API container starts."""

from sqlalchemy import select
from app.db import Base, engine
from app import models  # noqa: F401 - registers all SQLAlchemy models


def main() -> None:
    Base.metadata.create_all(bind=engine)
    print("Database schema initialized successfully.", flush=True)
    _seed_default_correlation_rules()
    _seed_default_playbooks()


def _seed_default_correlation_rules() -> None:
    """Создание базовых правил корреляции, если их ещё нет (согласно Главе 3.2)."""
    from sqlalchemy.orm import Session
    rules = [
        {
            "name": "brute_force_attempts",
            "description": "Множественные неудачные попытки входа с одного IP за короткое время",
            "conditions": [
                {"field": "event_type", "operator": "like", "value": "authentication_failed"},
                {"field": "src_ip", "operator": "in", "value": []},
            ],
            "time_window_minutes": 5,
            "priority": 2,
            "is_active": True,
        },
        {
            "name": "repeated_scan",
            "description": "Повторяющиеся события с одного IP в течение окна корреляции",
            "conditions": [
                {"field": "src_ip", "operator": "like", "value": ""},
            ],
            "time_window_minutes": 10,
            "priority": 1,
            "is_active": True,
        },
    ]
    with Session(engine) as session:
        for rule_data in rules:
            stmt = select(models.CorrelationRule).where(
                models.CorrelationRule.name == rule_data["name"]
            )
            existing = session.scalar(stmt)
            if not existing:
                rule = models.CorrelationRule(**rule_data)
                session.add(rule)
        session.commit()


def _seed_default_playbooks() -> None:
    """Создание базовых сценариев реагирования (согласно Главе 3.4)."""
    from sqlalchemy.orm import Session
    playbooks = [
        {
            "name": "block_ip",
            "description": "Блокировка IP-адреса источника подозрительной активности",
            "trigger_conditions": {"attack_type": ["network_scan", "brute_force"]},
            "allowed_actions": ["block_ip"],
            "steps": [
                {"action": "block_ip", "target": "{{src_ip}}", "tool": "firewall"}
            ],
            "priority": 1,
            "is_active": True,
        },
        {
            "name": "disable_account",
            "description": "Временная блокировка учётной записи при признаках компрометации",
            "trigger_conditions": {"attack_type": ["credential_attack"]},
            "allowed_actions": ["disable_account"],
            "steps": [
                {"action": "disable_account", "target": "{{user}}", "tool": "idm"}
            ],
            "priority": 2,
            "is_active": True,
        },
    ]
    with Session(engine) as session:
        for pb_data in playbooks:
            stmt = select(models.Playbook).where(
                models.Playbook.name == pb_data["name"]
            )
            existing = session.scalar(stmt)
            if not existing:
                pb = models.Playbook(**pb_data)
                session.add(pb)
        session.commit()


if __name__ == "__main__":
    main()

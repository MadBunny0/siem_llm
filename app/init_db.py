"""Initialize the PostgreSQL schema before the API container starts."""

from sqlalchemy import select
from app.db import Base, engine
from app import models  # noqa: F401 - registers all SQLAlchemy models


def main() -> None:
    Base.metadata.create_all(bind=engine)
    print("Database schema initialized successfully.", flush=True)
    _seed_default_users()
    _seed_default_assets()
    _seed_default_correlation_rules()
    _seed_default_playbooks()


def _seed_default_users() -> None:
    """Создание базовых пользователей системы (аналитики SOC)."""
    from sqlalchemy.orm import Session
    users = [
        {
            "username": "analyst1",
            "password_hash": "pbkdf2:sha256:260000$...",
            "role": "analyst",
        },
        {
            "username": "analyst2",
            "password_hash": "pbkdf2:sha256:260000$...",
            "role": "analyst",
        },
        {
            "username": "soc_lead",
            "password_hash": "pbkdf2:sha256:260000$...",
            "role": "analyst",
        },
    ]
    with Session(engine) as session:
        for user_data in users:
            stmt = select(models.User).where(models.User.username == user_data["username"])
            existing = session.scalar(stmt)
            if not existing:
                user = models.User(**user_data)
                session.add(user)
        session.commit()


def _seed_default_assets() -> None:
    """Создание базовых защищаемых активов (согласно Главе 3.2)."""
    from sqlalchemy.orm import Session

    assets = [
        {
            "name": "mail-prod-01",
            "type": "server",
            "criticality": "critical",
            "network_segment": "DMZ",
            "description": "Продуктовый почтовый сервер",
            "ip_addresses": "10.20.30.10",
        },
        {
            "name": "db-primary-01",
            "type": "database",
            "criticality": "critical",
            "network_segment": "internal",
            "description": "Основной сервер баз данных (PostgreSQL)",
            "ip_addresses": "10.20.40.5",
        },
        {
            "name": "fw-edge-01",
            "type": "network_device",
            "criticality": "high",
            "network_segment": "edge",
            "description": "Периметровый фаервол",
            "ip_addresses": "10.0.0.1",
        },
        {
            "name": "wks-finance-12",
            "type": "workstation",
            "criticality": "medium",
            "network_segment": "internal",
            "description": "АРМ финансового отдела",
            "ip_addresses": "10.20.50.12",
        },
        {
            "name": "app-web-01",
            "type": "application",
            "criticality": "high",
            "network_segment": "internal",
            "description": "Веб-сервер клиентского приложения",
            "ip_addresses": "10.20.60.20",
        },
    ]
    with Session(engine) as session:
        for asset_data in assets:
            stmt = select(models.Asset).where(models.Asset.name == asset_data["name"])
            existing = session.scalar(stmt)
            if not existing:
                asset = models.Asset(**asset_data)
                session.add(asset)
        session.commit()


def _seed_default_correlation_rules() -> None:
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

"""Initialize the PostgreSQL schema before the API container starts."""

from sqlalchemy import select
from app.db import Base, engine
from app import models  # noqa: F401 - registers all SQLAlchemy models


def main() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_schema_updates()
    print("Database schema initialized successfully.", flush=True)
    _seed_default_users()
    _seed_default_assets()
    _seed_default_correlation_rules()
    _seed_default_playbooks()


def _ensure_schema_updates() -> None:
    """Лёгкие миграции для существующих БД (Alembic не используется).

    create_all создаёт только новые таблицы, но не добавляет колонки
    в существующие — добавляем недостающие колонки явно.
    """
    from sqlalchemy import text

    statements = [
        # порог повторений для правил корреляции (§3.3.2 ВКР)
        "ALTER TABLE correlation_rules ADD COLUMN IF NOT EXISTS min_events INTEGER NOT NULL DEFAULT 1",
    ]
    with engine.begin() as conn:
        for stmt in statements:
            conn.execute(text(stmt))


def _seed_default_users() -> None:
    """Создание базовых пользователей SOC (stage-09: реальные PBKDF2-хеши).

    Демо-учётки: analyst1/analyst123, analyst2/analyst123 (аналитики),
    soc_lead/soclead123 (администратор — подтверждение действий на
    критических активах, §3.4 ВКР, p:17).
    """
    from sqlalchemy.orm import Session

    from app.services.security import hash_password

    users = [
        {"username": "analyst1", "password": "analyst123", "role": "analyst"},
        {"username": "analyst2", "password": "analyst123", "role": "analyst"},
        {"username": "soc_lead", "password": "soclead123", "role": "admin"},
    ]
    with Session(engine) as session:
        for user_data in users:
            stmt = select(models.User).where(models.User.username == user_data["username"])
            existing = session.scalar(stmt)
            if not existing:
                user = models.User(
                    username=user_data["username"],
                    password_hash=hash_password(user_data["password"]),
                    role=user_data["role"],
                )
                session.add(user)
            else:
                # миграция старых seed-заглушек ("pbkdf2:sha256:260000$...") —
                # они не проходят проверку verify_password; заодно роли
                if existing.password_hash.startswith("pbkdf2:"):
                    existing.password_hash = hash_password(user_data["password"])
                    session.add(existing)
                if existing.role != user_data["role"]:
                    existing.role = user_data["role"]
                    session.add(existing)
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
                {"field": "user", "operator": "neq", "value": ""},
            ],
            "time_window_minutes": 5,
            "min_events": 3,  # порог повторений (§3.3.2)
            "priority": 2,
            "is_active": True,
        },
        {
            "name": "repeated_scan",
            "description": "Повторяющиеся события с одного IP в течение окна корреляции",
            "conditions": [
                {"field": "src_ip", "operator": "neq", "value": ""},
            ],
            "time_window_minutes": 10,
            "min_events": 2,
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
            elif existing.min_events != rule_data.get("min_events", 1):
                existing.min_events = rule_data.get("min_events", 1)  # обновление порога
                session.add(existing)
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
        {
            "name": "isolate_host",
            "description": "Изоляция скомпрометированного узла от корпоративной сети",
            "trigger_conditions": {"attack_type": ["malware", "privilege_escalation"]},
            "allowed_actions": ["isolate_host"],
            "steps": [
                {"action": "isolate_host", "target": "{{asset}}", "tool": "edr"}
            ],
            "priority": 3,
            "is_active": True,
        },
        {
            "name": "collect_evidence",
            "description": "Сбор и сохранение доказательств по инциденту",
            "trigger_conditions": {"attack_type": ["monitor", "collect_evidence"]},
            "allowed_actions": ["collect_evidence"],
            "steps": [
                {"action": "collect_evidence", "target": "{{incident}}", "tool": "audit"}
            ],
            "priority": 1,
            "is_active": True,
        },
        {
            "name": "monitor",
            "description": "Наблюдение за инцидентом без активного вмешательства",
            "trigger_conditions": {"attack_type": ["monitor"]},
            "allowed_actions": ["monitor"],
            "steps": [
                {"action": "monitor", "target": "{{incident}}", "tool": "none"}
            ],
            "priority": 1,
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

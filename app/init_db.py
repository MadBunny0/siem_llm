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
    _seed_validation_policy()


def _ensure_schema_updates() -> None:
    """Лёгкие миграции для существующих БД (Alembic не используется).

    create_all создаёт только новые таблицы, но не добавляет колонки
    и индексы в существующие — добавляем явно.
    """
    from sqlalchemy import text

    statements = [
        # порог повторений для правил корреляции (§3.3.2 ВКР)
        "ALTER TABLE correlation_rules ADD COLUMN IF NOT EXISTS min_events INTEGER NOT NULL DEFAULT 1",
        # критерии успешного завершения сценария (§3.4 ВКР, p:105)
        "ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS success_criteria JSON",
        # индексы под корреляцию (stage-11: окно + совпадение атрибутов в SQL)
        "CREATE INDEX IF NOT EXISTS ix_events_timestamp ON events (timestamp)",
        "CREATE INDEX IF NOT EXISTS ix_events_src_ip ON events (src_ip)",
        # "user" — зарезервированное слово Postgres (без кавычек парсится как функция user())
        'CREATE INDEX IF NOT EXISTS ix_events_user ON events ("user")',
        "CREATE INDEX IF NOT EXISTS ix_events_asset_id ON events (asset_id)",
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
    """Seed-правила корреляции по техникам MITRE ATT&CK (база mitre.ptsecurity.com,
    ATT&CK v15.1) — покрывают классы атак из §3.3.2 ВКР (p:61)."""
    from sqlalchemy.orm import Session

    rules = [
        {
            # T1110 Метод перебора (§3.3.2: «подбор паролей»)
            "name": "brute_force_attempts",
            "description": "T1110 Метод перебора: множественные неудачные попытки входа с одного IP за короткое время",
            "conditions": [
                {"field": "event_type", "operator": "like", "value": "authentication_failed"},
                {"field": "user", "operator": "neq", "value": ""},
            ],
            "time_window_minutes": 5,
            "min_events": 3,
            "priority": 2,
            "is_active": True,
        },
        {
            # T1110.003 Распыление паролей (§3.3.2: «перебор учётных записей»):
            # одна учётка после другой с одного IP — совпадение по src_ip
            "name": "password_spraying",
            "description": "T1110.003 Распыление паролей: перебор разных учётных записей с одного IP за окно",
            "conditions": [
                {"field": "event_type", "operator": "like", "value": "authentication_failed"},
                {"field": "src_ip", "operator": "neq", "value": ""},
            ],
            "time_window_minutes": 10,
            "min_events": 5,  # выше brute_force: 4 события одной учётки = brute, 5+ разных = spraying
            "priority": 3,  # spraying специфичнее brute_force — детерминированно перебивает его
            "is_active": True,
        },
        {
            # T1046 Изучение сетевых служб (§3.3.2: «сетевое сканирование»)
            "name": "repeated_scan",
            "description": "T1046 Изучение сетевых служб: повторяющиеся события с одного IP в течение окна корреляции",
            "conditions": [
                {"field": "src_ip", "operator": "neq", "value": ""},
            ],
            "time_window_minutes": 10,
            "min_events": 2,
            "priority": 1,
            "is_active": True,
        },
        {
            # T1068 / T1548 Повышение привилегий (§3.3.2: «попытки получения НСД»)
            "name": "privilege_escalation_attempt",
            "description": "T1068/T1548 Повышение привилегий: эксплуатация уязвимостей или обход контроля привилегий",
            "conditions": [
                {"field": "event_type", "operator": "like", "value": "privilege"},
            ],
            "time_window_minutes": 10,
            "min_events": 1,
            "priority": 3,
            "is_active": True,
        },
        {
            # T1190 Недостатки в общедоступном приложении
            "name": "web_attack",
            "description": "T1190 Недостатки в общедоступном приложении: попытки эксплуатации веб-ресурсов",
            "conditions": [
                {"field": "event_type", "operator": "like", "value": "web"},
            ],
            "time_window_minutes": 5,
            "min_events": 2,
            "priority": 2,
            "is_active": True,
        },
        {
            # T1204 Выполнение с участием пользователя (запуск вредоносного ПО)
            "name": "malware_detection",
            "description": "T1204 Вредоносное ПО: обнаружение вредоносной активности или выполнения",
            "conditions": [
                {"field": "event_type", "operator": "like", "value": "malware"},
            ],
            "time_window_minutes": 10,
            "min_events": 1,
            "priority": 3,
            "is_active": True,
        },
        {
            # T1048 Эксфильтрация по альтернативному протоколу
            "name": "data_exfiltration",
            "description": "T1048 Эксфильтрация данных: признаки несанкционированной передачи данных",
            "conditions": [
                {"field": "event_type", "operator": "like", "value": "exfiltration"},
            ],
            "time_window_minutes": 15,
            "min_events": 1,
            "priority": 3,
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
            "success_criteria": [
                "Новые соединения с заблокированного IP-адреса отсутствуют",
                "Правило блокировки подтверждено межсетевым экраном",
                "Инцидент переведён в статус in_progress",
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
            "success_criteria": [
                "Учётная запись заблокирована в подсистеме управления пользователями",
                "Попытки входа под учётной записью отклоняются",
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
            "success_criteria": [
                "Узел изолирован от корпоративной сети (карантин EDR)",
                "Доступ к узлу сохранён только для администратора безопасности",
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
            "success_criteria": [
                "Снимки событий и результатов анализа сохранены для расследования",
                "Материалы инцидента доступны в журнале аудита",
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
            "success_criteria": [
                "Инцидент взят под наблюдение",
                "Повторные события фиксируются в журнале аудита",
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


def _seed_validation_policy() -> None:
    """Seed формализованной политики DVE в БД (§3.4, p:103, stage-11).

    Источник значений — DEFAULT_ALLOWED_ACTIONS из app/services/validation.py:
    какие действия разрешены для каждого уровня риска инцидента.
    """
    from sqlalchemy.orm import Session

    from app.services.validation import ALLOWED_ACTIONS

    with Session(engine) as session:
        for severity, allowed in ALLOWED_ACTIONS.items():
            stmt = select(models.ValidationPolicy).where(models.ValidationPolicy.severity == severity)
            existing = session.scalar(stmt)
            if not existing:
                session.add(
                    models.ValidationPolicy(
                        severity=severity,
                        allowed_actions=sorted(allowed),
                    )
                )
        session.commit()


if __name__ == "__main__":
    main()

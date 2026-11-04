"""Тесты авторизации (stage-09): /auth/login, /auth/me, JWT-защита эндпоинтов.

В отличие от test_routes.py (где авторизация обходится через dependency_overrides),
здесь проверяется реальный флоу: seed пользователей с PBKDF2-хешами → вход →
Bearer-токен → доступ/401/403.
"""

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.db import get_db
from app.main import app
from app.models import Base, User
from app.services.security import create_access_token, hash_password

API = "/api/v1"


@pytest.fixture
def engine():
    """Изолированная in-memory SQLite-БД, общая для всех соединений (StaticPool)."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(engine):
    """Прямая сессия — для seed демо-пользователей с реальными хешами."""
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(engine, db_session, monkeypatch):
    """TestClient на тестовой БД; auth НЕ патчится — проверяем реальный флоу."""
    # LLM-автоанализ и реагирование не нужны в auth-тестах
    monkeypatch.setattr(settings, "auto_analysis", False)
    monkeypatch.setattr(settings, "auto_response", False)

    def override_get_db():
        db = sessionmaker(bind=engine)()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def seed_users(db_session):
    """Демо-пользователи: два аналитика и администратор."""
    db_session.add(User(username="analyst1", password_hash=hash_password("analyst123"), role="analyst"))
    db_session.add(User(username="analyst2", password_hash=hash_password("analyst123"), role="analyst"))
    db_session.add(User(username="soc_lead", password_hash=hash_password("soclead123"), role="admin"))
    db_session.commit()


def login(client, username, password):
    return client.post(f"{API}/auth/login", json={"username": username, "password": password})


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_login_success(client, db_session):
    """Вход с корректными данными выдаёт JWT-токен."""
    seed_users(db_session)
    resp = login(client, "analyst1", "analyst123")
    assert resp.status_code == 200
    data = resp.json()
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 20


def test_login_wrong_password(client, db_session):
    """Неверный пароль → 401."""
    seed_users(db_session)
    resp = login(client, "analyst1", "wrong-password")
    assert resp.status_code == 401


def test_login_unknown_user(client, db_session):
    """Несуществующий пользователь → 401 (не раскрываем, кто именно)."""
    seed_users(db_session)
    resp = login(client, "ghost", "whatever")
    assert resp.status_code == 401


def test_me_requires_token(client, db_session):
    """GET /auth/me без токена → 401."""
    seed_users(db_session)
    assert client.get(f"{API}/auth/me").status_code == 401


def test_me_with_token(client, db_session):
    """GET /auth/me с валидным Bearer-токеном возвращает пользователя и роль."""
    seed_users(db_session)
    token = login(client, "soc_lead", "soclead123").json()["access_token"]
    resp = client.get(f"{API}/auth/me", headers=auth_header(token))
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "soc_lead"
    assert data["role"] == "admin"


def test_expired_token_rejected(client, db_session):
    """Просроченный JWT → 401."""
    seed_users(db_session)
    expired = pyjwt.encode(
        {"sub": "1", "username": "soc_lead", "role": "admin", "exp": 0},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    resp = client.get(f"{API}/auth/me", headers=auth_header(expired))
    assert resp.status_code == 401


def test_garbage_token_rejected(client, db_session):
    """Мусорный/поддельный токен → 401."""
    seed_users(db_session)
    resp = client.get(f"{API}/auth/me", headers=auth_header("not-a-jwt"))
    assert resp.status_code == 401


def test_business_endpoint_requires_token(client, db_session):
    """Бизнес-эндпоинты защищены: GET /incidents без токена → 401."""
    seed_users(db_session)
    assert client.get(f"{API}/incidents").status_code == 401
    # с токеном — доступен
    token = login(client, "analyst1", "analyst123").json()["access_token"]
    assert client.get(f"{API}/incidents", headers=auth_header(token)).status_code == 200


def test_analyst_forbidden_on_admin_endpoints(client, db_session):
    """Аналитику запрещены CRUD правил/playbooks и confirm-action → 403."""
    seed_users(db_session)
    token = login(client, "analyst1", "analyst123").json()["access_token"]
    headers = auth_header(token)

    assert client.post(
        f"{API}/correlation-rules", json={"name": "r"}, headers=headers
    ).status_code == 403
    assert client.delete(f"{API}/correlation-rules/1", headers=headers).status_code == 403
    assert client.post(
        f"{API}/playbooks", json={"name": "p"}, headers=headers
    ).status_code == 403
    assert client.post(f"{API}/incidents/1/confirm-action", headers=headers).status_code == 403
    # чтение при этом разрешено
    assert client.get(f"{API}/correlation-rules", headers=headers).status_code == 200


def test_admin_allowed_on_admin_endpoints(client, db_session):
    """Администратор создаёт и удаляет правило корреляции."""
    seed_users(db_session)
    token = login(client, "soc_lead", "soclead123").json()["access_token"]
    headers = auth_header(token)

    created = client.post(
        f"{API}/correlation-rules",
        json={"name": "r1", "conditions": []},
        headers=headers,
    )
    assert created.status_code in (200, 201)
    rule_id = created.json()["id"]
    assert client.delete(f"{API}/correlation-rules/{rule_id}", headers=headers).status_code in (200, 204)


def test_analyst_can_change_incident_status(client, db_session):
    """Смена статуса инцидента доступна любому аутентифицированному пользователю.

    Проверяется на несуществующем инциденте: 404 (а не 401/403) —
    авторизация пройдена, дело дошло до поиска инцидента.
    """
    seed_users(db_session)
    token = login(client, "analyst1", "analyst123").json()["access_token"]
    resp = client.patch(
        f"{API}/incidents/99999/status", json={"status": "closed"}, headers=auth_header(token)
    )
    assert resp.status_code == 404


def test_health_and_ingest_open(client, db_session):
    """health и ingest интеграции остаются открытыми (без токена)."""
    assert client.get(f"{API}/health").status_code == 200


def test_register_admin_only(client, db_session):
    """Создание пользователя — только администратором; дубликат → 409."""
    seed_users(db_session)
    admin_token = login(client, "soc_lead", "soclead123").json()["access_token"]
    analyst_token = login(client, "analyst1", "analyst123").json()["access_token"]

    # аналитик не может создавать пользователей
    assert client.post(
        f"{API}/auth/register",
        json={"username": "new_user", "password": "secret1"},
        headers=auth_header(analyst_token),
    ).status_code == 403

    # администратор создаёт
    created = client.post(
        f"{API}/auth/register",
        json={"username": "new_user", "password": "secret1"},
        headers=auth_header(admin_token),
    )
    assert created.status_code == 201

    # дубликат → 409
    dup = client.post(
        f"{API}/auth/register",
        json={"username": "new_user", "password": "secret1"},
        headers=auth_header(admin_token),
    )
    assert dup.status_code == 409

    # новый пользователь может войти
    assert login(client, "new_user", "secret1").status_code == 200


def test_password_hashing_roundtrip():
    """hash_password/verify_password: корректный пароль проходит, неверный — нет."""
    from app.services.security import verify_password

    stored = hash_password("s3cret-пароль")
    assert stored.startswith("pbkdf2_sha256$")
    assert verify_password("s3cret-пароль", stored) is True
    assert verify_password("wrong", stored) is False
    # битый формат хеша не должен ронять проверку
    assert verify_password("x", "broken-hash") is False


def test_token_contains_role_and_username(db_session):
    """JWT payload несёт sub/username/role — для role-зависимого UI."""
    token = create_access_token(7, "soc_lead", "admin")
    from app.services.security import decode_token

    payload = decode_token(token)
    assert payload["sub"] == "7"
    assert payload["username"] == "soc_lead"
    assert payload["role"] == "admin"


def test_incident_ownership(client, db_session, monkeypatch):
    """Владение инцидентом (stage-14): чужой аналитик не работает с чужим инцидентом."""
    from app.models import CorrelationRule

    seed_users(db_session)
    db_session.add(
        CorrelationRule(
            name="brute_rule", description="t",
            conditions=[{"field": "event_type", "operator": "like", "value": "auth"}],
            time_window_minutes=5, min_events=1, is_active=True,
        )
    )
    db_session.commit()

    async def fake_analyze(context):
        return {"description": "d", "attack_type": "brute_force", "confidence": 0.9,
                "explanation": "e", "recommended_action": "monitor"}

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)

    # инцидент создаётся свободным (аналитик не назначен)
    client.post(f"{API}/ingest/wazuh", json={
        "timestamp": "2026-11-04T10:00:00Z",
        "rule": {"level": 10, "description": "test", "groups": ["authentication_failed"]},
        "agent": {"id": "001", "name": "test-host"},
        "data": {"srcip": "192.0.2.10", "dstuser": "root"},
        "full_log": "Failed password",
    })

    analyst_token = login(client, "analyst1", "analyst123").json()["access_token"]
    admin_token = login(client, "soc_lead", "soclead123").json()["access_token"]

    detail = client.get(f"{API}/incidents/1", headers=auth_header(admin_token)).json()
    assert detail["analyst"] is None

    # аналитик-1 запускает анализ → инцидент закрепляется за ним
    resp = client.post(f"{API}/incidents/1/analyze", headers=auth_header(analyst_token))
    assert resp.status_code == 200
    detail = client.get(f"{API}/incidents/1", headers=auth_header(admin_token)).json()
    assert detail["analyst"]["username"] == "analyst1"

    # аналитик-2 не может анализировать и менять статус чужого инцидента
    analyst2_token = login(client, "analyst2", "analyst123").json()["access_token"]
    assert client.post(
        f"{API}/incidents/1/analyze", headers=auth_header(analyst2_token)
    ).status_code == 403
    forbidden = client.patch(
        f"{API}/incidents/1/status", json={"status": "closed"}, headers=auth_header(analyst2_token)
    )
    assert forbidden.status_code == 403
    assert "закреплён" in forbidden.json()["detail"]

    # владелец может менять статус
    assert client.patch(
        f"{API}/incidents/1/status", json={"status": "in_progress"}, headers=auth_header(analyst_token)
    ).status_code == 200

    # админ — исключение: работает с любым инцидентом
    assert client.patch(
        f"{API}/incidents/1/status", json={"status": "closed"}, headers=auth_header(admin_token)
    ).status_code == 200


def test_unassigned_incident_self_assign_on_status(client, db_session):
    """Незакреплённый инцидент закрепляется за тем, кто первым сменил статус."""
    from app.models import CorrelationRule

    seed_users(db_session)
    db_session.add(
        CorrelationRule(
            name="brute_rule", description="t",
            conditions=[{"field": "event_type", "operator": "like", "value": "auth"}],
            time_window_minutes=5, min_events=1, is_active=True,
        )
    )
    db_session.commit()
    client.post(f"{API}/ingest/wazuh", json={
        "timestamp": "2026-11-04T10:00:00Z",
        "rule": {"level": 5, "description": "test", "groups": ["authentication_failed"]},
        "agent": {"id": "001", "name": "test-host"},
        "data": {"srcip": "192.0.2.10", "dstuser": "root"},
        "full_log": "Failed password",
    })

    analyst_token = login(client, "analyst1", "analyst123").json()["access_token"]
    assert client.patch(
        f"{API}/incidents/1/status", json={"status": "in_progress"}, headers=auth_header(analyst_token)
    ).status_code == 200
    admin_token = login(client, "soc_lead", "soclead123").json()["access_token"]
    detail = client.get(f"{API}/incidents/1", headers=auth_header(admin_token)).json()
    assert detail["analyst"]["username"] == "analyst1"


def test_playbook_description_in_results(client, db_session, monkeypatch):
    """Результаты анализа содержат русское описание сценария (stage-14)."""
    from app.models import CorrelationRule, Playbook

    seed_users(db_session)
    db_session.add(
        CorrelationRule(
            name="brute_rule", description="t",
            conditions=[{"field": "event_type", "operator": "like", "value": "auth"}],
            time_window_minutes=5, min_events=1, is_active=True,
        )
    )
    db_session.add(
        Playbook(
            name="block_ip", description="Блокировка IP-адреса источника подозрительной активности",
            trigger_conditions={}, allowed_actions=["block_ip"], steps=[], is_active=True,
        )
    )
    db_session.commit()

    async def fake_analyze(context):
        return {"description": "d", "attack_type": "brute_force", "confidence": 0.9,
                "explanation": "e", "recommended_action": "block_ip"}

    monkeypatch.setattr("app.api.routes.analyze_incident", fake_analyze)
    admin_token = login(client, "soc_lead", "soclead123").json()["access_token"]

    client.post(f"{API}/ingest/wazuh", json={
        "timestamp": "2026-11-04T10:00:00Z",
        "rule": {"level": 10, "description": "test", "groups": ["authentication_failed"]},
        "agent": {"id": "001", "name": "test-host"},
        "data": {"srcip": "192.0.2.10", "dstuser": "root"},
        "full_log": "Failed password",
    })
    # инцидент не critical (level 10, активов нет) → block_ip без подтверждения
    resp = client.post(f"{API}/incidents/1/analyze", headers=auth_header(admin_token))
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["validation"]["approved"] is True
    assert result["execution"].get("playbook_description") == \
        "Блокировка IP-адреса источника подозрительной активности"

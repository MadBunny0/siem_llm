"""Общие фикстуры тестов backend (stage-19: вынос дублированного test setup).

- `db` — изолированная in-memory SQLite для сервисных тестов
  (test_correlation.py, test_audit.py, test_playbook.py, test_assets.py);
- `engine`/`db_session`/`client` — API-тесты (test_routes.py, test_auth.py):
  StaticPool делает одну in-memory базу общей для всех соединений, client
  подменяет зависимость get_db на тестовую БД и отключает LLM-автоанализ
  и реальное реагирование.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.db import get_db
from app.main import app
from app.models import Base


@pytest.fixture
def db():
    """Изолированная in-memory SQLite-БД для сервисных тестов."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    yield SessionLocal()
    engine.dispose()


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
    """Прямая сессия к той же БД — для подготовки данных (seed правил/пользователей)."""
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(engine, monkeypatch):
    """TestClient с подменой зависимости get_db на тестовую БД."""
    # LLM-автоанализ отключаем: тесты не должны зависеть ни от запущенного
    # Ollama, ни от локального .env. Реакции (execute-action) всегда реальные
    # (stage-23) — Wazuh API подменяется фейком в конкретных модулях
    # (test_routes/test_auth/test_responses_api: wazuh_mock)
    monkeypatch.setattr(settings, "auto_analysis", False)

    # та же конфигурация сессии, что в app.db.get_db (autoflush=False)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()

import pytest
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, Incident, Playbook
from app.services.playbook import execute_playbook, load_playbook_by_action


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    engine.dispose()


def test_execute_playbook_simulation_mode():
    with patch("app.services.playbook.settings.auto_response", False):
        result = execute_playbook("block_ip", {"incident_id": 1})
        assert result["executed"] is False
        assert result["mode"] == "simulation"
        assert result["action"] == "block_ip"


def test_execute_playbook_controlled_mode(db):
    """Контролируемый режим: playbook из БД, ResponseAction, ITSM, уведомление."""
    db.add(
        Playbook(
            name="block_ip",
            description="Блокировка IP",
            trigger_conditions={},
            allowed_actions=["block_ip"],
            steps=[{"action": "block_ip", "target": "{{src_ip}}", "tool": "firewall"}],
            priority=1,
            is_active=True,
        )
    )
    db.add(
        Incident(
            id=1,
            title="Тестовый инцидент",
            description="d",
            severity="high",
            status="new",
            risk_score=70,
        )
    )
    db.commit()

    with patch("app.services.playbook.settings.auto_response", True):
        result = execute_playbook("block_ip", {"incident_id": 1}, db=db)
        assert result["executed"] is True
        assert result["mode"] == "controlled"
        assert result["action"] == "block_ip"
        assert result["playbook"] == "block_ip"
        # запись о выполненном действии сохранена
        assert result["response_action_id"] is not None

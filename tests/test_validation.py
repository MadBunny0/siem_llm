import pytest

from app.services.validation import validate_recommendation, ALLOWED_ACTIONS


def test_allowed_actions_low():
    recommendation = {"recommended_action": "monitor"}
    result = validate_recommendation("low", recommendation)
    assert result["approved"] is True
    assert result["action"] == "monitor"


def test_allowed_actions_monitor_critical():
    recommendation = {"recommended_action": "monitor"}
    result = validate_recommendation("critical", recommendation)
    assert result["approved"] is True


def test_allowed_actions_block_ip_high():
    recommendation = {"recommended_action": "block_ip"}
    result = validate_recommendation("high", recommendation)
    assert result["approved"] is True


def test_allowed_actions_disable_account_low():
    recommendation = {"recommended_action": "disable_account"}
    result = validate_recommendation("low", recommendation)
    assert result["approved"] is False
    assert result["action"] == "monitor"
    assert "policy" in result["reason"]


def test_allowed_actions_disable_account_critical():
    recommendation = {"recommended_action": "disable_account"}
    result = validate_recommendation("critical", recommendation)
    assert result["approved"] is True


def test_default_action():
    recommendation = {}
    result = validate_recommendation("medium", recommendation)
    assert result["action"] == "monitor"
    assert result["approved"] is True


def test_allowed_actions_collect_evidence_medium():
    recommendation = {"recommended_action": "collect_evidence"}
    result = validate_recommendation("medium", recommendation)
    assert result["approved"] is True

def test_policy_from_db_overrides_defaults():
    """Политика из БД (validation_policy) переопределяет встроенные дефолты (§3.4, p:103)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.models import Base, ValidationPolicy
    from app.services.validation import validate_recommendation

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(ValidationPolicy(severity="low", allowed_actions=["monitor"]))
    session.commit()

    # collect_evidence разрешён по умолчанию, но в БД-политике для low его нет
    result = validate_recommendation(
        "low", {"recommended_action": "collect_evidence"}, db=session
    )
    assert result["approved"] is False
    assert result["action"] == "monitor"
    session.close()
    engine.dispose()


def test_policy_fallback_without_db():
    """Без сессии БД используется встроенная политика (совместимость с тестами)."""
    from app.services.validation import validate_recommendation

    result = validate_recommendation("medium", {"recommended_action": "collect_evidence"})
    assert result["approved"] is True

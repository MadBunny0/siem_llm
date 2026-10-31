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
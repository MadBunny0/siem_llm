from app.services.risk import LEVEL_TO_SCORE, score_to_severity


def test_level_to_score():
    assert LEVEL_TO_SCORE["0"] == 0
    assert LEVEL_TO_SCORE["3"] == 21
    assert LEVEL_TO_SCORE["15"] == 100


def test_severity():
    assert score_to_severity(0) == "low"
    assert score_to_severity(10) == "low"
    assert score_to_severity(40) == "medium"
    assert score_to_severity(50) == "medium"
    assert score_to_severity(70) == "high"
    assert score_to_severity(85) == "critical"
    assert score_to_severity(100) == "critical"


def test_calculate_risk():
    from app.services.risk import calculate_risk

    events = [
        {"raw_data": {"rule": {"level": "5"}}},
        {"raw_data": {"rule": {"level": "8"}}},
    ]
    score, severity = calculate_risk(events)
    assert score >= 56
    assert severity in ("low", "medium", "high", "critical")


def test_calculate_risk_asset_criticality():
    from app.services.risk import calculate_risk

    # критический актив + событие уровня 3 должны дать высокий риск
    events = [
        {
            "raw_data": {"rule": {"level": "3"}},
            "asset_criticality": "critical",
        },
    ]
    score, severity = calculate_risk(events)
    assert score >= 85
    assert severity in ("high", "critical")


def test_calculate_risk_correlation_bonus():
    from app.services.risk import calculate_risk

    # серия из 5 связанных событий даёт бонус +20
    events = [
        {"raw_data": {"rule": {"level": "1"}}},
        {"raw_data": {"rule": {"level": "1"}}},
        {"raw_data": {"rule": {"level": "1"}}},
        {"raw_data": {"rule": {"level": "1"}}},
        {"raw_data": {"rule": {"level": "1"}}},
    ]
    score, severity = calculate_risk(events)
    assert score == 20
    assert severity == "low"


def test_calculate_risk_medium_asset():
    from app.services.risk import calculate_risk

    events = [
        {
            "raw_data": {"rule": {"level": "2"}},
            "asset_criticality": "medium",
        },
    ]
    score, severity = calculate_risk(events)
    assert score == 60
    assert severity == "medium"

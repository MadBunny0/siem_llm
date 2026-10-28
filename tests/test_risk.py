from app.services.risk import score_to_severity

def test_severity():
    assert score_to_severity(10) == "low"
    assert score_to_severity(50) == "medium"
    assert score_to_severity(70) == "high"
    assert score_to_severity(90) == "critical"

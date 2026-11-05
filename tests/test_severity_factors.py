"""Тесты разбора оценки критичности инцидента (stage-22).

Incident.severity_factors — сохраняемый при ingest разбор: почему инцидент
получил свою критичность (матрица MITRE: база по тактике + повышения с
объяснениями; числовая модель риска §3.3.3: слагаемые базы, бонус серии,
p_implement, достоверность корреляции). Блок «Оценка критичности» в карточке
читает это поле из GET /incidents/{id}.
"""

import pytest

from app.main import app
from app.models import Asset
from app.services.auth import get_current_user
from app.services.criticality import derive_severity, derive_severity_detail
from app.services.risk import calculate_risk, calculate_risk_detail

API = "/api/v1"


def make_alert(**overrides):
    """Тестовый алерт Wazuh (как в test_routes)."""
    alert = {
        "timestamp": "2026-01-01T10:00:00Z",
        "rule": {
            "level": 10,
            "description": "test",
            "groups": ["authentication_failed"],
        },
        "agent": {"id": "001", "name": "test-host"},
        "data": {"srcip": "192.0.2.10", "dstuser": "root"},
        "full_log": "Failed password",
    }
    alert.update(overrides)
    return alert


@pytest.fixture
def client(client):
    """Базовый client (conftest) + обход авторизации (фейковый админ)."""
    from app.models import User

    app.dependency_overrides[get_current_user] = lambda: User(
        id=1, username="tester", role="admin"
    )
    yield client


def seed_rule(db_session, name="brute_rule", **overrides):
    """Активное правило корреляции напрямую в тестовой БД (как в test_routes)."""
    from app.models import CorrelationRule

    params = dict(
        name=name,
        description="тестовое правило",
        conditions=[{"field": "event_type", "operator": "like", "value": "auth"}],
        time_window_minutes=5,
        min_events=1,
        priority=1,
        is_active=True,
    )
    params.update(overrides)
    rule = CorrelationRule(**params)
    db_session.add(rule)
    db_session.commit()
    return rule


def seed_asset(db_session, name="test-host", **overrides):
    """Актив с именем = имя агента алерта (привязка по агенту)."""
    params = dict(type="server", criticality="critical")
    params.update(overrides)
    asset = Asset(name=name, **params)
    db_session.add(asset)
    db_session.commit()
    return asset


# ---------------------------------------------------------------------------
# Юнит: calculate_risk_detail — числа и объяснения числовой модели
# ---------------------------------------------------------------------------
def test_calculate_risk_detail_rule_level_factor():
    """Одиночное событие: база = перевод уровня правила Wazuh, бонус серии 0."""
    events = [{"raw_data": {"rule": {"level": 10}}, "event_type": "x"}]
    score, severity, breakdown = calculate_risk_detail(events, p_implement=1.0)

    assert score == 70  # LEVEL_TO_SCORE["10"]
    assert severity == "high"
    assert breakdown["base"] == 70
    assert breakdown["base_from"] == "rule_level"
    assert breakdown["series_bonus"] == 0
    assert breakdown["adjusted_bonus"] == 0
    assert breakdown["factors"] == [{
        "kind": "rule_level", "value": 70,
        "detail": "Уровень правила Wazuh: 10 → 70/100",
    }]
    assert breakdown["thresholds"] == {"critical": 85, "high": 65, "medium": 40}


def test_calculate_risk_detail_base_is_max_of_factors():
    """База = максимум слагаемых: attack_danger 80 перебивает уровень 42."""
    events = [{
        "raw_data": {"rule": {"level": 6, "groups": ["brute"]}},
        "event_type": "brute_force",
    }]
    _, _, breakdown = calculate_risk_detail(events)

    assert breakdown["base"] == 80  # ATTACK_TYPE_DANGER["brute"]
    assert breakdown["base_from"] == "attack_danger"
    kinds = {f["kind"]: f["value"] for f in breakdown["factors"]}
    assert kinds == {"rule_level": 42, "attack_danger": 80}
    danger_detail = next(f for f in breakdown["factors"] if f["kind"] == "attack_danger")
    assert "brute" in danger_detail["detail"]


def test_calculate_risk_detail_series_bonus_and_confidence():
    """Бонус серии = (события-1)*5 до 20; сужается p_implement × достоверность."""
    events = [{"raw_data": {"rule": {"level": 8}}, "event_type": "x"} for _ in range(3)]
    score, severity, breakdown = calculate_risk_detail(
        events, p_implement=0.5, correlation_confidence=1.0
    )
    # база 56 + бонус 10 * 0.5 * 1.0 = 61 → medium (порог high = 65)
    assert breakdown["series_bonus"] == 10
    assert breakdown["adjusted_bonus"] == 5.0
    assert score == 61
    assert severity == "medium"

    score_low, _, breakdown_low = calculate_risk_detail(
        events, p_implement=0.5, correlation_confidence=1 / 3
    )
    assert breakdown_low["correlation_confidence"] == round(1 / 3, 3)
    assert score_low < score


def test_calculate_risk_detail_matches_calculate_risk():
    """calculate_risk (обёртка) и calculate_risk_detail дают те же числа."""
    events = [{
        "raw_data": {"rule": {"level": 12, "groups": ["credential"]}},
        "event_type": "authentication_failed",
        "asset_criticality": "high",
    }]
    expected_score, expected_severity = calculate_risk(events, p_implement=0.8)
    score, severity, breakdown = calculate_risk_detail(events, p_implement=0.8)

    assert (score, severity) == (expected_score, expected_severity)
    assert breakdown["score"] == score
    assert breakdown["p_implement"] == 0.8
    # критичность актива high → 75 попала в слагаемые
    kinds = {f["kind"]: f["value"] for f in breakdown["factors"]}
    assert kinds["asset_criticality"] == 75


# ---------------------------------------------------------------------------
# Юнит: derive_severity_detail — объяснения повышений матрицы MITRE
# ---------------------------------------------------------------------------
def test_derive_severity_detail_no_tactic_empty():
    """Без тактики — (None, [], []) (fallback числовой модели)."""
    rule = type("R", (), {"mitre_tactic": None, "name": "r", "description": "",
                          "escalated_by_vendor": False})()
    severity, reasons, detail = derive_severity_detail(rule, [], None)
    assert severity is None and reasons == [] and detail == []
    # обёртка derive_severity совместима (stage-17)
    assert derive_severity(rule, [], None) == (None, [])


def test_derive_severity_detail_critical_asset_explanation():
    """critical_asset: объяснение содержит имя актива и его критичность."""
    rule = type("R", (), {"mitre_tactic": "credential_access", "name": "r",
                          "description": "", "escalated_by_vendor": False})()
    event = type("E", (), {"event_type": "auth", "raw_data": {"rule": {"groups": []}},
                           "src_ip": None})()
    asset = type("A", (), {"name": "db-primary-01", "criticality": "critical",
                           "network_segment": None})()

    severity, reasons, detail = derive_severity_detail(rule, [event], asset)
    assert severity == "critical"  # high + 1 (потолок critical)
    assert reasons == ["critical_asset"]
    assert detail[0]["category"] == "critical_asset"
    assert "db-primary-01" in detail[0]["explanation"]
    assert detail[0]["title"]


def test_derive_severity_detail_marker_explanation():
    """Маркер категории: объяснение называет маркер и правило."""
    rule = type("R", (), {"mitre_tactic": "initial_access", "name": "pii_rule",
                          "description": "", "escalated_by_vendor": False})()
    event = type("E", (), {"event_type": "web", "raw_data": {"rule": {"groups": ["pii"]}},
                           "src_ip": None})()
    asset = type("A", (), {"name": "app-01", "criticality": "medium",
                           "network_segment": None})()

    severity, reasons, detail = derive_severity_detail(rule, [event], asset)
    assert severity == "high"  # medium + 1
    assert reasons == ["personal_data"]
    assert detail[0]["explanation"].startswith("Маркер «pii»")
    assert "pii_rule" in detail[0]["explanation"]


def test_derive_severity_detail_vendor_flag_explanation():
    """vendor_flag: объяснение ссылается на п.7 процедуры."""
    rule = type("R", (), {"mitre_tactic": "discovery", "name": "r", "description": "",
                          "escalated_by_vendor": True})()
    event = type("E", (), {"event_type": "scan", "raw_data": {"rule": {"groups": []}},
                           "src_ip": None})()

    _, reasons, detail = derive_severity_detail(rule, [event], None)
    assert reasons == ["vendor_flag"]
    assert "п.7" in detail[0]["explanation"]


# ---------------------------------------------------------------------------
# Интеграция: ingest сохраняет severity_factors, карточка их отдаёт
# ---------------------------------------------------------------------------
def test_ingest_persists_mitre_factors(client, db_session):
    """Матрица MITRE: basis=mitre_matrix, база по тактике + повышение с объяснением."""
    seed_asset(db_session, name="test-host", criticality="critical")
    seed_rule(db_session, mitre_tactic="credential_access", mitre_technique="T1110")

    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]
    detail = client.get(f"{API}/incidents/{incident_id}").json()
    factors = detail["severity_factors"]

    assert factors["basis"] == "mitre_matrix"
    assert factors["severity"] == "critical"  # high (credential_access) + 1
    assert factors["computed_at"]
    assert factors["mitre"]["tactic"] == "credential_access"
    assert factors["mitre"]["technique"] == "T1110"
    assert factors["mitre"]["base_severity"] == "high"
    escalations = factors["mitre"]["escalations"]
    assert [e["category"] for e in escalations] == ["critical_asset"]
    assert "test-host" in escalations[0]["explanation"]
    # числовая модель рассчитывается всегда (метрика «уровень риска»)
    assert factors["risk"]["score"] == detail["risk_score"]
    assert factors["risk"]["factors"]


def test_ingest_persists_risk_score_fallback(client, db_session):
    """Правило без тактики: basis=risk_score, блок mitre отсутствует."""
    seed_rule(db_session)  # mitre_tactic не задан

    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]
    factors = client.get(f"{API}/incidents/{incident_id}").json()["severity_factors"]

    assert factors["basis"] == "risk_score"
    assert factors["mitre"] is None
    assert factors["risk"]["base_from"] in ("rule_level", "attack_danger", "asset_criticality")
    assert factors["risk"]["thresholds"] == {"critical": 85, "high": 65, "medium": 40}


def test_update_branch_refreshes_severity_factors(client, db_session):
    """Второе событие в том же инциденте пересчитывает разбор (2 события в серии)."""
    seed_rule(db_session)

    incident_id = client.post(f"{API}/ingest/wazuh", json=make_alert()).json()["incident_id"]
    client.post(f"{API}/ingest/wazuh", json=make_alert())
    factors = client.get(f"{API}/incidents/{incident_id}").json()["severity_factors"]

    assert factors["risk"]["series_bonus"] == 5  # 2 события → бонус серии

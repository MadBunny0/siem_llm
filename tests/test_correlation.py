import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.models import Base, Event, CorrelationRule


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    yield SessionLocal()
    engine.dispose()


def test_match_condition_src_ip_eq(db):
    from app.services.correlation import check_rule_conditions
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source="wazuh",
        event_type="authentication_failed",
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=3,
        raw_message="test",
        raw_data={},
    )
    rule = CorrelationRule(
        name="test_rule",
        description="test",
        conditions=[{"field": "src_ip", "operator": "eq", "value": "192.168.1.100"}],
        time_window_minutes=5,
    )
    db.add(rule)
    db.flush()
    assert check_rule_conditions(rule, event) is True


def test_match_condition_event_type(db):
    from app.services.correlation import check_rule_conditions
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source="wazuh",
        event_type="authentication_failed",
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=3,
        raw_message="test",
        raw_data={},
    )
    rule = CorrelationRule(
        name="test_rule",
        description="test",
        conditions=[{"field": "event_type", "operator": "like", "value": "auth"}],
        time_window_minutes=5,
    )
    db.add(rule)
    db.flush()
    assert check_rule_conditions(rule, event) is True


def test_match_condition_neq(db):
    from app.services.correlation import check_rule_conditions
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source="wazuh",
        event_type="authentication_failed",
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=3,
        raw_message="test",
        raw_data={},
    )
    rule = CorrelationRule(
        name="test_rule",
        description="test",
        conditions=[{"field": "user", "operator": "neq", "value": "root"}],
        time_window_minutes=5,
    )
    db.add(rule)
    db.flush()
    assert check_rule_conditions(rule, event) is True


def test_match_condition_in(db):
    from app.services.correlation import check_rule_conditions
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source="wazuh",
        event_type="authentication_failed",
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=3,
        raw_message="test",
        raw_data={},
    )
    rule = CorrelationRule(
        name="test_rule",
        description="test",
        conditions=[{"field": "user", "operator": "in", "value": ["admin", "root"]}],
        time_window_minutes=5,
    )
    db.add(rule)
    db.flush()
    assert check_rule_conditions(rule, event) is True


def test_match_condition_eq_false(db):
    from app.services.correlation import check_rule_conditions
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source="wazuh",
        event_type="authentication_failed",
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=3,
        raw_message="test",
        raw_data={},
    )
    rule = CorrelationRule(
        name="test_rule",
        description="test",
        conditions=[{"field": "user", "operator": "eq", "value": "root"}],
        time_window_minutes=5,
    )
    db.add(rule)
    db.flush()
    assert check_rule_conditions(rule, event) is False


def test_match_multiple_conditions(db):
    from app.services.correlation import check_rule_conditions
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source="wazuh",
        event_type="authentication_failed",
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=3,
        raw_message="test",
        raw_data={},
    )
    rule = CorrelationRule(
        name="test_rule",
        description="test",
        conditions=[
            {"field": "src_ip", "operator": "eq", "value": "192.168.1.100"},
            {"field": "event_type", "operator": "like", "value": "auth"},
        ],
        time_window_minutes=5,
    )
    db.add(rule)
    db.flush()
    assert check_rule_conditions(rule, event) is True


def test_find_related_events_window(db):
    from app.services.correlation import load_correlation_rules, find_related_events
    rule = CorrelationRule(
        name="test_rule",
        description="test",
        conditions=[{"field": "event_type", "operator": "like", "value": "auth"}],
        time_window_minutes=5,
        is_active=True,
    )
    db.add(rule)
    db.flush()
    now = datetime.now(timezone.utc)
    close_event = Event(
        timestamp=now - timedelta(minutes=2),
        source="wazuh",
        event_type="authentication_failed",
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=3,
        raw_message="close",
        raw_data={},
    )
    far_event = Event(
        timestamp=now - timedelta(minutes=20),
        source="wazuh",
        event_type="authentication_failed",
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=3,
        raw_message="far",
        raw_data={},
    )
    new_event = Event(
        timestamp=now,
        source="wazuh",
        event_type="authentication_failed",
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=3,
        raw_message="new",
        raw_data={},
    )
    db.add(close_event)
    db.add(far_event)
    db.add(new_event)
    db.flush()
    related = find_related_events(db, new_event)
    related_ids = [e.id for e in related]
    assert close_event.id in related_ids
    assert far_event.id not in related_ids
    assert len(related) >= 1


def test_load_correlation_rules_filters_inactive(db):
    from app.services.correlation import load_correlation_rules
    active_rule = CorrelationRule(
        name="active_rule",
        description="test",
        conditions=[{"field": "event_type", "operator": "like", "value": "auth"}],
        time_window_minutes=5,
        is_active=True,
    )
    inactive_rule = CorrelationRule(
        name="inactive_rule",
        description="test",
        conditions=[{"field": "event_type", "operator": "like", "value": "scan"}],
        time_window_minutes=5,
        is_active=False,
    )
    db.add(active_rule)
    db.add(inactive_rule)
    db.flush()
    rules = load_correlation_rules(db)
    assert len(rules) == 1
    assert rules[0].name == "active_rule"


def test_create_or_update_incident(db):
    from app.services.correlation import create_or_update_incident
    now = datetime.now(timezone.utc)
    events = [
        Event(
            timestamp=now,
            source="wazuh",
            event_type="authentication_failed",
            user="admin",
            src_ip="192.168.1.100",
            criticality_level=3,
            raw_message="test",
            raw_data={"rule": {"description": "test desc"}},
        ),
    ]
    incident = create_or_update_incident(db, events, risk_score=70)
    assert incident.risk_score == 70
    assert incident.title == "test desc"
    assert len(incident.events) == 1
    assert incident.status == "new"
    assert incident.severity == "low"
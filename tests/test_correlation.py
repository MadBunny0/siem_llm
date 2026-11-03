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

def test_evaluate_correlation_sql_match_and_confidence(db):
    """evaluate_correlation: SQL-сопоставление по атрибутам + достоверность корреляции."""
    from app.services.correlation import evaluate_correlation

    rule = CorrelationRule(
        name="test_rule",
        description="test",
        conditions=[{"field": "event_type", "operator": "like", "value": "auth"}],
        time_window_minutes=5,
        min_events=2,
        is_active=True,
    )
    db.add(rule)
    db.flush()
    now = datetime.now(timezone.utc)
    prev = Event(
        timestamp=now - timedelta(minutes=2),
        source="wazuh",
        event_type="authentication_failed",
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=3,
        raw_message="prev",
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
    other_host = Event(
        timestamp=now - timedelta(minutes=1),
        source="wazuh",
        event_type="authentication_failed",
        user="other",
        src_ip="203.0.113.5",
        criticality_level=3,
        raw_message="other",
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
    db.add_all([prev, new_event, other_host, far_event])
    db.flush()

    hit_rule, related, confidence = evaluate_correlation(db, new_event)
    assert hit_rule is not None and hit_rule.name == "test_rule"
    related_ids = [e.id for e in related]
    assert prev.id in related_ids and new_event.id in related_ids
    assert other_host.id not in related_ids  # другой IP/учётка/актив — не связано
    assert far_event.id not in related_ids   # вне временного окна
    # оба события совпали по 2 признакам (IP + учётка) → достоверность 2/3
    assert abs(confidence - 2 / 3) < 1e-9


def test_evaluate_correlation_no_rules(db):
    """Без правил корреляции — (None, [], 0.0): инцидент не формируется."""
    from app.services.correlation import evaluate_correlation

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
    db.add(event)
    db.flush()

    hit_rule, related, confidence = evaluate_correlation(db, event)
    assert hit_rule is None
    assert related == []
    assert confidence == 0.0


def test_evaluate_correlation_min_events_threshold(db):
    """Порог повторений: одно событие не срабатывает при min_events=2."""
    from app.services.correlation import evaluate_correlation

    db.add(
        CorrelationRule(
            name="threshold_rule",
            description="test",
            conditions=[{"field": "event_type", "operator": "like", "value": "auth"}],
            time_window_minutes=5,
            min_events=2,
            is_active=True,
        )
    )
    db.flush()
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source="wazuh",
        event_type="authentication_failed",
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=3,
        raw_message="single",
        raw_data={},
    )
    db.add(event)
    db.flush()

    hit_rule, _related, confidence = evaluate_correlation(db, event)
    assert hit_rule is None
    assert confidence == 0.0


def test_event_type_matches_real_wazuh_group_ordering(db):
    """Реальный алерт Wazuh несёт группы служебными тегами вперёд:
    ["syslog", "sshd", "authentication_failed"] → event_type = "syslog".
    Условие по таксономической группе должно срабатывать по всему набору групп
    (stage-11), иначе seed-правила не работают на настоящем стенде."""
    from app.services.correlation import evaluate_correlation, match_condition

    event = Event(
        timestamp=datetime.now(timezone.utc),
        source="wazuh",
        event_type="syslog",  # groups[0] реального алерта Wazuh
        user="admin",
        src_ip="192.168.1.100",
        criticality_level=5,
        raw_message="Failed password for admin from 192.168.1.100",
        raw_data={"rule": {"groups": ["syslog", "sshd", "authentication_failed"]}},
    )
    db.add(event)
    db.flush()

    condition = {"field": "event_type", "operator": "like", "value": "authentication_failed"}
    assert match_condition(event, condition) is True

    db.add(
        CorrelationRule(
            name="brute_rule",
            description="test",
            conditions=[{"field": "event_type", "operator": "like", "value": "authentication_failed"}],
            time_window_minutes=5,
            min_events=1,
            is_active=True,
        )
    )
    db.flush()
    hit_rule, related, confidence = evaluate_correlation(db, event)
    assert hit_rule is not None and hit_rule.name == "brute_rule"
    assert len(related) == 1  # порог пройден самим событием

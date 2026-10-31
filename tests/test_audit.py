import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.models import Base, AuditLog, Incident, Event


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    yield SessionLocal()
    engine.dispose()


def test_log_audit(db):
    incident = Incident(title="test", description="test")
    db.add(incident)
    db.flush()
    from app.services.audit import audit
    audit("test_event", {"key": "value"}, db, incident_id=incident.id)
    assert len(db.scalars(select(AuditLog)).all()) == 1


def test_log_audit_with_event_id(db):
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
    from app.services.audit import audit
    audit("test_event", {"key": "value"}, db, event_id=event.id, incident_id=1)
    log = db.scalars(select(AuditLog).where(AuditLog.event_id == event.id)).first()
    assert log is not None
    assert log.details == {"key": "value"}


def test_log_audit_no_db(db):
    from app.services.audit import audit
    audit("test_event", {"key": "value"})
    assert len(db.scalars(select(AuditLog)).all()) == 0
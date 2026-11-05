from datetime import datetime, timezone

from sqlalchemy import select

from app.models import AuditLog, Incident, Event


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
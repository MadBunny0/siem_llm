from datetime import timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.config import settings
from app.models import Event, Incident

def correlation_key(event: Event):
    raw = event.raw_data or {}
    data = raw.get("data") or {}
    return (
        str(data.get("srcip") or data.get("src_ip") or ""),
        str(data.get("dstuser") or data.get("user") or ""),
    )

def find_related_events(db: Session, event: Event):
    start = event.timestamp - timedelta(minutes=settings.correlation_window_minutes)
    end = event.timestamp + timedelta(minutes=settings.correlation_window_minutes)
    candidates = list(db.scalars(
        select(Event).where(Event.timestamp.between(start, end))
    ).all())
    key = correlation_key(event)
    related = [e for e in candidates if correlation_key(e) == key and key != ("", "")]
    return related or [event]

def create_or_update_incident(db: Session, events):
    for event in events:
        if event.incidents:
            incident = event.incidents[0]
            for e in events:
                if e not in incident.events:
                    incident.events.append(e)
            return incident

    first = events[0]
    rule = (first.raw_data or {}).get("rule") or {}
    incident = Incident(
        title=rule.get("description") or first.event_type,
        description=f"Инцидент сформирован на основе {len(events)} связанных событий.",
        severity="low",
        status="new",
        events=list(events),
    )
    db.add(incident)
    db.flush()
    return incident

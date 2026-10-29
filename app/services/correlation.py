from datetime import timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.config import settings
from app.models import CorrelationRule, Event, Incident


def load_correlation_rules(db: Session) -> list[CorrelationRule]:
    """Загрузка активных правил корреляции из БД (согласно Главе 3.2 — CorrelationRule)."""
    return list(db.scalars(
        select(CorrelationRule).where(CorrelationRule.is_active.is_(True))
    ).all())


def match_condition(event: Event, condition: dict) -> bool:
    """Проверка одного условия правила корреляции."""
    field = condition.get("field")
    operator = condition.get("operator", "eq")
    expected = condition.get("value")

    if field == "src_ip":
        actual = event.src_ip
    elif field == "user":
        actual = event.user
    elif field == "event_type":
        actual = event.event_type
    elif field == "criticality":
        actual = event.criticality_level
    else:
        actual = (event.raw_data or {}).get("data", {}).get(field)

    if actual is None:
        return False

    if operator == "eq":
        return str(actual) == str(expected)
    if operator == "neq":
        return str(actual) != str(expected)
    if operator == "in":
        return str(actual) in [str(v) for v in expected]
    if operator == "like":
        return str(expected) in str(actual)

    return False


def check_rule_conditions(rule: CorrelationRule, event: Event) -> bool:
    """Проверка всех условий правила корреляции."""
    conditions = rule.conditions or []
    return all(match_condition(event, cond) for cond in conditions)


def find_related_events(db: Session, event: Event) -> list[Event]:
    """Поиск связанных событий на основе активных правил корреляции."""
    rules = load_correlation_rules(db)

    related = []
    for rule in rules:
        if check_rule_conditions(rule, event):
            window = rule.time_window_minutes if rule.time_window_minutes else settings.correlation_window_minutes
            start = event.timestamp - timedelta(minutes=window)
            end = event.timestamp + timedelta(minutes=window)
            candidates = list(db.scalars(
                select(Event).where(Event.timestamp.between(start, end))
            ).all())
            related.extend([e for e in candidates if e.id != event.id])

    # Дедупликация и добавление самого события
    seen = set()
    unique_related = []
    for e in related:
        if e.id not in seen:
            seen.add(e.id)
            unique_related.append(e)
    return unique_related + [event]

def create_or_update_incident(db: Session, events, risk_score: int = 0) -> Incident:
    for event in events:
        if event.incidents:
            incident = event.incidents[0]
            for e in events:
                if e not in incident.events:
                    incident.events.append(e)
            return incident

    first = events[0]
    rule = (first.raw_data or {}).get("rule") or {}
    asset_id = first.asset_id
    incident = Incident(
        title=rule.get("description") or first.event_type,
        description=f"Инцидент сформирован на основе {len(events)} связанных событий.",
        severity="low",
        status="new",
        asset_id=asset_id,
        risk_score=risk_score,
        events=list(events),
    )
    db.add(incident)
    db.flush()
    return incident

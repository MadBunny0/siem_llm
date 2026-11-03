from datetime import timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import CorrelationRule, Event, Incident


def load_correlation_rules(db: Session) -> list[CorrelationRule]:
    """Загрузка активных правил корреляции из БД (согласно Главе 3.2 — CorrelationRule)."""
    return list(db.scalars(
        select(CorrelationRule).where(CorrelationRule.is_active.is_(True))
    ).all())


def _event_type_values(event: Event) -> list[str]:
    """Все значения типа события: event_type + группы правила Wazuh.

    Реальные алерты Wazuh аккумулируют группы служебными тегами вперёд
    (например ["syslog", "sshd", "authentication_failed"]), таксономическая
    группа оказывается последней, а event_type у нас = groups[0] (§3.3.1).
    Поэтому условия правил сопоставляются со всем набором групп (stage-11) —
    иначе seed-правила не срабатывали бы на настоящем стенде.
    """
    values = []
    if event.event_type:
        values.append(str(event.event_type))
    groups = (event.raw_data or {}).get("rule", {}).get("groups") or []
    values.extend(str(g) for g in groups if g)
    return values


def match_condition(event: Event, condition: dict) -> bool:
    """Проверка одного условия правила корреляции."""
    field = condition.get("field")
    operator = condition.get("operator", "eq")
    expected = condition.get("value")

    if field == "event_type":
        values = _event_type_values(event)
        if operator == "like":
            return any(str(expected) in v for v in values)
        if operator == "eq":
            return any(v == str(expected) for v in values)
        if operator == "in":
            expected_list = [str(v) for v in expected]
            return any(v in expected_list for v in values)
        if operator == "neq":
            return all(v != str(expected) for v in values)
        return False

    if field == "src_ip":
        actual = event.src_ip
    elif field == "user":
        actual = event.user
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

def match_attribute(event_a: Event, event_b: Event) -> bool:
    """Сопоставление двух событий по признакам (§3.3.2):
    IP-адрес источника, учётная запись пользователя, защищаемый актив."""
    return match_factor_count(event_a, event_b) > 0


def match_factor_count(event_a: Event, event_b: Event) -> int:
    """Сколько признаков совпало у двух событий (0–3): IP, учётная запись, актив.

    Используется как мера «достоверности результатов корреляции» (§3.3.3, p:74):
    чем больше совпавших признаков, тем выше уверенность, что события связаны.
    """
    factors = 0
    if event_a.src_ip and event_a.src_ip == event_b.src_ip:
        factors += 1
    if event_a.user and event_a.user == event_b.user:
        factors += 1
    if event_a.asset_id is not None and event_a.asset_id == event_b.asset_id:
        factors += 1
    return factors


def _candidate_conditions(event: Event) -> list:
    """SQL-условия совпадения атрибутов события (только по непустым полям)."""
    conditions = []
    if event.src_ip:
        conditions.append(Event.src_ip == event.src_ip)
    if event.user:
        conditions.append(Event.user == event.user)
    if event.asset_id is not None:
        conditions.append(Event.asset_id == event.asset_id)
    return conditions


def evaluate_correlation(db: Session, event: Event) -> tuple[CorrelationRule | None, list[Event], float]:
    """Оценка активных правил корреляции для события (§3.3.2 ВКР).

    Связанными считаются события того же временного окна, совпадающие
    с текущим по IP-адресу источника, учётной записи или защищаемому активу
    (p:59) — совпадение проверяется в SQL, а не перебором всех событий окна.
    Правило срабатывает, если накоплено не меньше rule.min_events событий —
    порог повторений («количество повторений аналогичных записей»).
    При срабатывании нескольких правил выбирается правило с наибольшим
    приоритетом.

    Возвращает (сработавшее правило, связанные события, достоверность
    корреляции 1/3…1.0 — средняя доля совпавших признаков) либо
    (None, [], 0.0), если ни одно правило не сработало — тогда инцидент
    не формируется, а событие сохраняется в БД до появления
    дополнительных событий (p:60).
    """
    best_rule: CorrelationRule | None = None
    best_related: list[Event] = []
    best_confidence = 0.0

    for rule in load_correlation_rules(db):
        if not check_rule_conditions(rule, event):
            continue
        conditions = _candidate_conditions(event)
        if not conditions:
            continue  # не с чем сопоставлять — событие без IP/учётки/актива
        window = rule.time_window_minutes if rule.time_window_minutes else settings.correlation_window_minutes
        start = event.timestamp - timedelta(minutes=window)
        end = event.timestamp + timedelta(minutes=window)
        # совпадение атрибутов отфильтровывается в SQL (stage-11, производительность)
        candidates = list(db.scalars(
            select(Event).where(
                Event.timestamp.between(start, end),
                or_(*conditions),
            )
        ).all())
        related = [e for e in candidates if e.id != event.id]
        min_events = rule.min_events or 1
        if len(related) + 1 < min_events:
            continue
        # достоверность корреляции: средняя доля совпавших признаков (1..3)/3
        if related:
            confidence = sum(match_factor_count(event, e) for e in related) / (3 * len(related))
        else:
            confidence = 1.0  # одиночное событие — корреляция не разбавляет оценку
        # выбор правила: наивысший приоритет; при равном приоритете — то,
        # что дало больше связанных событий (детерминированный выбор для демо)
        if (
            best_rule is None
            or (rule.priority, len(related)) > (best_rule.priority, len(best_related))
        ):
            best_rule = rule
            best_related = related
            best_confidence = confidence

    if best_rule is None:
        return None, [], 0.0
    return best_rule, best_related + [event], best_confidence


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

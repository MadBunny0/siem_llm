"""Конвейер приёма события (§3.1–3.3) — вынесен из app/api/routes.py (stage-19).

Этапы обработки события (§3.1, рис. 3.1):
сбор (ingest) → нормализация → привязка актива → корреляция по правилам БД →
оценка риска → [авто]LLM-анализ → Decision Validation Engine → playbook → аудит.

ingest_alert возвращает (result, should_auto_analyze): result — тело ответа
endpoint'ов /ingest/wazuh и /demo/*, should_auto_analyze — запланировать ли
фоновый LLM-анализ (auto_analysis включён И severity инцидента входит в
AUTO_ANALYSIS_LEVELS). Вызвавший сам ставит BackgroundTasks — семантика
фонового запуска прежняя (stage-12); служебный ключ _auto_analysis_incident_id
в result больше не кладётся.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Asset, Event
from app.services.assets import resolve_asset_id
from app.services.audit import audit
from app.services.auto_analysis import auto_analysis_levels
from app.services.correlation import create_or_update_incident, evaluate_correlation
from app.services.criticality import MITRE_TACTIC_SEVERITY, derive_severity_detail
from app.services.normalization import normalize_wazuh
from app.services.notification import notify_analyst
from app.services.risk import calculate_risk_detail, score_to_severity


def ingest_alert(db: Session, alert_payload: dict) -> tuple[dict, bool]:
    """Полный конвейер обработки одного алерта (используется ingest и мок-сценарии).

    Возвращает (result, should_auto_analyze) — см. docstring модуля.
    """
    # 1. Нормализация (§3.3.1)
    normalized = normalize_wazuh(alert_payload)

    # 2. Привязка к защищаемому активу (§3.2, сущность Asset)
    asset_id = resolve_asset_id(
        db,
        src_ip=normalized.get("src_ip"),
        agent_name=normalized.get("source"),
    )
    normalized["asset_id"] = asset_id

    event = Event(
        timestamp=normalized["timestamp"],
        source=normalized["source"],
        event_type=normalized["event_type"],
        user=normalized.get("user"),
        src_ip=normalized.get("src_ip"),
        asset_id=normalized.get("asset_id"),
        criticality_level=normalized.get("criticality_level"),
        raw_message=normalized.get("raw_message"),
        raw_data=normalized["raw_data"],
    )
    db.add(event)
    db.flush()

    audit(
        "event_ingested",
        {"event_id": event.id, "source": event.source},
        db=db,
        event_id=event.id,
    )
    audit(
        "normalized",
        {
            "event_id": event.id,
            "event_type": event.event_type,
            "src_ip": event.src_ip,
            "user": event.user,
            "asset_id": event.asset_id,
            "criticality_level": event.criticality_level,
        },
        db=db,
        event_id=event.id,
    )

    # 3. Корреляция по правилам из БД (§3.3.2)
    rule, related, correlation_confidence = evaluate_correlation(db, event)

    if rule is None:
        # Инцидент не формируется: событие сохраняется в БД до появления
        # дополнительных событий, позволяющих выполнить корреляцию (§3.3.2, p:60)
        audit(
            "event_stored",
            {"event_id": event.id, "reason": "правила корреляции не сработали"},
            db=db,
            event_id=event.id,
        )
        db.commit()
        return {
            "event_id": event.id,
            "correlated": False,
            "incident_id": None,
            "related_events": 0,
        }, False

    # 4. Оценка риска с учётом критичности актива (§3.3.3)
    risk_events = [
        {
            "raw_data": e.raw_data,
            "event_type": e.event_type,
            "asset_criticality": get_asset_criticality(db, e.asset_id),
        }
        for e in related
    ]
    # вероятность реализации угрозы — из данных события (§3.3.3, p:74);
    # числовая оценка остаётся для сортировки/отображения (считается один раз —
    # используется и в расчёте риска, и в severity_factors/аудите)
    threat_probability = p_implement(risk_events)
    score, _, risk_breakdown = calculate_risk_detail(
        risk_events,
        p_implement=threat_probability,
        correlation_confidence=correlation_confidence,
    )

    incident = create_or_update_incident(db, related, risk_score=score)

    # Критичность по матрице MITRE (stage-17, процедура PDF v3.1,
    # docs/CRITICALITY_MATRIX.md): базовая — по тактике правила, повышение —
    # по условиям процедуры (критичный актив, маркеры, периметр, флаг
    # поставщика). Без тактики — числовая модель риска (fallback, §3.3.3)
    matrix_severity, escalation_reasons, escalation_detail = derive_severity_detail(
        rule, related, incident.asset
    )
    if matrix_severity is not None:
        severity = matrix_severity
        severity_basis = "mitre_matrix"
    else:
        severity = score_to_severity(score)
        severity_basis = "risk_score"
    incident.severity = severity

    # Разбор оценки критичности для карточки инцидента (stage-22): из каких
    # факторов и с какими числами получился итоговый уровень. Полное
    # переприсвоение JSON-колонки (частичное изменение не отслеживается
    # SQLAlchemy — см. common.py); на обновлённых инцидентах разбор
    # пересчитывается под фактический набор событий
    incident.severity_factors = {
        "basis": severity_basis,
        "severity": severity,
        "computed_at": datetime.now(timezone.utc).isoformat(),
        # матрица MITRE (basis=mitre_matrix): базовый уровень по тактике +
        # сработавшие условия повышения с объяснениями
        "mitre": {
            "tactic": rule.mitre_tactic,
            "technique": rule.mitre_technique,
            "base_severity": MITRE_TACTIC_SEVERITY.get(rule.mitre_tactic),
            "escalations": escalation_detail,
        } if matrix_severity is not None else None,
        # числовая модель риска (§3.3.3) — рассчитывается всегда (fallback и
        # числовая метрика «уровень риска» в карточке)
        "risk": risk_breakdown,
    }

    audit(
        "correlated",
        {"rule": rule.name, "related_events": len(related)},
        db=db,
        incident_id=incident.id,
        event_id=event.id,
    )
    audit(
        "risk_calculated",
        {
            "risk_score": score,
            "severity": severity,
            "severity_basis": severity_basis,
            "mitre_tactic": rule.mitre_tactic,
            "escalation_reasons": escalation_reasons,
            "p_implement": threat_probability,
        },
        db=db,
        incident_id=incident.id,
    )
    audit(
        "incident_created_or_updated",
        {"incident_id": incident.id, "risk_score": score, "severity": severity},
        db=db,
        incident_id=incident.id,
        event_id=event.id,
    )

    db.commit()
    db.refresh(incident)

    # 5. Уведомление специалистов по ИБ о новом инциденте (§3.4)
    notify_analyst(db, incident, "incident_created")
    db.commit()

    result = {
        "event_id": event.id,
        "correlated": True,
        "incident_id": incident.id,
        "related_events": len(related),
        "risk_score": score,
        "severity": severity,
        "rule": rule.name,
    }

    # 6. Инциденты из auto_analysis_levels передаются в LLM без задержек (§3.3.3, p:80) —
    # в фоне (stage-12): приём события не блокируется CPU-инференсом модели.
    # Признак возвращается явно (stage-19): вызавший ставит BackgroundTasks
    should_auto_analyze = bool(
        settings.auto_analysis and incident.severity in auto_analysis_levels()
    )
    return result, should_auto_analyze


def p_implement(risk_events: list[dict]) -> float:
    """Вероятность реализации угрозы (§3.3.3, p:74) из данных события.

    Явный rule.confidence в алерте (кастомные правила Wazuh) приоритетнее;
    иначе эвристика по уровню правила: level/15, зажатый в [0.05, 0.95]
    (уровень 3 → 0.2, уровень 10 → 0.67, уровень 15 → 0.95).
    """
    confidences = [
        (e.get("raw_data") or {}).get("rule", {}).get("confidence")
        for e in risk_events
    ]
    confidences = [float(c) for c in confidences if c is not None]
    if confidences:
        return max(0.05, min(0.95, max(confidences)))
    levels = [
        float((e.get("raw_data") or {}).get("rule", {}).get("level", 3) or 3)
        for e in risk_events
    ]
    return max(0.05, min(0.95, (max(levels, default=3.0)) / 15.0))


def get_asset_criticality(db: Session, asset_id: int | None) -> str | None:
    """Критичность защищаемого актива по id (None — актив не определён)."""
    if asset_id is None:
        return None
    asset = db.get(Asset, asset_id)
    return asset.criticality if asset else None

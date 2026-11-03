"""REST API — оркестрация конвейера обработки инцидентов (Главы 3.1–3.4 ВКР).

Этапы обработки события (§3.1, рис. 3.1):
сбор (ingest) → нормализация → привязка актива → корреляция по правилам БД →
оценка риска → [авто]LLM-анализ → Decision Validation Engine → playbook → аудит.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import Analysis, Asset, Event, Incident, Notification
from app.schemas import AnalysisOut, IncidentOut, NotificationOut, WazuhAlert
from app.services.audit import audit
from app.services.assets import resolve_asset_id
from app.services.correlation import create_or_update_incident, evaluate_correlation
from app.services.llm import analyze_incident, render_full_prompt
from app.services.normalization import normalize_wazuh
from app.services.notification import notify_analyst
from app.services.playbook import execute_playbook, load_playbook_by_action
from app.services.risk import calculate_risk
from app.services.validation import validate_recommendation

router = APIRouter(prefix="/api/v1", tags=["SIEM"])


@router.post("/ingest/wazuh")
async def ingest_wazuh(alert: WazuhAlert, db: Session = Depends(get_db)):
    """Приём алерта Wazuh: нормализация → корреляция → риск → инцидент (§3.1–3.3)."""
    # 1. Нормализация (§3.3.1)
    normalized = normalize_wazuh(alert.model_dump(exclude_none=True))

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
    rule, related = evaluate_correlation(db, event)

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
        }

    # 4. Оценка риска с учётом критичности актива (§3.3.3)
    risk_events = [
        {
            "raw_data": e.raw_data,
            "event_type": e.event_type,
            "asset_criticality": _get_asset_criticality(db, e.asset_id),
        }
        for e in related
    ]
    confidence = max(
        ((e.get("raw_data") or {}).get("rule", {}).get("confidence", 0.5) for e in risk_events),
        default=0.5,
    )
    score, severity = calculate_risk(risk_events, p_implement=confidence, min_events=rule.min_events or 1)

    incident = create_or_update_incident(db, related, risk_score=score)
    incident.severity = severity

    audit(
        "correlated",
        {"rule": rule.name, "related_events": len(related)},
        db=db,
        incident_id=incident.id,
        event_id=event.id,
    )
    audit(
        "risk_calculated",
        {"risk_score": score, "severity": severity, "p_implement": confidence},
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

    # 6. Критические инциденты передаются модулю интеллектуального анализа
    # без задержек (§3.3.3, p:80)
    if settings.auto_analysis and incident.severity == "critical":
        result["analysis"] = await _run_incident_analysis(db, incident, raise_on_error=False)

    return result


def _get_asset_criticality(db: Session, asset_id: int | None) -> str | None:
    if asset_id is None:
        return None
    asset = db.get(Asset, asset_id)
    return asset.criticality if asset else None


@router.get("/incidents", response_model=list[IncidentOut])
def incidents(db: Session = Depends(get_db)):
    items = list(db.scalars(
        select(Incident).order_by(Incident.created_at.desc())
    ).all())
    # from_attributes в схемах — валидация напрямую из ORM-объектов
    return [IncidentOut.model_validate(incident) for incident in items]


@router.post("/incidents/{incident_id}/analyze")
async def analyze(incident_id: int, db: Session = Depends(get_db)):
    """Ручной запуск интеллектуального анализа инцидента (§3.3.4, §3.4)."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return await _run_incident_analysis(db, incident)


@router.post("/incidents/{incident_id}/confirm-action")
def confirm_action(incident_id: int, db: Session = Depends(get_db)):
    """Подтверждение администратором отложенного действия (§3.4, p:17, p:102).

    Выполняет последнее рекомендованное действие по инциденту, если оно
    разрешено политикой уровня риска и для него зарегистрирован playbook.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    analysis = db.scalar(
        select(Analysis)
        .where(Analysis.incident_id == incident_id)
        .order_by(Analysis.created_at.desc())
    )
    if not analysis or not analysis.recommended_action:
        raise HTTPException(status_code=404, detail="No pending recommendation found")

    action = analysis.recommended_action.split(",")[0].strip()
    playbook = load_playbook_by_action(db, action)
    asset = incident.asset
    validation = validate_recommendation(
        incident.severity,
        {"recommended_action": action},
        asset_criticality=asset.criticality if asset else None,
        playbook_found=playbook is not None,
        admin_confirmed=True,
    )
    if not validation["approved"]:
        raise HTTPException(status_code=422, detail=validation["reason"])

    execution = execute_playbook(validation["action"], {"incident_id": incident.id}, db)
    audit(
        "action_confirmed_by_admin",
        {"action": validation["action"], "execution": execution},
        db=db,
        incident_id=incident.id,
    )
    db.commit()
    return {"incident_id": incident.id, "validation": validation, "execution": execution}


async def _run_incident_analysis(
    db: Session,
    incident: Incident,
    raise_on_error: bool = True,
) -> dict:
    """Интеллектуальный анализ инцидента (§3.3.4 + §3.4).

    Контекст → Ollama → Decision Validation Engine → playbook → аудит.
    Результаты сохраняются в Analysis (LLMAnalysis).
    """
    asset = incident.asset
    context = {
        "incident_id": incident.id,
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        # сведения о защищаемом активе (§3.3.4, p:86)
        "asset": {
            "name": asset.name,
            "type": asset.type,
            "criticality": asset.criticality,
            "network_segment": asset.network_segment,
        } if asset else None,
        # последовательность развития инцидента (§3.3.4, p:86)
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "source": e.source,
                "event_type": e.event_type,
                "user": e.user,
                "src_ip": e.src_ip,
                "message": (e.raw_message or "")[:500],
            }
            for e in sorted(incident.events, key=lambda x: x.timestamp)
        ],
    }
    prompt_text = render_full_prompt(context)

    try:
        recommendation = await analyze_incident(context)
    except Exception as exc:
        audit(
            "llm_analysis_failed",
            {"incident_id": incident.id, "error": str(exc)},
            db=db,
            incident_id=incident.id,
        )
        db.commit()
        if raise_on_error:
            raise HTTPException(
                status_code=503,
                detail=f"LLM service unavailable: {exc}",
            ) from exc
        return {"incident_id": incident.id, "error": f"LLM service unavailable: {exc}"}

    if "recommended_action" in recommendation and "action" not in recommendation:
        recommendation["action"] = recommendation["recommended_action"]
    if "explanation" in recommendation and "reason" not in recommendation:
        recommendation["reason"] = recommendation["explanation"]

    # LLM может вернуть несколько действий через запятую — берём первое
    raw_action = str(recommendation.get("recommended_action") or "monitor").split(",")[0].strip()
    recommendation["recommended_action"] = raw_action

    # Decision Validation Engine (§3.4): политика уровня риска + playbook + актив
    playbook = load_playbook_by_action(db, raw_action)
    validation = validate_recommendation(
        incident.severity,
        recommendation,
        asset_criticality=asset.criticality if asset else None,
        playbook_found=playbook is not None,
    )

    if validation.get("requires_confirmation"):
        # Критический актив: действие отложено до подтверждения администратора
        execution = {
            "executed": False,
            "mode": "pending_confirmation",
            "action": validation["action"],
            "reason": validation["reason"],
        }
        notify_analyst(db, incident, "action_pending_confirmation")
    else:
        execution = execute_playbook(validation["action"], context, db)

    # Сохранение результатов интеллектуального анализа (модель Analysis / LLMAnalysis)
    # Поля по Таблице 3.1 (§3.2 ВКР): описание, тип атаки, достоверность, обоснование, рекомендации
    analysis = Analysis(
        incident_id=incident.id,
        model=settings.ollama_model,
        prompt=prompt_text,  # реальный текст запроса к LLM (§3.3.4)
        description=recommendation.get("description") or incident.description,
        attack_type=recommendation.get("attack_type"),
        confidence=recommendation.get("confidence"),
        explanation=recommendation.get("explanation") or recommendation.get("reason"),
        recommended_action=recommendation.get("recommended_action") or recommendation.get("action"),
        # полный ответ модели LLM сохраняем в JSON для расследований
        response_raw={
            "recommendation": recommendation,
            "validation": validation,
            "execution": execution,
        },
    )
    analysis.updated_at = datetime.now(timezone.utc)
    db.add(analysis)
    # предполагаемый тип атаки попадает в карточку инцидента (§3.2, p:30)
    incident.attack_type = recommendation.get("attack_type") or incident.attack_type
    incident.status = "in_progress"
    db.commit()
    db.refresh(incident)

    audit("validation_result", validation, db=db, incident_id=incident.id)
    audit(
        "playbook_selected",
        {"playbook": playbook.name if playbook else None},
        db=db,
        incident_id=incident.id,
    )
    audit("action_executed", execution, db=db, incident_id=incident.id)
    db.commit()

    # ITSM-уведомление аналитикам о результатах анализа LLM
    notify_analyst(db, incident, "incident_analyzed")
    db.commit()

    return {
        "incident_id": incident.id,
        "recommendation": recommendation,
        "validation": validation,
        "execution": execution,
    }


@router.get("/notifications", response_model=list[NotificationOut])
def notifications(db: Session = Depends(get_db)):
    return list(db.scalars(
        select(Notification).order_by(Notification.created_at.desc())
    ).all())


@router.get("/analyses", response_model=list[AnalysisOut])
def analyses(db: Session = Depends(get_db)):
    """Статистика качества работы LLM-модуля (Таблица 3.1, §3.2 ВКР)."""
    return list(db.scalars(
        select(Analysis).order_by(Analysis.created_at.desc())
    ).all())


@router.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "database": "ok",
        "llm_model": settings.ollama_model,
        "auto_response": settings.auto_response,
        "auto_analysis": settings.auto_analysis,
    }

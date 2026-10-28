from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import Analysis, Event, Incident
from app.schemas import IncidentOut, WazuhAlert
from app.services.audit import audit
from app.services.correlation import create_or_update_incident, find_related_events
from app.services.llm import analyze_incident
from app.services.normalization import normalize_wazuh
from app.services.playbook import execute_playbook
from app.services.risk import calculate_risk
from app.services.validation import validate_recommendation

router = APIRouter(prefix="/api/v1", tags=["SIEM"])


@router.post("/ingest/wazuh")
def ingest_wazuh(alert: WazuhAlert, db: Session = Depends(get_db)):
    normalized = normalize_wazuh(alert.model_dump(exclude_none=True))
    event = Event(
        timestamp=normalized["timestamp"],
        source=normalized["source"],
        event_type=normalized["event_type"],
        raw_data=normalized["raw_data"]
    )

    db.add(event)
    db.flush()

    related = find_related_events(db, event)
    incident = create_or_update_incident(db, related)

    score, severity = calculate_risk([
        {"raw_data": e.raw_data} for e in related
    ])
    incident.severity = severity
    db.commit()
    db.refresh(incident)

    audit("incident_created_or_updated", {
        "incident_id": incident.id,
        "event_id": event.id,
        "related_events": len(related),
        "risk_score": score,
        "severity": severity,
    })

    return {
        "event_id": event.id,
        "incident_id": incident.id,
        "related_events": len(related),
        "risk_score": score,
        "severity": severity,
    }


@router.get("/incidents", response_model=list[IncidentOut])
def incidents(db: Session = Depends(get_db)):
    return list(db.scalars(
        select(Incident).order_by(Incident.created_at.desc())
    ).all())


@router.post("/incidents/{incident_id}/analyze")
async def analyze(incident_id: int, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    context = {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp,
                "source": e.source,
                "event_type": e.event_type,
                "raw_data": e.raw_data,
            }
            for e in incident.events
        ],
    }

    try:
        recommendation = await analyze_incident(context)
    except Exception as exc:
        audit("llm_analysis_failed", {
            "incident_id": incident.id,
            "error": str(exc),
        })
        raise HTTPException(
            status_code=503,
            detail=f"LLM service unavailable: {exc}",
        ) from exc

    if "recommended_action" in recommendation and "action" not in recommendation:
        recommendation["action"] = recommendation["recommended_action"]
    if "explanation" in recommendation and "reason" not in recommendation:
        recommendation["reason"] = recommendation["explanation"]

    validation = validate_recommendation(incident.severity, recommendation)
    execution = execute_playbook(validation["action"], context)

    analysis = Analysis(
        incident_id=incident.id,
        model=settings.ollama_model,
        prompt="SOC incident analysis",
        response={
            "recommendation": recommendation,
            "validation": validation,
            "execution": execution,
        },
    )
    db.add(analysis)
    incident.status = "in_progress"
    db.commit()

    audit("llm_analysis_completed", {
        "incident_id": incident.id,
        "recommendation": recommendation,
        "validation": validation,
        "execution": execution,
    })

    return {
        "incident_id": incident.id,
        "recommendation": recommendation,
        "validation": validation,
        "execution": execution,
    }


@router.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "database": "ok",
        "llm_model": settings.ollama_model,
        "auto_response": settings.auto_response,
    }

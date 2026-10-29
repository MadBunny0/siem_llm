import json
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.models import AuditLog

logger = logging.getLogger("audit")


def log_audit(
    db: Session,
    event_type: str,
    incident_id: int | None = None,
    event_id: int | None = None,
    user_id: int | None = None,
    details: dict | None = None,
) -> None:
    """
    Запись записи в таблицу AuditLog (согласно Главе 3.2).
    details — дополнительные сведения об этапе обработки.
    """
    record = AuditLog(
        event_type=event_type,
        incident_id=incident_id,
        event_id=event_id,
        user_id=user_id,
        details=details or {},
    )
    db.add(record)
    db.flush()


def audit(event: str, payload: dict, db: Session | None = None, **meta) -> None:
    """
    Логирование этапа обработки: запись в журнал аудита AuditLog + вывод в лог.
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "payload": payload,
    }
    logger.info("AUDIT %s", json.dumps(record, ensure_ascii=False, default=str))

    if db is not None:
        log_audit(
            db,
            event_type=event,
            incident_id=meta.get("incident_id"),
            event_id=meta.get("event_id"),
            user_id=meta.get("user_id"),
            details=payload,
        )

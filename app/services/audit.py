import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("audit")

def audit(event: str, payload: dict):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "payload": payload,
    }
    logger.info("AUDIT %s", json.dumps(record, ensure_ascii=False, default=str))

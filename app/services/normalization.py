from datetime import datetime, timezone
from typing import Dict, Any

def normalize_wazuh(alert: Dict[str, Any]) -> Dict[str, Any]:
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    ts = alert.get("timestamp")

    if ts is None:
        timestamp = datetime.now(timezone.utc)
    elif isinstance(ts, str):
        try:
            ts_normalized = ts.replace("Z", "+00:00")
            timestamp = datetime.fromisoformat(ts_normalized)
        except (ValueError, AttributeError):
            timestamp = datetime.now(timezone.utc)
    else:
        try:
            timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)
        except (TypeError, ValueError):
            timestamp = datetime.now(timezone.utc)

    source = agent.get("name") or agent.get("id") or data.get("srcip") or "wazuh"
    event_type = (
        rule.get("groups", ["security_event"])[0]
        if rule.get("groups") else "security_event"
    )

    return {
        "timestamp": timestamp,
        "source": str(source),
        "event_type": str(event_type),
        "raw_data": alert,
    }
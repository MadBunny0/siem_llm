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
    user = data.get("dstuser") or data.get("user") or agent.get("username")
    src_ip = data.get("srcip") or data.get("src_ip")
    level = rule.get("level", 3)
    groups = rule.get("groups") or []
    event_type = groups[0] if groups else "security_event"

    return {
        "timestamp": timestamp,
        "source": str(source),
        "event_type": str(event_type),
        "user": str(user) if user else None,
        "src_ip": str(src_ip) if src_ip else None,
        "asset_id": None,  # устанавливается модулем оценки риска на основе Asset
        "criticality_level": int(level) if isinstance(level, (int, str)) else 3,
        "raw_message": str(alert.get("full_log")) if alert.get("full_log") else None,
        "raw_data": alert,
    }
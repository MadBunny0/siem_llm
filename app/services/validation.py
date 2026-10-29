ALLOWED_ACTIONS = {
    "low": {"monitor", "collect_evidence"},
    "medium": {"monitor", "collect_evidence"},
    "high": {"monitor", "collect_evidence", "isolate_host", "block_ip"},
    "critical": {
        "monitor", "collect_evidence", "isolate_host",
        "block_ip", "disable_account"
    },
}

def validate_recommendation(severity: str, recommendation: dict) -> dict:
    action = recommendation.get("recommended_action") or recommendation.get("action") or "monitor"
    allowed_actions = ALLOWED_ACTIONS.get(severity.lower(), {"monitor"})
    allowed = action in allowed_actions
    safe_action = action if allowed else "monitor"
    return {
        "approved": allowed,
        "action": safe_action,
        "reason": (
            "Действие разрешено политикой"
            if allowed else
            "Действие заменено на monitor: оно отсутствует в политике уровня риска"
        ),
    }

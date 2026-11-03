"""Decision Validation Engine — модуль проверки решений (§3.4 ВКР).

Последовательная проверка рекомендаций LLM перед выполнением:
1. действие разрешено политикой для уровня риска инцидента (p:103);
2. для действия зарегистрирован сценарий реагирования (playbook) из БД (p:103-104);
3. критический актив → обязательное подтверждение администратора (p:17, p:102).
"""

ALLOWED_ACTIONS = {
    "low": {"monitor", "collect_evidence"},
    "medium": {"monitor", "collect_evidence"},
    "high": {"monitor", "collect_evidence", "isolate_host", "block_ip"},
    "critical": {
        "monitor", "collect_evidence", "isolate_host",
        "block_ip", "disable_account"
    },
}

# Действия, требующие подтверждения администратора для критически важных активов
CONFIRMATION_REQUIRED_ACTIONS = {"block_ip", "disable_account", "isolate_host"}

# Действия, допустимые без зарегистрированного playbook (не меняют инфраструктуру)
PASSIVE_ACTIONS = {"monitor", "collect_evidence"}


def validate_recommendation(
    severity: str,
    recommendation: dict,
    asset_criticality: str | None = None,
    playbook_found: bool | None = None,
    admin_confirmed: bool = False,
) -> dict:
    """Проверка рекомендации LLM перед выполнением (§3.4).

    Аргументы:
    severity — уровень риска инцидента (low/medium/high/critical);
    asset_criticality — критичность защищаемого актива (если определён);
    playbook_found — найден ли зарегистрированный playbook для действия
        (None — проверка не выполнялась, для обратной совместимости);
    admin_confirmed — действие явно подтверждено администратором
        (endpoint POST /incidents/{id}/confirm-action).

    При нарушении любого ограничения действие заменяется на безопасный
    monitor, кроме случая, когда требуется подтверждение администратора —
    тогда действие сохраняется до подтверждения (requires_confirmation).
    """
    action = recommendation.get("recommended_action") or recommendation.get("action") or "monitor"
    allowed_actions = ALLOWED_ACTIONS.get(severity.lower(), {"monitor"})

    # 1. Политика уровня риска
    if action not in allowed_actions:
        return {
            "approved": False,
            "action": "monitor",
            "requires_confirmation": False,
            "reason": (
                "Действие заменено на monitor: оно отсутствует в политике "
                "(policy) уровня риска"
            ),
        }

    # 2. Отсутствие зарегистрированного сценария реагирования — только уведомление (p:104)
    if playbook_found is False and action not in PASSIVE_ACTIONS:
        return {
            "approved": False,
            "action": "monitor",
            "requires_confirmation": False,
            "reason": (
                "Действие заменено на monitor: отсутствует зарегистрированный "
                "сценарий реагирования (playbook), специалист уведомлён"
            ),
        }

    # 3. Критический актив — обязательное подтверждение администратора (p:17)
    if (
        not admin_confirmed
        and asset_criticality == "critical"
        and action in CONFIRMATION_REQUIRED_ACTIONS
    ):
        return {
            "approved": False,
            "action": action,  # действие сохраняется до подтверждения
            "requires_confirmation": True,
            "reason": (
                "Действие отложено: критический актив требует подтверждения "
                "администратора безопасности"
            ),
        }

    return {
        "approved": True,
        "action": action,
        "requires_confirmation": False,
        "reason": "Действие разрешено политикой",
    }

"""Decision Validation Engine — модуль проверки решений (§3.4 ВКР).

Последовательная проверка рекомендаций LLM перед выполнением:
1. действие разрешено политикой для уровня риска инцидента (p:103);
2. для действия зарегистрирован сценарий реагирования (playbook) из БД (p:103-104);
3. критический актив → обязательное подтверждение администратора (p:17, p:102).

Политика разрешённых действий хранится в БД (таблица validation_policy,
stage-11) — соответствует p:103 «формализованные правила реагирования,
хранящиеся в базе данных». При отсутствии сессии БД (юнит-тесты, миграции)
используются встроенные DEFAULT_ALLOWED_ACTIONS.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ValidationPolicy

# Действия, требующие подтверждения администратора для критически важных активов
CONFIRMATION_REQUIRED_ACTIONS = {"block_ip", "disable_account", "isolate_host"}

# Действия, допустимые без зарегистрированного playbook (не меняют инфраструктуру)
PASSIVE_ACTIONS = {"monitor", "collect_evidence"}

# Встроенная политика — seed для validation_policy и fallback без БД
ALLOWED_ACTIONS = {
    "low": {"monitor", "collect_evidence"},
    "medium": {"monitor", "collect_evidence"},
    "high": {"monitor", "collect_evidence", "isolate_host", "block_ip"},
    "critical": {
        "monitor", "collect_evidence", "isolate_host",
        "block_ip", "disable_account"
    },
}

DEFAULT_ALLOWED_ACTIONS = ALLOWED_ACTIONS  # алиас для читаемости


def load_allowed_actions(severity: str, db: Session | None = None) -> set[str]:
    """Разрешённые действия для уровня риска: из БД (validation_policy),
    при отсутствии строки/сессии — встроенные DEFAULT_ALLOWED_ACTIONS."""
    if db is not None:
        row = db.scalar(
            select(ValidationPolicy).where(
                ValidationPolicy.severity == severity.lower()
            )
        )
        if row and row.allowed_actions:
            return set(row.allowed_actions)
    return DEFAULT_ALLOWED_ACTIONS.get(severity.lower(), {"monitor"})


def validate_recommendation(
    severity: str,
    recommendation: dict,
    asset_criticality: str | None = None,
    playbook_found: bool | None = None,
    admin_confirmed: bool = False,
    db: Session | None = None,
) -> dict:
    """Проверка рекомендации LLM перед выполнением (§3.4).

    Аргументы:
    severity — уровень риска инцидента (low/medium/high/critical);
    asset_criticality — критичность защищаемого актива (если определён);
    playbook_found — найден ли зарегистрированный playbook для действия
        (None — проверка не выполнялась, для обратной совместимости);
    admin_confirmed — действие явно подтверждено администратором
        (endpoint POST /incidents/{id}/confirm-action);
    db — сессия БД: политика разрешённых действий берётся из
        validation_policy; без неё — встроенные DEFAULT_ALLOWED_ACTIONS.

    При нарушении любого ограничения действие заменяется на безопасный
    monitor, кроме случая, когда требуется подтверждение администратора —
    тогда действие сохраняется до подтверждения (requires_confirmation).
    """
    action = recommendation.get("recommended_action") or recommendation.get("action") or "monitor"
    allowed_actions = load_allowed_actions(severity, db)

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

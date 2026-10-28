import logging
from app.config import settings

logger = logging.getLogger("playbook")

def execute_playbook(action: str, context: dict) -> dict:
    # Безопасный режим демонстрации. Реальное изменение инфраструктуры выключено.
    if not settings.auto_response:
        logger.warning("SIMULATION: action=%s context=%s", action, context)
        return {"executed": False, "mode": "simulation", "action": action}

    # Точка интеграции с Wazuh Active Response.
    logger.warning("CONTROLLED RESPONSE: action=%s context=%s", action, context)
    return {"executed": True, "mode": "controlled", "action": action}

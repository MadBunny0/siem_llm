import json

import httpx

from app.config import settings

SYSTEM_PROMPT = """
Ты выполняешь роль аналитика SOC.
Анализируй только переданный контекст инцидента и не выдумывай факты.
Верни строго JSON со следующими полями:
description (сформированное описание инцидента),
category (предполагаемый тип атаки: network_scan, brute_force, credential_attack, privilege_escalation, malware, data_exfiltration, или monitor),
explanation (текстовое обоснование принятого решения),
confidence (уровень достоверности результата, число от 0.0 до 1.0),
recommended_action (один или несколько, разделённых запятой: monitor, collect_evidence, isolate_host, block_ip, disable_account).

recommended_action должен быть только одним из:
monitor, collect_evidence, isolate_host, block_ip, disable_account.

confidence — число от 0 до 1.
Если данных недостаточно для активного реагирования, выбирай monitor или collect_evidence.
""".strip()


async def analyze_incident(incident: dict) -> dict:
    payload = {
        "model": settings.ollama_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(incident, ensure_ascii=False, default=str),
            },
        ],
        "stream": False,
        "format": "json",
    }

    async with httpx.AsyncClient(timeout=180) as client:
        response = await client.post(
            f"{settings.ollama_url.rstrip('/')}/api/chat",
            json=payload,
        )
        response.raise_for_status()
        body = response.json()

    content = body.get("message", {}).get("content", "")
    if not content:
        raise ValueError("Ollama returned an empty response")

    result = json.loads(content)
    if not isinstance(result, dict):
        raise ValueError("LLM response must be a JSON object")
    # Нормализация ответов LLM под поля модели Analysis (LLMAnalysis)
    normalized = {
        "description": result.get("description") or f"Анализ инцидента #{incident.get('id')}: {result.get('category') or 'Неизвестно'}",
        "attack_type": result.get("category"),
        "confidence": result.get("confidence"),
        "explanation": result.get("explanation") or "",
        "recommended_action": result.get("recommended_action") or "monitor",
    }
    return normalized

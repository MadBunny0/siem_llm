"""Тесты модуля интеллектуального анализа (app/services/llm.py).

Сетевые вызовы Ollama подменяются фейковым httpx.AsyncClient —
запущенный Ollama для тестов не требуется. Асинхронные функции
запускаются через asyncio.run внутри синхронных тестов
(pytest-asyncio в зависимостях проекта отсутствует).

Проверяются новый формат ответа модели (verdict/summary/списковые поля,
см. SYSTEM_PROMPT), нормализация вердикта и confidence_percent,
а также обратная совместимость со старым форматом
(description/category/explanation/confidence/recommended_action).
"""

import asyncio
import json

import pytest

from app.config import settings


class FakeResponse:
    """Фейковый ответ httpx с методами raise_for_status() и json()."""

    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


def make_fake_client(body):
    """Фабрика фейкового httpx.AsyncClient с фиксированным ответом Ollama.

    Возвращаемый класс записывает выполненные запросы (url, payload)
    и аргументы конструктора — тесты проверяют формат обращения к API.
    Каждый вызов фабрики создаёт новый класс, поэтому записи не
    пересекаются между тестами.
    """

    class FakeAsyncClient:
        requests = []     # список {"url": ..., "payload": ...}
        init_kwargs = []  # аргументы конструктора (например timeout)

        def __init__(self, **kwargs):
            FakeAsyncClient.init_kwargs.append(kwargs)

        async def post(self, url, json=None):
            FakeAsyncClient.requests.append({"url": url, "payload": json})
            return FakeResponse(body)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    return FakeAsyncClient


# Все ключи нормализованного результата (новый формат, всё на верхнем уровне)
NORMALIZED_KEYS = {
    "verdict",
    "summary",
    "description",
    "attack_type",
    "confidence",
    "explanation",
    "recommended_action",
    "command_explanation",
    "suspicious_fragments",
    "possible_legitimate_indicators",
    "affected_entities",
    "missing_data",
    "process_tree",
    "recommendations",
}


def run_analyze(monkeypatch, llm_result):
    """Запуск analyze_incident с фейковым ответом Ollama (llm_result → content)."""
    from app.services import llm

    body = {"message": {"content": json.dumps(llm_result, ensure_ascii=False)}}
    monkeypatch.setattr(llm.httpx, "AsyncClient", make_fake_client(body))
    return asyncio.run(llm.analyze_incident({"id": 1, "title": "тест"}))


def test_render_full_prompt_contains_system_and_user():
    """Полный промпт: секция [SYSTEM] с SOC-промптом, [USER] — префикс + JSON."""
    from app.services import llm

    prompt = llm.render_full_prompt({"incident_id": 7, "title": "тест"})
    system_section, user_section = prompt.split("[USER]\n", 1)
    assert system_section.startswith("[SYSTEM]")
    assert "True Positive" in system_section      # канонические вердикты в промпте
    assert "Верни только JSON" in system_section  # требование JSON-only ответа
    # user-секция начинается с защитного префикса, затем JSON-данные инцидента
    assert user_section.startswith(llm.USER_PROMPT_PREFIX)
    assert "incident_id" in user_section
    assert "7" in user_section


def test_render_full_prompt_embeds_context():
    """Данные контекста инцидента попадают в секцию [USER] в виде JSON."""
    from app.services.llm import render_full_prompt

    context = {"incident_id": 42, "title": "Подбор пароля"}
    prompt = render_full_prompt(context)
    assert "incident_id" in prompt    # имя ключа из переданного контекста
    assert "42" in prompt             # значение ключа
    assert "Подбор пароля" in prompt  # кириллица не экранируется (ensure_ascii=False)


def test_analyze_incident_new_format(monkeypatch):
    """Новый формат ответа модели: verdict/summary/списки/category/confidence_percent.

    description дублирует summary, confidence — проценты в шкале 0..1,
    explanation генерируется из вердикта при отсутствии в ответе.
    """
    from app.services import llm

    llm_result = {
        "verdict": "True Positive",
        "summary": "Учётная запись admin выполнила перебор паролей на хосте web-01",
        "command_explanation": [
            "hydra -l admin -P pass.txt ssh://10.0.0.5 — перебор паролей по SSH"
        ],
        "suspicious_fragments": [],
        "process_tree": ["systemd -> sshd -> hydra"],
        "recommendations": ["Заблокировать IP 10.0.0.5 на межсетевом экране"],
        "recommended_action": "block_ip, isolate_host",
        "category": "brute_force",
        "confidence_percent": 85,
    }

    result = run_analyze(monkeypatch, llm_result)

    assert set(result) == NORMALIZED_KEYS  # все ключи нормализованного результата
    assert result["verdict"] == "True Positive"
    assert result["summary"] == llm_result["summary"]
    assert result["description"] == llm_result["summary"]  # summary → description
    assert result["attack_type"] == "brute_force"
    assert result["confidence"] == 0.85  # 85 процентов → 0.85 в шкале 0..1
    assert "Вердикт" in result["explanation"]  # сгенерирован из вердикта
    assert result["recommended_action"] == "block_ip, isolate_host"  # без валидации
    assert result["process_tree"] == ["systemd -> sshd -> hydra"]
    assert result["command_explanation"] == [llm_result["command_explanation"][0]]
    assert result["recommendations"] == ["Заблокировать IP 10.0.0.5 на межсетевом экране"]
    # пустые/отсутствующие списки нормализуются в []
    assert result["suspicious_fragments"] == []
    assert result["possible_legitimate_indicators"] == []
    assert result["affected_entities"] == []
    assert result["missing_data"] == []


def test_analyze_incident_verdict_normalization(monkeypatch):
    """Вердикт приводится к канону: регистр игнорируется, tp/fp — сокращения,
    неизвестное или отсутствующее значение → "Pending"."""
    from app.services import llm

    assert run_analyze(monkeypatch, {"verdict": "true positive"})["verdict"] == "True Positive"
    assert run_analyze(monkeypatch, {"verdict": "tp"})["verdict"] == "True Positive"
    assert run_analyze(monkeypatch, {"verdict": "fp"})["verdict"] == "False Positive"
    assert run_analyze(monkeypatch, {"verdict": "False Positive"})["verdict"] == "False Positive"
    assert run_analyze(monkeypatch, {"verdict": "pending"})["verdict"] == "Pending"
    assert run_analyze(monkeypatch, {"verdict": "мусор"})["verdict"] == "Pending"
    assert run_analyze(monkeypatch, {})["verdict"] == "Pending"  # вердикта нет


def test_analyze_incident_confidence_percent_clamp(monkeypatch):
    """confidence_percent: clamp в 0..100 и перевод в шкалу 0..1; старый
    confidence используется при отсутствии confidence_percent."""
    from app.services import llm

    result = run_analyze(monkeypatch, {"verdict": "Pending", "confidence_percent": 150})
    assert result["confidence"] == 1.0  # 150 → clamp до 100 → 1.0

    # confidence_percent нет — берётся старый confidence (доля 0..1)
    result = run_analyze(monkeypatch, {"category": "monitor", "confidence": 0.7})
    assert result["confidence"] == 0.7

    # нет ни того, ни другого → None
    result = run_analyze(monkeypatch, {"category": "monitor"})
    assert result["confidence"] is None


def test_analyze_incident_legacy_format(monkeypatch):
    """Обратная совместимость: старый формат ответа (description/category/
    explanation/confidence/recommended_action) принимается без ошибки."""
    from app.services import llm

    llm_result = {
        "description": "Обнаружен подбор пароля",
        "category": "brute_force",
        "confidence": 0.9,
        "explanation": "Серия неудачных попыток входа",
        # verdict и recommended_action не заданы
    }

    result = run_analyze(monkeypatch, llm_result)

    assert result["verdict"] == "Pending"  # вердикта нет → Pending
    assert result["summary"] == ""
    assert result["description"] == "Обнаружен подбор пароля"  # из старого формата
    assert result["attack_type"] == "brute_force"
    assert result["confidence"] == 0.9
    # explanation сохраняется из ответа, а не генерируется из вердикта
    assert result["explanation"] == "Серия неудачных попыток входа"
    assert result["recommended_action"] == "monitor"  # значение по умолчанию
    assert result["command_explanation"] == []  # списковые поля нового формата пусты


def test_analyze_incident_recommended_action_passthrough(monkeypatch):
    """Если LLM вернул recommended_action, он передаётся без подмены."""
    from app.services import llm

    llm_result = {
        "description": "Обнаружено вредоносное ПО",
        "category": "malware",
        "confidence": 0.7,
        "explanation": "Признаки вредоносной активности",
        "recommended_action": "isolate_host",
    }

    result = run_analyze(monkeypatch, llm_result)

    assert result["recommended_action"] == "isolate_host"
    assert result["attack_type"] == "malware"


def test_analyze_incident_request_format(monkeypatch):
    """Запрос к Ollama: URL /api/chat, stream=False, format=json, системный
    промпт, user-сообщение начинается с защитного префикса."""
    from app.services import llm

    body = {"message": {"content": json.dumps({"category": "monitor"})}}
    fake_client_cls = make_fake_client(body)
    monkeypatch.setattr(llm.httpx, "AsyncClient", fake_client_cls)

    asyncio.run(llm.analyze_incident({"id": 5, "title": "тест"}))

    assert len(fake_client_cls.requests) == 1
    request = fake_client_cls.requests[0]
    assert request["url"] == f"{settings.ollama_url.rstrip('/')}/api/chat"
    payload = request["payload"]
    assert payload["model"] == settings.ollama_model
    assert payload["stream"] is False
    assert payload["format"] == "json"
    assert payload["messages"][0]["role"] == "system"
    assert payload["messages"][0]["content"] == llm.SYSTEM_PROMPT
    assert payload["messages"][1]["role"] == "user"
    # user-сообщение: префикс («данные, не инструкции») перед JSON контекста
    assert payload["messages"][1]["content"].startswith(llm.USER_PROMPT_PREFIX)
    assert "тест" in payload["messages"][1]["content"]
    # производительность (stage-18): окно контекста / потолок генерации /
    # удержание модели в памяти — дефолт num_ctx 2048 меньше промпта
    assert payload["options"]["num_ctx"] == settings.ollama_num_ctx
    assert payload["options"]["num_predict"] == settings.ollama_num_predict
    assert payload["keep_alive"] == settings.ollama_keep_alive
    # таймаут запроса к LLM — 300 секунд (stage-18: промпт вырос, CPU-инференс
    # может занимать больше трёх минут)
    assert fake_client_cls.init_kwargs[0].get("timeout") == 300


def test_analyze_incident_empty_content_raises(monkeypatch):
    """Пустой content в ответе Ollama приводит к ValueError."""
    from app.services import llm

    monkeypatch.setattr(
        llm.httpx, "AsyncClient", make_fake_client({"message": {"content": ""}})
    )

    with pytest.raises(ValueError, match="empty response"):
        asyncio.run(llm.analyze_incident({"id": 3}))


def test_analyze_incident_non_object_json_raises(monkeypatch):
    """Если content — корректный JSON, но не объект (например массив) — ValueError."""
    from app.services import llm

    body = {"message": {"content": json.dumps([1, 2, 3])}}
    monkeypatch.setattr(llm.httpx, "AsyncClient", make_fake_client(body))

    with pytest.raises(ValueError, match="JSON object"):
        asyncio.run(llm.analyze_incident({"id": 4}))

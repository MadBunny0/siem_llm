"""Тесты модуля интеллектуального анализа (app/services/llm.py).

Сетевые вызовы Ollama подменяются фейковым httpx.AsyncClient —
запущенный Ollama для тестов не требуется. Асинхронные функции
запускаются через asyncio.run внутри синхронных тестов
(pytest-asyncio в зависимостях проекта отсутствует).
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


def test_render_full_prompt_contains_system_and_user():
    """Полный промпт содержит секции [SYSTEM]/[USER] и текст SOC-промпта."""
    from app.services.llm import render_full_prompt

    prompt = render_full_prompt({"id": 1})
    assert "[SYSTEM]" in prompt
    assert "[USER]" in prompt
    assert "SOC" in prompt  # подстрока системного промпта SOC-аналитика


def test_render_full_prompt_embeds_context():
    """Данные контекста инцидента попадают в секцию [USER] в виде JSON."""
    from app.services.llm import render_full_prompt

    context = {"incident_id": 42, "title": "Подбор пароля"}
    prompt = render_full_prompt(context)
    assert "incident_id" in prompt    # имя ключа из переданного контекста
    assert "42" in prompt             # значение ключа
    assert "Подбор пароля" in prompt  # кириллица не экранируется (ensure_ascii=False)


def test_analyze_incident_success(monkeypatch):
    """Успешный ответ Ollama нормализуется: category → attack_type, действие по умолчанию."""
    from app.services import llm

    llm_result = {
        "description": "Обнаружен подбор пароля",
        "category": "brute_force",
        "confidence": 0.9,
        "explanation": "Серия неудачных попыток входа",
        # recommended_action не задан — должен подставиться "monitor"
    }
    body = {"message": {"content": json.dumps(llm_result, ensure_ascii=False)}}
    fake_client_cls = make_fake_client(body)
    monkeypatch.setattr(llm.httpx, "AsyncClient", fake_client_cls)

    result = asyncio.run(llm.analyze_incident({"id": 1, "title": "тест"}))

    assert result["attack_type"] == "brute_force"  # category маппится в attack_type
    assert result["description"] == "Обнаружен подбор пароля"
    assert result["confidence"] == 0.9
    assert result["explanation"] == "Серия неудачных попыток входа"
    assert result["recommended_action"] == "monitor"  # значение по умолчанию


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
    body = {"message": {"content": json.dumps(llm_result, ensure_ascii=False)}}
    monkeypatch.setattr(llm.httpx, "AsyncClient", make_fake_client(body))

    result = asyncio.run(llm.analyze_incident({"id": 2}))

    assert result["recommended_action"] == "isolate_host"
    assert result["attack_type"] == "malware"


def test_analyze_incident_request_format(monkeypatch):
    """Запрос к Ollama: URL /api/chat, stream=False, format=json, системный промпт."""
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
    # контекст инцидента передаётся в user-сообщении как JSON (без экранирования кириллицы)
    assert "тест" in payload["messages"][1]["content"]
    # таймаут запроса к LLM — 180 секунд
    assert fake_client_cls.init_kwargs[0].get("timeout") == 180


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

"""Тесты OpenAI-совместимого провайдера LLM (ветка test-glm-cloud-adapter).

Формат запроса/ответа отличается от Ollama (/chat/completions, Bearer-заголовок,
choices вместо message), нормализация результата общая. Сетевые вызовы
подменяются фейковым httpx.AsyncClient — как в test_llm.py.
"""

import asyncio
import json

from app.config import settings


class FakeResponse:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


def make_fake_client(body):
    """Фейковый AsyncClient: фиксированный ответ, запись (url, payload, headers)."""

    class FakeAsyncClient:
        requests = []

        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def post(self, url, json=None, headers=None):
            FakeAsyncClient.requests.append(
                {"url": url, "payload": json, "headers": headers}
            )
            return FakeResponse(body)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    return FakeAsyncClient


def with_provider(monkeypatch, provider, api_key=""):
    """Переключение провайдера на время теста (env стенда не трогаем)."""
    from app.services import llm

    monkeypatch.setattr(llm.settings, "llm_provider", provider)
    monkeypatch.setattr(llm.settings, "llm_api_key", api_key)


def run_analyze(monkeypatch, provider, body, api_key=""):
    from app.services import llm

    with_provider(monkeypatch, provider, api_key)
    fake_cls = make_fake_client(body)
    monkeypatch.setattr(llm.httpx, "AsyncClient", fake_cls)
    result = asyncio.run(llm.analyze_incident({"id": 1, "title": "тест"}))
    return result, fake_cls


def openai_body(llm_result):
    """Тело ответа OpenAI-совместимого API: content в choices[0].message."""
    return {
        "choices": [{"message": {"content": json.dumps(llm_result, ensure_ascii=False)}}]
    }


def test_openai_request_format(monkeypatch):
    """Запрос к провайдеру: URL .../chat/completions, Bearer-заголовок,
    model/messages/max_tokens/temperature, без опций Ollama (num_ctx и пр.)."""
    from app.services import llm

    result, fake_cls = run_analyze(
        monkeypatch,
        "openai",
        openai_body({"verdict": "Pending", "summary": "резюме"}),
        api_key="test-token-123",
    )

    assert len(fake_cls.requests) == 1
    request = fake_cls.requests[0]
    assert request["url"] == f"{settings.ollama_url.rstrip('/')}/chat/completions"
    assert request["headers"]["Authorization"] == "Bearer test-token-123"
    payload = request["payload"]
    assert payload["model"] == settings.ollama_model
    assert payload["stream"] is False
    assert payload["max_tokens"] == settings.ollama_num_predict
    assert payload["temperature"] == settings.ollama_temperature
    assert payload["messages"][0]["role"] == "system"
    assert payload["messages"][1]["role"] == "user"
    # опции Ollama в openai-запрос не переносятся
    assert "options" not in payload
    assert "format" not in payload
    assert "keep_alive" not in payload
    # нормализация результата общая с ollama-путём
    assert result["verdict"] == "Pending"
    assert result["summary"] == "резюме"
    assert result["description"] == "резюме"


def test_openai_empty_key_sends_no_headers(monkeypatch):
    """Без llm_api_key заголовок Authorization не отправляется (локальные
    OpenAI-совместимые шлюзы без авторизации)."""
    _, fake_cls = run_analyze(
        monkeypatch, "openai", openai_body({"verdict": "Pending"}), api_key=""
    )
    assert fake_cls.requests[0]["headers"] is None


def test_openai_legacy_format_and_verdict_normalization(monkeypatch):
    """Нормализация вердикта/полей на openai-пути идентична ollama-пути."""
    result, _ = run_analyze(
        monkeypatch,
        "openai",
        openai_body({"verdict": "tp", "category": "brute_force", "confidence_percent": 85}),
    )
    assert result["verdict"] == "True Positive"
    assert result["attack_type"] == "brute_force"
    assert result["confidence"] == 0.85


def test_openai_no_choices_raises(monkeypatch):
    """Ответ без choices (например ошибка провайдера в JSON) — ValueError."""
    import pytest

    with pytest.raises(ValueError, match="no choices"):
        run_analyze(monkeypatch, "openai", {"error": {"message": "boom"}})


def test_openai_empty_content_raises(monkeypatch):
    """Пустой content у провайдера — тот же отказ, что у пустого Ollama."""
    import pytest

    with pytest.raises(ValueError, match="empty response"):
        run_analyze(monkeypatch, "openai", {"choices": [{"message": {"content": ""}}]})


def test_default_provider_is_ollama(monkeypatch):
    """Дефолтный провайдер — ollama: прежнее поведение стенда не меняется
    (URL /api/chat, format=json, options, keep_alive)."""
    from app.services import llm

    body = {"message": {"content": json.dumps({"category": "monitor"})}}
    fake_cls = make_fake_client(body)
    monkeypatch.setattr(llm.httpx, "AsyncClient", fake_cls)
    assert settings.llm_provider == "ollama"

    asyncio.run(llm.analyze_incident({"id": 2, "title": "тест"}))

    request = fake_cls.requests[0]
    assert request["url"] == f"{settings.ollama_url.rstrip('/')}/api/chat"
    assert request["payload"]["format"] == "json"
    assert "options" in request["payload"]
    assert request["headers"] is None  # ollama-путь без заголовков

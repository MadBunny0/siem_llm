"""Тонкий клиент Wazuh Manager API (stage-23).

Реальные реакции playbook (block_ip / disable_account / isolate_host)
выполняются через active response API менеджера: POST /active-response
доставляет команду кастомного AR-скрипта wazuh-агенту на ВМ актива
(доставка и исполнение — забота менеджера, см. docs/E2E_STAND.md).

Особенности:
- self-signed сертификат менеджера — verify=False (wazuh_api_verify_tls);
- JWT-аутентификация POST /security/user/authenticate (basic auth),
  токен кэшируется в экземпляре, при 401 — одна повторная аутентификация;
- поиск агента по имени актива: GET /agents?limit=500 и фильтр на клиенте
  (не полагаемся на серверный параметр agents?name — семантика фильтра
  меняется между версиями API);
- реакции verified live (Wazuh 4.7.4): **PUT /active-response?agents_list=<id>**
  с телом {"command", "arguments"} — НЕ POST с полем agents (405/400);
  учётка по умолчанию wazuh/wazuh (read-only роль включает active-response:run,
  проверено; wazuh-wui требует run_as — сложнее без пользы).

Формат аргументов PUT /active-response (Wazuh 4.7.4, verified live):
  PUT /active-response?agents_list=001  body: {"command": "block-ip",
  "arguments": ["add", "192.168.56.101"]}
Аргументы приходят скрипту на агенте как позиционные параметры (порядок
может искажаться менеджером) — AR-скрипты сканируют все аргументы,
см. wazuh/ar/*.sh.
"""

import logging

import httpx

from app.config import settings

logger = logging.getLogger("wazuh_api")


class WazuhAPIError(Exception):
    """Ошибка обращения к Wazuh Manager API (сеть/HTTP)."""

    def __init__(self, detail: str, status_code: int | None = None):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class WazuhUnreachable(WazuhAPIError):
    """Менеджер недоступен (сеть/таймаут) — HTTP-статуса нет."""


def _create_client() -> httpx.Client:
    """HTTP-клиент менеджера (отдельная функция — точка подмены в тестах
    через httpx.MockTransport)."""
    return httpx.Client(
        base_url=settings.wazuh_api_url.rstrip("/"),
        timeout=settings.wazuh_api_timeout_seconds,
        verify=settings.wazuh_api_verify_tls,
    )


class WazuhClient:
    """Клиент Wazuh Manager API с JWT-сессией одного экземпляра."""

    def __init__(self):
        self._http = _create_client()
        self._token: str | None = None

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "WazuhClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Аутентификация
    # ------------------------------------------------------------------
    def _authenticate(self) -> str:
        """POST /security/user/authenticate (basic auth) → JWT токен."""
        try:
            response = self._http.post(
                "/security/user/authenticate",
                auth=(settings.wazuh_api_user, settings.wazuh_api_password),
            )
        except httpx.HTTPError as exc:
            raise WazuhUnreachable(f"Wazuh Manager недоступен: {exc}") from exc
        if response.status_code >= 400:
            raise WazuhAPIError(
                f"Аутентификация в Wazuh API не удалась (HTTP {response.status_code})",
                status_code=response.status_code,
            )
        token = (response.json().get("data") or {}).get("token")
        if not token:
            raise WazuhAPIError("Wazuh API не вернул токен аутентификации")
        logger.debug("wazuh api: authenticated as %s", settings.wazuh_api_user)
        return token

    def _send(self, method: str, path: str, json: dict | None, params: dict | None):
        """Один запрос с Bearer-токеном; сетевая ошибка → WazuhUnreachable."""
        try:
            return self._http.request(
                method,
                path,
                json=json,
                params=params,
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            raise WazuhUnreachable(f"Wazuh Manager недоступен: {exc}") from exc

    def _request(self, method: str, path: str, json: dict | None = None, params: dict | None = None) -> dict:
        """Запрос с ре-аутентификацией: кэшированный токен, при 401 — одна
        повторная аутентификация и повтор запроса; прочие 4xx/5xx —
        WazuhAPIError с телом ответа."""
        if self._token is None:
            self._token = self._authenticate()
        response = self._send(method, path, json, params)
        if response.status_code == 401:
            logger.info("wazuh api: token rejected (401) — re-authenticating")
            self._token = self._authenticate()
            response = self._send(method, path, json, params)
        if response.status_code >= 400:
            raise WazuhAPIError(
                f"Wazuh API {method} {path} → HTTP {response.status_code}: "
                f"{response.text[:300]}",
                status_code=response.status_code,
            )
        return response.json()

    # ------------------------------------------------------------------
    # Операции
    # ------------------------------------------------------------------
    def find_agent_id(self, name: str) -> str | None:
        """id wazuh-агента по имени (= имя актива, docs/E2E_STAND.md); None —
        агент не зарегистрирован/не активен. Сервер возвращает всех агентов
        (в т.ч. never_connected) — фильтр по статусу здесь не нужен: менеджер
        сам вернёт ошибку доставки, а реестр должны видеть все агенты."""
        data = self._request("GET", "/agents", params={"limit": 500})
        items = (data.get("data") or {}).get("affected_items") or []
        for item in items:
            if item.get("name") == name:
                return str(item.get("id"))
        return None

    def active_response(self, agent_id: str, command: str, arguments: list[str]) -> dict:
        """PUT /active-response?agents_list=<id> (формат Wazuh 4.7.4, verified
        live): запуск AR-команды на агенте — доставку выполняет менеджер.
        agents_list — СТРОКОВЫЙ id агента в query-параметре."""
        payload = {
            "command": command,
            "arguments": [str(a) for a in arguments],
        }
        return self._request(
            "PUT", "/active-response", json=payload, params={"agents_list": str(agent_id)}
        )

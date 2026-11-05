from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://siem:siem@localhost:5432/siem"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    # производительность инференса (stage-18, фидбек «qwen очень долго отрабатывает»):
    # num_ctx — окно контекста (дефолт Ollama 2048 меньше нашего промпта с
    # ECS-JSON — модель теряла контекст); num_predict — потолок генерации
    # (реальный ответ укладывается, ограничивает «расползание»); keep_alive —
    # сколько держать модель в памяти после запроса (иначе каждый холодный
    # анализ платит десятки секунд за загрузку модели)
    ollama_num_ctx: int = 8192
    ollama_num_predict: int = 2048
    ollama_keep_alive: str = "30m"
    correlation_window_minutes: int = 5
    # автоматический LLM-анализ инцидентов без задержек (§3.3.3 ВКР, p:80):
    # auto_analysis — главный выключатель, auto_analysis_levels — какие уровни
    # риска анализировать автоматически (плановый режим: перечислить все уровни).
    # Stage-18 (фидбек): автоанализ и автоконвейер реагирования — ТОЛЬКО для
    # low; critical/high/medium анализирует и закрывает оператор
    auto_analysis: bool = True
    auto_analysis_levels: str = "low"
    # автоматическое закрытие инцидента (stage-17): уровни, при которых система
    # АВТОМАТИЧЕСКИ закрывает инцидент после успешного автоанализа и выполнения
    # действий («фильтр автоматического закрытия»); пустая строка — выключено
    auto_close_levels: str = "low"
    # JWT-авторизация пользователей SOC (stage-09)
    jwt_secret: str = "dev-secret-change-me-in-production"
    jwt_algorithm: str = "HS256"
    token_expire_minutes: int = 480

    # Wazuh Manager API (stage-23): активные реакции playbook (block_ip /
    # disable_account / isolate_host) уходят в PUT /active-response менеджера,
    # менеджер доставляет команду wazuh-агенту на ВМ актива (docs/E2E_STAND.md).
    # Self-signed сертификат менеджера — verify_tls=False по умолчанию.
    # Учётка wazuh/wazuh — дефолт стенда (read-only роль включает
    # active-response:run, verified live); wazuh-wui требует run_as.
    wazuh_api_url: str = "https://wazuh-manager:55000"
    wazuh_api_user: str = "wazuh"
    wazuh_api_password: str = "wazuh"
    wazuh_api_verify_tls: bool = False
    # таймаут вызова Wazuh API (сек): реакции быстрые, долгих операций нет
    wazuh_api_timeout_seconds: int = 15

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

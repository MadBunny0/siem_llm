from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://siem:siem@localhost:5432/siem"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    correlation_window_minutes: int = 5
    auto_response: bool = False
    # автоматический LLM-анализ инцидентов без задержек (§3.3.3 ВКР, p:80):
    # auto_analysis — главный выключатель, auto_analysis_levels — какие уровни
    # риска анализировать автоматически (плановый режим: перечислить все уровни).
    # Stage-17: low обрабатывается автоматически, без участия человека
    auto_analysis: bool = True
    auto_analysis_levels: str = "critical,low"
    # автоматическое закрытие инцидента (stage-17): уровни, при которых система
    # АВТОМАТИЧЕСКИ закрывает инцидент после успешного автоанализа и выполнения
    # действий («фильтр автоматического закрытия»); пустая строка — выключено
    auto_close_levels: str = "low"
    # JWT-авторизация пользователей SOC (stage-09)
    jwt_secret: str = "dev-secret-change-me-in-production"
    jwt_algorithm: str = "HS256"
    token_expire_minutes: int = 480

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

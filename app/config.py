from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://siem:siem@localhost:5432/siem"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    correlation_window_minutes: int = 5
    auto_response: bool = False
    # автоматический LLM-анализ критических инцидентов без задержек (§3.3.3 ВКР, p:80)
    auto_analysis: bool = True
    # JWT-авторизация пользователей SOC (stage-09)
    jwt_secret: str = "dev-secret-change-me-in-production"
    jwt_algorithm: str = "HS256"
    token_expire_minutes: int = 480

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

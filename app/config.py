from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://siem:siem@localhost:5432/siem"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    correlation_window_minutes: int = 5
    auto_response: bool = False

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

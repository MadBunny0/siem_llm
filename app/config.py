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
    auto_response: bool = False
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

    # Реальное исполнение ответных действий (stage-20): реестр целей —
    # агентов на виртуальных машинах наблюдаемых пользователей (docs/REAL_EXECUTION.md).
    # Формат EXECUTION_TARGETS: "name=url:token[,name=url:token…]" — имя цели
    # должно совпадать с именем актива (Asset.name), тогда инцидент по активу
    # автоматически находит цель исполнения. Пусто — реестр пуст, действия в
    # режиме real возвращают reason=no_target.
    execution_targets: str = ""
    # таймаут вызова агента (сек): действия быстрые, долгих операций нет
    execution_timeout_seconds: int = 10
    # режим по умолчанию для execute-action: simulation (dry run, как в ВКР §3.4)
    # или real (реальное исполнение на ВМ через агента)
    execution_default_mode: str = "simulation"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

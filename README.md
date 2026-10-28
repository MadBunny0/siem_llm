# SIEM + LLM — итоговый прототип

Полноценный учебно-экспериментальный стенд интеллектуальной обработки инцидентов информационной безопасности:

**Wazuh → прием события → нормализация → корреляция → оценка риска → Qwen2.5-3B → Decision Validation Engine → Playbook → Audit Log → Web-интерфейс**

Wazuh используется как базовая SIEM-система. Разрабатываемый модуль добавляет интеллектуальный анализ локальной LLM и контролируемое реагирование.

## Стек

- Python 3.12
- FastAPI
- SQLAlchemy 2
- PostgreSQL 16
- Wazuh
- Ollama
- Qwen2.5-3B (`qwen2.5:3b`)
- Docker / Docker Compose
- React + Vite
- Nginx
- VirtualBox — для виртуального экспериментального стенда с Wazuh

## Архитектура запуска

Docker Compose специально разделяет подготовку зависимостей и запуск API:

1. PostgreSQL запускается и проходит healthcheck.
2. `db-init` после готовности PostgreSQL создаёт все таблицы БД.
3. Ollama запускается и проходит healthcheck.
4. `ollama-init` загружает `qwen2.5:3b` в постоянный volume.
5. Только после успешного завершения `db-init` и `ollama-init` запускается FastAPI.
6. Только после healthcheck FastAPI запускается frontend.

При повторном запуске существующие данные PostgreSQL и скачанная модель сохраняются в Docker volumes.

## Запуск на macOS

Требуется Docker Desktop.

В папке проекта:

```bash
docker compose up --build
```

Первый запуск может занять заметное время: PostgreSQL создаёт БД, а Ollama скачивает модель Qwen2.5-3B.

После запуска:

- **Web-интерфейс:** http://localhost:3000
- **Swagger API:** http://localhost:3000/docs
- **FastAPI напрямую:** http://localhost:8000/docs
- **Health:** http://localhost:8000/api/v1/health

В веб-интерфейсе можно обновлять список инцидентов, фильтровать их, создавать тестовое событие Wazuh и запускать интеллектуальный анализ выбранного инцидента.

## Проверка через терминал

```bash
curl http://localhost:8000/api/v1/health
```

При успешном запуске ответ содержит статус БД, название LLM и режим автоматического реагирования.

Тестовое событие:

```bash
curl -X POST http://localhost:8000/api/v1/ingest/wazuh \
  -H 'Content-Type: application/json' \
  --data @sample_wazuh_alert.json
```

Получение инцидентов:

```bash
curl http://localhost:8000/api/v1/incidents
```

Анализ инцидента:

```bash
curl -X POST http://localhost:8000/api/v1/incidents/1/analyze
```

## Виртуальное окружение Python

Для локальной разработки:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Для основного запуска через Docker виртуальное окружение не требуется.

## Безопасность стенда

По умолчанию:

```text
AUTO_RESPONSE=false
```

Поэтому playbook работает в безопасном демонстрационном режиме и не выполняет реальные блокировки IP, отключение учётных записей или изоляцию узлов.

## Остановка

```bash
docker compose down
```

Данные сохраняются.

Для полного удаления данных PostgreSQL и загруженной модели:

```bash
docker compose down -v
```

Не используйте `down -v`, если хотите сохранить БД и модель.

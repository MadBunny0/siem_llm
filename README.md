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

## Структура проекта

```
siem_llm/
├── app/                  # Бэкенд: FastAPI (api/, services/, models, init_db)
├── frontend/             # React-дашборд (src/lib — хелперы, src/components — компоненты)
├── tests/                # pytest-тесты бэкенда (86, запускаются в контейнере)
├── docs/                 # DEPLOYMENT, WAZUH_INTEGRATION, DOCUMENTATION
├── samples/              # Примеры алертов Wazuh (JSON)
├── analysis/             # Рабочие материалы: gap-анализ, реестр отклонений, контекст
├── wazuh/                # Файлы интеграции с Wazuh (integrator, фрагмент ossec.conf)
├── docker-compose.yml    # Оркестрация: db → db-init → ollama → api → frontend (+adminer)
├── Dockerfile            # Бэкенд: multi-stage (base — прод, dev — +тесты)
└── requirements.txt, pytest.ini, .env.example
```

Тесты: 86 backend (pytest) + 49 frontend (Vitest + RTL) — запускаются в контейнере,
инструкции в [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), раздел 6.

---

## Запуск

> **Полная инструкция по развёртыванию «с нуля» (Windows/Linux/macOS): [DEPLOYMENT.md](docs/DEPLOYMENT.md)** —
> требования, установка Docker/WSL2, первый запуск, демо-сценарий, тесты, GPU, troubleshooting.

### Быстрый старт (macOS)

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
  --data @samples/sample_wazuh_alert.json
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

## Авторизация (stage-09)

API защищено JWT (Bearer). Открыты только `GET /health` (мониторинг) и `POST /ingest/wazuh` (интеграция с Wazuh). Демо-учётки создаются при инициализации БД:

| Пользователь | Пароль | Роль | Права |
|---|---|---|---|
| `analyst1` | `analyst123` | аналитик | чтение, LLM-анализ, смена статуса инцидента |
| `analyst2` | `analyst123` | аналитик | как у analyst1 |
| `soc_lead` | `soclead123` | администратор | + CRUD правил/playbooks, подтверждение действий на критических активах, создание пользователей |

Вход в веб-интерфейсе — через экран логина; в Swagger (`/docs`) — кнопка Authorize, вставьте `access_token` из `POST /api/v1/auth/login`.

### Плановый режим LLM-анализа (§3.3.3, p:80)

`AUTO_ANALYSIS_LEVELS` — уровни риска, анализируемые LLM **автоматически** при поступлении
события (по умолчанию `critical` — «передаются без задержек»). Для имитации планового режима
по всем уровням укажите все: `AUTO_ANALYSIS_LEVELS=low,medium,high,critical`.

Политика Decision Validation Engine (какие действия разрешены для каждого уровня риска)
хранится в БД (`validation_policy`, seed при инициализации) и доступна через
`GET /api/v1/validation-policy` (§3.4, p:103).

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"soc_lead","password":"soclead123"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl http://localhost:8000/api/v1/incidents -H "Authorization: Bearer $TOKEN"
```

Секрет подписи токена задаётся переменной `JWT_SECRET` (см. `.env.example`) — смените его для окружения, отличного от локального.

## Wazuh (§3.5 ВКР)

- **Быстрый старт** — контейнерный Wazuh-менеджер под опциональным профилем:
  `docker compose --profile wazuh up --build` (обычный `up` его не поднимает).
  Настройка интеграции — 3 команды из [WAZUH_INTEGRATION.md](docs/WAZUH_INTEGRATION.md).
- **Экспериментальный стенд** (VirtualBox: ВМ менеджера, цели с агентом и атакующего)
  для Главы 4 — топология, регистрация агента, моделирование атак и что фиксировать:
  тот же [WAZUH_INTEGRATION.md](docs/WAZUH_INTEGRATION.md).

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

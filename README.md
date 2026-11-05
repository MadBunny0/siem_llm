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
├── app/                  # Бэкенд: FastAPI
│   ├── api/              # HTTP-маршруты: routes.py — агрегатор; под-роутеры по доменам
│   │                     # (auth/ingest/incident/catalog/demo/response/system_routes.py) + common.py
│   ├── services/         # Логика конвейера (normalization, correlation, risk, llm, ...)
│   │                     # + ingest.py (приём события), auto_analysis.py (оркестрация анализа),
│   │                     # execution.py + wazuh_api.py (stage-23: реакции через Wazuh active response)
│   └── models.py, schemas.py, config.py, db.py, init_db.py, main.py
├── frontend/             # React-дашборд: src/App.jsx (логика UI), src/api.js, src/constants.js,
│                         # src/components/* (вкладки, логин), src/lib — хелперы
├── tests/                # pytest-тесты бэкенда (192, запускаются в контейнере; общие фикстуры — conftest.py)
├── docs/                 # DEPLOYMENT, WAZUH_INTEGRATION, DOCUMENTATION, CRITICALITY_MATRIX, E2E_STAND, E2E_SCENARIOS
├── samples/              # Примеры алертов Wazuh (JSON)
├── analysis/             # Рабочие материалы: gap-анализ, реестр отклонений, контекст
├── wazuh/                # Интеграция с Wazuh (integrator, setup, правила/декодеры, AR-скрипты реакций)
├── docker-compose.yml    # Оркестрация: db → db-init → ollama → api → frontend (+adminer, wazuh-manager)
├── Dockerfile            # Бэкенд: multi-stage (base — прод, dev — +тесты)
└── requirements.txt, pytest.ini, .env.example, .gitattributes
```

Тесты: 192 backend (pytest) + 124 frontend (Vitest + RTL) — запускаются в контейнере,
инструкции в [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), раздел 6.

---

## Запуск

> **Полная инструкция по развёртыванию «с нуля» (Windows/Linux/macOS): [DEPLOYMENT.md](docs/DEPLOYMENT.md)** —
> требования, установка Docker/WSL2, первый запуск, демо-сценарий, тесты, производительность LLM, troubleshooting.

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

В веб-интерфейсе можно обновлять список инцидентов, фильтровать их, запускать интеллектуальный анализ и реальные реакции playbook (Wazuh active response на ВМ актива). События поступают только с wazuh-агентов виртуальных машин — сценарии атак для оператора: [docs/E2E_SCENARIOS.md](docs/E2E_SCENARIOS.md).

## Проверка через терминал

```bash
curl http://localhost:8000/api/v1/health
```

При успешном запуске ответ содержит статус БД, название LLM и уровни автообработки.

Тестовый алерт формата Wazuh (так же шлёт интегратор менеджера):

```bash
curl -X POST http://localhost:8000/api/v1/ingest/wazuh \
  -H 'Content-Type: application/json' \
  -d '{"timestamp":"2026-11-05T10:00:00.000+0000","rule":{"level":10,"description":"sshd: authentication failed","groups":["authentication_failed"]},"agent":{"id":"001","name":"mail-prod-01"},"data":{"srcip":"192.168.56.102","dstuser":"admin"},"full_log":"Failed password for admin from 192.168.56.102 port 22 ssh2"}'
```

Получение инцидентов:

```bash
curl http://localhost:8000/api/v1/incidents
```

Анализ инцидента:

```bash
curl -X POST http://localhost:8000/api/v1/incidents/1/analyze
```

## Среда исполнения

Проект запускается и тестируется только через Docker (`docker compose up --build`,
тесты — `docker compose --profile tests run --rm tests` и `frontend-tests`,
см. `docs/DEPLOYMENT.md`). Виртуальное окружение Python (`.venv`) в репо не
используется и в git не входит.

## Реакции — только реальные (stage-23)

Режима симуляции в системе нет: события приходят только с wazuh-агентов
виртуальных машин ([E2E_STAND.md](docs/E2E_STAND.md)), а одобренные DVE реакции
playbook **по-настоящему** меняют состояние ВМ через Wazuh active response
(`iptables`-блокировка IP, `passwd -l` учётной записи, изоляция узла).
Учебный стенд — контролируемая среда: ВМ созданы для экспериментов и
восстанавливаются кнопкой «Сбросить реакции» + снапшотом гипервизора.

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

Секрет подписи токена задаётся переменной `JWT_SECRET` (см. `.env.example`) — смените его для окружения, отличного от локального. С stage-19 тюнируемые переменные сервиса api (`JWT_SECRET`, `JWT_ALGORITHM`, `TOKEN_EXPIRE_MINUTES`, `AUTO_*`, `CORRELATION_WINDOW_MINUTES`) доставляются в контейнер из `.env`; значения по умолчанию — в `docker-compose.yml`.

## Wazuh (§3.5 ВКР, stage-23)

- **Менеджер — базовый сервис compose** (поднимается обычным `docker compose up`).
  Настройка — одна идемпотентная команда:
  `docker compose exec wazuh-manager bash /wazuh-config/setup.sh` (после каждого
  recreate контейнера). Детали — [WAZUH_INTEGRATION.md](docs/WAZUH_INTEGRATION.md).
- **Реальный E2E-стенд** (VirtualBox: 2 ВМ Kali с wazuh-агентами; события идут в SIEM,
  реакции playbook — Wazuh active response — реально меняют состояние ВМ):
  инструкция — [E2E_STAND.md](docs/E2E_STAND.md), 3 сценария атак для оператора
  (SSH-брутфорс, SQLi, инсайдерский бэкдор-аккаунт) — [E2E_SCENARIOS.md](docs/E2E_SCENARIOS.md).

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

# PROJECT_CONTEXT — кэш контекста проекта siem_llm

> **Назначение файла:** восстановление полного контекста проекта в новой сессии.
> **Как использовать:** покажи этот файл ассистенту в начале новой сессии — он содержит всё необходимое:
> цель, эталон, карту кода, статус, найденные проблемы и следующие шаги.
> **Обновляй** после каждой существенной доработки (статус, ветка, закрытые пункты).

---

## 1. Суть проекта (2 строки)

Учебный прототип из ВКР: **SIEM (Wazuh) + локальная LLM (Qwen2.5-3b через Ollama)** для интеллектуальной
обработки инцидентов ИБ. Конвейер:
`Wazuh-алерт → нормализация → корреляция (правила из БД) → оценка риска → LLM-анализ → Decision Validation Engine → Playbook → Аудит → React-дашборд`.

**Эталонная документация — Глава 3 `vkr.docx`** (путь от корня: `vkr.docx`; урезанная копия текста: `vkr.txt` — использовать только если docx не читается).
Глава 4 пока **не** рассматривается.

## 2. Ключевые файлы (routing)

| Файл | Что там | Соответствие Главе 3 |
|------|---------|----------------------|
| `vkr.docx` | Текст ВКР. Глава 3 = параграфы p:1–p:142: §3.1 p:2 (архитектура, 8 модулей), §3.2 p:20 (модель данных, таблица 3.1 = t:1), §3.3 p:41 (алгоритмы; 3.3.1 нормализация p:48, 3.3.2 корреляция p:57, 3.3.3 приоритизация p:66, 3.3.4 подготовка данных LLM p:84), §3.4 p:94 (реагирование, DVE, 5 сценариев), §3.5 p:120 (стек, таблица 3.2 = t:2) | эталон |
| `analysis/GAP_ANALYSIS_CH3.md` | **Главный рабочий документ**: детальная таблица «требование → статус → код → что доработать», список багов, приоритеты P0/P1/P2 | — |
| `analysis/PROJECT_CONTEXT.md` | Этот файл | — |
| `DOCUMENTATION.md` | Самоописание проекта (этапы, таблицы БД, пайплайн) — местами устарело | — |
| `app/api/routes.py` | Все эндпоинты: `POST /api/v1/ingest/wazuh`, `GET /incidents`, `POST /incidents/{id}/analyze`, `GET /notifications`, `GET /analyses`, `GET /health` | модули 1,5,6,7 (§3.1) |
| `app/services/normalization.py` | `normalize_wazuh()` — единый шаблон Wazuh | §3.3.1 |
| `app/services/correlation.py` | правила из БД, `find_related_events`, `create_or_update_incident` | §3.3.2 |
| `app/services/risk.py` | `calculate_risk(events, p_implement)`, `score_to_severity` (low/medium/high/critical) | §3.3.3 |
| `app/services/llm.py` | `analyze_incident(context)` → Ollama `/api/chat`, JSON-ответ | §3.3.4 |
| `app/services/validation.py` | DVE: `ALLOWED_ACTIONS` по severity | §3.4 |
| `app/services/playbook.py` | playbook из БД, `ResponseAction`, `ITSMClient.create_ticket` (заглушка) | §3.4 |
| `app/services/notification.py` | `notify_analyst()` → `notification_logs` (email/slack имитация) | §3.4 |
| `app/services/audit.py` | `audit()` → `AuditLog` + лог | §3.1 (модуль 8) |
| `app/models.py` | 10 моделей: User, Event, Incident, Analysis(=LLMAnalysis), Asset, Notification, CorrelationRule, Playbook, ResponseAction, AuditLog | §3.2, таблица 3.1 — все 8 сущностей есть |
| `app/schemas.py` | Pydantic: AssetOut, NotificationOut, AnalysisOut, WazuhAlert, IncidentOut | — |
| `app/init_db.py` | `create_all` + seed: 3 пользователя, 5 активов, 2 правила корреляции, 2 playbook | — |
| `app/config.py` | Settings: DATABASE_URL, OLLAMA_URL/MODEL, CORRELATION_WINDOW_MINUTES, AUTO_RESPONSE | — |
| `app/main.py`, `app/db.py` | FastAPI app; engine/session | — |
| `frontend/src/main.jsx` | Весь UI одним файлом: статистика, лента инцидентов, фильтры, формы создания события, ручной анализ, визуализация конвейера | §3.5 (веб-интерфейс) |
| `docker-compose.yml` | db → db-init → ollama(+ollama-init) → api → frontend | §3.5 (Docker) |
| `tests/` | 30 тестов: risk(7), correlation(9), normalization(2), validation(7), playbook(2), audit(3). Нет test_llm и тестов routes | — |
| `sample_wazuh_alert.json`, `test_incident_{low,high,critical}.json` | тестовые данные | — |

## 3. Стек (совпадает с таблицей 3.2 ВКР)

Python 3.12 · FastAPI · SQLAlchemy 2 + psycopg3 · PostgreSQL 16 · Ollama + qwen2.5:3b · Docker Compose · React 19 + Vite + Nginx.
Отсутствуют в репо (по Главе 3.5 заявлены): контейнер Wazuh, стенд VirtualBox.

## 4. Статус на 2026-11-03 (после stage-07)

- **stage-07 влит в `main`** (PR #5, merge-коммит `506229a`). Ветка `stage-07-ch3-gap-fixes` удалена (локально и на GitHub).
- Git вычищен: все служебные ветки (stage-02…stage-07, hotfixes/*) удалены как полностью слитые; остались только `main` (локально и на GitHub). Remote — `siem_llm` (GitHub MadBunny0/siem_llm).
- Новые доработки ведутся от `main`; следующий этап — stage-08 (P2: тесты → UI → CRUD → Wazuh-стенд).
- **Запуск и тесты на этом ПК запрещены** (нет инструментов; Python отсутствует — синтаксическая проверка инструментами не проводилась, только вычитка). Проверка — только чтение кода.
- **Stage-07 реализован:** все P0-баги закрыты, основная часть P1 выполнена (детали — `GAP_ANALYSIS_CH3.md`, раздел 9).

### Что сделано в stage-07 (кратко)

- P0: импорт `notify_analyst`; `IncidentOut.model_validate` + `from_attributes` во всех Out-схемах; починена связь `Notification.incident`; удалён мусорный импорт; инцидент создаётся **только** при срабатывании правила корреляции (`evaluate_correlation`).
- P1: `app/services/assets.py` (resolve_asset_id по IP/агенту) → критичность актива влияет на риск; корреляция «событие-к-событию» (`match_attribute`) + порог `CorrelationRule.min_events` (+ALTER-миграция в `init_db._ensure_schema_updates`); риск-факторы «опасность типа атаки» (`ATTACK_TYPE_DANGER`) и «достоверность корреляции»; автоанализ critical в ingest (`AUTO_ANALYSIS`); DVE трёхступенчатый (политика → playbook → подтверждение админа) + endpoint `POST /incidents/{id}/confirm-action`; полный аудит этапов конвейера; контекст LLM с активом и таймлайном, реальный промпт в `Analysis.prompt`; уведомления `incident_created` / `action_pending_confirmation`; seed 5 playbook + пороги правил; toast-сообщения фронта.

### Осталось сделать (P2, не тронуто)

1. CRUD API + UI для CorrelationRule и Playbook (§3.2 p:32, §3.4 p:112).
2. UI: журнал аудита, списки анализов/уведомлений, детальная страница инцидента со событиями, смена статуса, подтверждение отложенного действия.
3. Тесты: `test_llm.py` (мок Ollama), тесты routes.py, интеграционный тест пайплайна.
4. Wazuh в docker-compose / стенд VirtualBox (§3.5).
5. (Опционально) Alembic вместо ALTER-миграций; авторизация по User-модели (сверх Главы 3).
6. Проверка запуском на ПК с Docker (`docker compose up --build`); перед этим удалить старый volume БД или положиться на `_ensure_schema_updates`.

## 5. Следующие шаги (roadmap)

1. P2 по списку выше, по приоритету: тесты → UI → CRUD → Wazuh-стенд.
2. После Главы 3 — переход к Главе 4 (реализация и эксперименты; отдельное обсуждение).

## 6. Соглашения по работе

- Язык общения и документов — русский; код и идентификаторы — английский.
- Код проекта менять **только по явному запросу** пользователя (этот файл и GAP-анализ — исключение, они созданы по запросу).
- Главу 4 ВКР пока не трогать.
- На этом ПК **не запускать** проект и **не выполнять** тесты (нет окружения).
- Эталон: `vkr.docx` Глава 3. Если docx недоступен — резерв `vkr.txt`.
- В `vkr.docx` есть артефакт на p:39 (забытый текст ИИ-ассистента) — напомнить пользователю удалить перед сдачей.
- Изменения в коде коммитить по образцу существующих: `stage-NN: <описание>` или `fix(scope): <описание>` (но только по запросу пользователя).

## 7. История обновлений файла

- 2026-11-03 — создан: первичный gap-анализ Главы 3, баги P0, roadmap.
- 2026-11-03 — stage-07: реализованы P0-фиксы и основная часть P1 (см. раздел 4); обновлён статус, roadmap сокращён до P2.

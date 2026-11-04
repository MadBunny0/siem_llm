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
| `docs/DOCUMENTATION.md` | Самоописание проекта (этапы, таблицы БД, пайплайн) — местами устарело | — |
| `app/api/routes.py` | Все эндпоинты: `POST /api/v1/ingest/wazuh`, `GET /incidents` (мультифильтры status/severity, stage-15), `POST /incidents/{id}/analyze`, `POST /incidents/{id}/execute-action` (владелец/админ, stage-15), `GET /notifications`, `GET /analyses`, `GET /health`, `POST /demo/populate` + `POST /demo/test-event` (stage-15), `GET /ingest/reference` (stage-15), `GET /assets` | модули 1,5,6,7 (§3.1) |
| `app/services/normalization.py` | `normalize_wazuh()` — единый шаблон Wazuh | §3.3.1 |
| `app/services/correlation.py` | правила из БД, `find_related_events`, `create_or_update_incident` | §3.3.2 |
| `app/services/risk.py` | `calculate_risk(events, p_implement)`, `score_to_severity` (low/medium/high/critical) | §3.3.3 |
| `app/services/llm.py` | `analyze_incident(context)` → Ollama `/api/chat`, JSON-ответ | §3.3.4 |
| `app/services/validation.py` | DVE: `ALLOWED_ACTIONS` по severity | §3.4 |
| `app/services/playbook.py` | playbook из БД, `ResponseAction`, `ITSMClient.create_ticket` (заглушка) | §3.4 |
| `app/services/notification.py` | `notify_analyst()` → `notification_logs` (email/slack имитация) | §3.4 |
| `app/services/audit.py` | `audit()` → `AuditLog` + лог | §3.1 (модуль 8) |
| `app/services/demo_events.py` | Мок-сценарии демо: `MockScenario{key,title,events}`, `build_mock_scenarios(now)` — общий пул для /demo/populate и /demo/test-event (stage-15) | — |
| `app/models.py` | 10 моделей: User, Event, Incident, Analysis(=LLMAnalysis), Asset, Notification, CorrelationRule, Playbook, ResponseAction, AuditLog | §3.2, таблица 3.1 — все 8 сущностей есть |
| `app/schemas.py` | Pydantic: AssetOut, NotificationOut, AnalysisOut, WazuhAlert, IncidentOut | — |
| `app/init_db.py` | `create_all` + seed: 3 пользователя, 5 активов, 2 правила корреляции, 2 playbook | — |
| `app/config.py` | Settings: DATABASE_URL, OLLAMA_URL/MODEL, CORRELATION_WINDOW_MINUTES, AUTO_RESPONSE | — |
| `app/main.py`, `app/db.py` | FastAPI app; engine/session | — |
| `frontend/src/main.jsx` | Весь UI одним файлом: статистика, лента инцидентов, фильтры, формы создания события, ручной анализ, визуализация конвейера | §3.5 (веб-интерфейс) |
| `docker-compose.yml` | db → db-init → ollama(+ollama-init) → api → frontend | §3.5 (Docker) |
| `tests/` | 30 тестов: risk(7), correlation(9), normalization(2), validation(7), playbook(2), audit(3). Нет test_llm и тестов routes | — |
| `samples/sample_wazuh_alert.json`, `samples/test_incident_{low,high,critical}.json` | тестовые данные | — |

## 3. Стек (совпадает с таблицей 3.2 ВКР)

Python 3.12 · FastAPI · SQLAlchemy 2 + psycopg3 · PostgreSQL 16 · Ollama + qwen2.5:3b · Docker Compose · React 19 + Vite + Nginx.
Отсутствуют в репо (по Главе 3.5 заявлены): контейнер Wazuh, стенд VirtualBox.

## 4. Статус на 2026-11-04 (после stage-15; stage-16 в ветке `stage-16-feedback-fixes`, ждёт PR)

- **stage-16 (фидбек пользователя, отложенный со stage-15): 4 бага.** Бэкенд: закрытый инцидент защищён (analyze/execute-action/confirm-action → 409, из статусов только closed→in_progress, остальное 409; админ при assign закрепляет свободный инцидент за собой, чужое владение не перехватывает). Фронтенд: dry run (mode=simulation) в тостах — успех («Действие выполнено (dry run…)»), после ручного запуска кнопка сменяется disabled «✓ Выполнено (dry run)» (метка `run_manually` в React-состоянии, сбрасывается при смене инцидента); UI закрытого инцидента блокирует анализ/действия/подтверждение, статус-кнопки — только «В работе»; в строке фильтров счётчик «Показано: N из M» + кнопка «✕ Сбросить». Тесты: 101 бэкенд (+3), 91 фронт (+5), build frontend зелёный. **Важно: баг «не вижу фильтров» — пользователь тестировал сборку stage-14; мультифильтры stage-15 в коде есть, стенду нужна пересборка `docker compose up -d --build`.**

- **stage-12/13 влиты** (PR #10/#11); **stage-14 (`stage-14-ownership-action-ux`) — запушен, ждёт PR**; **stage-15 (`stage-15-ux-logic-fixes`, стековая от stage-14) — сделан двумя параллельными сессиями, сведён ревью-сессией, закоммичен и запушен, ждёт PR**.
- **stage-15 backend** (фидбек пользователя: случайное тестовое событие, справочник для формы, мультифильтры; + сохранены правки параллельной сессии): мок-сценарии вынесены в `app/services/demo_events.py` (`MockScenario{key,title,events}`, `build_mock_scenarios(now)`; demo_populate переведён, поведение идентично); `POST /demo/test-event` — random сценарий → random событие → `_ingest_alert` → фоновый автоанализ critical как в ingest; аудит `test_event_generated`; `GET /incidents?status=&severity=` — мультивыбор через запятую (`_parse_multiselect`, 422 на недопустимое, пустой = без фильтра); `GET /ingest/reference` — справочник (rules из raw_data событий, groups из событий + условий правил корреляции, agents, assets, users, src_ips); `GET /assets`; `execute-action` — владелец инцидента или админ (`admin_confirmed=user.role=="admin"`; аналитик на критическом активе получает pending_confirmation); `playbook_steps` в execution всех режимов. Тестов 98 (+9; ревью-сессия добавила test_execute_action_permissions в test_auth.py: владелец может, чужой 403, critical-актив → pending, админ снимает).
- **stage-15 frontend:** кнопка «🎲 Тестовое событие» → `/demo/test-event` (тост называет сценарий и исход); форма «Добавить событие Wazuh»: select «Шаблон события» из `reference.rules` + datalist-подсказки на всех полях (ID правила, группы, имя/ID агента, пользователь, IP — свободный ввод сохранён, справочник грузится при открытии модалки, ошибка глотается); мультиселект-фильтры ленты — две группы чипов «Статус»/«Критичность» (пусто = все, AND между группами; чистая `applyIncidentFilters` в helpers.js); шаги playbook в результатах («Что было бы выполнено (симуляция)»); сырой JSON → `<details class="result-raw">`; тосты executionModeRu; disabled-кнопки статуса + подсказка при чужом владении (foreignOwner). Тестов 86 (+26: после ревью удалены 6 тестов мёртвых хелперов).
- **Урок stage-15:** две параллельные сессии правили одно дерево одновременно — правки ревью-сессии (random-event, EVENT_PRESETS, GET /assets, foreignOwner) сводились к фиксированным контрактам, её мёртвые после сведения экспорты (EVENT_PRESETS/applyEventPreset/buildGroupsOptions/SAMPLE_*) удалены при ревью. Две сессии на одно дерево — плохая практика: сначала остановить параллельную.
- **stage-14 backend:** `_ensure_incident_access` — владение инцидентом (analyst_id закрепляется при analyze/status; чужой аналитик 403 «закреплён за другим аналитиком»; админ — исключение); `Incident.analyst` relationship + `analyst` (id/username/role) в GET /incidents и detail; `playbook_description` в execution всех режимов (включая simulation).
- **stage-14 frontend:** result-item — одна главная кнопка по состоянию (pending → «✓ Подтвердить и выполнить» → confirm-action; approved → «▶ Выполнить: <RU>» → execute-action; blocked — только reason); панель последнего анализа восстанавливается из истории (`analysisFromHistory`, бейдж «из истории», защита от гонок detailReqRef, повторный клик по инциденту не сбрасывает панель); RU-расшифровки (ACTION_RU) в результатах, истории и playbooks; бейдж «Назначен: username» (+ «твой»).
- **Пайплайн разработки (от пользователя, обязателен):** Анализ → код → тесты → исправление → тесты → готово. Субагентам запрещены tmp-скрипты вне репо (D:\tmp чистить) и сетевые вызовы из тестов — только штатный vitest/pytest-набор; нехватку зависимостей сообщать в отчёте (добавляются в package.json/requirements).
- Урок: субагент может упасть фатально (SSL к localhost API) — его частичную работу в рабочем дереве дочищать самостоятельно по его diff; мусор за ним чистить (D:\tmp).

### stage-13 (влит, PR #11): фронтенд-тесты + реорганизация.

- **stage-13 (`stage-13-frontend-tests-restructure`, стековая от stage-12): фронтенд-тесты + реорганизация.** Из main.jsx вынесены хелперы → `frontend/src/lib/helpers.js` и PipelineStatus → `frontend/src/components/PipelineStatus.jsx` (pipelineStageStatuses + data-stage); Vitest + RTL: 49 тестов (`docker compose --profile tests run --rm frontend-tests`, node:20-alpine + volume node_modules); реорганизация: docs/ (3 дока), samples/ (JSON-алерты), ссылки обновлены, analysis/ остался в корне; package-lock.json в репо. Урок: дубль STATUS_LABELS (import vs const) поймал только производственный `vite build` на стенде.

- **stage-08/09/10/11 влиты** (PR #6–#9); **stage-12 (правки бизнес-логики, ветка `stage-12-business-logic-fixes`) — на ревью пользователя**. 
- **Деплой выполнен и живой:** 86 тестов зелёных в контейнере; стенд 6 сервисов (добавлен Adminer :8080 — веб-UI PG, логин siem/siem); демо-данные на стенде пересозданы через `POST /demo/populate` (7 инцидентов: 4 critical / 2 high / 1 low, правила распределены верно); фоновый автоанализ проверен живьём (critical → scheduled → Analysis с initiated_by=auto_analysis).
- **stage-12 содержит (по 12 пунктам фидбека пользователя):** Adminer; описание инцидента актуализируется при добавлении событий; автоанализ LLM уходит в фон (ingest мгновенный, BackgroundTasks + собственная сессия); `POST /incidents/{id}/execute-action` (admin) — ручной запуск playbook-действия; `initiated_by` (auto_analysis/manual) в response_raw + UI-бейджи; `POST /demo/populate` + кнопка «🎬 Мок-сценарии» + тестовое событие привязано к mail-prod-01; UI: шрифт 15px/адаптив (1400/1024/640), анимации и focus-visible всех кнопок, спиннеры на всех async-операциях, Pipeline по факту (closed/возврат в работу не сбрасывают этапы), блок «Роль аналитика», кнопка ▶ у результатов.
- **Тонкие места разведены:** spraying priority 3/min 5 (детерминированно перебивает brute_force; seed обновляет priority в существующих БД); `load_correlation_rules` с ORDER BY (priority↓, id) — выбор правила не зависит от произвола БД; мок-сценарии разведены по времени/активам, чтобы не склеивались (общий актив = совпадение по asset).
- **stage-11 (сверка с эталоном, ветка `stage-11-reference-alignment`):** создан **`analysis/DEVIATIONS.md` — реестр отклонений от Главы 3** (вести по мере разработки!). Реализовано: seed-правила по техникам MITRE ATT&CK (mitre.ptsecurity.com, v15.1: T1110.003 распыление паролей, T1068/T1548 повышение привилегий, T1190 web, T1204 malware, T1048 эксфильтрация — всего 7 правил); корреляция через SQL (`or_` по IP/юзеру/активу) + индексы events(timestamp, src_ip, user, asset_id); риск — честные факторы: `p_implement` из level/15 (или rule.confidence), достоверность корреляции = доля совпавших признаков (1/3…1) из `evaluate_correlation` → 3-tuple; `AUTO_ANALYSIS_LEVELS` (плановый режим, default critical); политика DVE в БД (`validation_policy` + seed + `GET /validation-policy`, `validate_recommendation(..., db=)` с fallback); перечень действий LLM — все действия проходят DVE/исполняются (ответ `results: [...]`, в response_raw тоже; compat-ключи validation/execution = первый); `Playbook.success_criteria` (JSON, seed, UI-форма). Тестов 77 (+7). Фронтенд: results-список с бейджами, pending-банер по любому результату, форма критериев. Оставлено как есть (решение пользователя): симуляция реальных действий, m2m Event↔Incident, черновик p:39 в ВКР — всё зафиксировано в DEVIATIONS.md.
- **stage-08 (P2):** тесты +27 (test_llm — мок Ollama; test_assets; test_routes — TestClient + sqlite StaticPool); CRUD `/correlation-rules` и `/playbooks` (409 при удалении используемого playbook); `GET /incidents/{id}` (events+analyses); `PATCH /incidents/{id}/status`; `GET /audit-logs`; UI — 6 вкладок, детальная карточка инцидента, смена статуса, confirm-action, CRUD-формы.
- **stage-09 (авторизация):** JWT Bearer (PyJWT HS256, `JWT_SECRET`), пароли PBKDF2-SHA256 (`app/services/security.py`), `get_current_user`/`require_admin` (`app/services/auth.py`). Открыты `/health`, `/ingest/wazuh`, `/auth/login`. Роли: analyst (чтение, анализ, смена статуса) / admin (CRUD правил/playbooks, confirm-action, register). Демо-учётки: analyst1/analyst123, analyst2/analyst123, soc_lead/soclead123 (admin). UI: AuthGate, логин-экран, 401→re-login, роль-зависимый UI. Тестов всего ~71 (test_auth.py +14; test_routes обходит auth через override).
- **⚠️ Всё проверено только статически** — Python/Node на рабочем ПК нет. Первый приоритет — проверка запуском на ПК с инструментами: `pytest`, `docker compose up --build`, `npm run build` (frontend), логин демо-учётками.
- **stage-10 (Wazuh, ветка `stage-10-wazuh-stand`):** сервис `wazuh-manager` (4.7.4) в compose под опциональным профилем `--profile wazuh`; `wazuh/integrator.sh` (JSON-алерт → открытый `/ingest/wazuh`); `wazuh/ossec-integration.xml` (level≥3); `WAZUH_INTEGRATION.md` — настройка интеграции за 3 команды + инструкция VirtualBox-стенда для Главы 4 (топология, агент с именем=активом, атаки hydra/nmap, метрики эксперимента). Этим закрыт последний пункт P2.
- **Stage-08 (P2) сделан:**
  - Тесты: +27 (test_llm — мок Ollama через фейковый httpx.AsyncClient; test_assets; test_routes — TestClient + sqlite StaticPool, патч `app.api.routes.analyze_incident`). Итого 57. **Не запускались** (Python на ПК нет).
  - Бэкенд: CRUD `/correlation-rules` и `/playbooks` (POST/PUT/DELETE, 409 при удалении playbook с response_actions); `GET /incidents/{id}` (детально: events+analyses); `PATCH /incidents/{id}/status` (new/in_progress/closed, 422 на иное); `GET /audit-logs?limit`. Схемы: EventOut, IncidentDetailOut, IncidentStatusIn, AuditLogOut, CorrelationRuleIn/Out, PlaybookIn/Out.
  - UI (main.jsx ~1580 строк, styles.css +блок): 6 вкладок (Инциденты / Анализы / Уведомления / Аудит / Правила / Playbooks); детальная карточка инцидента (таймлайн событий, история анализов, смена статуса, плашка «Требуется подтверждение» + кнопка confirm-action — проверяет и `response_raw` сохранённых анализов); CRUD-формы правил (конструктор условий eq/neq/in/like) и playbooks (чекбоксы действий, steps через JSON).
- **Осталось из P2:** Wazuh в docker-compose / стенд VirtualBox; (опционально) Alembic, авторизация. **Проверка запуском** (`pytest`, `docker compose up --build`) — на ПК с инструментами; сборка фронтенда (Node) тоже не проверялась.
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

1. **Wazuh на стенде** (по запросу): `docker compose --profile wazuh up -d` + 3 команды настройки из WAZUH_INTEGRATION.md → живые события в корреляцию.
2. **Глава 4 ВКР** — реализация и эксперименты; переход по явному запросу пользователя (демо-матрица атак в docs/WAZUH_INTEGRATION.md; VirtualBox-стенд позже).
3. UI посмотреть в браузере: http://localhost:3000 (soc_lead/soclead123) — вкладки, карточка инцидента, подтверждение действий.
4. При каждом новом этапе — актуализировать `analysis/DEVIATIONS.md` (реестр отклонений).

## 6. Соглашения по работе

- Язык общения и документов — русский; код и идентификаторы — английский.
- Код проекта менять **только по явному запросу** пользователя (этот файл и GAP-анализ — исключение, они созданы по запросу).
- Главу 4 ВКР пока не трогать.
- На этом ПК **не запускать** проект и **не выполнять** тесты (нет окружения).
- Эталон: `vkr.docx` Глава 3. Если docx недоступен — резерв `vkr.txt`.
- В `vkr.docx` есть артефакт на p:39 (забытый текст ИИ-ассистента) — напомнить пользователю удалить перед сдачей.
- Изменения в коде коммитить по образцу существующих: `stage-NN: <описание>` или `fix(scope): <описание>` (но только по запросу пользователя).

## 7. История обновлений файла

- 2026-11-04 — stage-16: фидбек (dry run как ошибка, защита закрытых инцидентов, назначение при взятии админом, заметность фильтров) закрыт; ветка stage-16-feedback-fixes; тесты 101+91.

- 2026-11-04 — stage-15: random test-event (/demo/test-event + demo_events.py), /ingest/reference + datalists/шаблон в форме, мультифильтры status/severity (API+UI-чипы), execute-action владельцу (+ тесты прав), playbook_steps, JSON под details; тесты 98+86; правки параллельной сессии сведены к контрактам, мёртвые экспорты удалены; ветка stage-15-ux-logic-fixes запушена.
- 2026-11-03 — создан: первичный gap-анализ Главы 3, баги P0, roadmap.
- 2026-11-03 — stage-07: реализованы P0-фиксы и основная часть P1 (см. раздел 4); обновлён статус, roadmap сокращён до P2.
- 2026-11-03 — stage-08: P2 выполнен (тесты, CRUD API, UI-вкладки) силами субагентов + ревью; ветка `stage-08-p2-tests-ui-crud`, ожидает PR.

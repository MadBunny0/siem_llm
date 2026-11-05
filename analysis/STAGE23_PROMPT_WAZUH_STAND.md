# ПРОМТ ДЛЯ АГЕНТА-ИСПОЛНИТЕЛЯ — stage-23 «Реальный E2E-стенд с Wazuh»

> Этот файл — рабочее задание. Оно самодостаточно: все пути, эндпоинты, сценарии и ограничения внутри.

## 0. Роль и результат

Ты — исполнитель этапа **stage-23** проекта SIEM+LLM (ВКР). Результат этапа:

1. Полностью убрана старая реализация «агентов ВМ» (stage-20/21: эмуляторы хостов, реестр `ExecutionTarget`, вкладка «Агенты (ВМ)») — **удаление явно разрешено пользователем** (см. §2).
2. Реальные реакции плейбуков через **Wazuh active response API** (block_ip → на ВМ-активе реально блокируется IP; disable_account → учётка реально блокируется; isolate_host → ВМ реально изолируется).
3. Данные идут с **настоящих wazuh-агентов**, установленных на виртуальных машинах Kali Linux, в Wazuh-менеджер (контейнер уже есть в compose) и далее через существующий интегратор в `POST /api/v1/ingest/wazuh`.
4. Готовы инструкции стенда и **3 сценария для живого человека-оператора** (он сам выполняет действия на ВМ по сценариям).
5. Документация обновлена, тесты зелёные, PR создан. **Merge — только по явной команде пользователя.**

## 1. Контекст проекта (текущее состояние)

- Репозиторий: `D:\VScodeProjects\siem_llm`, GitHub `MadBunny0/siem_llm`. Бэкенд в корне (`app/`), фронтенд в `frontend/`.
- main = merge PR #19 (stage-21). Ветка **stage-22-severity-factors** (stage-22: разбор критичности `severity_factors` в карточке инцидента) ещё не слита.
- **Перед стартом спроси пользователя**: слит ли stage-22 в main. Ветвись от `main`, если слит; иначе от кончика `stage-22-severity-factors` (stage-23 опирается на UI severity_factors). Новая ветка: `stage-23-real-wazuh-stand`.
- Пайплайн алерта: `POST /api/v1/ingest/wazuh` (открытый, без auth) → нормализация (`app/services/normalization.py`: `event_type = rule.groups[0]`) → привязка к активу (`app/services/assets.py::resolve_asset_id`: сначала `src_ip ∈ asset.ip_addresses`, иначе `agent_name == Asset.name`) → корреляция (seed-правила в `app/init_db.py:159-263`) → риск (`app/services/risk.py`) → критичность (`app/services/criticality.py`, матрица MITRE + повышения) → инцидент → LLM-анализ (Ollama qwen2.5:3b, ~1.5–2 мин на CPU) → DVE-валидация (`app/services/validation.py`: ALLOWED_ACTIONS по severity) → плейбук/реакция.
- Seed-активы (`app/init_db.py:97-148`): `mail-prod-01` (server, **critical**, DMZ, 10.20.30.10), `db-primary-01` (database, critical, без агента), `fw-edge-01` (network_device, high, без агента), `wks-finance-12` (workstation, medium, 10.20.50.12), `app-web-01` (application, high, 10.20.60.20).
- Seed-корреляции: `brute_force_attempts` (authentication_failed, 3 за 5 мин, T1110 credential_access), `password_spraying` (5/10мин), `repeated_scan` (2/10мин), `privilege_escalation_attempt` (1 событие, T1068), `web_attack` (2/5мин, T1190), `malware_detection` (1, T1204), `data_exfiltration` (1, T1048).
- Seed-пользователи UI: `soc_lead/soclead123` (admin), `analyst1/analyst123`, `analyst2/analyst123`.
- Wazuh-менеджер уже есть: `docker-compose.yml:197-214`, сервис `wazuh-manager` (образ `wazuh/wazuh-manager:4.7.4`, профиль `wazuh`, порты 1514/1515/55000, env `HOOK_URL`, volume `wazuh_data:/var/ossec/data`, маунты `./wazuh/integrator.sh` → `/var/ossec/integrator_files/custom-integration:ro` и `./wazuh/ossec-integration.xml` → `/wazuh-config/ossec-integration.xml:ro`).
- Интегратор уже написан: `wazuh/integrator.sh` (POST алерта в `$3`/`HOOK_URL` = `http://api:8000/api/v1/ingest/wazuh`), фрагмент `wazuh/ossec-integration.xml` (`<integration><name>custom-integration</name><hook_url>…</hook_url><level>3</level><alert_format>json</alert_format></integration>`). Сейчас подключается **вручную** (доки `docs/WAZUH_INTEGRATION.md:29-41`).
- Режимы исполнения: карточка инцидента переключатель «симуляция/реально» → `POST /api/v1/incidents/{id}/execute-action {action, mode}` (`app/api/incident_routes.py:260`); `mode=real` → `app/services/execution.py` → HTTP к агентам; `POST /incidents/{id}/reset-actions` (`incident_routes.py:355`) сбрасывает отметки `manual_actions` (stage-18).
- Тесты: 189 backend (`tests/` + `tests_agent/`) + 119 frontend, гоняются только в контейнерах.
- Пайплайн уведомлений/ITSM — заглушки (это норма, не трогать). Демо-форма в UI (`agent_id: '001'`) — Wazuh-ingest форма, не относится к агентам, не трогать.

## 2. Жёсткие ограничения и директивы

1. **Docker-only.** Проект и тесты — только через `docker compose`. Python на хосте — заглушка Windows Store (exit 49), не запускать.
2. **Тесты в контейнерах с пересборкой**: образ `tests` копирует код → перед прогоном `docker compose --profile tests build tests` (и `frontend-tests`).
3. **Длинные файлы — только через Write/Edit-инструменты.** Heredoc в Git Bash ломает CRLF на длинных файлах.
4. **JSON-колонки БД** (`manual_actions` и др.) — только полное переписывание dict (read-modify-write всего объекта).
5. **«Не удалять — помечать»**: артефакты не удаляются молча. ИСКЛЮЧЕНИЕ, явно авторизованное пользователем (2026-11-05, дословно: «Предыдущую реализацию агентов я хочу убрать» + подтверждено: вкладку агентов удалить совсем): список из §4 можно удалять физически. Все удаления всё равно фиксируются записями в `analysis/DEVIATIONS.md`.
6. **PR**: ассистент создаёт PR сам, когда всё готово и проверено. **Merge/вливание — только по явной команде пользователя.**
7. `gh` CLI отсутствует: PR через `git credential fill` + GitHub API; JSON через `perl JSON::PP`; ⚠ не сочетать `binmode(STDOUT,':utf8')` с `->utf8->encode` (двойная кодировка); проверять байты через `od`.
8. GPU-ускорение LLM **отклонено пользователем** — не предлагать.
9. Дерево `D:\VScodeProjects\siem_llm` может быть занято другой сессией — при конфликте работай в отдельном worktree (`git worktree add`).
10. Пользователь — человек-оператор сценариев. Всё, что человек делает руками, должно быть пошагово описано в доках.
11. Документация — на русском.

## 3. Целевая архитектура stage-23

```
[ВМ-1 Kali «mail-prod-01»]  sshd + nginx        ──wazuh-agent──┐
[ВМ-2 Kali «wks-finance-12»] АРМ пользователя   ──wazuh-agent──┤  1514
                                                               ▼
              Windows-хост, Docker Desktop:  [wazuh-manager:4.7.4]
                                             │ alerts.json → integrator (level≥3)
                                             ▼
                                     POST /api/v1/ingest/wazuh  → [api] → БД → LLM → UI
                                             ▲
              [UI: карточка инцидента, режим «Реально»] ── POST /active-response (55000)
                                             │                    │ firewall-drop / lock-account / isolate-host
                                             ▼                    ▼
                              «Реакции (ВМ)» в UI      РЕАЛЬНЫЙ эффект на ВМ (iptables/usermod)
```

- ВМ в одной сети с разными IP (VirtualBox Host-Only 192.168.56.0/24 + DHCP; хост для агентов = `192.168.56.1`; + NAT-адаптер для интернета). Требование: IP у ВМ разные, ВМ достают хост по 1514/1515/55000.
- Имя wazuh-агента = имя seed-актива → автопривязка алертов к активу.
- `db-primary-01` / `fw-edge-01` остаются без агентов → естественное демо `no_target`.
- Реакции: бэкенд вызывает Wazuh API `POST https://wazuh-manager:55000/active-response` (self-signed → `verify=False`). Кастомные AR-скрипты на агенте: `block-ip.sh`, `isolate-host.sh`, `lock-account.sh` (детерминированные, свои — не полагаться на конвенции встроенных).
- `monitor` / `collect_evidence` — пассивные отметки (как сейчас), попадают в сводку «Реакции (ВМ)».
- Undo: «Сбросить реакции» (`reset-actions`) теперь дополнительно выполняет обратные AR-действия (delete/unlock/release).

## 4. Задача A — удалить старую реализацию агентов (авторизовано)

Удалить физически:

| Что | Где |
|---|---|
| Клиент-эмулятор агента целиком | каталог `agent/` (main.py, emu_state.py, activity.py, Dockerfile, README.md) |
| Тесты агента | каталог `tests_agent/` |
| pytest-конфиг | `pytest.ini`: `testpaths = tests` (убрать `tests_agent`), `pythonpath = .` (убрать `agent`) |
| Модель и схемы реестра | `app/models.py:238-260` `ExecutionTarget`; `app/schemas.py`: `ExecutionTargetOut` (174-188), `ExecutionJournalEntry` (191-200), `ExecutionSimulateIn` (203-211) |
| Роуты реестра/прокси (все 6) | `app/api/execution_routes.py` целиком; регистрацию в `app/api/routes.py:45,64` убрать |
| Сид реестра | `app/init_db.py`: `_parse_execution_targets` (404-422), `_seed_execution_targets` (425-460), вызов в `main()` (строка 22) |
| Compose | сервисы `agent-wks`/`agent-app`/`agent-mail` (125-173), тома `agent_*_data` (216-223), env `EXECUTION_TARGETS` у `db-init` (строка 27) и у `api` (строки 88-90) |
| Фронтенд: вкладка | `frontend/src/components/TargetsView.jsx`, `TargetsView.test.jsx`; в `frontend/src/constants.js:12` запись таба `targets`; в `App.jsx:23` импорт и `App.jsx:1036-1037` рендер; мета «РЕАЛЬНОЕ ИСПОЛНЕНИЕ (STAGE-20)» в constants.js; стили `.target-*` в `frontend/src/styles.css:2320-2389` |
| Доки | `docs/REAL_EXECUTION.md` (заменяется `docs/E2E_STAND.md`), упоминания в `docs/DEPLOYMENT.md` (порты 8101-8103, EXECUTION_TARGETS, agent/ в Dockerfile targets, tests_agent), `docs/DOCUMENTATION.md` |
| Dockerfile | dev-таргет корневого `Dockerfile`: убрать копирование `agent/` |
| БД | в `app/init_db.py::_ensure_schema_updates` добавить миграцию `DROP TABLE IF EXISTS execution_targets` |

**НЕ трогать**: переключатель режимов «симуляция/реально» в карточке инцидента (`App.jsx` executionMode 44-46, 897-914, executeAction 350), `reset-actions`, `manual_actions` (stage-18), демо-форму ingest, `samples/sample_wazuh_alert.json`.

Записать в `analysis/DEVIATIONS.md` строки об удалении (по явной команде пользователя 2026-11-05, stage-23).

## 5. Задача B — Wazuh-менеджер: turnkey

Файлы в репо:

1. **`wazuh/local_rules.xml`** — кастомные правила под seed-корреляции (полный черновик — §10). Критично: наша нормализация берёт `event_type = rule.groups[0]` → первая группа должна быть семантической (`authentication_failed`, `web_attack`, `privilege_escalation`). Маунтить поверх дефолтного `/var/ossec/etc/rules/local_rules.xml` (дефолтный содержит только сэмпл 100001 — перезапись безопасна, маунт переживает recreate контейнера).
2. **`wazuh/ar/block-ip.sh`**, **`wazuh/ar/isolate-host.sh`**, **`wazuh/ar/lock-account.sh`** — код в §9.3. Маунт в `/var/ossec/active-response/bin/` (Docker Desktop Windows отдаёт exec-бит; если нет — setup.sh делает chmod).
3. **`wazuh/setup.sh`** — идемпотентный сетап внутри контейнера (запуск: `docker compose exec wazuh-manager bash /wazuh-config/setup.sh`, маунт `./wazuh/setup.sh:/wazuh-config/setup.sh:ro`):
   - chmod +x `/var/ossec/integrator_files/custom-integration` (маунт интегратора сменить с `:ro` на rw);
   - дописать блок `<integration>` из `/wazuh-config/ossec-integration.xml` в `/var/ossec/etc/ossec.conf`, если `grep -q custom-integration` не находит;
   - убедиться, что active-response включён (`<active-response><disabled>no</disabled>`, при отсутствии — дописать);
   - дописать `<command>`-блоки для `block-ip`, `isolate-host`, `lock-account` (executable = имя .sh, `<timeout_allowed>no</timeout_allowed>`) — idempotent по grep;
   - `wazuh-control restart`.
   Привязки `<active-response>` к правилам НЕ нужны (запуск через API) — но проверь эмпирически; если менеджер требует, добавь.
4. **`docker-compose.yml`**: у `wazuh-manager` убрать `profiles: [wazuh]` (базовый сервис); добавить маунты `local_rules.xml`, `./wazuh/ar/…` в `active-response/bin`, `setup.sh`; env оставшиеся. У `api` добавить env: `WAZUH_API_URL=https://wazuh-manager:55000`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`. Обновить `.env.example`.
5. **API-учётка Wazuh**: дефолтные пользователи API — `wazuh/wazuh` (read-only) и `wazuh-wui/wazuh-wui` (полный, но требует run_as). Эмпирически подбери рабочую комбинацию: проверь `GET /agents` и `POST /active-response` поочерёдно под обоими пользователями (для wazuh-wui — аутентификация с `run_as`, см. доку Wazuh 4.7 API). Если прав не хватает — через admin-API создать пользователя `siem-backend` и выдать права. Итоговую рабочую пару зафиксируй в compose/.env.example и в `docs/DEPLOYMENT.md` с примечанием, что на стенде пароли дефолтные, для «продакшена» сменить.

## 6. Задача C — бэкенд

1. **Новый `app/services/wazuh_api.py`** — тонкий клиент (httpx, `verify=False`):
   - `_token()`: `POST /security/user/authenticate` (basic auth) → JWT, кэш, re-auth на 401;
   - `find_agent_id(name)`: `GET /agents?limit=500` → фильтр по `name == asset.name` (не полагаться на серверный параметр name), вернуть `id` или None;
   - `active_response(agent_id, command, arguments)`: `POST /active-response` `{"command": ..., "arguments": [...], "agents": [agent_id]}` (формат аргументов сверь с докой 4.7.4 и проверь живьём — см. §12).
2. **Переписать `app/services/execution.py`** (сигнатуру `execute_real_action` и форму результата сохранить):
   - resolve цели: `incident.asset_id → Asset.name → find_agent_id` (нет агента → `reason="no_target"`);
   - параметры из событий (как раньше `_agent_params`: `block_ip` ← `src_ip`, `disable_account` ← `user`, `isolate_host` ← имя актива; отсутствие → `missing_parameters`);
   - соответствие действий: `block_ip` → (`block-ip`, `["add", src_ip]`, undo `["delete", src_ip]`); `disable_account` → (`lock-account`, `["lock", user]`, undo `["unlock", user]`); `isolate_host` → (`isolate-host`, `["add"]`, undo `["delete"]`);
   - `monitor`/`collect_evidence` — пассивные, без вызова API;
   - недостижимый менеджер/API-ошибка → `reason="target_unreachable"`, ответ API — в результат;
   - сохранить запись `ResponseAction` (в `metadata_json` теперь `{mode:"real", wazuh:{agent_id, agent_name, command, arguments}, context, …}`) и аудит-события `real_action_executed/failed/skipped` + новые `real_action_undone`;
   - новая функция `undo_real_action(action, target, incident)` для reset.
3. **`app/config.py`**: убрать `execution_targets`, `execution_timeout_seconds` → заменить на `wazuh_api_url`, `wazuh_api_user`, `wazuh_api_password`, `wazuh_api_verify_tls: bool = False`, `wazuh_api_timeout_seconds: int = 15`; `execution_default_mode` оставить.
4. **`reset-actions`** (`incident_routes.py:355`): перед сбросом отметок для каждой `mode=real` записи не-undo выполнить обратное AR-действие (best-effort, результаты вернуть в ответе), пометить запись `undone_at/undone_by` (JSON — полная перезапись), аудит `real_action_undone`. Серверная семантика сброса сохраняется даже при неудаче undo (ошибки — в ответ и UI).
5. **Отметки `manual_actions`**: при реальном исполнении дополнительно сохранять `target` (IP/пользователь) в записи (`{mode, at, by, target}`).
6. **Новый эндпоинт `GET /api/v1/responses/state`** — агрегат активных реальных реакций по всем инцидентам (mode=real и не undone): `[{asset, incident_id, actions: [{action, target, at, by}]}]`. Роутер зарегистрировать.
7. **`app/schemas.py`**: убрать схемы ExecutionTarget*; добавить схемы ответа `/responses/state`; в `WazuhAlert` добавить `model_config = ConfigDict(extra="allow")` (чтобы `manager.name`, `location` выживали в `raw_data`).
8. **Тесты**: `tests/test_execution.py` переписать под мок Wazuh API (httpx.MockTransport): токен, resolve по имени актива, block_ip success, no_target (актив без агента), unreachable, missing_parameters, disable_account берёт user из событий, undo при reset. `tests/test_execution_routes.py` удалить (роутов больше нет), но покрытие execute-action mode=real перенести (мок `execute_real_action`). Проверить `tests/test_routes.py` (asserts `execution.mode` для симуляции — не должны сломаться). Пассивные monitor/collect_evidence покрыть.

## 7. Задача D — фронтенд

1. Удалить вкладку `targets` и всё из §4 (фронтенд-часть).
2. **Новая вкладка «Реакции (ВМ)»** (`id: 'responses'`): компонент `frontend/src/components/ResponsesView.jsx` — грузит `GET /api/v1/responses/state` (обновление 10 с), карточки по активам: имя актива, бейджи действий (`block_ip: <IP>`, `disable_account: <user>`, `isolate_host`, `monitor`, `collect_evidence`), кем/когда. Переиспользовать существующие badge-классы; стили `.responses-*` минимальные. Удалённые `.target-*` стили убрать.
3. Карточку инцидента не менять (режимы симуляция/реально и кнопки остаются); в тостах реального режима текст про «команду на ВМ через Wazuh active response».
4. `helpers.js`: `EXECUTION_MODE_RU` оставить; добавить `RESPONSE_ACTION_RU`.
5. Тест `ResponsesView.test.jsx` (контракт полей + рендер), vite build зелёный, `frontend-tests` зелёные.

## 8. Задача E — `docs/E2E_STAND.md` (инструкция стенда)

Разделы:

1. **Состав стенда**: Windows-хост (Docker Desktop) + 2 ВМ Kali Linux Light (`https://www.kali.org/get-kali/`, образ kali-linux-light). Таблица ролей: ВМ-1 `mail-prod-01` — сервер (критичный актив): sshd + nginx + wazuh-agent; ВМ-2 `wks-finance-12` — АРМ пользователя (источник действий/атак) + wazuh-agent; опционально ВМ-3 `app-web-01`. `db-primary-01`/`fw-edge-01` — без агентов (демо `no_target`).
2. **Сеть (проще всего)**: VirtualBox, ВМ с двумя адаптерами: NAT (интернет) + Host-Only 192.168.56.0/24 c DHCP (IP у ВМ автоматически разные; хост = `192.168.56.1`). Требование: ВМ достают хост по TCP 1514/1515/55000 и 8000 (проверка: `curl http://192.168.56.1:8000/api/v1/health`). Если Windows Firewall режет — разрешить входящие на частной сети. Альтернатива — любой гипервизор/сеть, где IP разные и доступ к хосту есть; ниже всюду `<HOST_IP>` = 192.168.56.1.
3. **Подготовка ВМ-1**: `apt update && apt install -y openssh-server nginx && systemctl enable --now ssh nginx`; создать пользователя для брутфорса (`useradd -m -s /bin/bash admin && passwd admin`); обычный пользователь с sudo для оператора.
4. **Установка wazuh-agent** (обе ВМ; версия 4.7.4):
   ```
   WAZUH_MANAGER="<HOST_IP>" WAZUH_AGENT_NAME="mail-prod-01" apt install -y wazuh-agent
   systemctl daemon-reload && systemctl enable --now wazuh-agent
   ```
   (для ВМ-2 — `WAZUH_AGENT_NAME="wks-finance-12"`). Локалфайл nginx на ВМ-1 — добавить в `/var/ossec/etc/ossec.conf`:
   ```xml
   <localfile>
     <log_format>apache</log_format>
     <location>/var/log/nginx/access.log</location>
   </localfile>
   ```
   и `systemctl restart wazuh-agent`.
5. **Запуск проекта**: `docker compose up --build` (менеджер теперь базовый сервис; первый pull ~1.5 ГБ; менеджер ~0.5–1 ГБ RAM). Затем ОДИН раз: `docker compose exec wazuh-manager bash /wazuh-config/setup.sh` (и после каждого `down`/recreate контейнера менеджера — повторить).
6. **Проверка enrollment**: `docker compose exec wazuh-manager /var/ossec/bin/agent_control -l` → оба агента Active. Проверка потока: на ВМ-1 `ssh admin@localhost` с неверным паролем → `docker compose exec wazuh-manager tail -n 5 /var/ossec/logs/alerts/alerts.json` → алерт виден; через минуту в UI появляется событие (Если инцидента нет — смотри §12, чек-лист диагностики).
7. **(Опционально) привести IP активов** к реальным через Adminer (:8080): `UPDATE assets SET ip_addresses='["192.168.56.101"]' WHERE name='mail-prod-01';` — косметика + привязка по src_ip; привязка по имени агента работает и без этого.
8. Таблица портов финальная (3000, 8000, 5433, 11434, 8080, 1514, 1515, 55000) — обновить `docs/DEPLOYMENT.md`.

## 9. Задача F — `docs/E2E_SCENARIOS.md` (3 сценария — полный текст ниже, перенести с адаптацией)

Общие предусловия: стенд по §8 поднят, агенты Active, setup.sh выполнен, вход в UI http://localhost:3000 под `soc_lead/soclead123` (админ — нужен для подтверждения реакций на критичных активах). `<IP_ВМ-1>` = текущий IP ВМ-1 (`ip a`). После каждого сценария — «Сбросить реакции» и закрыть инцидент.

### Сценарий 1 — «Подбор пароля по SSH» (реакция: block_ip)

1. С ВМ-2 выполнить **3–4 неудачных** входа подряд (интервал < 5 мин): `ssh admin@<IP_ВМ-1>` — неверный пароль каждый раз.
   Альтернатива (Kali): `hydra -l admin -P /usr/share/wordlists/fasttrack.txt <IP_ВМ-1> ssh -t 4 -V` (достаточно 3–10 попыток).
2. UI: в «Событиях» — записи `authentication_failed` от агента `mail-prod-01`; появился инцидент **brute_force_attempts** (3 события за 5 мин, T1110). В карточке: severity **critical** (база high за credential_access + повышение за критичный актив — сверить с блоком «Оценка критичности», stage-22), источник — IP ВМ-2.
3. Нажать «Запустить анализ» (~1.5–2 мин на CPU) → вердикт LLM, рекомендация block_ip.
4. Переключить режим «Реально» → **block_ip** → подтвердить (критичный актив — подтверждение админа).
5. **Физическая проверка**: с ВМ-2 `ssh admin@<IP_ВМ-1>` — соединение не проходит (timeout/refused); `ping <IP_ВМ-1>` — нет ответа. На ВМ-1: `sudo iptables -L INPUT -n --line-numbers` — DROP для IP ВМ-2. На ВМ-1: `tail /var/ossec/logs/active-responses.log` — запись block-ip.
6. Undo: «Сбросить реакции» → с ВМ-2 доступ восстановлен (проверить). Закрыть инцидент.

### Сценарий 2 — «SQL-инъекция на веб-сервис» (реакция: block_ip / collect_evidence)

1. С ВМ-2 два запроса (ответ 404 — норм, логируется сам запрос):
   ```
   curl "http://<IP_ВМ-1>/index.php?id=1'%20OR%20'1'='1"
   curl "http://<IP_ВМ-1>/index.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users"
   ```
2. UI: инцидент **web_attack** (2 события web_attack за 5 мин, T1190; ожидаемо severity high: база medium за initial_access + критичный актив — сверить с «Оценкой критичности»).
3. Анализ LLM → рекомендация. Реакция «Реально» → **block_ip** (IP ВМ-2).
4. Физическая проверка: с ВМ-2 `curl -m 3 http://<IP_ВМ-1>/` — недоступен; браузер ВМ-2 тоже. Undo, закрыть.

### Сценарий 3 — «Инсайдер: бэкдор-аккаунт на сервере» (реакция: disable_account)

1. Легенда: злоумышленник получил сессию на критичном сервере ВМ-1. На **ВМ-1**:
   ```
   sudo useradd -m -s /bin/bash svc_helper
   sudo usermod -aG sudo svc_helper
   sudo passwd svc_helper
   ```
2. UI: инцидент **privilege_escalation_attempt** (1 событие privilege_escalation, T1068; severity critical: база high + критичный актив). Пометка: реакция disable_account доступна только при critical — это DVE-политика; для наглядности можно отдельно показать отказ валидации при high-инциденте.
3. Анализ LLM → рекомендация disable_account. Режим «Реально» → **disable_account** (user = svc_helper).
4. **Физическая проверка** на ВМ-1: `su svc_helper` — «authentication failure»; `sudo passwd -S svc_helper` — статус `L` (locked). Вход по ssh под svc_helper тоже закрыт.
5. Undo: «Сбросить реакции» → `passwd -S svc_helper` = `P`, вход работает. Закрыть инцидент.

К каждому сценарию приложить таблицу «для Главы 4»: правило Wazuh → событие → корреляция → severity_factors → время детекции → рекомендация LLM → реакция → время реакции → подтверждённый физический эффект.

## 10. Задача G — `wazuh/local_rules.xml` (черновик) + обязательная верификация правил

```xml
<group name="local,stand,">
  <!-- С1: неудачная аутентификация SSH. -->
  <!-- Первая группа = тип события для нашей нормализации (rule.groups[0])! -->
  <rule id="100100" level="6">
    <if_sid>5710,5711,5716</if_sid>
    <description>sshd: неудачная попытка аутентификации (стенд).</description>
  </rule>
  <!-- Fallback, если if_sid не сработает: убрать if_sid, добавить
       <regex>Failed password for|Invalid user|maximum authentication attempts exceeded</regex> -->

  <group name="web_attack,nginx,">
    <rule id="100200" level="6">
      <regex type="pcre2">(?i)(%27|')\s*(or|and|union|select)|union(\s|%20|%2B)+select|sleep\(|information_schema</regex>
      <description>nginx: SQL-инъекция в параметрах запроса.</description>
    </rule>
  </group>

  <group name="privilege_escalation,accounts,">
    <rule id="100300" level="8">
      <regex>useradd|adduser|usermod|/etc/sudoers</regex>
      <description>Изменение учётных записей: возможное повышение привилегий.</description>
    </rule>
  </group>
</group>
```

Верификация (обязательна, до PR):
1. `wazuh-logtest` для каждого правила (подать строки логов из сценариев — с ВМ или из истории auth.log/access.log).
2. Реальный прогон сценария 1 → `alerts.json`: убедиться, что у алерта `rule.groups[0] == "authentication_failed"` (порядок групп!). Если первая группа не семантическая — поправить разметку правил до такого состояния.
3. Уровень каждого правила ≥ 3 (порог интегратора).
4. Для web-правила проверить оба варианта строки (с `%27` и с literal `'`).

## 11. Задача H — остальная документация

- `docs/DEPLOYMENT.md`: убрать всё про 8101-8103/EXECUTION_TARGETS/agent/tests_agent; менеджер — базовый сервис; новая таблица портов; env `WAZUH_API_*`; шаг setup.sh; секция «Тесты» пересчитать (новые счётчики по факту); ссылка на E2E_STAND/E2E_SCENARIOS вместо REAL_EXECUTION.
- `docs/DOCUMENTATION.md`: карта файлов (нет `agent/`, есть `wazuh/` целиком), шаг 7 пайплайна = Wazuh active response, новые аудит-события, новый эндпоинт.
- `docs/WAZUH_INTEGRATION.md`: секцию «Способ 2» переписать под реальный стенд (агенты на ВМ), секцию «без Wazuh-менеджера: агент-симулятор stage-20» заменить пометкой «удалено в stage-23».
- `README.md`: команды запуска/порты/сценарии.
- `analysis/PROJECT_CONTEXT.md`: статус stage-23, карта, история.
- `analysis/DEVIATIONS.md`: строки об удалении stage-20 агентов (авторизовано), DROP таблицы, профиль wazuh → базовый сервис, дефолтные пароли API Wazuh на стенде, REAL_EXECUTION.md удалён и заменён.

## 12. Задача I — тесты и общая верификация (порядок)

1. `docker compose --profile tests build tests` → `docker compose --profile tests run --rm tests` (все зелёные; счётчики пересчитать).
2. `docker compose --profile tests build frontend-tests` → `run --rm frontend-tests` + `vite build` зелёный.
3. Правила: `wazuh-logtest` + проверка `groups[0]` по §10.
4. Smoke менеджера: `docker compose up -d wazuh-manager api` → setup.sh → API-проверки:
   - `GET /agents` под выбранной учёткой (200);
   - `POST /active-response` на тестового агента с `block-ip add 127.0.0.1`-подобными аргументами → на ВМ `iptables -L` / `active-responses.log`. **Если аргументы приходят не в ожидаемом порядке (менеджер подставляет placeholder первым) — скрипты уже сканируют все аргументы, но убедиться, что `add/delete/lock/unlock` и цель распознаны.**
5. E2E сценарий 1 — прогнать ЛИЧНО с пользователем по docs/E2E_SCENARIOS.md (он оператор). Сценарии 2–3 — по готовности пользователя; минимум сценарий 1 обязателен до PR.
6. Диагностика «алерт не дошёл»: agent_control -l (Active?) → alerts.json (алерт есть? группы?) → `docker compose logs api` / таблица events (ingest?) → correlation (`correlated: false` в ответе ingest?).

## 13. Порядок работ и PR

1. Вопросы пользователю перед стартом: stage-22 слит? дерево свободно? ВМ/гипервизор готовы?
2. Ветка `stage-23-real-wazuh-stand` (или worktree, если дерево занято).
3. Порядок: §4 удаление → §5 менеджер → §6 бэкенд → §7 фронтенд → тесты → доки → правила → стенд-инструкция → верификация → PR.
4. PR: заголовок `stage-23: реальный E2E-стенд с Wazuh (агенты на ВМ, active response, сценарии)`; создание PR — сам, когда всё зелёное и верифицировано; merge — только по команде пользователя.

## 14. Чек-лист готовности PR

- [ ] `agent/`, `tests_agent/`, execution_routes, ExecutionTarget, TargetsView, REAL_EXECUTION.md удалены; DEVIATIONS-записи есть
- [ ] `wazuh/local_rules.xml` + `wazuh/ar/*.sh` + `wazuh/setup.sh` в репо; менеджер — базовый сервис; setup.sh идемпотентен
- [ ] `execution.py` через Wazuh API; undo в reset-actions; `GET /responses/state`; `WazuhAlert extra="allow"`
- [ ] Вкладка «Реакции (ВМ)» работает; вкладки «Агенты (ВМ)» нет
- [ ] Тесты backend/frontend зелёные в контейнерах; vite build зелёный
- [ ] wazuh-logtest + groups[0] проверены; сценарий 1 прогнан с пользователем; физические эффекты подтверждены
- [ ] Доки обновлены (DEPLOYMENT, DOCUMENTATION, WAZUH_INTEGRATION, E2E_STAND, E2E_SCENARIOS, README, PROJECT_CONTEXT, DEVIATIONS)

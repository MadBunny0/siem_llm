# Развёртывание проекта (Docker-стенд)

Инструкция для развёртывания «с нуля» на чистой машине. Стенд целиком поднимается в
контейнерах; Wazuh-менеджер — базовый сервис compose (stage-23). Полный E2E-стенд
с настоящими wazuh-агентами на виртуальных машинах Kali Linux (эксперименты Главы 4,
реакции playbook на ВМ) — [E2E_STAND.md](E2E_STAND.md), сценарии атак —
[E2E_SCENARIOS.md](E2E_SCENARIOS.md).

---

## 1. Требования к машине

| Ресурс | Только контейнеры | + ВМ Kali (E2E-стенд) |
|---|---|---|
| ОС | Windows 10/11 64-bit, Linux, macOS | Windows (VirtualBox Host-Only) |
| RAM | **8 ГБ** минимум (комфортно 12+) | **16 ГБ** |
| CPU | 4+ ядра (LLM работает на CPU) | 6+ ядер |
| Диск | **20 ГБ** свободно (образ wazuh-manager ~1.5 ГБ) | **40 ГБ** (+2 ВМ Kali) |
| Интернет | нужен для первичной загрузки образов и модели LLM (~4 ГБ) | то же |

GPU не используется: `qwen2.5:3b` в Ollama работает на CPU; ускорение инференса —
раздел 7 (конфигурация без GPU).

## 2. Установка ПО (Windows; для Linux/macOS — проще, см. примечания)

### 2.1 Docker Desktop — единственная обязательная программа

1. Включить виртуализацию в BIOS/UEFI (Intel VT-x / AMD-V) — обычно включена.
2. Установить WSL2: открой PowerShell **от администратора** и выполни:
   ```powershell
   wsl --install
   ```
   Перезагрузка. (На свежих Windows 11 обычно уже установлено.)
3. Скачать и установить **Docker Desktop for Windows**: https://www.docker.com/products/docker-desktop/
   — при установке оставить выбранным «Use WSL 2 instead of Hyper-V».
4. Запустить Docker Desktop и дождаться статуса «Engine running» (зелёный индикатор слева внизу).
5. Проверка (PowerShell или терминал):
   ```bash
   docker --version          # Docker version 27.x или новее
   docker compose version    # Docker Compose version v2.x
   ```

> **Linux:** поставить `docker-ce` + плагин `docker-compose-plugin` по официальной доке,
> добавить себя в группу `docker`. **macOS:** Docker Desktop из официального сайта.

### 2.2 Git

```powershell
winget install Git.Git        # или скачать с git-scm.com
git clone https://github.com/MadBunny0/siem_llm.git
cd siem_llm
```
(Если репозиторий уже есть локально — достаточно `git pull` на `main`.)

### 2.3 Python 3.12 и Node.js — опционально

Нужны **только** для запуска автотестов и локальной сборки фронтенда (раздел 6).
Работа стенда от них не зависит — всё собирается в контейнерах.

- Python 3.12: https://www.python.org/downloads/ (при установке отметить **Add python.exe to PATH**)
- Node.js 22 LTS: https://nodejs.org/

## 3. Настройка окружения

1. **Порты** должны быть свободны: `3000` (веб-интерфейс), `8000` (API/Swagger), `5433`
   (PostgreSQL наружу), `11434` (Ollama), `8080` (Adminer — веб-UI PostgreSQL),
   `1514`/`1515` (приём событий и регистрация wazuh-агентов), `55000` (Wazuh API —
   реакции playbook и диагностика).
2. **Файл `.env`** (необязательно на старте): скопируй `.env.example` → `.env` при желании
   переопределить параметры. Ключевые переменные:

   | Переменная | По умолчанию | Смысл |
   |---|---|---|
   | `JWT_SECRET` | `dev-secret-change-me-in-production` | секрет JWT — **смени** для машины, доступной другим |
   | `JWT_ALGORITHM` | `HS256` | алгоритм подписи JWT |
   | `TOKEN_EXPIRE_MINUTES` | `480` | время жизни access-токена (минуты) |
   | `AUTO_ANALYSIS` | `true` | главный выключатель автоанализа LLM |
   | `AUTO_ANALYSIS_LEVELS` | `low` | уровни риска для автоанализа (плановый режим: `low,medium,high,critical`) |
   | `AUTO_CLOSE_LEVELS` | `low` | уровни автозакрытия после успешного автоанализа (реакции не исполняются автоматически, stage-23); пусто = выключено |
   | `CORRELATION_WINDOW_MINUTES` | `5` | окно корреляции по умолчанию |
   | `OLLAMA_MODEL` | `qwen2.5:3b` | модель интеллектуального анализа |
   | `WAZUH_API_URL` | `https://wazuh-manager:55000` | Wazuh Manager API (stage-23): реальные реакции playbook уходят в `PUT /active-response` менеджера |
   | `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | `wazuh` / `wazuh` | учётка Wazuh API. Дефолт стенда — `wazuh/wazuh`: read-only роль API включает `active-response:run` (verified live; `wazuh-wui` требует run_as). **На стенде пароли дефолтные**; для контура вне учебного стенда — сменить и/или завести отдельного пользователя API (Wazuh UI → Security) |
   | `WAZUH_API_VERIFY_TLS` | `false` | self-signed сертификат менеджера — проверка TLS выключена на стенде |
   | `WAZUH_API_TIMEOUT_SECONDS` | `15` | таймаут вызова Wazuh API при исполнении реакции |

   Все тюнируемые переменные сервиса api из таблицы выше (`JWT_SECRET`, `JWT_ALGORITHM`,
   `TOKEN_EXPIRE_MINUTES`, `AUTO_RESPONSE`, `AUTO_ANALYSIS`, `AUTO_ANALYSIS_LEVELS`,
   `AUTO_CLOSE_LEVELS`, `CORRELATION_WINDOW_MINUTES`) с stage-19 **пробрасываются в контейнер
   api из `.env`**; значения по умолчанию в `docker-compose.yml` совпадают с прежними —
   совет «смените `JWT_SECRET` в `.env`» теперь реально работает.

## 4. Запуск стенда

В папке проекта:

```bash
docker compose up --build
```

Первый запуск **15–40 минут** (зависит от канала): сборка образов API и фронтенда →
загрузка PostgreSQL и Ollama → `db-init` (схема + seed) → `ollama-init` скачивает
модель `qwen2.5:3b` (~2 ГБ) → старт API → старт фронтенда. Порядок контролируется
healthcheck'ами. Последующие запуски — минуты.

Что создаст seed при инициализации БД:

| Объект | Состав |
|---|---|
| Пользователи | `analyst1/analyst123`, `analyst2/analyst123` (аналитики), `soc_lead/soclead123` (администратор) |
| Активы | 5 шт. (`mail-prod-01`, `db-primary-01` — critical; `fw-edge-01`, `app-web-01` — high; `wks-finance-12` — medium) |
| Правила корреляции | 7 шт. по MITRE ATT&CK (T1110, T1110.003, T1046, T1068/T1548, T1190, T1204, T1048) |
| Playbooks | 5 шт. (block_ip, disable_account, isolate_host, collect_evidence, monitor) с критериями успешного завершения |
| Политика DVE | 4 уровня (validation_policy) |

### Проверка после запуска

- **Веб-интерфейс:** http://localhost:3000 → экран логина
- **Swagger API:** http://localhost:8000/docs (или http://localhost:3000/docs через nginx)
- **Adminer (веб-UI PostgreSQL):** http://localhost:8080 → Система: PostgreSQL ·
  Сервер: `db` · Пользователь: `siem` · Пароль: `siem` · База: `siem`
  (доступ с правами суперпользователя этой БД; можно смотреть/править все таблицы)
- **Health:** `curl http://localhost:8000/api/v1/health` — ответ содержит `status: ok`,
  модель и уровни автоанализа
- **Wazuh-менеджер:** `docker compose exec wazuh-manager /var/ossec/bin/wazuh-control status`
  — демоны active-response/analysisd/... запущены; `agent_control -l` — список агентов
  (пусто, пока ВМ с агентами не подключены — [E2E_STAND.md](E2E_STAND.md))

### Первое демо (важно: 1 событие ≠ инцидент)

По эталону (§3.3.2) инцидент создаётся **только при срабатывании правила корреляции**.
Seed-правило `brute_force_attempts` требует 3 события за окно. События поступают
**только с wazuh-агентов ВМ** (генераторы демо-данных удалены в stage-23):

1. Подними стенд с ВМ по [E2E_STAND.md](E2E_STAND.md) (агенты Active).
2. Войди как `soc_lead / soclead123` (или любой аналитик).
3. Выполни **сценарий 1** из [E2E_SCENARIOS.md](E2E_SCENARIOS.md): 3–4 неудачных
   входа `ssh admin@<IP_ВМ-1>` с ВМ-2 → в ленте появится инцидент
   `brute_force_attempts` (критичный актив → critical).
4. Выбери инцидент → **«✦ Запустить интеллектуальный анализ»** — увидишь вердикт
   LLM, решение DVE и блок «Все действия playbook». Запуск действия — **реальная
   реакция** на ВМ через Wazuh active response (физическую проверку см. в сценарии).
5. Инциденты уровней из `AUTO_ANALYSIS_LEVELS` (по умолчанию low) анализируются
   **автоматически в фоне** и закрываются (`AUTO_CLOSE_LEVELS`) — реакции при
   этом не исполняются автоматически.
6. Загляни во вкладки: **Правила** (7 правил MITRE), **Playbooks** (критерии
   завершения), **Аудит** (все этапы конвейера), **Анализы**, **Уведомления**,
   **Реакции (ВМ)** — и в **Adminer** (п. выше).

### Демо реальной реакции playbook (stage-23)

Полное описание стенда с ВМ — [E2E_STAND.md](E2E_STAND.md), сценарии атак для
человека-оператора — [E2E_SCENARIOS.md](E2E_SCENARIOS.md). Коротко:

1. Подними стенд с ВМ Kali по E2E_STAND (агенты `mail-prod-01`, `wks-finance-12` — Active).
2. Выполни сценарий 1 (SSH-брутфорс с ВМ-2) → в «Событиях» записи `authentication_failed`,
   инцидент `brute_force_attempts`.
3. Открой инцидент → запусти анализ → в боксе «Все действия playbook» переключи
   **режим исполнения на «Реально (Wazuh AR)»** → нажми **«▶ Блокировать IP»** —
   Wazuh Manager доставит AR-команду `block-ip` на ВМ-1, IP ВМ-2 реально заблокируется
   (проверка — `ssh`/`ping` с ВМ-2, `iptables -L INPUT -n` на ВМ-1).
4. Активные реакции видны во вкладке **«Реакции (ВМ)»**; «Сбросить реакции» в карточке
   инцидента выполняет обратные AR-команды (снятие блокировки) и возвращает ВМ
   к исходному состоянию.
5. DVE работает одинаково в обоих режимах: аналитик на критическом активе получит
   `pending_confirmation` — подтверждает soc_lead (кнопка «✓ Подтвердить и выполнить»).

## 5. Wazuh-менеджер — коротко

Базовый сервис compose (поднимается обычным `docker compose up`, профиль не нужен),
+1–2 ГБ RAM. Правила/декодеры/AR-скрипты приходят маунтами из `wazuh/`; конфигурация
менеджера — один идемпотентный шаг после старта (и после каждого recreate контейнера):

```bash
docker compose exec wazuh-manager bash /wazuh-config/setup.sh
```

Подробности интеграции — [WAZUH_INTEGRATION.md](WAZUH_INTEGRATION.md); демо-матрица
атак (hydra/curl/useradd) — [E2E_SCENARIOS.md](E2E_SCENARIOS.md).

## 6. Автотесты — только Docker, локальный Python/Node не нужны

**Бэкенд (171 тест, pytest):** тесты запечены в dev-стадию образа (Dockerfile multi-stage:
`base` — прод, `dev` — прод + тесты):

```bash
docker compose --profile tests build tests      # собрать образ с тестами
docker compose --profile tests run --rm tests   # прогнать pytest
```

Тесты самодостаточны (SQLite in-memory) — БД/Ollama/Wazuh/запущенный стенд не требуются:
вызовы Wazuh API подменяются фейком на `httpx.MockTransport`. Повторный прогон после
правок: та же команда `run` (кэш сборки обновит только слои с изменившимися файлами —
это секунды).

**Фронтенд (113 тестов, Vitest + React Testing Library):**

```bash
docker compose --profile tests run --rm frontend-tests
```

Контейнер Node монтирует `frontend/` (node_modules кэшируется в volume `frontend_node_modules`)
и гоняет `vitest run`. Покрыты чистые хелперы (`frontend/src/lib/helpers.js`) и логика
конвейера (`frontend/src/components/PipelineStatus.jsx` — рендер через RTL).

**Вариант A — локально (для разработчиков):**

Виртуальное окружение `.venv` в репо не используется и в git не входит — тесты
запускаются только в контейнерах (Docker — единственная среда исполнения проекта).
Локальный прогон возможен при отдельно установленном Python 3.12 / Node 22:

```powershell
pip install -r requirements.txt pytest
pytest

cd frontend && npm ci && npm test
```

Сборка фронтенда (проверка UI) выполняется сама при `docker compose up --build`
(в образе — `npm ci` по `package-lock.json`, воспроизводимая сборка);
вручную: `cd frontend && npm ci && npm run build`.

## 7. Производительность LLM

По умолчанию Ollama работает на CPU — инференс qwen2.5:3b на большой JSON-схеме
(stage-18) занимает 1–3 минуты на анализ. Оптимизации, встроенные в проект:

| Рычаг | Где | Что даёт |
|---|---|---|
| `OLLAMA_NUM_CTX=8192` | `.env` / compose | Дефолт Ollama **2048 меньше нашего промпта** (система ~1100 токенов + ECS-JSON) — модель теряла контекст и «сдвигала» окно. 8192 вмещает промпт целиком: качество выше, нет накладных расходов на сдвиг |
| `OLLAMA_NUM_PREDICT=2048` | `.env` / compose | Потолок генерации — защита от «расползающегося» ответа (реальный ответ укладывается) |
| `OLLAMA_KEEP_ALIVE=30m` | `.env` / compose | Модель остаётся в памяти 30 минут после запроса — повторные анализы не платят ~20–40с за загрузку с диска |
| `OLLAMA_FLASH_ATTENTION` / `OLLAMA_KV_CACHE_TYPE=q8_0` | compose (ollama) | Ускорение генерации + вдвое меньше памяти под KV-кэш |
| Обрезка контекста | `auto_analysis.py` (`_trim_ecs`) | Последние 12 событий, строки ECS до 800 символов — промпт гарантированно влезает в `num_ctx` |
| Сериализация запросов | `llm.py` (`LLM_INFERENCE_LOCK`) | CPU-модель обрабатывает запросы по одному — параллельные только трешат CPU |

Быстрая демонстрация (если скорость важнее качества): `OLLAMA_MODEL=qwen2.5:1.5b`
в compose — генерация в ~2–3 раза быстрее, качество анализа ниже.

Диагностика скорости: `docker compose exec ollama ollama run qwen2.5:3b "тест" --verbose`
показывает `eval rate` (токенов/с) и `load duration` (холодная загрузка модели).
Замер на этой конфигурации: eval rate 12.6–15 токенов/с — полный анализ занимает
~1.5–2 минуты, это предел CPU для 3B-модели (GPU-ускорение не используется).

## 8. Полезные команды

```bash
docker compose ps                  # статус сервисов
docker compose logs -f api         # логи API (Ctrl+C — выход)
docker compose logs -f wazuh-manager
docker compose stop                # остановить (данные сохраняются)
docker compose start               # продолжить
docker compose down                # остановить и убрать контейнеры (данные в volumes сохраняются)
docker compose down -v             # ⚠️ ПОЛНЫЙ СБРОС: удалит БД, модель и данные Wazuh
docker compose run --rm ollama-init  # докачать модель, если загрузка прервалась (идемпотентно)
docker compose exec wazuh-manager bash /wazuh-config/setup.sh  # настройка менеджера (после recreate)
docker compose exec wazuh-manager /var/ossec/bin/agent_control -l  # список wazuh-агентов
docker compose exec wazuh-manager tail -n 20 /var/ossec/logs/alerts/alerts.json  # последние алерты
```

## 9. Типичные проблемы

| Симптом | Причина / решение |
|---|---|
| Docker Desktop: «There was a problem with WSL… wsl.exe --version: exit status 1 (Системе не удается найти указанный путь)» | Компоненты WSL не установлены/сломаны (stub без начинки). 1) Включить виртуализацию в BIOS (Диспетчер задач → ЦП → «Виртуализация: Включено»). 2) PowerShell **от администратора**: `dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart`, `dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart`, `bcdedit /set hypervisorlaunchtype auto` → **перезагрузка**. 3) `wsl --install --no-distribution`; если `wsl.exe` снова падает — установить MSI отсюда: https://github.com/microsoft/WSL/releases → перезагрузка. 4) Проверка: `wsl --version` печатает версию |
| Docker Desktop не стартует (без явной ошибки WSL) | `wsl --update`; виртуализация выключена в BIOS |
| `wsl.exe` падает («Системе не удается найти указанный путь») **даже от администратора**, в т.ч. `wsl --install` | Битый stub/alias: 1) `where.exe wsl` — если есть `...\Microsoft\WindowsApps\wsl.exe`, удалить осиротевший пакет: `Get-AppxPackage -AllUsers MicrosoftCorporationII.WindowsSubsystemForLinux \| Remove-AppxPackage -AllUsers`; 2) установить MSI с https://github.com/microsoft/WSL/releases (заменяет stub в System32); если MSI не может заменить `wsl.exe`: `takeown /f C:\Windows\System32\wsl.exe` → `icacls ... /grant Administrators:F` → `del` → MSI; 3) ремонт системных файлов: `DISM /Online /Cleanup-Image /RestoreHealth` + `sfc /scannow`; 4) перезагрузка → `wsl --version` |
| «port is already allocated» | Занят один из портов (3000/8000/5433/11434) — освободи или поменяй левую часть маппинга в `docker-compose.yml` |
| Первый ответ LLM очень медленный | Прогрев модели после загрузки; дальше быстрее. Проверь `docker compose logs -f ollama-init` — модель скачана? |
| Анализ возвращает 503 | Ollama не готова: `docker compose ps` (healthcheck), `docker compose logs ollama` |
| Ошибки схемы БД у старого volume | Миграции `init_db` накатываются автоматически; если volume от очень старой версии — `docker compose down -v` (⚠️ удалит данные) и заново |
| В списке пусто, «правила не сработали» | Так и задумано (§3.3.2): нужно ≥3 связанных события в окне — жми «Тестовое событие» 3 раза |
| `integrator.sh: Permission denied` (Wazuh) | Exec-бит на mount с Windows: `docker compose exec wazuh-manager bash /wazuh-config/setup.sh` (шаг 1 ставит его сам) |
| Альтернативные реакции «не выполнено — Wazuh API вернул ошибку» | Менеджер не поднялся/не прошёл setup.sh; проверь `docker compose logs wazuh-manager` и повтори setup.sh. Диагностика доставки — [E2E_STAND.md](E2E_STAND.md), раздел «Диагностика» |
| Предупреждения `LF will be replaced by CRLF` при git-операциях | Безвредно (для скриптов стенда действует `.gitattributes` с `eol=lf`) |

## 10. Что дальше

- Полный E2E-стенд с ВМ Kali (агенты, реакции playbook по-настоящему) —
  установка ВМ с нуля: [E2E_VM_SETUP.md](E2E_VM_SETUP.md); стенд:
  [E2E_STAND.md](E2E_STAND.md); сценарии атак для оператора — [E2E_SCENARIOS.md](E2E_SCENARIOS.md).
- Подключение и настройка Wazuh — [WAZUH_INTEGRATION.md](WAZUH_INTEGRATION.md).
- Описание системы — [README.md](../README.md) и [DOCUMENTATION.md](DOCUMENTATION.md).

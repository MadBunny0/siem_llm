# Развёртывание проекта (Docker-стенд, без VirtualBox)

Инструкция для развёртывания «с нуля» на чистой машине. Стенд целиком поднимается в
контейнерах; VirtualBox-стенд с ВМ (для экспериментов Главы 4) — отдельная история,
см. [WAZUH_INTEGRATION.md](WAZUH_INTEGRATION.md) (раздел «Способ 2»).

---

## 1. Требования к машине

| Ресурс | Без Wazuh | С профилем Wazuh |
|---|---|---|
| ОС | Windows 10/11 64-bit, Linux, macOS | то же |
| RAM | **8 ГБ** минимум (комфортно 12+) | **16 ГБ** |
| CPU | 4+ ядра (LLM работает на CPU) | 6+ ядер |
| Диск | **15 ГБ** свободно | **20 ГБ** |
| Интернет | нужен для первичной загрузки образов и модели LLM (~4 ГБ) | то же |

GPU не обязателен: `qwen2.5:3b` в Ollama работает на CPU (секунды–десятки секунд на
анализ). Как включить GPU — см. раздел 7.

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
- Node.js 20 LTS: https://nodejs.org/

## 3. Настройка окружения

1. **Порты** должны быть свободны: `3000` (веб-интерфейс), `8000` (API/Swagger), `5433`
   (PostgreSQL наружу), `11434` (Ollama), `8080` (Adminer — веб-UI PostgreSQL), а с профилем
   Wazuh ещё `1514`, `1515`, `55000`.
2. **Файл `.env`** (необязательно на старте): скопируй `.env.example` → `.env` при желании
   переопределить параметры. Ключевые переменные:

   | Переменная | По умолчанию | Смысл |
   |---|---|---|
   | `JWT_SECRET` | `dev-secret-change-me-in-production` | секрет JWT — **смени** для машины, доступной другим |
   | `AUTO_RESPONSE` | `false` | безопасный демо-режим реагирования (симуляция) |
   | `AUTO_ANALYSIS` | `true` | главный выключатель автоанализа LLM |
   | `AUTO_ANALYSIS_LEVELS` | `critical` | уровни риска для автоанализа (плановый режим: `low,medium,high,critical`) |
   | `CORRELATION_WINDOW_MINUTES` | `5` | окно корреляции по умолчанию |
   | `OLLAMA_MODEL` | `qwen2.5:3b` | модель интеллектуального анализа |

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

### Первое демо (важно: 1 событие ≠ инцидент)

По эталону (§3.3.2) инцидент создаётся **только при срабатывании правила корреляции**.
Seed-правило `brute_force_attempts` требует 3 события за окно:

1. Войди как `soc_lead / soclead123` (или любой аналитик).
2. **Быстрый способ — кнопка «🎬 Мок-сценарии»** (видна админу): генерирует 19 событий →
   7 инцидентов всех уровней (low/medium/high/critical), разные активы и классы атак
   MITRE ATT&CK. Идеально для демонстрации системы.
3. Ручной способ: **«＋ Тестовое событие» 3 раза** — первые два ответят «правила
   корреляции не сработали» (события копятся), на третьем появится инцидент. Тестовое
   событие привязано к активу `mail-prod-01` (critical) — критичность учтётся в риске.
4. Выбери инцидент → **«✦ Запустить интеллектуальный анализ»** — увидишь рекомендацию
   LLM, решение DVE (список действий с бейджами) и режим playbook (симуляция). Админ
   может вручную запустить действие кнопкой **▶ Выполнить** на строке результата.
5. Инцидент уровня `critical` (например, событие level 15) анализируется **автоматически
   в фоне** — приём события отвечает мгновенно, анализ появится в карточке через ~1 мин
   (бейдж «авто (critical)» в истории анализов).
6. Загляни во вкладки: **Правила** (7 правил MITRE), **Playbooks** (критерии завершения),
   **Аудит** (все этапы конвейера), **Анализы**, **Уведомления**, и в **Adminer** (п. выше).

## 5. Wazuh (профиль) — коротко

+2–4 ГБ RAM. Запуск и настройка — 3 команды:

```bash
docker compose --profile wazuh up --build
```

и инструкции из [WAZUH_INTEGRATION.md](WAZUH_INTEGRATION.md) (раздел «Способ 1»).
Обычный `docker compose up` Wazuh не поднимает. Демо-матрица атак (hydra/nmap/curl) —
там же.

## 6. Автотесты — только Docker, локальный Python/Node не нужны

**Бэкенд (86 тестов, pytest):** тесты запечены в dev-стадию образа (Dockerfile multi-stage:
`base` — прод, `dev` — прод + тесты):

```bash
docker compose --profile tests build tests      # собрать образ с тестами
docker compose --profile tests run --rm tests   # прогнать pytest
```

Тесты самодостаточны (SQLite in-memory) — БД/Ollama/запущенный стенд не требуются.
Повторный прогон после правок: та же команда `run` (кэш сборки обновит только слои
с изменившимися файлами — это секунды).

**Фронтенд (49 тестов, Vitest + React Testing Library):**

```bash
docker compose --profile tests run --rm frontend-tests
```

Контейнер Node монтирует `frontend/` (node_modules кэшируется в volume `frontend_node_modules`)
и гоняет `vitest run`. Покрыты чистые хелперы (`frontend/src/lib/helpers.js`) и логика
конвейера (`frontend/src/components/PipelineStatus.jsx` — рендер через RTL).

**Вариант A — локально (для разработчиков):**

```powershell
python -m venv .venv
.venv\Scripts\activate            # Windows; в bash: source .venv/bin/activate
pip install -r requirements.txt pytest
pytest

cd frontend && npm install && npm test
```

Сборка фронтенда (проверка UI) выполняется сама при `docker compose up --build`;
вручную: `cd frontend && npm install && npm run build`.

## 7. GPU для LLM (опционально)

По умолчанию Ollama работает на CPU. Если на машине NVIDIA GPU с последним драйвером
(Docker Desktop + WSL2 пробрасывает его автоматически), можно создать
`docker-compose.gpu.yml`:

```yaml
services:
  ollama:
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

и запускать `docker compose -f docker-compose.yml -f docker-compose.gpu.yml up --build`.
Проверить, что модель видит GPU: `docker compose exec ollama ollama ps`.

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
| `integrator.sh: Permission denied` (Wazuh) | Exec-бит на mount с Windows: `docker compose --profile wazuh exec wazuh-manager chmod +x /var/ossec/integrator_files/custom-integration` |
| Предупреждения `LF will be replaced by CRLF` при git-операциях | Безвредно (Windows line endings) |

## 10. Что дальше

- Подключить реальные события Wazuh и атаки — [WAZUH_INTEGRATION.md](WAZUH_INTEGRATION.md)
  (демо-матрица: какие seed-правила чем воспроизводить).
- Стенд с виртуальными машинами (VirtualBox) для экспериментов — там же, «Способ 2».
- Описание системы — [README.md](../README.md) и [DOCUMENTATION.md](DOCUMENTATION.md).

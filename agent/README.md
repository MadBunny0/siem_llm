# Endpoint-агент ВМ наблюдаемого пользователя (stage-20)

Standalone-сервис, разворачиваемый на виртуальной машине, эмулирующей
наблюдаемого пользователя прод-инфраструктуры. Исполняет ответные действия
playbook **реально** (блокировка IP, изоляция узла, блокировка учётной записи,
карантин файла, сбор доказательств) и эмулирует активность пользователя/
атакующего — алерты в формате Wazuh отправляются в SIEM.

Полное описание архитектуры и демонстрация — [docs/REAL_EXECUTION.md](../docs/REAL_EXECUTION.md).

## Состав (переносится на ВМ как есть)

| Файл | Назначение |
|---|---|
| `main.py` | FastAPI-приложение: эндпоинты агента, Bearer-авторизация |
| `emu_state.py` | Состояние узла (учётки/процессы/фаервол/изоляция) + журнал + персистентность |
| `activity.py` | Генератор активности: сценарии → алерты Wazuh → SIEM |
| `requirements.txt` | fastapi + uvicorn (больше ничего) |

## Запуск в Docker-стенде (автоматически)

```bash
docker compose up --build   # агенты поднимаются сервисами agent-wks/agent-app/agent-mail
```

## Запуск на реальной виртуальной машине (VirtualBox/VMware/облако)

1. Скопируйте каталог `agent/` на ВМ (Ubuntu 22.04+):
   ```bash
   scp -r agent/ user@vm-ip:~/siem-agent
   ssh user@vm-ip "cd ~/siem-agent && pip install -r requirements.txt"
   ```
2. Запустите с параметрами:
   ```bash
   AGENT_HOSTNAME=mail-prod-01 \
   AGENT_TOKEN=<тот же токен, что в EXECUTION_TARGETS SIEM> \
   SIEM_URL=http://<IP_хоста>:8000/api/v1 \
   AGENT_ADAPTER=linux \
   AGENT_STATE_FILE=/home/user/siem-agent/state.json \
   uvicorn main:app --host 0.0.0.0 --port 8100
   ```
3. Зарегистрируйте цель в SIEM: `EXECUTION_TARGETS="mail-prod-01=http://<vm-ip>:8100:<токен>"`.
4. Чтобы SIEM видел события ВМ, поставьте Wazuh-агент на ту же ВМ
   (см. [WAZUH_INTEGRATION.md](../docs/WAZUH_INTEGRATION.md), «Способ 2»).

### Adapter: state vs linux

| Режим | Что происходит при действии |
|---|---|
| `state` (по умолчанию, стенд) | Меняется логическое состояние контейнера (фаервол-список, статусы учёток, изоляция). Изменение видно в `GET /agent/status` и журнале — демонстрация полная, но системных вызовов нет |
| `linux` (реальная ВМ) | Дополнительно исполняются системные команды (`iptables`, `usermod -L`, `kill`, `mv` → карантин). Требует root. Если команда недоступна — честная пометка в результате, логическое состояние всё равно меняется |

Windows-адаптер (netsh/локальные политики) **не реализован** — см. ограничения
в REAL_EXECUTION.md.

## Переменные окружения

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `AGENT_HOSTNAME` | `emu-host` | Имя узла (= имя актива SIEM для связки) |
| `AGENT_TOKEN` | пусто | Bearer-токен для мутаций (пусто = без авторизации, только отладка) |
| `AGENT_ADAPTER` | `state` | `state` — эмуляция; `linux` — реальные команды |
| `AGENT_STATE_FILE` | пусто | Файл персистентности состояния (в compose — `/data/state.json`) |
| `AGENT_PLATFORM` | `linux` | Отображаемая платформа (информационно) |
| `SIEM_URL` | `http://api:8000/api/v1` | Куда отправлять алерты активности |
| `ATTACKER_IP` | `203.0.113.66` | IP атакующего в сценариях атак |

## API (кратко)

```
GET  /agent/health          # healthcheck
GET  /agent/status          # состояние узла (открыто — для демонстрации)
GET  /agent/journal         # журнал действий SIEM (Bearer)
GET  /agent/activity        # журнал активности пользователей (Bearer)
POST /agent/action          # исполнить действие playbook (Bearer)
POST /agent/reset           # сброс состояния (Bearer)
POST /agent/simulate        # активность: normal_activity / атака (Bearer)
```

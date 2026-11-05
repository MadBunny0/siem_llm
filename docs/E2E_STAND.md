# E2E-стенд: реальные ВМ с wazuh-агентами и реакции playbook (stage-23)

Инструкция развёртывания полного учебного стенда: события идут с **настоящих
wazuh-агентов** на виртуальных машинах Kali Linux, а реакции playbook
(block_ip / disable_account / isolate_host) **по-настоящему** меняют состояние
ВМ через Wazuh active response. Симуляций в этой версии нет: данные — только
с ВМ, эффект каждой реакции проверяется физически.

Если ВМ ещё не созданы — начни с [E2E_VM_SETUP.md](E2E_VM_SETUP.md)
(установка VirtualBox и урезанных консольных ВМ Kali с нуля, шаги 1–8).

Сценарии атак для человека-оператора — [E2E_SCENARIOS.md](E2E_SCENARIOS.md).

---

## 1. Состав стенда

| Узел | Роль | Что установлено |
|---|---|---|
| Windows-хост | Docker Desktop: весь SIEM (api, db, ollama, frontend, **wazuh-manager**) + оператор | репозиторий `siem_llm` |
| **ВМ-1 Kali «mail-prod-01»** | критичный сервер (цель атак) | sshd + nginx + **wazuh-agent** + AR-скрипты |
| **ВМ-2 Kali «wks-finance-12»** | АРМ пользователя (источник действий/атак) | **wazuh-agent** + AR-скрипты, инструменты: ssh, curl, (опц.) hydra |

- Активы seed `db-primary-01` и `fw-edge-01` агентов **не имеют** — на них
  `mode real` естественно возвращает `no_target` (демо ограничения доставки).
- Опционально: ВМ-3 `app-web-01` — ещё один сервер с агентом (сценарии те же).
- Образ Kali: https://www.kali.org/get-kali/ → **kali-linux-light** (≈3 ГБ,
  1 vCPU / 2–4 ГБ RAM на ВМ достаточно).

## 2. Сеть

Проще всего — VirtualBox, каждой ВМ **два адаптера**:

1. **NAT** — интернет (установка пакетов).
2. **Host-Only** (`File → Host Network Manager → создать`; сеть `192.168.56.0/24`,
   **DHCP включён**): IP у ВМ автоматически разные, хост доступен как `192.168.56.1`.

Требования: IP у ВМ разные; ВМ достают хост по TCP **1514/1515/55000** (Wazuh) и
**8000** (API). Проверка с ВМ:

```bash
ip a                      # адрес в сети 192.168.56.x
curl http://192.168.56.1:8000/api/v1/health
```

Если Windows Firewall режет — разрешить входящие для частной сети (или точечно
порты 1514, 1515, 55000, 8000). Альтернативный гипервизор/сеть — любые, где IP
разные и хост доступен; ниже всюду `<HOST_IP>` = `192.168.56.1`.

## 3. Подготовка ВМ-1 (сервер mail-prod-01)

```bash
sudo apt update && sudo apt install -y openssh-server nginx rsyslog
sudo systemctl enable --now ssh nginx rsyslog

# пользователь-жертва для брутфорса (сценарий 1)
sudo useradd -m -s /bin/bash admin && sudo passwd admin

# обычный пользователь с sudo для оператора ВМ (создаётся при установке Kali)
ls -l /var/log/auth.log   # лог должен существовать — его читает wazuh-agent
```

nginx пишет access-лог по умолчанию (`/var/log/nginx/access.log`) — для сценария 2
агенту разрешают его читать (шаг 4).

## 4. Установка wazuh-agent 4.7.4 (обе ВМ)

Подключить репозиторий Wazuh 4.x (один раз, с интернета через NAT):

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --dearmor | sudo tee /usr/share/keyrings/wazuh.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

Установка; **имя агента = имя seed-актива** — по нему SIEM привязывает алерты
к активу и находит цель реакций:

```bash
# ВМ-1:
WAZUH_MANAGER="<HOST_IP>" WAZUH_AGENT_NAME="mail-prod-01" sudo apt install -y wazuh-agent
# ВМ-2:
WAZUH_MANAGER="<HOST_IP>" WAZUH_AGENT_NAME="wks-finance-12" sudo apt install -y wazuh-agent

sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
```

**Локалфайл nginx** (только ВМ-1): добавить в `/var/ossec/etc/ossec.conf` перед
`</ossec_config>`:

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/nginx/access.log</location>
</localfile>
```

и `sudo systemctl restart wazuh-agent`.

## 5. AR-скрипты на ВМ (обязательно, обе ВМ)

Active response исполняется **на агенте**: менеджер не рассылает кастомные
скрипты — их копируют на каждую ВМ вручную. На Windows-хосте (в каталоге репо):

```powershell
# скопировать три скрипта на ВМ (пароль оператора ВМ)
scp wazuh/ar/*.sh <user>@192.168.56.101:/tmp/
scp wazuh/ar/*.sh <user>@192.168.56.102:/tmp/
```

На каждой ВМ:

```bash
sudo install -m 750 /tmp/block-ip.sh /tmp/lock-account.sh /tmp/isolate-host.sh \
  /var/ossec/active-response/bin/
ls -l /var/ossec/active-response/bin/   # block-ip.sh lock-account.sh isolate-host.sh
```

(`install -m 750` задаёт исполнимость — bind-mount/vmshare на менеджере мог
потерять exec-бит, здесь это не важно: исполняются копии на ВМ.)

## 6. Запуск проекта и настройка менеджера

На Windows-хосте, в каталоге репозитория:

```bash
docker compose up --build        # wazuh-manager — базовый сервис (первый pull ~1.5 ГБ, ~0.5–1 ГБ RAM)
```

Затем **один раз** (и после каждого `down`/recreate контейнера менеджера —
повторить; `ossec.conf` живёт в образе, а не в томе):

```bash
docker compose exec wazuh-manager bash /wazuh-config/setup.sh
```

setup.sh идемпотентен: ставит exec-биты интегратору и AR-скриптам, дописывает в
`ossec.conf` блок `<integration>` (алерты → `POST /api/v1/ingest/wazuh`) и
объявления AR-команд `block-ip` / `isolate-host` / `lock-account`, включает
active-response, отключает cluster (standalone) и перезапускает менеджер.
Правила (`wazuh/local_rules.xml`), декодеры (`wazuh/local_decoder.xml`) и скрипты
приходят маунтом `/wazuh-config-mount` (образ копирует их в `/var/ossec` на старте
контейнера — прямые маунты в `/var/ossec/etc/**` запрещены, они ломают первую
инициализацию образа).

## 7. Проверка стенда

1. **Enrollment** (после запуска агентов на ВМ):

   ```bash
   docker compose exec wazuh-manager /var/ossec/bin/agent_control -l
   #   mail-prod-01      192.168.56.101   Active
   #   wks-finance-12    192.168.56.102   Active
   ```

2. **Поток событий**: на ВМ-1 выполнить `ssh admin@localhost` с неверным паролем,
   затем:

   ```bash
   docker compose exec wazuh-manager tail -n 5 /var/ossec/logs/alerts/alerts.json
   ```

   Алерт виден; через минуту событие появляется в UI («События» карточки
   инцидента). Правило стенда 100100 даёт `rule.groups[0] == "authentication_failed"`
   — это событие корреляция `brute_force_attempts` (3 за 5 мин) превращает в инцидент.

3. **Проверка правил** без атак (в контейнере менеджера):

   ```bash
   docker compose exec wazuh-manager /var/ossec/bin/wazuh-logtest
   # вставить: Failed password for admin from 192.168.56.102 port 51234 ssh2
   # ожидание: правило 100100, level 7, группы начинаются с authentication_failed
   ```

4. **Аутентификация Wazuh API** (используется реакциями): env `WAZUH_API_*`
   (по умолчанию `wazuh/wazuh` — read-only роль API включает
   `active-response:run`; `wazuh-wui` требует run_as, сложнее без пользы;
   для контура вне учебного стенда сменить, см. [DEPLOYMENT.md](DEPLOYMENT.md)):

   ```bash
   TOKEN=$(curl -sk -u wazuh:wazuh -X POST "https://localhost:55000/security/user/authenticate?raw=true")
   curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:55000/agents | head -c 300
   ```

   Если учётка не подходит — сменить пароль/создать пользователя в Wazuh UI
   (Security → Users) и прописать в `.env` (`WAZUH_API_USER`/`WAZUH_API_PASSWORD`).

5. **(Опционально) косметика IP активов** — Adminer (:8080):

   ```sql
   UPDATE assets SET ip_addresses='["192.168.56.101"]' WHERE name='mail-prod-01';
   UPDATE assets SET ip_addresses='["192.168.56.102"]' WHERE name='wks-finance-12';
   ```

   Привязка алертов к активам работает и без этого (по имени агента);
   обновление делает корректной привязку по `src_ip`.

## 8. Порты

| Порт | Сервис |
|---|---|
| 3000 | Frontend (UI) |
| 8000 | FastAPI (Swagger: `/docs`) |
| 5433 | PostgreSQL (наружу) |
| 11434 | Ollama |
| 8080 | Adminer (веб-UI PostgreSQL) |
| 1514 | wazuh-manager — приём событий агентов |
| 1515 | wazuh-manager — регистрация агентов (enrollment) |
| 55000 | wazuh-manager — Wazuh API (реакции + диагностика) |

## 9. Диагностика «алерт не дошёл» / «реакция не выполнилась»

| Проверка | Команда / место |
|---|---|
| Агент Active? | `docker compose exec wazuh-manager /var/ossec/bin/agent_control -l` |
| Алерт в менеджере? | `tail /var/ossec/logs/alerts/alerts.json` — есть ли `rule.groups[0]` семантический (`authentication_failed`, `web_attack`, `privilege_escalation`)? Если первый группа служебная (`syslog`/`sshd`) — сработало built-in правило, а не 100100/100200/100300: проверить `wazuh-logtest` |
| Дошло ли в SIEM? | `docker compose logs api` (POST /ingest/wazuh), таблица `events` в Adminer; в ответе ingest `correlated: false` — правило корреляции не набрало порог |
| AR-команда принята менеджером? | `docker compose exec wazuh-manager tail -n 20 /var/ossec/logs/api.log` и `alerts.json` (алерты `ossec: active response` с level 3+) |
| Скрипт выполнился на ВМ? | на ВМ: `tail /var/ossec/logs/active-responses.log` — строки `block-ip.sh:` / `lock-account.sh:` / `isolate-host.sh:` |
| Эффект на ВМ | `sudo iptables -L INPUT -n --line-numbers` (block-ip / isolate), `sudo passwd -S <user>` (lock-account) |
| Менеджер не принял реакцию (401/403)? | проверить `WAZUH_API_USER/PASSWORD` (п.7.4), `docker compose logs api` — реакции идут через `PUT /active-response?agents_list=<id>` (формат 4.7.4; `wazuh/wazuh` — read-only роль с правом AR) |
| setup.sh после recreate | `docker compose exec wazuh-manager bash /wazuh-config/setup.sh` |

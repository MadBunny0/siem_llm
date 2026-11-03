# Интеграция с Wazuh и экспериментальный стенд (§3.5 ВКР)

Wazuh — базовая SIEM-система прототипа (§3.5, p:130): собирает события с контролируемых
узлов и передаёт алерты в наш модуль. Дальше работает конвейер:
**нормализация → корреляция → риск → LLM → DVE → playbook → аудит**.

Есть два способа поднять Wazuh. Оба ведут в один эндпоинт — `POST /api/v1/ingest/wazuh`
(открытый для машинной интеграции; авторизация JWT на него сознательно не распространяется).

---

## Способ 1 (быстрый): Wazuh-менеджер в Docker — профиль `wazuh`

Обычный `docker compose up` Wazuh **не поднимает** (он тяжёлый и нужен не всегда).
Добавлен опциональный сервис под профилем:

```bash
docker compose --profile wazuh up --build
```

В составе: `wazuh/wazuh-manager:4.7.4` + том `wazuh_data` (конфигурация и алерты переживают
перезапуск). Порт 55000 — Wazuh API, 1514/1515 — агенты.

### Настройка интеграции (один раз после первого старта)

Файлы уже смонтированы в контейнер — нужно добавить фрагмент в `ossec.conf`
и сделать скрипт исполняемым:

```bash
# 1. добавить блок <integration> в конец ossec.conf
docker compose --profile wazuh exec wazuh-manager \
  bash -c "cat /wazuh-config/ossec-integration.xml >> /var/ossec/etc/ossec.conf"

# 2. права на скрипт интеграции (mount с Windows-хоста теряет exec-бит)
docker compose --profile wazuh exec wazuh-manager \
  chmod +x /var/ossec/integrator_files/custom-integration

# 3. перезапуск менеджера, чтобы integratord подхватил блок
docker compose --profile wazuh exec wazuh-manager \
  /var/ossec/bin/wazuh-control restart
```

Что делают смонтированные файлы:

| Файл | Куда смонтирован | Назначение |
|---|---|---|
| `wazuh/integrator.sh` | `/var/ossec/integrator_files/custom-integration` | скрипт интеграции: читает JSON-алерт и POST-ит его в наш API (через встроенный python менеджера) |
| `wazuh/ossec-integration.xml` | `/wazuh-config/ossec-integration.xml` | фрагмент `<integration>`: все события уровня ≥3 в формате JSON на `http://api:8000/api/v1/ingest/wazuh` |

**Проверка:** после настройки сгенерируйте событие уровня ≥3 на любом подключённом узле
(или в самом контейнере: `docker compose --profile wazuh exec wazuh-manager /var/ossec/bin/wazuh-logtest`
— либо просто дождитесь системных событий). В ленте инцидентов (или `GET /api/v1/incidents`)
должен появиться инцидент с `source` = имя агента/менеджера.

---

## Способ 2 (полный): VirtualBox-стенд для экспериментов Главы 4

Контейнерного менеджера достаточно для демонстрации конвейера. Для **экспериментальной
проверки разработанного способа** (Глава 4 ВКР: моделирование реальных атак и оценка
работоспособности) нужен стенд на виртуальных машинах — он и заявлен в таблице 3.2
(«VirtualBox — развертывание виртуальных машин для моделирования событий ИБ»).

### Топология стенда

```
VirtualBox (NAT Network "siem-stand", чтобы ВМ видели друг друга)
│
├── ВМ "wazuh-manager" (Ubuntu Server 22.04, 2 vCPU / 4 ГБ)
│     └── Wazuh all-in-one: менеджер + индексер + дашборд
│         (официальный установщик: https://documentation.wazuh.com/current/installation-guide/)
│
├── ВМ "target" (Ubuntu Desktop/Server 22.04, 1 vCPU / 2 ГБ)
│     └── Агент Wazuh, имя агента = имя актива из таблицы assets
│         (например mail-prod-01 или wks-finance-12 — тогда привязка актива
│          и учёт его критичности в риске сработают автоматически)
│
└── ВМ "attacker" (Kali Linux, 1 vCPU / 2 ГБ)
      └── инструменты моделирования атак (hydra, nmap)
```

Все ВМ в одной NAT-сети VirtualBox. Наше приложение продолжает работать в контейнерах
на хост-машине; Wazuh-менеджер стенда должен достучаться до API хоста: в блоке
`<integration>` укажите `hook_url=http://<IP_хоста>:8000/api/v1/ingest/wazuh`
(внутри NAT-сети хост доступен по адресу шлюза, обычно `10.0.2.2` для NAT VirtualBox).

### Регистрация агента (на ВМ "target")

```bash
sudo WAZUH_MANAGER="<IP_менеджера>" WAZUH_AGENT_NAME="mail-prod-01" \
  apt install wazuh-agent     # после подключения репозитория Wazuh 4.x
sudo systemctl enable --now wazuh-agent
```

### Моделирование атак (с ВМ "attacker")

| Атака | Команда (пример) | Что должно произойти в системе |
|---|---|---|
| Подбор пароля SSH | `hydra -l root -P /usr/share/wordlists/rockyou.txt <IP_target> ssh -t 4` | правило 5710/5712 (`authentication_failed`), после 3 событий за окно — инцидент `brute_force_attempts`, высокий риск |
| Сетевое сканирование | `nmap -sS <IP_target>` | события `syslog`/`sshd` с одного IP → правило `repeated_scan` |
| Множественные неудачные входы | `for u in root admin test; do ssh $u@<IP_target>; done` | серия `authentication_failed` → инцидент |

### Что фиксировать в эксперименте (для Главы 4)

- время от события до инцидента (`audit_logs`: `event_ingested` → `incident_created_or_updated`);
- рассчитанный риск и severity для активов разной критичности (проверка фактора актива);
- вывод LLM (attack_type, confidence) и решение DVE;
- содержимое `analyses` / `audit-logs` — как статистика качества интеллектуального модуля
  (снимки через `GET /api/v1/analyses` и `GET /api/v1/audit-logs`).

---

## Поток данных (оба способа)

```
[ВМ/контейнер] Wazuh-менеджер (integratord, level>=3, JSON)
      │  POST /api/v1/ingest/wazuh (открытый эндпоинт интеграции)
      ▼
наш API: нормализация → привязка актива (по IP/имени агента)
      → корреляция по правилам БД → риск → [critical: авто-LLM] → DVE → playbook → аудит
```

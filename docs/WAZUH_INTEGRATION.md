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

## Демо-матрица: seed-правила корреляции ↔ техники MITRE ATT&CK ↔ стенд

Seed-правила сопоставляются с **всем набором групп** алерта Wazuh (реальные алерты несут
служебные теги вперёд: `["syslog", "sshd", "authentication_failed"]`), поэтому срабатывают
на настоящих событиях, а не только на ручных тестовых.

| Seed-правило (порог) | Техника MITRE | Wazuh-правила (примеры) | Как воспроизвести на стенде | Из коробки? |
|---|---|---|---|---|
| `brute_force_attempts` (3 за 5 мин) | T1110 Метод перебора | 5710, 5712, 5716 (sshd), 5503 (PAM) | `hydra -l root -P rockyou.txt <IP_target> ssh -t 4` либо серия `ssh root@<IP>` с неверным паролем | ✅ |
| `password_spraying` (4 за 10 мин) | T1110.003 Распыление паролей | те же (много разных `dstuser` с одного `srcip`) | `hydra -L users.txt -p Password1 <IP_target> ssh` | ✅ |
| `repeated_scan` (2 за 10 мин) | T1046 Изучение сетевых служб | 5722 «sshd: Possible attack…», любые события с `srcip` | `nmap -sT <IP_target>` | ✅ |
| `web_attack` (2 за 5 мин) | T1190 Недостатки в общедоступном приложении | 31100–31151 (Apache/nginx: sqlinjection, xss; группы `web,attack`) | `curl "http://<IP_target>/index.php?id=1' OR '1'='1"` ×2 (агент читает access-лог) | ✅ (нужен агент с чтением access-лога) |
| `privilege_escalation_attempt` (1) | T1068 / T1548 Повышение привилегий | группы `privilege_escalation` — по умолчанию редки; добавьте кастомное правило (ниже) | изменить `/etc/sudoers` или добавить пользователя в группу sudo | ⚙️ кастомное правило |
| `malware_detection` (1) | T1204 Вредоносное ПО | ClamAV (52500+) / VirusTotal (553, 554) | EICAR-файл на цели + ClamAV/VT-интеграция | ⚙️ интеграция |
| `data_exfiltration` (1) | T1048 Эксфильтрация | IDS (Suricata) — правила exfil-класса | объёмный исходящий трафик на нестандартный порт | ⚙️ IDS (Suricata) |

Пример кастомного правила для `privilege_escalation_attempt` (на менеджере в
`/var/ossec/etc/rules/local_rules.xml`) — это одновременно демонстрация требования
§3.3.2 (p:61): «перечень правил может быть дополнен без изменения программного кода»:

```xml
<group name="privilege_escalation,">
  <rule id="100500" level="8">
    <match>added to group sudo|/etc/sudoers|usermod</match>
    <description>Изменение привилегий: пользователь добавлен в sudo / изменён sudoers</description>
  </rule>
</group>
```

Для правил ⚙️ можно также добавить условия через `POST /api/v1/correlation-rules` (CRUD,
stage-08) — без правки кода системы.

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
| Подбор пароля SSH | `hydra -l root -P /usr/share/wordlists/rockyou.txt <IP_target> ssh -t 4` | правило 5710/5712 (`authentication_failed`) → seed-правило `brute_force_attempts` (3 за 5 мин) → инцидент, высокий риск; LLM рекомендует `block_ip`; на критическом активе — подтверждение админа |
| Распыление паролей | `hydra -L users.txt -p Password1 <IP_target> ssh` | серия с разными `dstuser` → seed-правило `password_spraying` (T1110.003) |
| Сетевое сканирование | `nmap -sT <IP_target>` | события с одного IP → seed-правило `repeated_scan` (T1046) |
| Веб-атака | `curl "http://<IP_target>/index.php?id=1' OR '1'='1"` ×2 | группы `web,attack` → seed-правило `web_attack` (T1190) |
| Повышение привилегий | `sudo usermod -aG sudo testuser` на цели (+ кастомное правило Wazuh из демо-матрицы) | группа `privilege_escalation` → seed-правило `privilege_escalation_attempt` (T1068/T1548) |

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

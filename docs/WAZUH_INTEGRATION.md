# Интеграция с Wazuh и реальный E2E-стенд (§3.5 ВКР, stage-23)

Wazuh — базовая SIEM-система прототипа (§3.5, p:130): собирает события с контролируемых
узлов и передаёт алерты в наш модуль. Дальше работает конвейер:
**нормализация → корреляция → риск → LLM → DVE → playbook → аудит**.

С stage-23 Wazuh-менеджер — **базовый сервис compose** (поднимается обычным
`docker compose up`, профиль не нужен), а события приходят с **настоящих wazuh-агентов**,
установленных на виртуальных машинах Kali Linux. Оба направления ведут в один эндпоинт —
`POST /api/v1/ingest/wazuh` (открытый для машинной интеграции; авторизация JWT на него
сознательно не распространяется), а реакции playbook идут **обратно** — через Wazuh API
(`POST /active-response`, порт 55000) на те же ВМ.

> Пошаговая инструкция стенда с ВМ — [E2E_STAND.md](E2E_STAND.md);
> сценарии атак для человека-оператора — [E2E_SCENARIOS.md](E2E_SCENARIOS.md).

---

## Состав интеграции (файлы репо, монтируются в контейнер менеджера)

Все кастомизации монтируются ТОЛЬКО в `/wazuh-config-mount` — штатный механизм
образа: на старте контейнера его содержимое копируется в `/var/ossec` с
сохранением путей. Прямые маунты файлов в `/var/ossec/etc/**` запрещены:
непустой `/var/ossec/etc` на первом старте ломает инициализацию образа
(менеджер остаётся без `ossec.conf` — все демоны не стартуют).

| Файл | Куда смонтирован | Куда попадает в контейнере | Назначение |
|---|---|---|---|
| `wazuh/integrator.sh` | `/wazuh-config-mount/integrations/custom-integration` | `/var/ossec/integrations/custom-integration` | скрипт интеграции (НАСТОЯЩИЙ каталог интеграций Wazuh): читает JSON-алерт и POST-ит его в наш API |
| `wazuh/local_rules.xml` | `/wazuh-config-mount/etc/rules/local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` | правила стенда: 100100/100101 (SSH-неудачки), 100200/100201 (SQLi), 100300/100301/100302 (useradd/usermod/passwd) — первая группа = event_type |
| `wazuh/local_decoder.xml` | `/wazuh-config-mount/etc/decoders/local_decoder.xml` | `/var/ossec/etc/decoders/local_decoder.xml` | декодеры: имя учётной записи из useradd/usermod/passwd → `dstuser` (цель реакции disable_account) |
| `wazuh/ar/*.sh` | `/wazuh-config-mount/active-response/bin/` | `/var/ossec/active-response/bin/` | AR-скрипты (копия менеджера; **исполняются на агентах** — на ВМ ставятся вручную, E2E_STAND шаг 5) |
| `wazuh/ossec-integration.xml`, `wazuh/setup.sh` | `/wazuh-config/…` (вне mount-копирования) | — | фрагмент `<integration>` и идемпотентный setup |

## Настройка менеджера — один идемпотентный шаг

```bash
docker compose exec wazuh-manager bash /wazuh-config/setup.sh
```

Скрипт: ставит exec-биты интегратору и AR-скриптам (копия из mount теряет права),
дописывает блок `<integration>` и `<command>`-объявления реакций в `ossec.conf`,
включает active-response, отключает cluster (standalone: без ключа clusterd
падает с Configuration error) и перезапускает менеджер. Повторять **после
каждого recreate контейнера** (`down`/`up`): правки `ossec.conf` живут в
контейнере, не в томе.

Кастомные правила гарантируют, что первая группа алерта (`rule.groups[0]`) семантическая
(`authentication_failed` / `web_attack` / `privilege_escalation`) — именно её берёт
нормализация SIEM (`app/services/normalization.py`). У built-in правил первой группой
служебная (`syslog`, `sshd`, …), поэтому правила стенда сделаны ДОЧЕРНИМИ к built-in
(if_sid 5710/5711/5716, 31164/31103, 5902) — ребёнок подменяет алерт родителя нашими
группами; анализd берёт первое совпадение по порядку загрузки, уровень приоритета не
задаёт. Проверено live через wazuh-logtest.

## Направление 1: события — агенты → менеджер → SIEM

```
[ВМ Kali «mail-prod-01»]  wazuh-agent (sshd, nginx, auth.log)  ──1514──┐
[ВМ Kali «wks-finance-12»] wazuh-agent                                  ▼
                                          [wazuh-manager:4.7.4]
                                          │ alerts.json → integrator (level ≥ 3)
                                          ▼
                          POST /api/v1/ingest/wazuh → нормализация (event_type =
                          rule.groups[0]) → привязка актива (имя агента = имя
                          актива) → корреляция → риск → критичность → инцидент
```

Регистрация агента на ВМ (после подключения репозитория Wazuh 4.7.4):

```bash
WAZUH_MANAGER="<HOST_IP>" WAZUH_AGENT_NAME="mail-prod-01" apt install -y wazuh-agent
systemctl enable --now wazuh-agent
```

**Имя агента = имя seed-актива** — привязка алертов к активу срабатывает автоматически
(`app/services/assets.py::resolve_asset_id`), критичность актива учитывается в риске и
критичности. Проверка доставки: `docker compose exec wazuh-manager tail -n 5
/var/ossec/logs/alerts/alerts.json` — событие видно в менеджере; через минуту оно в
ленте «События» UI. Если нет — чек-лист диагностики в [E2E_STAND.md](E2E_STAND.md).

## Направление 2: реакции — SIEM → Wazuh API → агент → ВМ

Реальный режим playbook (`mode=real`) вызывает Wazuh API менеджера:

| Действие playbook | AR-команда (ossec.conf) | Скрипт на ВМ | Реальный эффект | Откат («Сбросить реакции») |
|---|---|---|---|---|
| `block_ip` | `block-ip` | `block-ip.sh` | `iptables INPUT/OUTPUT DROP` для IP источника | `delete` — снятие правил |
| `disable_account` | `lock-account` | `lock-account.sh` | `passwd -l` учётной записи | `unlock` — `passwd -u` |
| `isolate_host` | `isolate-host` | `isolate-host.sh` | изоляция узла (цепочка `SIEM_ISOLATE`, кроме loopback/established/1514-1515) | `delete` — снятие изоляции |
| `monitor`, `collect_evidence` | — | — | пассивные отметки, без вызова Wazuh API | отметка снимается со сводки |

Активные реакции видны во вкладке **«Реакции (ВМ)»** (`GET /api/v1/responses/state`);
«Сбросить реакции» в карточке инцидента выполняет обратные AR-команды (best-effort) и
помечает записи отменёнными. Цели доставки менеджер находит по **имени агента = имени
актива**; активы `db-primary-01` / `fw-edge-01` агентов не имеют — на них `mode=real`
возвращает `no_target` (естественное демо ограничения).

Учётная запись Wazuh API задаётся env `WAZUH_API_*` (по умолчанию `wazuh/wazuh` —
read-only роль API включает `active-response:run`, verified live; `wazuh-wui`
требует run_as; для контура вне учебного стенда сменить, см. [DEPLOYMENT.md](DEPLOYMENT.md)).
Формат вызова (Wazuh 4.7.4): `PUT /active-response?agents_list=<id>`, тело
`{"command", "arguments"}` — POST/поле agents из старых версий не работают (405/400).

## Демо-матрица: seed-правила корреляции ↔ техники MITRE ATT&CK ↔ стенд

Сценарии воспроизведения (команды для человека-оператора, ожидаемые инциденты и
физические проверки реакций) — [E2E_SCENARIOS.md](E2E_SCENARIOS.md).

| Seed-правило (порог) | Техника MITRE | Wazuh-правило стенда | Как воспроизвести | Из коробки? |
|---|---|---|---|---|
| `brute_force_attempts` (3 за 5 мин) | T1110 Метод перебора | 100100 (дочернее к 5710/5711/5716) / 100101 | серия `ssh admin@<IP_ВМ-1>` с неверным паролем или `hydra` с ВМ-2 | ✅ |
| `password_spraying` (5 за 10 мин) | T1110.003 Распыление паролей | те же (разные `dstuser` с одного `srcip`) | `hydra -L users.txt -p Password1 <IP_ВМ-1> ssh` | ✅ |
| `repeated_scan` (2 за 10 мин) | T1046 Изучение сетевых служб | любые события с `srcip` | `nmap -sT <IP_ВМ-1>` | ✅ |
| `web_attack` (2 за 5 мин) | T1190 Недостатки в общедоступном приложении | 100200 (nginx access.log) | `curl "http://<IP_ВМ-1>/index.php?id=1'%20OR%20'1'='1"` ×2 | ✅ (агент читает access-лог) |
| `privilege_escalation_attempt` (1) | T1068 / T1548 Повышение привилегий | 100300 (useradd/usermod/sudoers) | `sudo useradd -m svc_helper && sudo passwd svc_helper` на ВМ-1 | ✅ (декодер stand-useradd даёт dstuser) |
| `malware_detection` (1) | T1204 Вредоносное ПО | — | EICAR-файл + ClamAV/VT-интеграция | ⚙️ интеграция |
| `data_exfiltration` (1) | T1048 Эксфильтрация | — | IDS (Suricata), правила exfil-класса | ⚙️ IDS |

Правила стенда — дополнение без изменения кода (требование §3.3.2, p:61): новые классы
добавляются в `wazuh/local_rules.xml` (первая группа = тип события для нормализации)
и/или правилами корреляции через `POST /api/v1/correlation-rules` (CRUD, stage-08).

## Проверка правил (wazuh-logtest)

```bash
docker compose exec wazuh-manager /var/ossec/bin/wazuh-logtest
```

Подать строку лога (например, из `/var/log/auth.log` ВМ-1):
`Failed password for admin from 192.168.56.102 port 51234 ssh2` — ожидается правило
**100100**, уровень 7, первая группа `authentication_failed`. Для SQLi — строка
access-лога с `id=1'%20OR%20'1'='1` → правило **100200**; для useradd → **100300**.

## Поток данных (итог)

```
[ВМ-агенты] ──1514──► wazuh-manager ──integrator──► POST /api/v1/ingest/wazuh
                                                          │
                    конвейер: нормализация → корреляция → риск → LLM → DVE
                                                          │
UI (режим «Реально») ──► POST /incidents/{id}/execute-action ──► Wazuh API :55000
                                                          │ POST /active-response
                 ВМ актива: block-ip.sh / lock-account.sh / isolate-host.sh
                                                          │
UI вкладка «Реакции (ВМ)» ◄── GET /api/v1/responses/state ◄┘ (откат — reset-actions)
```

---

## Историческая справка: агент-симулятор stage-20 (удалено в stage-23)

До stage-23 активности «без Wazuh» генерировала собственная реализация
агентов-эмуляторов (каталог `agent/`, сервисы `agent-wks/app/mail`, вкладка
«Агенты (ВМ)», реестр `ExecutionTarget`): агенты проигрывали сценарии и отправляли
алерты в SIEM, а реакции playbook исполнялись HTTP-вызовом к агенту. По явной команде
пользователя (2026-11-05) реализация удалена: данные теперь идут с настоящих
wazuh-агентов на ВМ, реакции — через Wazuh active response API (см. выше и
`analysis/DEVIATIONS.md`).

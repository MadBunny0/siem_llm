"""Активность виртуальной машины наблюдаемого пользователя (stage-20).

ВМ эмулирует пользователя прод-инфраструктуры: фоновая нормальная активность
(вход в систему, почта, файлы) и, по запросу оператора, активность атакующего.
Каждая активность превращается в алерт формата Wazuh-менеджера (те же поля,
что присылает integratord: rule{id,level,groups}, agent, data{srcip,dstuser})
и отправляется в SIEM — POST {SIEM_URL}/ingest/wazuh. Сценарии подобраны под
seed-правила корреляции (см. docs/REAL_EXECUTION.md, таблица демонстрации).

Модуль самодостаточен (только stdlib) — переносится на ВМ без зависимостей.
"""

import json
import random
import urllib.request
from datetime import datetime, timezone

# TEST-NET-3 (RFC 5737) — «атакующий» стенда; замените на реальный источник
DEFAULT_ATTACKER_IP = "203.0.113.66"

NORMAL_USERS = ["alice", "bob"]

# нормальная активность наблюдаемых пользователей (level 3 — Wazuh пересылает
# с level>=3, но ни одно seed-правило корреляции на неё не реагирует:
# authentication_success/почта не совпадают с условиями)
NORMAL_ACTIVITIES = [
    {
        "rule_id": "5715",
        "level": 3,
        "description": "sshd: authentication success",
        "groups": ["syslog", "sshd", "authentication_success"],
        "location": "/var/log/auth.log",
        "make": lambda ip, user: (
            f"Accepted publickey for {user} from 10.20.50.1 port 45222 ssh2",
            {"srcip": "10.20.50.1", "dstuser": user},
        ),
        "text": "Вход пользователя {user} в систему (успешный)",
    },
    {
        "rule_id": "100502",
        "level": 3,
        "description": "postfix: mail sent by local user",
        "groups": ["mail", "postfix", "normal_activity"],
        "location": "/var/log/mail.log",
        "make": lambda ip, user: (
            f"postfix/smtpd[{random.randint(1000, 9999)}]: client={user} from=<user@example.com>",
            {"srcip": ip, "dstuser": user},
        ),
        "text": "Пользователь {user} отправил почтовое сообщение",
    },
    {
        "rule_id": "100503",
        "level": 3,
        "description": "auditd: file opened by user",
        "groups": ["auditd", "file_access", "normal_activity"],
        "location": "/var/log/audit/audit.log",
        "make": lambda ip, user: (
            f"audit: OPEN pathname=/home/{user}/documents user={user}",
            {"srcip": ip, "dstuser": user},
        ),
        "text": "Пользователь {user} открыл рабочий документ",
    },
]

# атакующая активность: сценарии подобраны под seed-правила корреляции SIEM
ATTACK_SCENARIOS = {
    "brute_force": {
        "count": 4,
        "alert": {
            "rule_id": "5712",
            "level": 10,
            "description": "sshd: brute force trying to get access to the system.",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "location": "/var/log/auth.log",
        },
        "make": lambda ip, i: (
            f"Failed password for root from {ip} port {40000 + i} ssh2 (attempt {i + 1})",
            {"srcip": ip, "dstuser": "root"},
        ),
        "text": "Атакующий {ip}: неудачная попытка входа под root (подбор пароля)",
    },
    "password_spraying": {
        "count": 6,
        "alert": {
            "rule_id": "5712",
            "level": 10,
            "description": "sshd: brute force trying to get access to the system.",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "location": "/var/log/auth.log",
        },
        "make": lambda ip, i: (
            f"Failed password for user_{i % 5} from {ip} port {41000 + i} ssh2",
            {"srcip": ip, "dstuser": f"user_{i % 5}"},
        ),
        "text": "Атакующий {ip}: перебор учётных записей (распыление паролей)",
    },
    "repeated_scan": {
        "count": 3,
        "alert": {
            "rule_id": "5722",
            "level": 10,
            "description": "sshd: Possible attack on the server (or an attempt to read).",
            "groups": ["syslog", "sshd"],
            "location": "/var/log/auth.log",
        },
        "make": lambda ip, i: (
            f"Connection attempt from {ip} port {42000 + i} (scan probe {i + 1})",
            {"srcip": ip},
        ),
        "text": "Атакующий {ip}: сетевое сканирование служб узла",
    },
    "web_attack": {
        "count": 2,
        "alert": {
            "rule_id": "31101",
            "level": 6,
            "description": "Web attack: SQL injection attempt.",
            "groups": ["web", "attack"],
            "location": "/var/log/nginx/access.log",
        },
        "make": lambda ip, i: (
            f'GET /index.php?id=1%27+OR+%271%27%3D%271 HTTP/1.1 from {ip} (probe {i + 1})',
            {"srcip": ip},
        ),
        "text": "Атакующий {ip}: SQL-инъекция в веб-приложение",
    },
    "malware": {
        "count": 1,
        "alert": {
            "rule_id": "554",
            "level": 7,
            "description": "ClamAV: Malware detected - EICAR test file.",
            "groups": ["clamav", "malware"],
            "location": "/var/log/clamav/clamd.log",
        },
        "make": lambda ip, i: (
            f"clamd: /home/alice/downloads/invoice.exe found: EICAR-Test-File MALWARE",
            {"srcip": ip, "dstuser": "alice"},
        ),
        "text": "Пользователь alice скачал файл с вредоносным кодом (EICAR)",
    },
    "privilege_escalation": {
        "count": 1,
        "alert": {
            "rule_id": "100500",
            "level": 8,
            "description": "Изменение привилегий: пользователь добавлен в sudo / изменён sudoers",
            "groups": ["syslog", "useradd", "privilege_escalation"],
            "location": "/var/log/auth.log",
        },
        "make": lambda ip, i: (
            f"usermod: user 'bob' added to group sudo (from {ip})",
            {"srcip": ip, "dstuser": "bob"},
        ),
        "text": "Атакующий {ip}: попытка повышения привилегий (bob -> sudo)",
    },
    "data_exfiltration": {
        "count": 1,
        "alert": {
            "rule_id": "100501",
            "level": 10,
            "description": "Suricata: massive outbound data transfer to external host (exfiltration).",
            "groups": ["ids", "suricata", "exfiltration"],
            "location": "/var/log/suricata/eve.json",
        },
        "make": lambda ip, i: (
            f"suspicious outbound transfer 1.2GB to {ip}:4444 (archive.tar.gz)",
            {"srcip": ip, "dstuser": "svc_backup"},
        ),
        "text": "Атакующий {ip}: эксфильтрация данных на внешний сервер",
    },
}


def _alert_id() -> str:
    return f"{datetime.now(timezone.utc).timestamp():.0f}.{random.randint(100, 999)}"


def build_alert(activity: dict, agent_name: str, agent_id: str, attacker_ip: str, index: int = 0) -> dict:
    """Алерт формата Wazuh-менеджера (как присылает integratord в integrator.sh):
    timestamp / rule{id,level,description,groups} / agent{id,name} / data / full_log."""
    full_log, data = activity["make"](attacker_ip, index)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {
            "id": activity["rule_id"],
            "level": activity["level"],
            "description": activity["description"],
            "groups": activity["groups"],
        },
        "agent": {"id": agent_id, "name": agent_name},
        "data": data,
        "full_log": full_log,
        "location": activity["location"],
        "id": _alert_id(),
        "manager": {"name": "emu-agent"},
    }


def send_to_siem(siem_url: str, alert: dict, timeout: float = 5.0) -> tuple[bool, dict]:
    """POST алерта в SIEM (тот же эндпоинт, что у интеграции Wazuh):
    {SIEM_URL}/ingest/wazuh. Ответ SIEM ({correlated, incident_id, ...})
    возвращается оператору — видно, что родила активность."""
    url = f"{siem_url.rstrip('/')}/ingest/wazuh"
    request = urllib.request.Request(
        url,
        data=json.dumps(alert).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return True, json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        return False, {"error": str(exc)}


def run_scenario(siem_url: str, host: object, scenario: str, count: int | None, attacker_ip: str) -> dict:
    """Проигрывание сценария активности: каждая активность → алерт → SIEM;
    журнал активности узла пополняется (видно в UI агентов)."""
    if scenario == "normal_activity":
        activities = NORMAL_ACTIVITIES
        default_count = 3
    elif scenario in ATTACK_SCENARIOS:
        # спека атаки: {count, alert{rule_id,...}, make, text} — приводим к
        # плоскому виду build_alert (rule_id/level/description/groups/location)
        spec = ATTACK_SCENARIOS[scenario]
        activities = [{**spec["alert"], "make": spec["make"], "text": spec["text"]}]
        default_count = spec["count"]
    else:
        return {"sent": 0, "failed": 0, "error": f"Неизвестный сценарий: {scenario}"}

    total = count if count and count > 0 else default_count
    agent_id = f"00{random.randint(1, 9)}"
    sent, failed, results = 0, 0, []
    for i in range(total):
        if scenario == "normal_activity":
            activity = random.choice(activities)
            user = random.choice(NORMAL_USERS)
            text = activity["text"].format(user=user)
            alert = build_alert(activity, host.hostname, agent_id, attacker_ip, i)
            # нормальная активность идёт с внутренних адресов рабочих мест
            # (не с IP атакующего) — make() получает attacker_ip как заглушку
            alert["data"]["srcip"] = f"10.20.{random.randint(1, 60)}.{random.randint(2, 250)}"
        else:
            activity = activities[0]
            text = activity["text"].format(ip=attacker_ip)
            alert = build_alert(activity, host.hostname, agent_id, attacker_ip, i)

        ok, response = send_to_siem(siem_url, alert)
        if ok:
            sent += 1
            incident_id = (response or {}).get("incident_id")
        else:
            failed += 1
            incident_id = None
        host.record_activity(text, alert_sent=ok, detail=json.dumps(response, ensure_ascii=False)[:300])
        results.append({"activity": text, "sent": ok, "siem_response": response})

    return {"sent": sent, "failed": failed, "scenario": scenario, "results": results}

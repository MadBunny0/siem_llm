"""Эмуляция состояния виртуальной машины наблюдаемого пользователя (stage-20).

Агентendpoint-стенда: держит состояние узла (учётные записи, процессы, файлы,
правила фаервола, сетевая изоляция) и исполняет ответные действия playbook
РЕАЛЬНО — в стенде изменение логического состояния контейнера (adapter="state"),
на реальной ВМ — через системные команды (adapter="linux", см. README агента;
непроверенные команды честно откатываются к эмуляции с пометкой).

Состояние персистентно (JSON-файл) — демонстрация переживает перезапуск
контейнера; POST /agent/reset возвращает узел к исходному состоянию.

Модуль самодостаточен (только stdlib) — переносится на ВМ без установки
зависимостей проекта.
"""

import json
import logging
import os
import shutil
import subprocess
import threading
from datetime import datetime, timezone

logger = logging.getLogger("agent.state")

# учётные записи наблюдаемых пользователей (учебный стенд): два человека
# и сервисная учётка; root есть на любой Linux-системе
DEFAULT_USERS = ["alice", "bob", "svc_backup"]

DEFAULT_PROCESSES = [
    {"pid": 1, "name": "systemd", "user": "root"},
    {"pid": 412, "name": "sshd", "user": "root"},
    {"pid": 556, "name": "cron", "user": "root"},
]

DEFAULT_FILES = [
    {"path": "/home/alice/report_q4.xlsx", "status": "present"},
    {"path": "/home/bob/deploy.sh", "status": "present"},
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EmulatedHost:
    """Состояние ВМ + журнал действий; потокобезопасность — threading.Lock
    (эндпоинты агента синхронные, FastAPI исполняет их в threadpool)."""

    def __init__(
        self,
        hostname: str,
        platform: str = "linux",
        adapter: str = "state",
        state_file: str | None = None,
    ):
        self.hostname = hostname
        self.platform = platform
        self.adapter = adapter if adapter in ("state", "linux") else "state"
        self.state_file = state_file
        self.lock = threading.Lock()
        self.started_at = _now()
        self._state = self._load_or_default()

    # ------------------------------------------------------------------
    # Персистентность
    # ------------------------------------------------------------------
    def _default_state(self) -> dict:
        return {
            "isolated": False,
            "firewall_rules": [],  # [{"ip", "added_at", "reason"}]
            "accounts": {
                name: {"status": "active", "last_change": self.started_at}
                for name in DEFAULT_USERS
            },
            "processes": [dict(p) for p in DEFAULT_PROCESSES],
            "files": [dict(f) for f in DEFAULT_FILES],
            "journal": [],  # исполненные действия (демонстрация реагирования)
            "activity": [],  # активность наблюдаемых пользователей/атакующих
        }

    def _load_or_default(self) -> dict:
        if self.state_file and os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as fh:
                    state = json.load(fh)
                # недостающие ключи — от старой версии файла
                default = self._default_state()
                for key, value in default.items():
                    state.setdefault(key, value)
                return state
            except Exception as exc:  # повреждённый файл — начинаем заново
                logger.warning("state file %s unreadable (%s) — fresh state", self.state_file, exc)
        return self._default_state()

    def _persist(self) -> None:
        if not self.state_file:
            return
        try:
            os.makedirs(os.path.dirname(self.state_file) or ".", exist_ok=True)
            with open(self.state_file, "w", encoding="utf-8") as fh:
                json.dump(self._state, fh, ensure_ascii=False, indent=1)
        except Exception as exc:
            logger.warning("state persist failed: %s", exc)

    # ------------------------------------------------------------------
    # Чтение
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        """Полное состояние узла для GET /agent/status (демонстрация в UI)."""
        with self.lock:
            return {
                "hostname": self.hostname,
                "platform": self.platform,
                "adapter": self.adapter,
                "status": "online",
                "isolated": self._state["isolated"],
                "firewall_rules": list(self._state["firewall_rules"]),
                "accounts": {k: dict(v) for k, v in self._state["accounts"].items()},
                "processes": list(self._state["processes"]),
                "files": list(self._state["files"]),
                "started_at": self.started_at,
                "journal_size": len(self._state["journal"]),
                "activity_size": len(self._state["activity"]),
            }

    def journal(self, limit: int = 50) -> list[dict]:
        with self.lock:
            entries = self._state["journal"][-limit:]
        return list(reversed(entries))  # свежие сверху

    def activity(self, limit: int = 50) -> list[dict]:
        with self.lock:
            entries = self._state["activity"][-limit:]
        return list(reversed(entries))

    def record_activity(self, description: str, alert_sent: bool, detail: str | None = None) -> None:
        with self.lock:
            self._state["activity"].append(
                {"at": _now(), "description": description, "alert_sent": alert_sent, "detail": detail}
            )
            self._state["activity"] = self._state["activity"][-500:]
            self._persist()

    # ------------------------------------------------------------------
    # Действия playbook (исполнение реагирования, §3.4)
    # ------------------------------------------------------------------
    def execute(self, action: str, params: dict, requested_by: str | None, incident_id: int | None) -> dict:
        """Исполнение одного действия: меняет состояние (и/или систему при
        adapter=linux), пишет журнал. Возвращает executed + человекочитаемый
        результат — оператор видит, что произошло на ВМ."""
        handler = {
            "block_ip": self._action_block_ip,
            "unblock_ip": self._action_unblock_ip,
            "isolate_host": self._action_isolate_host,
            "release_host": self._action_release_host,
            "disable_account": self._action_disable_account,
            "enable_account": self._action_enable_account,
            "kill_process": self._action_kill_process,
            "quarantine_file": self._action_quarantine_file,
            "collect_evidence": self._action_collect_evidence,
            "monitor": self._action_monitor,
        }.get(action)
        if handler is None:
            return {"executed": False, "result": f"Неизвестное действие: {action}", "detail": "unknown_action"}

        with self.lock:
            detail = handler(params)
            self._state["journal"].append(
                {
                    "at": _now(),
                    "action": action,
                    "params": params,
                    "executed": True,
                    "requested_by": requested_by,
                    "incident_id": incident_id,
                    "detail": detail,
                }
            )
            self._state["journal"] = self._state["journal"][-500:]
            self._persist()
        return {"executed": True, "result": detail}

    # --- конкретные действия (вызываются под lock) --------------------
    def _action_block_ip(self, params: dict) -> str:
        ip = str(params.get("ip") or "").strip()
        if not ip:
            return "IP не указан — действие не выполнено"
        if any(rule["ip"] == ip for rule in self._state["firewall_rules"]):
            return f"IP {ip} уже заблокирован"
        note = self._linux_try(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], "block_ip")
        self._state["firewall_rules"].append({"ip": ip, "added_at": _now(), "note": note})
        return f"IP-адрес {ip} заблокирован на фаерволе узла{note}"

    def _action_unblock_ip(self, params: dict) -> str:
        ip = str(params.get("ip") or "").strip()
        before = len(self._state["firewall_rules"])
        self._state["firewall_rules"] = [r for r in self._state["firewall_rules"] if r["ip"] != ip]
        note = self._linux_try(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], "unblock_ip")
        if len(self._state["firewall_rules"]) == before:
            return f"Блокировка IP {ip} не найдена"
        return f"Блокировка IP {ip} снята{note}"

    def _action_isolate_host(self, params: dict) -> str:
        if self._state["isolated"]:
            return "Узел уже изолирован"
        note = self._linux_isolate()
        self._state["isolated"] = True
        return (
            f"Узел изолирован от корпоративной сети (карантин EDR); "
            f"доступ сохранён только для канала управления{note}"
        )

    def _action_release_host(self, params: dict) -> str:
        if not self._state["isolated"]:
            return "Узел не изолирован"
        note = self._linux_release()
        self._state["isolated"] = False
        return f"Изоляция снята — узел возвращён в корпоративную сеть{note}"

    def _action_disable_account(self, params: dict) -> str:
        user = str(params.get("user") or "").strip()
        if not user:
            return "Учётная запись не указана"
        account = self._state["accounts"].get(user)
        note = self._linux_try(["usermod", "-L", user], "disable_account")
        if account:
            account["status"] = "locked"
            account["last_change"] = _now()
            return f"Учётная запись {user} заблокирована{note}"
        self._state["accounts"][user] = {"status": "locked", "last_change": _now()}
        return f"Учётная запись {user} заблокирована (создана запись о внешней учётке){note}"

    def _action_enable_account(self, params: dict) -> str:
        user = str(params.get("user") or "").strip()
        if not user:
            return "Учётная запись не указана"
        note = self._linux_try(["usermod", "-U", user], "enable_account")
        account = self._state["accounts"].get(user)
        if account:
            account["status"] = "active"
            account["last_change"] = _now()
        return f"Учётная запись {user} разблокирована{note}"

    def _action_kill_process(self, params: dict) -> str:
        pid = params.get("pid")
        name = str(params.get("name") or "").strip()
        before = len(self._state["processes"])
        if pid is not None:
            self._state["processes"] = [p for p in self._state["processes"] if p["pid"] != int(pid)]
            target = f"PID {pid}"
        elif name:
            self._state["processes"] = [p for p in self._state["processes"] if p["name"] != name]
            target = f"процесс {name}"
        else:
            return "Не указан PID или имя процесса"
        note = self._linux_try(["kill", str(pid or name)], "kill_process")
        if len(self._state["processes"]) == before:
            return f"{target} не найден"
        return f"{target} завершён{note}"

    def _action_quarantine_file(self, params: dict) -> str:
        path = str(params.get("path") or "").strip()
        if not path:
            return "Путь к файлу не указан"
        note = self._linux_try(
            ["mv", path, f"/quarantine/{os.path.basename(path)}"], "quarantine_file"
        )
        for item in self._state["files"]:
            if item["path"] == path:
                item["status"] = "quarantined"
                return f"Файл {path} помещён в карантин{note}"
        self._state["files"].append({"path": path, "status": "quarantined"})
        return f"Файл {path} помещён в карантин (запись о внешнем файле){note}"

    def _action_collect_evidence(self, params: dict) -> str:
        return "Снимок состояния узла приложен к результату действия"

    def _action_monitor(self, params: dict) -> str:
        return "Узел взят под наблюдение; состояние не изменялось"

    # ------------------------------------------------------------------
    # Adapter "linux": реальные команды (только на настоящей ВМ, см. README)
    # ------------------------------------------------------------------
    def _linux_try(self, cmd: list[str], label: str) -> str:
        """Попытка реальной команды при adapter=linux; неудача — честная
        пометка (стенд-контейнер не имеет iptables/usermod — остаётся
        логическое состояние)."""
        if self.adapter != "linux":
            return ""
        binary = shutil.which(cmd[0])
        if not binary:
            return f" (adapter=linux: {cmd[0]} не найден — изменено только логическое состояние)"
        try:
            proc = subprocess.run(
                [binary, *cmd[1:]], capture_output=True, text=True, timeout=10
            )
            if proc.returncode == 0:
                return f" (adapter=linux: {label} выполнен системной командой)"
            return f" (adapter=linux: команда вернула код {proc.returncode}: {proc.stderr.strip()[:120]})"
        except Exception as exc:
            return f" (adapter=linux: ошибка команды: {exc})"

    def _linux_isolate(self) -> str:
        if self.adapter != "linux":
            return ""
        return self._linux_try(["iptables", "-A", "INPUT", "-j", "DROP"], "isolate_host")

    def _linux_release(self) -> str:
        if self.adapter != "linux":
            return ""
        return self._linux_try(["iptables", "-D", "INPUT", "-j", "DROP"], "release_host")

    # ------------------------------------------------------------------
    # Сброс (повторяемость демонстрации)
    # ------------------------------------------------------------------
    def reset(self) -> None:
        with self.lock:
            self._state = self._default_state()
            self._persist()

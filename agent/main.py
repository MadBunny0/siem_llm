"""Агент виртуальной машины наблюдаемого пользователя (stage-20).

Endpoint-агент учебного стенда: standalone FastAPI-приложение, разворачиваемое
на «ВМ» (в Docker-стенде — контейнер с эмуляцией состояния, adapter="state";
на реальной виртуальной машине — те же файлы, adapter="linux" исполняет
системные команды; см. agent/README.md и docs/REAL_EXECUTION.md).

Эндпоинты:
  GET  /agent/health            — healthcheck (compose)
  GET  /agent/status            — состояние узла (открыто для демонстрации)
  GET  /agent/journal           — журнал исполненных действий SIEM (токен)
  GET  /agent/activity          — журнал активности наблюдаемого пользователя
  POST /agent/action            — исполнение действия playbook (токен)
  POST /agent/reset             — сброс состояния ВМ к исходному (токен)
  POST /agent/simulate          — активность: нормальная / атака → SIEM (токен)

Авторизация мутаций — Bearer AGENT_TOKEN; пустой AGENT_TOKEN отключает
проверку (только для локальной отладки, документировано).
"""

import logging
import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from activity import attacker_ip_for_host, run_scenario
from emu_state import EmulatedHost

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("agent")

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
AGENT_HOSTNAME = os.environ.get("AGENT_HOSTNAME", "emu-host")
AGENT_PLATFORM = os.environ.get("AGENT_PLATFORM", "linux")
AGENT_ADAPTER = os.environ.get("AGENT_ADAPTER", "state")  # state | linux
AGENT_STATE_FILE = os.environ.get("AGENT_STATE_FILE", "")  # пусто — без персистентности
SIEM_URL = os.environ.get("SIEM_URL", "http://api:8000/api/v1")
# IP атакующего сценариев: по умолчанию выводится из имени узла (разные ВМ —
# разные атакующие, инциденты не склеиваются); ATTACKER_IP задаёт явно
ATTACKER_IP = attacker_ip_for_host(AGENT_HOSTNAME, os.environ.get("ATTACKER_IP"))

host = EmulatedHost(
    hostname=AGENT_HOSTNAME,
    platform=AGENT_PLATFORM,
    adapter=AGENT_ADAPTER,
    state_file=AGENT_STATE_FILE or None,
)

app = FastAPI(
    title=f"Endpoint Agent {AGENT_HOSTNAME}",
    version="1.0.0",
    description=(
        "Агент ВМ наблюдаемого пользователя: исполнение ответных действий "
        "playbook + эмуляция активности пользователя/атакующего (stage-20)"
    ),
)


def require_token(authorization: str | None) -> None:
    if not AGENT_TOKEN:
        return  # отладочный режим без токена (документировано в README)
    if authorization != f"Bearer {AGENT_TOKEN}":
        raise HTTPException(status_code=401, detail="Требуется Bearer-токен агента")


class ActionIn(BaseModel):
    """Действие playbook от SIEM (services/execution.py)."""

    action: str = Field(min_length=1)
    params: dict = Field(default_factory=dict)
    incident_id: int | None = None
    requested_by: str | None = None


class SimulateIn(BaseModel):
    """Сценарий активности: normal_activity — наблюдаемые пользователи;
    brute_force / password_spraying / repeated_scan / web_attack / malware /
    privilege_escalation / data_exfiltration — активность атакующего
    (сценарии подобраны под seed-правила корреляции SIEM)."""

    scenario: str = Field(min_length=1)
    count: int | None = Field(default=None, ge=1, le=50)


@app.get("/agent/health")
def health():
    """Healthcheck для compose (без данных узла)."""
    return {"status": "ok", "hostname": AGENT_HOSTNAME}


@app.get("/agent/status")
def status():
    """Состояние узла — открыт для демонстрации: оператор видит, что реально
    изменилось на ВМ после исполнения playbook (фаервол, учётки, изоляция)."""
    return host.snapshot()


@app.get("/agent/journal")
def journal(limit: int = 50, authorization: str | None = Header(default=None)):
    """Журнал исполненных действий: чем, когда и кем SIEM менял узел."""
    require_token(authorization)
    return {"journal": host.journal(max(1, min(limit, 200)))}


@app.get("/agent/activity")
def activity_log(limit: int = 50, authorization: str | None = Header(default=None)):
    """Журнал активности наблюдаемого пользователя/атакующего узла."""
    require_token(authorization)
    return {"activity": host.activity(max(1, min(limit, 200)))}


@app.post("/agent/action")
def action(payload: ActionIn, authorization: str | None = Header(default=None)):
    """Исполнение действия playbook на узле (вызывает SIEM, services/execution.py)."""
    require_token(authorization)
    logger.info("action %s params=%s incident=%s by=%s", payload.action, payload.params, payload.incident_id, payload.requested_by)
    return host.execute(payload.action, payload.params, payload.requested_by, payload.incident_id)


@app.post("/agent/reset")
def reset(authorization: str | None = Header(default=None)):
    """Сброс состояния ВМ к исходному (повторяемость демонстрации)."""
    require_token(authorization)
    host.reset()
    logger.info("state reset")
    return {"reset": True, "hostname": AGENT_HOSTNAME}


@app.post("/agent/simulate")
def simulate(payload: SimulateIn, authorization: str | None = Header(default=None)):
    """Проигрывание активности наблюдаемого пользователя/атакующего:
    каждая активность → алерт формата Wazuh → POST {SIEM_URL}/ingest/wazuh.
    Ответ содержит результаты SIEM (correlated/incident_id) — видно, какие
    сценарии порождают инциденты."""
    require_token(authorization)
    logger.info("simulate scenario=%s count=%s", payload.scenario, payload.count)
    result = run_scenario(SIEM_URL, host, payload.scenario, payload.count, ATTACKER_IP)
    if "error" in result:
        raise HTTPException(status_code=422, detail=result["error"])
    return result


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("AGENT_PORT", "8100")))

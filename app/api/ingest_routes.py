"""Приём событий Wazuh (§3.1–3.3) и справочник формы события — вынесено из
app/api/routes.py (stage-19).
"""

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Asset, CorrelationRule, Event, User
from app.schemas import IngestReferenceOut, WazuhAlert
from app.services.auto_analysis import run_auto_analysis
from app.services.auth import get_current_user
from app.services.ingest import ingest_alert

router = APIRouter()


@router.post("/ingest/wazuh")
def ingest_wazuh(
    alert: WazuhAlert,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Приём алерта Wazuh: нормализация → корреляция → риск → инцидент (§3.1–3.3).

    Автоанализ LLM для уровней из AUTO_ANALYSIS_LEVELS выполняется в фоне
    (stage-12): приём события больше не блокируется на минутном CPU-инференсе.
    """
    result, should_auto_analyze = ingest_alert(db, alert.model_dump(exclude_none=True))

    if should_auto_analyze:
        background_tasks.add_task(run_auto_analysis, result["incident_id"])
        result["analysis"] = {"scheduled": True, "severity": result["severity"]}
    return result


# ---------------------------------------------------------------------------
# Справочник для формы добавления события Wazuh (stage-15, фидбек
# пользователя): поля формы — выпадающие списки из фактических данных БД,
# а не ручной ввод ID правила/группы/агента
# ---------------------------------------------------------------------------
def _ingest_reference(db: Session) -> dict:
    """Сбор справочных данных из БД (объём прототипа мал — Python-стороной).

    - rules: distinct по raw_data["rule"]["id"] из событий; level/description/
      groups — из первой встреченной записи этого id; события без rule пропускаются;
    - groups: union групп правил Wazuh из событий + значения условий
      корреляционных правил по полю event_type (ср. correlation._event_type_values);
    - agents: distinct пары (id, name) из raw_data["agent"] (пустые не включаются);
    - assets: весь инвентарь активов; users/src_ips: непустые значения событий.
    """
    rules: dict[str, dict] = {}
    groups: set[str] = set()
    agents: dict[tuple[str, str], None] = {}  # упорядоченный set пар (id, name)
    users: set[str] = set()
    src_ips: set[str] = set()

    events = list(db.scalars(select(Event).order_by(Event.id)).all())
    for e in events:
        rule = (e.raw_data or {}).get("rule") or {}
        rule_id = rule.get("id")
        if rule_id is not None and str(rule_id).strip():
            key = str(rule_id)
            if key not in rules:  # первая встреченная запись этого id
                level = rule.get("level")
                try:
                    level = int(level) if level is not None else None
                except (TypeError, ValueError):
                    level = None
                rules[key] = {
                    "id": key,
                    "level": level,
                    "description": rule.get("description"),
                    "groups": [str(g) for g in (rule.get("groups") or []) if g],
                }
        groups.update(str(g) for g in (rule.get("groups") or []) if g)

        agent = (e.raw_data or {}).get("agent") or {}
        if agent.get("id") and agent.get("name"):
            agents.setdefault((str(agent["id"]), str(agent["name"])), None)

        if e.user:
            users.add(str(e.user))
        if e.src_ip:
            src_ips.add(str(e.src_ip))

    # значения event_type из условий правил корреляции: скаляр (eq/like/neq)
    # или список (in) — справочник перечисляет таксономию, оператор не важен
    for corr in db.scalars(select(CorrelationRule)).all():
        for cond in (corr.conditions or []):
            if not isinstance(cond, dict) or cond.get("field") != "event_type":
                continue
            value = cond.get("value")
            if isinstance(value, list):
                groups.update(str(v) for v in value if v)
            elif value is not None and str(value).strip():
                groups.add(str(value))

    return {
        "rules": sorted(rules.values(), key=lambda r: r["id"]),
        "groups": sorted(groups),
        "agents": [{"id": agent_id, "name": agent_name} for agent_id, agent_name in sorted(agents)],
        "assets": [
            {
                "name": a.name,
                "type": a.type,
                "criticality": a.criticality,
                "network_segment": a.network_segment,
                "ip_addresses": a.ip_addresses,
            }
            for a in db.scalars(select(Asset).order_by(Asset.name)).all()
        ],
        "users": sorted(users),
        "src_ips": sorted(src_ips),
    }


@router.get("/ingest/reference", response_model=IngestReferenceOut)
def ingest_reference(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Справочник для формы добавления события Wazuh (stage-15).

    Собирается из фактических данных БД: правила/группы/агенты — из принятых
    событий и условий корреляции, активы — из инвентаря (§3.2).
    """
    return _ingest_reference(db)

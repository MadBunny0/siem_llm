"""Реакции на ВМ (stage-23): сводка активных реальных реакций —
отдельный роутер (домен «реагирование»; подключается в routes.py).

GET /responses/state — агрегат активных реальных реакций (mode=real,
без undone_at) по всем инцидентам, сгруппированный по активам и
инцидентам: вкладка «Реакции (ВМ)» показывает оператору, какие команды
сейчас реально действуют на виртуальных машинах (block_ip/disable_account/
isolate_host) и какие пассивные отметки (monitor/collect_evidence) открыты.
Источник — записи ResponseAction: metadata_json.target хранит цель
(IP/учётка/актив), metadata_json.undone_at — факт отката (ставится при
«Сбросить реакции», см. services/execution.py::undo_incident_real_actions).
"""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import ResponseAction, User
from app.schemas import ResponsesStateAction, ResponsesStateItem
from app.services.auth import get_current_user
from app.services.execution import PASSIVE_ACTIONS, WAZUH_AR_COMMANDS

router = APIRouter()

# действия, попадающие в сводку: активные AR-реакции + пассивные отметки
TRACKED_ACTIONS = set(WAZUH_AR_COMMANDS) | PASSIVE_ACTIONS


@router.get("/responses/state", response_model=list[ResponsesStateItem])
def responses_state(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Активные реальные реакции по всем инцидентам (stage-23): группировка
    {asset, incident_id} → список действий {action, target, at, by}.
    Отменённые (undone_at) и записи не-real режимов не попадают в ответ;
    сортировка — актив, затем инцидент."""
    records = db.scalars(
        select(ResponseAction).order_by(ResponseAction.executed_at.asc())
    ).all()
    grouped: dict[tuple[str, int], list[ResponsesStateAction]] = {}
    for record in records:
        metadata = record.metadata_json or {}
        if metadata.get("mode") != "real" or metadata.get("undone_at"):
            continue
        if record.action_type not in TRACKED_ACTIONS:
            continue
        incident = record.incident
        asset_name = incident.asset.name if incident is not None and incident.asset else "—"
        incident_id = incident.id if incident is not None else record.incident_id
        key = (asset_name, incident_id)
        grouped.setdefault(key, []).append(
            ResponsesStateAction(
                action=record.action_type,
                target=metadata.get("target"),
                at=record.executed_at,
                by=metadata.get("requested_by"),
            )
        )
    return [
        ResponsesStateItem(asset=asset, incident_id=incident_id, actions=actions)
        for (asset, incident_id), actions in sorted(
            grouped.items(), key=lambda kv: (kv[0][0], -kv[0][1])
        )
    ]

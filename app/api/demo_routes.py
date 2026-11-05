"""Демонстрационные мок-сценарии (stage-12/15) — вынесено из app/api/routes.py
(stage-19). Сценарии — общий пул из app/services/demo_events.py; конвейер
обработки — app/services/ingest.py (как у /ingest/wazuh).
"""

import random
from datetime import timezone

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from app.api.common import routes_datetime as datetime  # compat-шов: см. common.py
from app.db import get_db
from app.models import User
from app.services.audit import audit
from app.services.auth import get_current_user, require_admin
from app.services.auto_analysis import run_auto_analysis
from app.services.demo_events import build_mock_scenarios
from app.services.ingest import ingest_alert

router = APIRouter()


@router.post("/demo/populate")
def demo_populate(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Мок-сценарии для демонстрации (stage-12): 19 событий → 7 инцидентов
    всех уровней риска, разные активы и классы атак (MITRE ATT&CK).

    Сценарии — общий пул из app/services/demo_events.py (stage-15).
    Автоанализ (stage-17, фидбек): инциденты уровней из AUTO_ANALYSIS_LEVELS
    уходят в фоновый LLM-анализ как при обычном ingest — low после него
    закрывается автоматически (_maybe_auto_close). Ответ содержит
    auto_analysis_scheduled — сколько анализов запланировано.
    """
    created_incidents: dict[int, dict] = {}
    auto_analysis_ids: list[int] = []
    events_count = 0
    for scenario in build_mock_scenarios(datetime.now(timezone.utc)):
        for alert_payload in scenario.events:
            result, should_auto_analyze = ingest_alert(db, alert_payload)
            events_count += 1
            if result.get("correlated") and result.get("incident_id"):
                created_incidents[result["incident_id"]] = {
                    "incident_id": result["incident_id"],
                    "severity": result["severity"],
                    "rule": result["rule"],
                }
            if should_auto_analyze and result["incident_id"] not in auto_analysis_ids:
                auto_analysis_ids.append(result["incident_id"])

    # фоновый автоанализ — как в /ingest/wazuh (route ingest_wazuh)
    for incident_id in auto_analysis_ids:
        background_tasks.add_task(run_auto_analysis, incident_id)

    audit(
        "demo_populated",
        {
            "events": events_count,
            "incidents": len(created_incidents),
            "auto_analysis_scheduled": len(auto_analysis_ids),
            "by": admin.username,
        },
        db=db,
    )
    db.commit()
    return {
        "created_events": events_count,
        "incidents": sorted(created_incidents.values(), key=lambda x: x["incident_id"]),
        "auto_analysis_scheduled": len(auto_analysis_ids),
    }


@router.post("/demo/test-event")
def demo_test_event(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Случайное тестовое событие из мок-пула (stage-15, фидбек пользователя).

    random.choice по сценариям → random.choice по событиям выбранного сценария
    → полный конвейер ingest_alert. Доступно всем ролям (get_current_user,
    не require_admin). Автоанализ критических инцидентов — в фоне, как у
    POST /ingest/wazuh (stage-12); служебный ключ _auto_analysis_incident_id
    в ответ не попадает.
    """
    scenarios = build_mock_scenarios(datetime.now(timezone.utc))
    scenario = random.choice(scenarios)
    alert_payload = random.choice(scenario.events)

    result, should_auto_analyze = ingest_alert(db, alert_payload)

    # пост-обработка как в ingest_wazuh: автоанализ уходит в фон (stage-12)
    if should_auto_analyze:
        background_tasks.add_task(run_auto_analysis, result["incident_id"])

    audit(
        "test_event_generated",
        {
            "scenario": scenario.key,
            "event_id": result.get("event_id"),
            "correlated": result.get("correlated"),
            "incident_id": result.get("incident_id"),
        },
        db=db,
        event_id=result.get("event_id"),
        incident_id=result.get("incident_id"),
        user_id=user.id,
    )
    db.commit()
    return {
        "scenario": scenario.key,
        "scenario_title": scenario.title,
        "event": alert_payload,
        "result": result,
    }

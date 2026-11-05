"""Оркестрация интеллектуального анализа инцидента (§3.3.4 + §3.4) — вынесена
из app/api/routes.py (stage-19).

Контекст → Ollama → Decision Validation Engine → playbook → аудит.
run_auto_analysis — фоновая точка входа (BackgroundTasks из ingest/demo и
POST /incidents/{id}/analyze); _run_incident_analysis — сам конвейер анализа;
_maybe_auto_close — автозакрытие low-инцидентов (stage-17).

Stage-18 (фидбек): автоанализ и автоконвейер реагирования — только для low
(AUTO_ANALYSIS_LEVELS); critical/high/medium обрабатывает оператор. Ручной
POST /incidents/{id}/analyze выполняется в фоне (ответ scheduled) — синхронный
CPU-инференс упирался в таймаут nginx (504); инференс LLM сериализуется
(LLM_INFERENCE_LOCK) — пачка анализов не душит модель.
"""

from datetime import timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.common import _not_executed, _validate_with_playbook
from app.api.common import routes_datetime as datetime  # compat-шов: см. common.py
from app.config import settings
from app.models import Analysis, Incident
from app.services.audit import audit
from app.services.llm import render_full_prompt
from app.services.notification import notify_analyst


async def analyze_incident(context: dict) -> dict:
    """Делегат LLM-анализа через модуль-агрегатор app.api.routes (stage-19).

    Тесты подменяют зависимость именно на агрегаторе:
    monkeypatch.setattr("app.api.routes.analyze_incident", fake) — поэтому
    ссылка резолвится в момент вызова, а не при импорте модуля (from-import
    сохранил бы копию ссылки, сделанную до подмены). Импорт внутри функции
    заодно исключает цикл импорта services → api.
    """
    import app.api.routes as routes

    return await routes.analyze_incident(context)


async def run_auto_analysis(incident_id: int, initiated_by: str = "auto_analysis") -> None:
    """Фоновый LLM-анализ инцидента (stage-12): собственная сессия БД, после ответа API.

    Запускается и автоконвейером (ingest, demo — initiated_by="auto_analysis"),
    и ручным POST /incidents/{id}/analyze (stage-18: анализ выполняется в фоне,
    чтобы синхронный CPU-инференс не упирался в таймаут nginx). Автозакрытие
    (_maybe_auto_close, stage-17) — только для автоконвейера: ручной анализ
    никогда не закрывает инцидент автоматически.
    """
    from app.db import SessionLocal
    import logging

    logger = logging.getLogger("auto_analysis")
    db = SessionLocal()
    try:
        incident = db.get(Incident, incident_id)
        if incident is None:
            logger.warning("auto_analysis: incident %s not found", incident_id)
            return
        result = await _run_incident_analysis(
            db, incident, raise_on_error=False, initiated_by=initiated_by
        )
        if "error" not in result:
            if initiated_by == "auto_analysis":
                _maybe_auto_close(db, incident, result)
        db.commit()
        logger.info("auto_analysis: incident %s analyzed", incident_id)
    except Exception as exc:  # фон не должен ронять приложение
        db.rollback()
        logger.error("auto_analysis failed for incident %s: %s", incident_id, exc)
    finally:
        db.close()


def _levels(setting_value: str) -> set[str]:
    """Разбор CSV-списка уровней риска (общий для AUTO_ANALYSIS_LEVELS и
    AUTO_CLOSE_LEVELS, stage-19): strip, split по запятой, фильтр пустых,
    lowercase. Множество — как прежде (дубликаты в настройке схлопываются).
    """
    return {
        level.strip().lower()
        for level in setting_value.split(",")
        if level.strip()
    }


def auto_analysis_levels() -> set[str]:
    """Уровни риска, анализируемые LLM автоматически (AUTO_ANALYSIS_LEVELS)."""
    return _levels(settings.auto_analysis_levels or "low")


def auto_close_levels() -> set[str]:
    """Уровни, закрываемые автоматически после успешного автоанализа
    (AUTO_CLOSE_LEVELS, stage-17 — «фильтр автоматического закрытия»).

    Пустая строка/настройка → пустое множество: автозакрытие выключено.
    """
    return _levels(settings.auto_close_levels or "")


def _maybe_auto_close(db: Session, incident: Incident, analysis_result: dict) -> bool:
    """Автоматическое закрытие инцидента после успешного автоанализа (stage-17).

    Условия (все одновременно): критичность инцидента входит в
    AUTO_CLOSE_LEVELS; инцидент ещё не закрыт; аналитик не взял его в работу
    (analyst_id is None); ни одно из рекомендуемых действий не отложено до
    подтверждения администратора (pending_confirmation).

    Пометка auto_closed ставится в response_raw ПОСЛЕДНЕГО Analysis инцидента
    (переприсвоение JSON-колонок обязательно — канонический комментарий в
    app/api/common.py). Изменения сохраняются коммитом вызывающего
    (run_auto_analysis).

    Диагностируемость (stage-18, фидбек): если критичность инцидента входит
    в AUTO_CLOSE_LEVELS, но закрытие пропущено по причине (инцидент закреплён
    за аналитиком или действие ждёт подтверждения) — в аудит пишется
    incident_auto_close_skipped с reason/detail. Не применимые случаи
    (severity вне уровней, инцидент уже закрыт) проходят тихо.
    """
    if incident.severity not in auto_close_levels():
        return False
    if incident.status == "closed":
        return False
    if incident.analyst_id is not None:
        audit(
            "incident_auto_close_skipped",
            {
                "reason": "assigned_to_analyst",
                "detail": incident.analyst.username if incident.analyst else None,
            },
            db=db,
            incident_id=incident.id,
        )
        return False
    for r in analysis_result.get("results") or []:
        validation = r.get("validation") or {}
        execution = r.get("execution") or {}
        if validation.get("requires_confirmation") or execution.get("mode") == "pending_confirmation":
            audit(
                "incident_auto_close_skipped",
                {
                    "reason": "action_pending_confirmation",
                    "detail": r.get("action") or execution.get("action"),
                },
                db=db,
                incident_id=incident.id,
            )
            return False

    incident.status = "closed"
    audit(
        "incident_auto_closed",
        {
            "initiated_by": "auto_close",
            "severity": incident.severity,
            "risk_score": incident.risk_score,
        },
        db=db,
        incident_id=incident.id,
    )
    notify_analyst(db, incident, "incident_auto_closed")

    # пометка в последнем анализе: только полное переприсвоение JSON-словаря
    analysis = db.scalar(
        select(Analysis)
        .where(Analysis.incident_id == incident.id)
        .order_by(Analysis.created_at.desc(), Analysis.id.desc())
    )
    if analysis is not None:
        analysis.response_raw = {**(analysis.response_raw or {}), "auto_closed": True}
    return True


# Ограничение объёма ECS-контекста: маленькой локальной модели (qwen2.5:3b)
# достаточно 800 символов на строковое значение и 6 уровней вложенности.
# Чем меньше промпт, тем быстрее prefill на CPU (stage-18, фидбек про скорость)
_ECS_MAX_DEPTH = 6


def _trim_ecs(raw: dict, max_str: int = 800) -> dict | None:
    """Глубокая копия ECS-JSON события с обрезкой длинных строк (контекст LLM).

    Исходный JSON Wazuh/Elastic (rule, agent, data, full_log) может содержать
    очень длинные значения — для промпта они обрезаются до max_str символов;
    структуры глубже _ECS_MAX_DEPTH уровней отбрасываются. None/не-dict → None.
    """
    def trim(value, depth: int):
        if depth >= _ECS_MAX_DEPTH:
            return None
        if isinstance(value, dict):
            return {key: trim(val, depth + 1) for key, val in value.items()}
        if isinstance(value, list):
            return [trim(item, depth + 1) for item in value]
        if isinstance(value, str):
            return value[:max_str]
        return value

    if not isinstance(raw, dict):
        return None
    return trim(raw, 0)


def _event_recommendations(events) -> list[str]:
    """Рекомендации, имеющиеся в самих событиях, в плоский список строк.

    В raw_data событий ключ "recommendations" — список или строка; пустые и
    отсутствующие значения пропускаются. Подаётся отдельным верхнеуровневым
    ключом контекста: системный промпт LLM просит использовать «рекомендации,
    имеющиеся в самом событии».
    """
    collected: list[str] = []
    for event in events:
        raw = (event.raw_data or {}).get("recommendations")
        if isinstance(raw, list):
            collected.extend(str(item).strip() for item in raw if str(item).strip())
        elif isinstance(raw, str) and raw.strip():
            collected.append(raw.strip())
    return collected


async def _run_incident_analysis(
    db: Session,
    incident: Incident,
    raise_on_error: bool = True,
    initiated_by: str = "manual",
) -> dict:
    """Интеллектуальный анализ инцидента (§3.3.4 + §3.4).

    Контекст → Ollama → Decision Validation Engine → аудит. Результаты
    сохраняются в Analysis (LLMAnalysis); initiated_by: manual | auto_analysis
    (для UI-бейджа, stage-12).

    Stage-23: автоисполнение рекомендаций удалено вместе с режимом симуляции
    (по явной команде пользователя 2026-11-05) — реакция всегда реальная
    (Wazuh active response) и всегда запускается ОПЕРАТОРОМ: анализ любого
    уровня только рекомендует (execution.mode = "manual_run"), playbook
    выполняет оператор кнопкой «▶ Выполнить» → POST /execute-action.
    Заблокированные DVE действия не исполняются (stage-18), отложенные до
    подтверждения ждут администратора (POST /confirm-action). Автозакрытие
    low-инцидентов (_maybe_auto_close, stage-17) сохранено — закрывается
    статус, реакции не исполняются.
    """
    asset = incident.asset
    # контекст ограничен последними 12 событиями (хронологический порядок):
    # промпт должен целиком помещаться в num_ctx (8192) — переполнение окна
    # приводит к потере контекста и «сдвигу», что бьёт и по качеству, и по
    # скорости инференса (stage-18, фидбек про скорость)
    context_events = sorted(incident.events, key=lambda x: x.timestamp)[-12:]
    context = {
        "incident_id": incident.id,
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        # сведения о защищаемом активе (§3.3.4, p:86)
        "asset": {
            "name": asset.name,
            "type": asset.type,
            "criticality": asset.criticality,
            "network_segment": asset.network_segment,
        } if asset else None,
        # последовательность развития инцидента (§3.3.4, p:86)
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "source": e.source,
                "event_type": e.event_type,
                "user": e.user,
                "src_ip": e.src_ip,
                "message": (e.raw_message or "")[:500],
                # исходный JSON Wazuh/Elastic с парсингом ECS (rule, agent,
                # data, full_log) — системный промпт LLM ожидает «json из
                # Elastic Security Solution»; длинные строки обрезаются
                "ecs": _trim_ecs(e.raw_data),
            }
            for e in context_events
        ],
        # рекомендации из самих событий (raw_data) — промпт просит учитывать
        # их в рекомендациях для дальнейших действий
        "recommendations": _event_recommendations(context_events),
    }
    prompt_text = render_full_prompt(context)

    try:
        recommendation = await analyze_incident(context)
    except Exception as exc:
        audit(
            "llm_analysis_failed",
            {"incident_id": incident.id, "error": str(exc)},
            db=db,
            incident_id=incident.id,
        )
        db.commit()
        if raise_on_error:
            raise HTTPException(
                status_code=503,
                detail=f"LLM service unavailable: {exc}",
            ) from exc
        return {"incident_id": incident.id, "error": f"LLM service unavailable: {exc}"}

    if "recommended_action" in recommendation and "action" not in recommendation:
        recommendation["action"] = recommendation["recommended_action"]
    if "explanation" in recommendation and "reason" not in recommendation:
        recommendation["reason"] = recommendation["explanation"]

    # Перечень рекомендуемых действий (§3.4, p:15): LLM может вернуть несколько
    # через запятую — каждое проходит DVE и исполняется по порядку (stage-11)
    raw_actions = str(recommendation.get("recommended_action") or "monitor")
    action_list = [a.strip() for a in raw_actions.split(",") if a.strip()] or ["monitor"]
    recommendation["recommended_action"] = ", ".join(action_list)
    recommendation["action"] = action_list[0]

    # Decision Validation Engine (§3.4) для каждого действия:
    # политика уровня риска (из БД) + playbook + актив
    results: list[dict] = []
    pending_any = False
    for action in action_list:
        playbook, validation = _validate_with_playbook(db, incident, action)

        if validation.get("requires_confirmation"):
            # Критический актив: действие отложено до подтверждения администратора
            execution = _not_executed(
                "pending_confirmation", validation["action"], validation["reason"], playbook
            )
            pending_any = True
        elif not validation["approved"]:
            # DVE заблокировал действие (заменил на monitor): ничего не
            # исполняем (stage-18, фидбек). Оператор видит блокировку и причину
            execution = _not_executed("blocked", action, validation["reason"], playbook)
        else:
            # Ручной режим (stage-23): одобренное DVE действие выполняет
            # ОПЕРАТОР кнопкой «▶ Выполнить» (владелец инцидента или админ,
            # POST /execute-action → Wazuh active response) — анализ только
            # рекомендует, реальные реакции не запускаются автоматически
            execution = _not_executed(
                "manual_run", validation["action"], validation["reason"], playbook
            )

        audit("validation_result", validation, db=db, incident_id=incident.id)
        audit(
            "playbook_selected",
            {"playbook": playbook.name if playbook else None, "action": action},
            db=db,
            incident_id=incident.id,
        )
        audit(
            # действие ещё не исполнено — ждёт ручного запуска оператором
            "action_awaiting_manual_run"
            if execution.get("mode") == "manual_run"
            else "action_executed",
            execution,
            db=db,
            incident_id=incident.id,
        )

        results.append({"action": action, "validation": validation, "execution": execution})

    if pending_any:
        notify_analyst(db, incident, "action_pending_confirmation")

    # Сохранение результатов интеллектуального анализа (модель Analysis / LLMAnalysis)
    # Поля по Таблице 3.1 (§3.2 ВКР): описание, тип атаки, достоверность, обоснование, рекомендации
    analysis = Analysis(
        incident_id=incident.id,
        model=settings.ollama_model,
        prompt=prompt_text,  # реальный текст запроса к LLM (§3.3.4)
        description=recommendation.get("description") or incident.description,
        attack_type=recommendation.get("attack_type"),
        confidence=recommendation.get("confidence"),
        explanation=recommendation.get("explanation") or recommendation.get("reason"),
        # полный перечень действий сохраняется целиком (§3.4, p:15)
        recommended_action=recommendation.get("recommended_action"),
        # полный ответ модели LLM сохраняем в JSON для расследований
        response_raw={
            "recommendation": recommendation,
            "results": results,
            "initiated_by": initiated_by,  # manual | auto_analysis (stage-12)
            # совместимость со старым форматом: первый результат
            "validation": results[0]["validation"],
            "execution": results[0]["execution"],
        },
    )
    analysis.updated_at = datetime.now(timezone.utc)
    db.add(analysis)
    # предполагаемый тип атаки попадает в карточку инцидента (§3.2, p:30)
    incident.attack_type = recommendation.get("attack_type") or incident.attack_type
    incident.status = "in_progress"
    db.commit()
    db.refresh(incident)
    db.commit()

    # ITSM-уведомление аналитикам о результатах анализа LLM
    notify_analyst(db, incident, "incident_analyzed")
    db.commit()

    return {
        "incident_id": incident.id,
        "recommendation": recommendation,
        "results": results,
        # совместимость с прежним форматом ответа: первый результат
        "validation": results[0]["validation"],
        "execution": results[0]["execution"],
    }

"""REST API — оркестрация конвейера обработки инцидентов (Главы 3.1–3.4 ВКР).

Этапы обработки события (§3.1, рис. 3.1):
сбор (ingest) → нормализация → привязка актива → корреляция по правилам БД →
оценка риска → [авто]LLM-анализ → Decision Validation Engine → playbook → аудит.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import (
    Analysis,
    Asset,
    AuditLog,
    CorrelationRule,
    Event,
    Incident,
    Notification,
    Playbook,
    User,
    ValidationPolicy,
)
from app.schemas import (
    AnalysisOut,
    AuditLogOut,
    CorrelationRuleIn,
    CorrelationRuleOut,
    IncidentDetailOut,
    IncidentOut,
    IncidentStatusIn,
    LoginIn,
    NotificationOut,
    PlaybookIn,
    PlaybookOut,
    ExecuteActionIn,
    RegisterIn,
    ValidationPolicyOut,
    WazuhAlert,
)
from app.services.auth import get_current_user, require_admin
from app.services.security import create_access_token, hash_password, verify_password
from app.services.audit import audit
from app.services.assets import resolve_asset_id
from app.services.correlation import create_or_update_incident, evaluate_correlation
from app.services.llm import analyze_incident, render_full_prompt
from app.services.normalization import normalize_wazuh
from app.services.notification import notify_analyst
from app.services.playbook import execute_playbook, load_playbook_by_action
from app.services.risk import calculate_risk
from app.services.validation import validate_recommendation

router = APIRouter(prefix="/api/v1", tags=["SIEM"])


# ---------------------------------------------------------------------------
# Авторизация (stage-09) — JWT Bearer; /ingest/wazuh и /health остаются
# открытыми для интеграции с Wazuh и мониторинга
# ---------------------------------------------------------------------------
@router.post("/auth/login")
def login(payload: LoginIn, db: Session = Depends(get_db)):
    """Вход: выдача JWT-токена по логину/паролю."""
    user = db.scalar(select(User).where(User.username == payload.username))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Неверное имя пользователя или пароль")
    token = create_access_token(user.id, user.username, user.role)
    return {"access_token": token, "token_type": "bearer"}


@router.get("/auth/me")
def me(user: User = Depends(get_current_user)):
    """Текущий пользователь по токену (для UI: username, роль)."""
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/auth/register", status_code=201)
def register(payload: RegisterIn, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    """Создание пользователя SOC — только администратором."""
    if db.scalar(select(User).where(User.username == payload.username)):
        raise HTTPException(status_code=409, detail="Пользователь с таким именем уже существует")
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    audit("user_created", {"user_id": user.id, "username": user.username, "role": user.role}, db=db)
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role}


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
    result = _ingest_alert(db, alert.model_dump(exclude_none=True))

    if result.get("_auto_analysis_incident_id"):
        incident_id = result.pop("_auto_analysis_incident_id")
        background_tasks.add_task(run_auto_analysis, incident_id)
        result["analysis"] = {"scheduled": True, "severity": result["severity"]}
    return result


def _ingest_alert(db: Session, alert_payload: dict) -> dict:
    """Полный конвейер обработки одного алерта (используется ingest и мок-сценарии)."""
    # 1. Нормализация (§3.3.1)
    normalized = normalize_wazuh(alert_payload)

    # 2. Привязка к защищаемому активу (§3.2, сущность Asset)
    asset_id = resolve_asset_id(
        db,
        src_ip=normalized.get("src_ip"),
        agent_name=normalized.get("source"),
    )
    normalized["asset_id"] = asset_id

    event = Event(
        timestamp=normalized["timestamp"],
        source=normalized["source"],
        event_type=normalized["event_type"],
        user=normalized.get("user"),
        src_ip=normalized.get("src_ip"),
        asset_id=normalized.get("asset_id"),
        criticality_level=normalized.get("criticality_level"),
        raw_message=normalized.get("raw_message"),
        raw_data=normalized["raw_data"],
    )
    db.add(event)
    db.flush()

    audit(
        "event_ingested",
        {"event_id": event.id, "source": event.source},
        db=db,
        event_id=event.id,
    )
    audit(
        "normalized",
        {
            "event_id": event.id,
            "event_type": event.event_type,
            "src_ip": event.src_ip,
            "user": event.user,
            "asset_id": event.asset_id,
            "criticality_level": event.criticality_level,
        },
        db=db,
        event_id=event.id,
    )

    # 3. Корреляция по правилам из БД (§3.3.2)
    rule, related, correlation_confidence = evaluate_correlation(db, event)

    if rule is None:
        # Инцидент не формируется: событие сохраняется в БД до появления
        # дополнительных событий, позволяющих выполнить корреляцию (§3.3.2, p:60)
        audit(
            "event_stored",
            {"event_id": event.id, "reason": "правила корреляции не сработали"},
            db=db,
            event_id=event.id,
        )
        db.commit()
        return {
            "event_id": event.id,
            "correlated": False,
            "incident_id": None,
            "related_events": 0,
        }

    # 4. Оценка риска с учётом критичности актива (§3.3.3)
    risk_events = [
        {
            "raw_data": e.raw_data,
            "event_type": e.event_type,
            "asset_criticality": _get_asset_criticality(db, e.asset_id),
        }
        for e in related
    ]
    # вероятность реализации угрозы — из данных события (§3.3.3, p:74)
    score, severity = calculate_risk(
        risk_events,
        p_implement=_p_implement(risk_events),
        correlation_confidence=correlation_confidence,
    )

    incident = create_or_update_incident(db, related, risk_score=score)
    incident.severity = severity

    audit(
        "correlated",
        {"rule": rule.name, "related_events": len(related)},
        db=db,
        incident_id=incident.id,
        event_id=event.id,
    )
    audit(
        "risk_calculated",
        {"risk_score": score, "severity": severity, "p_implement": _p_implement(risk_events)},
        db=db,
        incident_id=incident.id,
    )
    audit(
        "incident_created_or_updated",
        {"incident_id": incident.id, "risk_score": score, "severity": severity},
        db=db,
        incident_id=incident.id,
        event_id=event.id,
    )

    db.commit()
    db.refresh(incident)

    # 5. Уведомление специалистов по ИБ о новом инциденте (§3.4)
    notify_analyst(db, incident, "incident_created")
    db.commit()

    result = {
        "event_id": event.id,
        "correlated": True,
        "incident_id": incident.id,
        "related_events": len(related),
        "risk_score": score,
        "severity": severity,
        "rule": rule.name,
    }

    # 6. Инциденты из auto_analysis_levels передаются в LLM без задержек (§3.3.3, p:80) —
    # в фоне (stage-12): приём события не блокируется CPU-инференсом модели
    if settings.auto_analysis and incident.severity in _auto_analysis_levels():
        result["_auto_analysis_incident_id"] = incident.id
    return result


async def run_auto_analysis(incident_id: int) -> None:
    """Фоновый автоанализ (stage-12): собственная сессия БД, после ответа API."""
    from app.db import SessionLocal
    import logging

    logger = logging.getLogger("auto_analysis")
    db = SessionLocal()
    try:
        incident = db.get(Incident, incident_id)
        if incident is None:
            logger.warning("auto_analysis: incident %s not found", incident_id)
            return
        await _run_incident_analysis(db, incident, raise_on_error=False, initiated_by="auto_analysis")
        db.commit()
        logger.info("auto_analysis: incident %s analyzed", incident_id)
    except Exception as exc:  # фон не должен ронять приложение
        db.rollback()
        logger.error("auto_analysis failed for incident %s: %s", incident_id, exc)
    finally:
        db.close()


def _auto_analysis_levels() -> set[str]:
    """Уровни риска, анализируемые LLM автоматически (AUTO_ANALYSIS_LEVELS)."""
    return {
        level.strip().lower()
        for level in (settings.auto_analysis_levels or "critical").split(",")
        if level.strip()
    }


def _p_implement(risk_events: list[dict]) -> float:
    """Вероятность реализации угрозы (§3.3.3, p:74) из данных события.

    Явный rule.confidence в алерте (кастомные правила Wazuh) приоритетнее;
    иначе эвристика по уровню правила: level/15, зажатый в [0.05, 0.95]
    (уровень 3 → 0.2, уровень 10 → 0.67, уровень 15 → 0.95).
    """
    confidences = [
        (e.get("raw_data") or {}).get("rule", {}).get("confidence")
        for e in risk_events
    ]
    confidences = [float(c) for c in confidences if c is not None]
    if confidences:
        return max(0.05, min(0.95, max(confidences)))
    levels = [
        float((e.get("raw_data") or {}).get("rule", {}).get("level", 3) or 3)
        for e in risk_events
    ]
    return max(0.05, min(0.95, (max(levels, default=3.0)) / 15.0))


def _get_asset_criticality(db: Session, asset_id: int | None) -> str | None:
    if asset_id is None:
        return None
    asset = db.get(Asset, asset_id)
    return asset.criticality if asset else None


@router.get("/incidents", response_model=list[IncidentOut])
def incidents(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    items = list(db.scalars(
        select(Incident).order_by(Incident.created_at.desc())
    ).all())
    # from_attributes в схемах — валидация напрямую из ORM-объектов
    return [IncidentOut.model_validate(incident) for incident in items]


@router.get("/incidents/{incident_id}", response_model=IncidentDetailOut)
def incident_detail(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Детальная карточка инцидента: события, история анализов, актив (§3.2)."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentDetailOut.model_validate(incident)


ALLOWED_INCIDENT_STATUSES = ("new", "in_progress", "closed")


@router.patch("/incidents/{incident_id}/status", response_model=IncidentOut)
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Смена статуса инцидента оператором (журналируется в аудит)."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if payload.status not in ALLOWED_INCIDENT_STATUSES:
        raise HTTPException(status_code=422, detail=f"Недопустимый статус: {payload.status}")

    previous = incident.status
    incident.status = payload.status
    db.commit()
    db.refresh(incident)

    audit(
        "incident_status_changed",
        {"incident_id": incident.id, "from": previous, "to": payload.status},
        db=db,
        incident_id=incident.id,
    )
    db.commit()
    return IncidentOut.model_validate(incident)


@router.post("/incidents/{incident_id}/analyze")
async def analyze(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Ручной запуск интеллектуального анализа инцидента (§3.3.4, §3.4)."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return await _run_incident_analysis(db, incident, initiated_by="manual")


@router.post("/incidents/{incident_id}/confirm-action")
def confirm_action(
    incident_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Подтверждение администратором отложенных действий (§3.4, p:17, p:102).

    Выполняет ВСЕ действия из последней рекомендации по инциденту, которые
    разрешены политикой уровня риска (из БД) и для которых зарегистрирован
    playbook. Ответ — список результатов по каждому действию.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    analysis = db.scalar(
        select(Analysis)
        .where(Analysis.incident_id == incident_id)
        .order_by(Analysis.created_at.desc())
    )
    if not analysis or not analysis.recommended_action:
        raise HTTPException(status_code=404, detail="No pending recommendation found")

    asset = incident.asset
    action_list = [a.strip() for a in str(analysis.recommended_action).split(",") if a.strip()]
    results: list[dict] = []
    for action in action_list:
        playbook = load_playbook_by_action(db, action)
        validation = validate_recommendation(
            incident.severity,
            {"recommended_action": action},
            asset_criticality=asset.criticality if asset else None,
            playbook_found=playbook is not None,
            admin_confirmed=True,
            db=db,
        )
        execution = (
            execute_playbook(validation["action"], {"incident_id": incident.id}, db)
            if validation["approved"]
            else {"executed": False, "mode": "blocked", "action": action, "reason": validation["reason"]}
        )
        audit(
            "action_confirmed_by_admin",
            {"action": action, "validation": validation, "execution": execution},
            db=db,
            incident_id=incident.id,
        )
        results.append({"action": action, "validation": validation, "execution": execution})

    db.commit()
    return {
        "incident_id": incident.id,
        "results": results,
        # совместимость с прежним форматом ответа: первый результат
        "validation": results[0]["validation"],
        "execution": results[0]["execution"],
    }


async def _run_incident_analysis(
    db: Session,
    incident: Incident,
    raise_on_error: bool = True,
    initiated_by: str = "manual",
) -> dict:
    """Интеллектуальный анализ инцидента (§3.3.4 + §3.4).

    Контекст → Ollama → Decision Validation Engine → playbook → аудит.
    Результаты сохраняются в Analysis (LLMAnalysis);
    initiated_by: manual | auto_analysis (для UI-бейджа, stage-12).
    """
    asset = incident.asset
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
            }
            for e in sorted(incident.events, key=lambda x: x.timestamp)
        ],
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
        playbook = load_playbook_by_action(db, action)
        validation = validate_recommendation(
            incident.severity,
            {"recommended_action": action},
            asset_criticality=asset.criticality if asset else None,
            playbook_found=playbook is not None,
            db=db,
        )

        if validation.get("requires_confirmation"):
            # Критический актив: действие отложено до подтверждения администратора
            execution = {
                "executed": False,
                "mode": "pending_confirmation",
                "action": validation["action"],
                "reason": validation["reason"],
            }
            pending_any = True
        else:
            execution = execute_playbook(validation["action"], context, db)

        audit("validation_result", validation, db=db, incident_id=incident.id)
        audit(
            "playbook_selected",
            {"playbook": playbook.name if playbook else None, "action": action},
            db=db,
            incident_id=incident.id,
        )
        audit("action_executed", execution, db=db, incident_id=incident.id)

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


@router.get("/notifications", response_model=list[NotificationOut])
def notifications(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return list(db.scalars(
        select(Notification).order_by(Notification.created_at.desc())
    ).all())


@router.get("/analyses", response_model=list[AnalysisOut])
def analyses(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Статистика качества работы LLM-модуля (Таблица 3.1, §3.2 ВКР)."""
    return list(db.scalars(
        select(Analysis).order_by(Analysis.created_at.desc())
    ).all())


@router.get("/audit-logs", response_model=list[AuditLogOut])
def audit_logs(limit: int = 100, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Журнал аудита всех этапов обработки инцидентов (§3.1, модуль 8; §3.4, p:117)."""
    limit = max(1, min(limit, 500))
    return list(db.scalars(
        select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    ).all())


# ---------------------------------------------------------------------------
# CRUD правил корреляции — §3.2, p:32 («изменять алгоритмы обработки без
# внесения изменений в программный код»)
# ---------------------------------------------------------------------------
@router.get("/correlation-rules", response_model=list[CorrelationRuleOut])
def correlation_rules(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return list(db.scalars(
        select(CorrelationRule).order_by(CorrelationRule.priority.desc(), CorrelationRule.id)
    ).all())


@router.post("/correlation-rules", response_model=CorrelationRuleOut)
def create_correlation_rule(payload: CorrelationRuleIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = CorrelationRule(**payload.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    audit("correlation_rule_created", {"rule_id": rule.id, "name": rule.name}, db=db)
    db.commit()
    return CorrelationRuleOut.model_validate(rule)


@router.put("/correlation-rules/{rule_id}", response_model=CorrelationRuleOut)
def update_correlation_rule(rule_id: int, payload: CorrelationRuleIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = db.get(CorrelationRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    for field, value in payload.model_dump().items():
        setattr(rule, field, value)
    db.commit()
    db.refresh(rule)
    audit("correlation_rule_updated", {"rule_id": rule.id, "name": rule.name}, db=db)
    db.commit()
    return CorrelationRuleOut.model_validate(rule)


@router.delete("/correlation-rules/{rule_id}")
def delete_correlation_rule(rule_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = db.get(CorrelationRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    audit("correlation_rule_deleted", {"rule_id": rule_id}, db=db)
    db.commit()
    return {"deleted": True, "id": rule_id}


# ---------------------------------------------------------------------------
# CRUD сценариев реагирования — §3.4, p:112 («изменять логику выполнения
# действий без модификации программного кода»)
# ---------------------------------------------------------------------------
@router.get("/playbooks", response_model=list[PlaybookOut])
def playbooks(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return list(db.scalars(
        select(Playbook).order_by(Playbook.priority.desc(), Playbook.id)
    ).all())


@router.post("/playbooks", response_model=PlaybookOut)
def create_playbook(payload: PlaybookIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    playbook = Playbook(**payload.model_dump())
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    audit("playbook_created", {"playbook_id": playbook.id, "name": playbook.name}, db=db)
    db.commit()
    return PlaybookOut.model_validate(playbook)


@router.put("/playbooks/{playbook_id}", response_model=PlaybookOut)
def update_playbook(playbook_id: int, payload: PlaybookIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    playbook = db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    for field, value in payload.model_dump().items():
        setattr(playbook, field, value)
    db.commit()
    db.refresh(playbook)
    audit("playbook_updated", {"playbook_id": playbook.id, "name": playbook.name}, db=db)
    db.commit()
    return PlaybookOut.model_validate(playbook)


@router.delete("/playbooks/{playbook_id}")
def delete_playbook(playbook_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    playbook = db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    try:
        db.delete(playbook)
        db.commit()
    except IntegrityError as exc:
        # playbook уже использовался в response_actions — ссылочная целостность (§3.2)
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Playbook используется в выполненных действиях (response_actions) — удаление запрещено",
        ) from exc
    audit("playbook_deleted", {"playbook_id": playbook_id}, db=db)
    db.commit()
    return {"deleted": True, "id": playbook_id}


@router.post("/incidents/{incident_id}/execute-action")
def execute_action(
    incident_id: int,
    payload: ExecuteActionIn,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Ручной запуск playbook-действия администратором (stage-12).

    DVE проверяет действие (администратор снимает требование подтверждения);
    при одобрении действие исполняется через execute_playbook (симуляция при
    AUTO_RESPONSE=false). Не одобренное — возвращается с причиной.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    action = payload.action.strip()
    playbook = load_playbook_by_action(db, action)
    asset = incident.asset
    validation = validate_recommendation(
        incident.severity,
        {"recommended_action": action},
        asset_criticality=asset.criticality if asset else None,
        playbook_found=playbook is not None,
        admin_confirmed=True,
        db=db,
    )
    execution = (
        execute_playbook(validation["action"], {"incident_id": incident.id}, db)
        if validation["approved"]
        else {"executed": False, "mode": "blocked", "action": action, "reason": validation["reason"]}
    )
    audit(
        "action_executed_manually",
        {"action": action, "validation": validation, "execution": execution, "by": admin.username},
        db=db,
        incident_id=incident.id,
    )
    db.commit()
    return {
        "incident_id": incident.id,
        "action": action,
        "validation": validation,
        "execution": execution,
    }


@router.post("/demo/populate")
def demo_populate(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Мок-сценарии для демонстрации (stage-12): 19 событий → 7 инцидентов
    всех уровней риска, разные активы и классы атак (MITRE ATT&CK).

    Автоанализ для critical здесь НЕ запускается — намеренно: демонстрация
    детерминированная, анализ запускается вручную кнопкой.
    """
    now = datetime.now(timezone.utc)

    def ev(minutes_ago: float, *, level: int, groups: list[str], agent: str,
           srcip: str, user: str | None = None, description: str = "") -> dict:
        return {
            "timestamp": (now - timedelta(minutes=minutes_ago)).isoformat(),
            "rule": {"id": "900000", "level": level, "description": description or groups[0],
                     "groups": groups},
            "agent": {"id": "001", "name": agent},
            "data": {"srcip": srcip, "dstuser": user} if user else {"srcip": srcip},
            "full_log": f"{groups[0]} from {srcip}" + (f" user={user}" if user else ""),
        }

    scenarios: list[list[dict]] = [
        # T1110 brute force на критическом активе (mail-prod-01) → critical
        [ev(4 - i, level=10, groups=["syslog", "sshd", "authentication_failed"],
            agent="mail-prod-01", srcip="198.51.100.7", user="root",
            description="sshd: authentication failure") for i in range(4)],
        # T1110.003 распыление паролей на db-primary-01 (critical) → critical
        # (6 событий: порог spraying 5, чтобы перебить brute_force на том же паттерне)
        [ev(6 - i, level=9, groups=["syslog", "sshd", "authentication_failed"],
            agent="db-primary-01", srcip="198.51.100.23", user=f"user{i:02d}",
            description="sshd: authentication failure") for i in range(6)],
        # T1068/T1548 повышение привилегий на mail-prod-01 → critical
        # (40 мин назад — вне окон других сценариев: общий актив иначе склеил бы инциденты)
        [ev(40, level=15, groups=["privilege_escalation"],
            agent="mail-prod-01", srcip="198.51.100.7", user="root",
            description="user added to sudo group")],
        # T1046 сканирование fw-edge-01 (high) → high
        [ev(8 - i, level=5, groups=["syslog", "sshd"],
            agent="fw-edge-01", srcip="203.0.113.99",
            description="Connection closed by scanning host") for i in range(3)],
        # T1190 веб-атака на app-web-01 (high) → high
        [ev(5 - i, level=8, groups=["web", "attack", "sqlinjection"],
            agent="app-web-01", srcip="203.0.113.77",
            description="SQL injection attempt in query string") for i in range(2)],
        # T1204 вредоносное ПО на wks-finance-12 (medium) → high
        [ev(3, level=12, groups=["malware"],
            agent="wks-finance-12", srcip="198.51.100.50",
            description="Malicious executable detected")],
        # фоновые события уровня low → low-инцидент
        # (41/40 мин назад — вне окна malware-сценария; агент вне инвентаря →
        # актив не определён, критичность актива не завышает оценку → низкий риск)
        [ev(41 - i, level=2, groups=["syslog"],
            agent="wks-office-15", srcip="203.0.113.250",
            description="Minor system event") for i in range(2)],
    ]

    created_incidents: dict[int, dict] = {}
    events_count = 0
    for scenario in scenarios:
        for alert_payload in scenario:
            result = _ingest_alert(db, alert_payload)
            events_count += 1
            if result.get("correlated") and result.get("incident_id"):
                created_incidents[result["incident_id"]] = {
                    "incident_id": result["incident_id"],
                    "severity": result["severity"],
                    "rule": result["rule"],
                }

    audit(
        "demo_populated",
        {"events": events_count, "incidents": len(created_incidents), "by": admin.username},
        db=db,
    )
    db.commit()
    return {
        "created_events": events_count,
        "incidents": sorted(created_incidents.values(), key=lambda x: x["incident_id"]),
    }


@router.get("/validation-policy", response_model=list[ValidationPolicyOut])
def validation_policy(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Политика DVE: разрешённые действия по уровням риска (§3.4, p:103, stage-11)."""
    return list(db.scalars(select(ValidationPolicy).order_by(ValidationPolicy.id)).all())


@router.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "database": "ok",
        "llm_model": settings.ollama_model,
        "auto_response": settings.auto_response,
        "auto_analysis": settings.auto_analysis,
        "auto_analysis_levels": sorted(_auto_analysis_levels()),
    }

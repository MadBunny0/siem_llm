"""REST API — оркестрация конвейера обработки инцидентов (Главы 3.1–3.4 ВКР).

Этапы обработки события (§3.1, рис. 3.1):
сбор (ingest) → нормализация → привязка актива → корреляция по правилам БД →
оценка риска → [авто]LLM-анализ → Decision Validation Engine → playbook → аудит.

Критичность инцидента (stage-17) — по матрице «тактика MITRE → критичность»
(процедура PDF v3.1, docs/CRITICALITY_MATRIX.md); при тактике без матричного
правила — числовая модель §3.3.3. Low-инциденты после успешного автоанализа
закрываются автоматически (AUTO_CLOSE_LEVELS) — без участия человека.
"""

import random
from datetime import datetime, timezone

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
    AssetOut,
    AuditLogOut,
    CorrelationRuleIn,
    CorrelationRuleOut,
    IncidentDetailOut,
    IncidentOut,
    IncidentStatusIn,
    IngestReferenceOut,
    LoginIn,
    NotificationOut,
    PlaybookIn,
    PlaybookOut,
    ExecuteActionIn,
    RegisterIn,
    ValidationPolicyOut,
    WazuhAlert,
)
from app.services.demo_events import build_mock_scenarios
from app.services.auth import get_current_user, require_admin
from app.services.security import create_access_token, hash_password, verify_password
from app.services.audit import audit
from app.services.assets import resolve_asset_id
from app.services.correlation import create_or_update_incident, evaluate_correlation
from app.services.criticality import derive_severity
from app.services.llm import analyze_incident, render_full_prompt
from app.services.normalization import normalize_wazuh
from app.services.notification import notify_analyst
from app.services.playbook import execute_playbook, load_playbook_by_action
from app.services.risk import calculate_risk, score_to_severity
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
    # вероятность реализации угрозы — из данных события (§3.3.3, p:74);
    # числовая оценка остаётся для сортировки/отображения
    score, _ = calculate_risk(
        risk_events,
        p_implement=_p_implement(risk_events),
        correlation_confidence=correlation_confidence,
    )

    incident = create_or_update_incident(db, related, risk_score=score)

    # Критичность по матрице MITRE (stage-17, процедура PDF v3.1,
    # docs/CRITICALITY_MATRIX.md): базовая — по тактике правила, повышение —
    # по условиям процедуры (критичный актив, маркеры, периметр, флаг
    # поставщика). Без тактики — числовая модель риска (fallback, §3.3.3)
    matrix_severity, escalation_reasons = derive_severity(rule, related, incident.asset)
    if matrix_severity is not None:
        severity = matrix_severity
        severity_basis = "mitre_matrix"
    else:
        severity = score_to_severity(score)
        severity_basis = "risk_score"
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
        {
            "risk_score": score,
            "severity": severity,
            "severity_basis": severity_basis,
            "mitre_tactic": rule.mitre_tactic,
            "escalation_reasons": escalation_reasons,
            "p_implement": _p_implement(risk_events),
        },
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
    """Фоновый автоанализ (stage-12): собственная сессия БД, после ответа API.

    После успешного анализа (stage-17) инциденты из AUTO_CLOSE_LEVELS
    закрываются автоматически (_maybe_auto_close) — low обрабатывается
    без участия человека.
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
            db, incident, raise_on_error=False, initiated_by="auto_analysis"
        )
        if "error" not in result:
            _maybe_auto_close(db, incident, result)
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


def _auto_close_levels() -> set[str]:
    """Уровни, закрываемые автоматически после успешного автоанализа
    (AUTO_CLOSE_LEVELS, stage-17 — «фильтр автоматического закрытия»).

    Пустая строка/настройка → пустое множество: автозакрытие выключено.
    """
    return {
        level.strip().lower()
        for level in (settings.auto_close_levels or "").split(",")
        if level.strip()
    }


def _maybe_auto_close(db: Session, incident: Incident, analysis_result: dict) -> bool:
    """Автоматическое закрытие инцидента после успешного автоанализа (stage-17).

    Условия (все одновременно): критичность инцидента входит в
    AUTO_CLOSE_LEVELS; инцидент ещё не закрыт; аналитик не взял его в работу
    (analyst_id is None); ни одно из рекомендуемых действий не отложено до
    подтверждения администратора (pending_confirmation).

    Пометка auto_closed ставится в response_raw ПОСЛЕДНЕГО Analysis инцидента.
    ВАЖНО (грабль проекта): мутация JSON-колонки не отслеживается SQLAlchemy —
    только полное переприсвоение словаря. Изменения сохраняются коммитом
    вызывающего (run_auto_analysis).
    """
    if incident.severity not in _auto_close_levels():
        return False
    if incident.status == "closed":
        return False
    if incident.analyst_id is not None:
        return False
    for r in analysis_result.get("results") or []:
        validation = r.get("validation") or {}
        execution = r.get("execution") or {}
        if validation.get("requires_confirmation") or execution.get("mode") == "pending_confirmation":
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


# Ограничение объёма ECS-контекста: маленькой локальной модели (qwen2.5:3b)
# достаточно 1000 символов на строковое значение и 6 уровней вложенности
_ECS_MAX_DEPTH = 6


def _trim_ecs(raw: dict, max_str: int = 1000) -> dict | None:
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


ALLOWED_INCIDENT_STATUSES = ("new", "in_progress", "closed")
ALLOWED_INCIDENT_SEVERITIES = ("low", "medium", "high", "critical")


def _parse_multiselect(raw: str | None, allowed: tuple[str, ...], name: str) -> list[str]:
    """Разбор query-параметра-мультивыбора «v1,v2» фильтров списка инцидентов (stage-15).

    Пустой/отсутствующий параметр → [] (без фильтра); недопустимое
    значение → 422 с перечнем допустимых.
    """
    if not raw or not raw.strip():
        return []
    values = [v.strip() for v in raw.split(",") if v.strip()]
    invalid = [v for v in values if v not in allowed]
    if invalid:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Недопустимое значение параметра {name}: {', '.join(invalid)}. "
                f"Допустимые значения: {', '.join(allowed)}"
            ),
        )
    return list(dict.fromkeys(values))  # без дубликатов, с сохранением порядка


@router.get("/incidents", response_model=list[IncidentOut])
def incidents(
    status: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Список инцидентов (created_at ↓) с мультифильтрами (stage-15):
    ?status=new,in_progress&severity=high,critical — значения через запятую;
    пустой/отсутствующий параметр = без фильтра (прежнее поведение).
    """
    statuses = _parse_multiselect(status, ALLOWED_INCIDENT_STATUSES, "status")
    severities = _parse_multiselect(severity, ALLOWED_INCIDENT_SEVERITIES, "severity")
    query = select(Incident).order_by(Incident.created_at.desc())
    if statuses:
        query = query.where(Incident.status.in_(statuses))
    if severities:
        query = query.where(Incident.severity.in_(severities))
    items = list(db.scalars(query).all())
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


@router.patch("/incidents/{incident_id}/status", response_model=IncidentOut)
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Смена статуса инцидента оператором (журналируется в аудит).

    Закрепляет инцидент за пользователем, если он свободен; чужой инцидент
    аналитику недоступен (stage-14). Закрытый инцидент допускает только
    возврат в работу (stage-16).
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    _ensure_incident_access(incident, user, assign=True)
    if payload.status not in ALLOWED_INCIDENT_STATUSES:
        raise HTTPException(status_code=422, detail=f"Недопустимый статус: {payload.status}")
    # инцидент закрыт — операции запрещены, доступен только возврат в работу
    # (stage-16, фидбек); проверка после access-чека: reopen — только владелец
    # или админ, чужой аналитик на чужом закрытом инциденте получает 403
    if incident.status == "closed" and payload.status != "in_progress":
        raise HTTPException(
            status_code=409,
            detail="Инцидент закрыт — доступен только возврат в работу",
        )

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


def _ensure_incident_access(incident: Incident, user: User, assign: bool = False) -> None:
    """Право на операцию с инцидентом (stage-14): владелец или администратор.

    assign=True — незакреплённый инцидент закрепляется за текущим пользователем
    (первым, кто взял его в работу). Чужой незакреплённый/чужой закреплённый для
    аналитика → 403; админ работает с любым и свободный инцидент тоже закрепляет
    за собой (stage-16) — иначе бейдж «Назначен» остаётся пустым. Закреплённый
    за аналитиком инцидент админ не перехватывает.
    """
    if user.role == "admin":
        # свободный инцидент закрепляется и за админом (stage-16);
        # чужое владение не перехватывается (философия stage-14)
        if assign and incident.analyst_id is None:
            incident.analyst_id = user.id
        return
    if incident.analyst_id is None:
        if assign:
            incident.analyst_id = user.id
        return
    if incident.analyst_id != user.id:
        raise HTTPException(
            status_code=403,
            detail=(
                "Инцидент закреплён за другим аналитиком — задачи нельзя "
                "перехватывать (обратитесь к администратору)"
            ),
        )


@router.post("/incidents/{incident_id}/analyze")
async def analyze(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Ручной запуск интеллектуального анализа инцидента (§3.3.4, §3.4).

    Закрепляет инцидент за аналитиком (если свободен); чужой инцидент
    аналитику недоступен (stage-14). Закрытый инцидент анализу недоступен
    (stage-16).
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    # инцидент закрыт — операции реагирования запрещены, доступен только
    # возврат в работу (stage-16, фидбек)
    if incident.status == "closed":
        raise HTTPException(
            status_code=409,
            detail="Инцидент закрыт — анализ недоступен. Верните инцидент в работу",
        )
    _ensure_incident_access(incident, user, assign=True)
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
    playbook. Ответ — список результатов по каждому действию. Закрытый
    инцидент подтверждению недоступен (stage-16).
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    # инцидент закрыт — операции реагирования запрещены, доступен только
    # возврат в работу (stage-16, фидбек)
    if incident.status == "closed":
        raise HTTPException(
            status_code=409,
            detail="Инцидент закрыт — подтверждение действий недоступно. Верните инцидент в работу",
        )

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

    Исполнение рекомендаций (stage-17, фидбек): инциденты уровней из
    AUTO_CLOSE_LEVELS (автоконвейер) — одобренные DVE действия исполняются
    сразу; остальные уровни — только рекомендация (execution.mode =
    "manual_run"), playbook запускает оператор через POST /execute-action.
    """
    asset = incident.asset
    # контекст ограничен последними 20 событиями (хронологический порядок):
    # длинные инциденты не должны переполнять контекст маленькой модели
    context_events = sorted(incident.events, key=lambda x: x.timestamp)[-20:]
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
                # описание и шаги сценария — чтобы действие было понятно
                # оператору (stage-14 описание, stage-15 шаги)
                "playbook": playbook.name if playbook else None,
                "playbook_description": playbook.description if playbook else None,
                "playbook_steps": playbook.steps if playbook else None,
            }
            pending_any = True
        elif incident.severity in _auto_close_levels():
            # Автоконвейер (stage-17): low-инциденты обрабатываются от начала
            # до конца без человека — одобренное DVE действие исполняется сразу
            # (при AUTO_RESPONSE=false — dry run симуляция)
            execution = execute_playbook(validation["action"], context, db)
        elif not validation["approved"]:
            # Ручной режим, DVE заблокировал действие (заменил на monitor):
            # ничего не исполняем — оператор видит блокировку и причину
            execution = {
                "executed": False,
                "mode": "blocked",
                "action": action,
                "reason": validation["reason"],
                "playbook": playbook.name if playbook else None,
                "playbook_description": playbook.description if playbook else None,
                "playbook_steps": playbook.steps if playbook else None,
            }
        else:
            # Ручной режим (stage-17, фидбек): для medium/high/critical playbook
            # выполняет ОПЕРАТОР кнопкой «▶ Выполнить» (владелец инцидента или
            # админ, POST /execute-action) — анализ только рекомендует
            execution = {
                "executed": False,
                "mode": "manual_run",
                "action": validation["action"],
                "reason": validation["reason"],
                "playbook": playbook.name if playbook else None,
                "playbook_description": playbook.description if playbook else None,
                "playbook_steps": playbook.steps if playbook else None,
            }

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
    user: User = Depends(get_current_user),
):
    """Ручной запуск playbook-действия (stage-12; stage-15: владелец инцидента или админ).

    Запуск действия — работа с инцидентом: свободный инцидент закрепляется за
    исполнителем, чужой аналитику недоступен (403), админ — без ограничений.
    Закрытый инцидент действиям недоступен (stage-16).
    DVE проверяет действие; требование подтверждения критического актива
    снимает только администратор (admin_confirmed по роли): аналитик на
    критическом активе получает pending_confirmation (§3.4, p:102).
    Исполнение — через execute_playbook: при AUTO_RESPONSE=false это dry run
    (симуляция, без изменения инфраструктуры), иначе — контролируемое выполнение.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    # инцидент закрыт — операции реагирования запрещены, доступен только
    # возврат в работу (stage-16, фидбек)
    if incident.status == "closed":
        raise HTTPException(
            status_code=409,
            detail="Инцидент закрыт — выполнение действий недоступно. Верните инцидент в работу",
        )
    _ensure_incident_access(incident, user, assign=True)

    action = payload.action.strip()
    playbook = load_playbook_by_action(db, action)
    asset = incident.asset
    validation = validate_recommendation(
        incident.severity,
        {"recommended_action": action},
        asset_criticality=asset.criticality if asset else None,
        playbook_found=playbook is not None,
        admin_confirmed=user.role == "admin",
        db=db,
    )
    if validation["approved"]:
        execution = execute_playbook(validation["action"], {"incident_id": incident.id}, db)
    elif validation.get("requires_confirmation"):
        # Аналитик запустил действие на критическом активе — как в анализе:
        # сохраняется до подтверждения администратора
        execution = {
            "executed": False,
            "mode": "pending_confirmation",
            "action": validation["action"],
            "reason": validation["reason"],
            "playbook": playbook.name if playbook else None,
            "playbook_description": playbook.description if playbook else None,
            "playbook_steps": playbook.steps if playbook else None,
        }
    else:
        execution = {
            "executed": False,
            "mode": "blocked",
            "action": action,
            "reason": validation["reason"],
        }
    audit(
        "action_executed_manually",
        {
            "action": action,
            "validation": validation,
            "execution": execution,
            "by": user.username,
            "role": user.role,
        },
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
            result = _ingest_alert(db, alert_payload)
            events_count += 1
            if result.get("correlated") and result.get("incident_id"):
                created_incidents[result["incident_id"]] = {
                    "incident_id": result["incident_id"],
                    "severity": result["severity"],
                    "rule": result["rule"],
                }
            auto_id = result.get("_auto_analysis_incident_id")
            if auto_id and auto_id not in auto_analysis_ids:
                auto_analysis_ids.append(auto_id)

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
    → полный конвейер _ingest_alert. Доступно всем ролям (get_current_user,
    не require_admin). Автоанализ критических инцидентов — в фоне, как у
    POST /ingest/wazuh (stage-12); служебный ключ _auto_analysis_incident_id
    в ответ не попадает.
    """
    scenarios = build_mock_scenarios(datetime.now(timezone.utc))
    scenario = random.choice(scenarios)
    alert_payload = random.choice(scenario.events)

    result = _ingest_alert(db, alert_payload)

    # пост-обработка как в ingest_wazuh: автоанализ уходит в фон (stage-12)
    auto_incident_id = result.pop("_auto_analysis_incident_id", None)
    if auto_incident_id:
        background_tasks.add_task(run_auto_analysis, auto_incident_id)

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


@router.get("/validation-policy", response_model=list[ValidationPolicyOut])
def validation_policy(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Политика DVE: разрешённые действия по уровням риска (§3.4, p:103, stage-11)."""
    return list(db.scalars(select(ValidationPolicy).order_by(ValidationPolicy.id)).all())


@router.get("/assets", response_model=list[AssetOut])
def assets(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Справочник защищаемых активов (§3.2) — выпадающие списки UI (stage-15)."""
    return list(db.scalars(select(Asset).order_by(Asset.name)).all())


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
        "auto_close_levels": sorted(_auto_close_levels()),
    }

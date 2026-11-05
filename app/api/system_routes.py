"""Служебные и наблюдаемые эндпоинты: уведомления, статистика анализов,
журнал аудита, health — вынесено из app/api/routes.py (stage-19).

/health остаётся без авторизации (мониторинг).
"""

from fastapi import APIRouter, Depends
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import Analysis, AuditLog, Notification, User
from app.schemas import AnalysisOut, AuditLogOut, NotificationOut
from app.services.auth import get_current_user
from app.services.auto_analysis import auto_analysis_levels, auto_close_levels

router = APIRouter()


@router.get("/notifications", response_model=list[NotificationOut])
def notifications(
    limit: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Список уведомлений (created_at ↓); ?limit — необязательное окно
    (legacy-cleanup, как у /audit-logs): без параметра ответ прежний."""
    query = select(Notification).order_by(Notification.created_at.desc())
    if limit is not None:
        query = query.limit(max(1, min(limit, 500)))
    return list(db.scalars(query).all())


@router.get("/analyses", response_model=list[AnalysisOut])
def analyses(
    limit: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Статистика качества работы LLM-модуля (Таблица 3.1, §3.2 ВКР);
    ?limit — необязательное окно (legacy-cleanup): без параметра ответ прежний."""
    query = select(Analysis).order_by(Analysis.created_at.desc())
    if limit is not None:
        query = query.limit(max(1, min(limit, 500)))
    return list(db.scalars(query).all())


@router.get("/audit-logs", response_model=list[AuditLogOut])
def audit_logs(limit: int = 100, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Журнал аудита всех этапов обработки инцидентов (§3.1, модуль 8; §3.4, p:117)."""
    limit = max(1, min(limit, 500))
    return list(db.scalars(
        select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    ).all())


@router.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "database": "ok",
        "llm_model": settings.ollama_model,
        "auto_analysis": settings.auto_analysis,
        "auto_analysis_levels": sorted(auto_analysis_levels()),
        "auto_close_levels": sorted(auto_close_levels()),
    }

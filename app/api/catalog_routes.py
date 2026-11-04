"""CRUD правил корреляции и сценариев реагирования, политика DVE — вынесено
из app/api/routes.py (stage-19).

Правила корреляции — §3.2, p:32 («изменять алгоритмы обработки без внесения
изменений в программный код»); сценарии реагирования — §3.4, p:112
(«изменять логику выполнения действий без модификации программного кода»).
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import CorrelationRule, Playbook, User, ValidationPolicy
from app.schemas import (
    CorrelationRuleIn,
    CorrelationRuleOut,
    PlaybookIn,
    PlaybookOut,
    ValidationPolicyOut,
)
from app.services.audit import audit
from app.services.auth import get_current_user, require_admin

router = APIRouter()


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


@router.get("/validation-policy", response_model=list[ValidationPolicyOut])
def validation_policy(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Политика DVE: разрешённые действия по уровням риска (§3.4, p:103, stage-11)."""
    return list(db.scalars(select(ValidationPolicy).order_by(ValidationPolicy.id)).all())

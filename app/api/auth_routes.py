"""Авторизация SOC (stage-09): JWT Bearer — вынесено из app/api/routes.py (stage-19).

/ingest/wazuh и /health остаются открытыми для интеграции с Wazuh и
мониторинга (см. app/services/auth.py).
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.schemas import LoginIn, RegisterIn
from app.services.audit import audit
from app.services.auth import get_current_user, require_admin
from app.services.security import create_access_token, hash_password, verify_password

router = APIRouter()


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

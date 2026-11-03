"""Зависимости FastAPI для авторизации (JWT Bearer).

get_current_user — обязательная аутентификация всех бизнес-эндпоинтов;
require_admin — доступ только администраторам SOC (подтверждение действий
на критических активах §3.4, p:17; управление правилами и playbook).
Эндпоинты интеграции (/ingest/wazuh) и health остаются открытыми.
"""

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.services.security import decode_token

# auto_error=False — сами формируем 401 (HTTPBearer по умолчанию отдаёт 403)
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Аутентификация по Bearer-токену; 401 при отсутствии/невалидности."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Требуется авторизация (Bearer-токен)")
    try:
        payload = decode_token(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="Недействительный или просроченный токен")

    user = db.get(User, int(payload.get("sub", 0)))
    if not user:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Разрешение только для роли admin; иначе 403."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    return user

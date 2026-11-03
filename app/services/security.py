"""Хеширование паролей и JWT-токены для авторизации пользователей SOC.

Пароли: PBKDF2-HMAC-SHA256 (260 000 итераций, соль 16 байт) — без внешних
зависимостей. Формат хранения: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>.
Токены: JWT HS256 (PyJWT), payload — sub (id), username, role, exp.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt

from app.config import settings

PBKDF2_ITERATIONS = 260_000
_HASH_FORMAT = "pbkdf2_sha256${iterations}${salt}${hash}"


def hash_password(password: str) -> str:
    """Хеширование пароля для хранения в users.password_hash."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()
    return _HASH_FORMAT.format(iterations=PBKDF2_ITERATIONS, salt=salt, hash=digest)


def verify_password(password: str, stored: str) -> bool:
    """Проверка пароля против сохранённого хеша (устойчива к timing-атакам)."""
    try:
        _, iterations, salt, expected = stored.split("$")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        ).hex()
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


def create_access_token(user_id: int, username: str, role: str) -> str:
    """Выпуск JWT-токена доступа (HS256, срок из settings.token_expire_minutes)."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.token_expire_minutes)
    payload = {"sub": str(user_id), "username": username, "role": role, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    """Декодирование JWT; ошибки PyJWT (просрочен/подделан) пробрасываются выше."""
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])

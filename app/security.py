from datetime import datetime, timedelta, timezone
import secrets

import jwt
from pwdlib import PasswordHash

from app.config import ACCESS_TOKEN_MINUTES, SECRET_KEY

password_hash = PasswordHash.recommended()
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def create_access_token(user_id: int, session_id: str, expires_at: int) -> str:
    return jwt.encode(
        {"sub": str(user_id), "jti": session_id, "exp": expires_at},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def create_session_id() -> str:
    return secrets.token_urlsafe(32)


def get_token_claims(token: str) -> tuple[int, str]:
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    subject = payload.get("sub")
    session_id = payload.get("jti")
    if (
        not isinstance(subject, str)
        or not subject.isdecimal()
        or not isinstance(session_id, str)
    ):
        raise jwt.InvalidTokenError("Invalid token claims")
    return int(subject), session_id


def session_expiration() -> int:
    return int(
        (datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES)).timestamp()
    )

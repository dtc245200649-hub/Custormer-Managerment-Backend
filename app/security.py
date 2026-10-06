from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash

from app.config import ACCESS_TOKEN_MINUTES, SECRET_KEY

password_hash = PasswordHash.recommended()
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def create_access_token(user_id: int) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    return jwt.encode(
        {"sub": str(user_id), "exp": expires_at},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def get_token_user_id(token: str) -> int:
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject.isdecimal():
        raise jwt.InvalidTokenError("Invalid token subject")
    return int(subject)

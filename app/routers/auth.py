import time
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import LoginSession, User
from app.schemas import (
    CurrentUserResponse,
    LoginRequest,
    LoginResponse,
    SessionResponse,
    UserResponse,
)
from app.security import (
    create_access_token,
    create_session_id,
    get_token_claims,
    hash_password,
    session_expiration,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["authentication"])
bearer_scheme = HTTPBearer(auto_error=False)
LOCK_DURATION_SECONDS = 15 * 60
MAX_FAILED_ATTEMPTS = 5
INVALID_CREDENTIALS = "Email hoặc mật khẩu không đúng hoặc tài khoản đang tạm khóa."
dummy_password_hash = hash_password("not-a-real-user-password")


def get_active_session(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ],
    db: Annotated[Session, Depends(get_db)],
) -> LoginSession:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Chưa đăng nhập.")
    try:
        user_id, session_id = get_token_claims(credentials.credentials)
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Phiên đăng nhập không hợp lệ hoặc đã hết hạn.",
        ) from None
    session = db.get(LoginSession, session_id)
    if (
        session is None
        or session.user_id != user_id
        or session.expires_at <= int(time.time())
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Phiên đăng nhập không hợp lệ hoặc đã hết hạn.",
        )
    return session


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Annotated[Session, Depends(get_db)]) -> LoginResponse:
    normalized_email = str(payload.email).strip().lower()
    user = db.scalar(select(User).where(User.email == normalized_email))
    now = int(time.time())

    if user is None:
        verify_password(payload.password, dummy_password_hash)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS,
        )

    if user.locked_until is not None and user.locked_until > now:
        verify_password(payload.password, dummy_password_hash)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS,
        )

    if not verify_password(payload.password, user.password_hash):
        if user.locked_until is not None and user.locked_until <= now:
            user.failed_attempts = 0
            user.locked_until = None
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + LOCK_DURATION_SECONDS
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS,
        )

    user.failed_attempts = 0
    user.locked_until = None
    expires_at = session_expiration()
    session_id = create_session_id()
    db.execute(delete(LoginSession).where(LoginSession.expires_at <= now))
    db.add(
        LoginSession(
            id=session_id,
            user_id=user.id,
            expires_at=expires_at,
        )
    )
    db.commit()
    return LoginResponse(
        access_token=create_access_token(user.id, session_id, expires_at),
        expires_in=max(0, expires_at - int(time.time())),
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=CurrentUserResponse)
def get_me(
    active_session: Annotated[LoginSession, Depends(get_active_session)],
    db: Annotated[Session, Depends(get_db)],
) -> CurrentUserResponse:
    user = db.get(User, active_session.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Phiên đăng nhập không hợp lệ hoặc đã hết hạn.",
        )
    return CurrentUserResponse(
        **UserResponse.model_validate(user).model_dump(),
        expires_in=max(0, active_session.expires_at - int(time.time())),
    )


@router.post("/refresh", response_model=SessionResponse)
def refresh_session(
    active_session: Annotated[LoginSession, Depends(get_active_session)],
    db: Annotated[Session, Depends(get_db)],
) -> SessionResponse:
    expires_at = session_expiration()
    active_session.expires_at = expires_at
    db.commit()
    return SessionResponse(
        access_token=create_access_token(
            active_session.user_id,
            active_session.id,
            expires_at,
        ),
        expires_in=max(0, expires_at - int(time.time())),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    active_session: Annotated[LoginSession, Depends(get_active_session)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    db.delete(active_session)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

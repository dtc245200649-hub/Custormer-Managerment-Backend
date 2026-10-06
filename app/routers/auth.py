import time
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import LoginRequest, LoginResponse, UserResponse
from app.security import (
    create_access_token,
    get_token_user_id,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["authentication"])
bearer_scheme = HTTPBearer(auto_error=False)
LOCK_DURATION_SECONDS = 15 * 60
MAX_FAILED_ATTEMPTS = 5
INVALID_CREDENTIALS = "Email hoặc mật khẩu không đúng hoặc tài khoản đang tạm khóa."
dummy_password_hash = hash_password("not-a-real-user-password")


def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Chưa đăng nhập.")
    try:
        user_id = get_token_user_id(credentials.credentials)
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Phiên đăng nhập không hợp lệ hoặc đã hết hạn.",
        ) from None
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Phiên đăng nhập không hợp lệ hoặc đã hết hạn.",
        )
    return user


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
    db.commit()
    return LoginResponse(
        access_token=create_access_token(user.id),
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
def get_me(user: Annotated[User, Depends(get_current_user)]) -> UserResponse:
    return UserResponse.model_validate(user)

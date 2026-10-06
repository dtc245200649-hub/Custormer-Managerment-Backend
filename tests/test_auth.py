import os
import time

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-local-tests-only")
os.environ.setdefault("DATABASE_URL", "sqlite://")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import LoginSession, User
from app.security import hash_password

test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSession = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
Base.metadata.create_all(bind=test_engine)


def override_get_db():
    with TestSession() as db:
        yield db


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def setup_function() -> None:
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    with TestSession() as db:
        db.add(
            User(
                email="user@example.com",
                password_hash=hash_password("correct-password"),
                role="staff",
            )
        )
        db.commit()


def test_login_returns_access_token_and_role() -> None:
    response = client.post(
        "/api/auth/login",
        json={"email": "user@example.com", "password": "correct-password"},
    )

    assert response.status_code == 200
    assert response.json()["user"]["role"] == "staff"
    assert response.json()["access_token"]
    assert response.json()["expires_in"] > 0
    me_response = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {response.json()['access_token']}"},
    )
    assert me_response.status_code == 200
    assert me_response.json()["email"] == "user@example.com"


def test_login_uses_same_error_for_unknown_email_and_wrong_password() -> None:
    wrong_password = client.post(
        "/api/auth/login",
        json={"email": "user@example.com", "password": "wrong-password"},
    )
    unknown_email = client.post(
        "/api/auth/login",
        json={"email": "unknown@example.com", "password": "wrong-password"},
    )

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()


def test_account_is_locked_after_five_consecutive_failures() -> None:
    for _ in range(5):
        response = client.post(
            "/api/auth/login",
            json={"email": "user@example.com", "password": "wrong-password"},
        )
        assert response.status_code == 401

    with TestSession() as db:
        user = db.query(User).filter_by(email="user@example.com").one()
        assert user.failed_attempts == 5
        assert user.locked_until is not None
        assert int(time.time()) + 899 <= user.locked_until <= int(time.time()) + 900

    correct_password = client.post(
        "/api/auth/login",
        json={"email": "user@example.com", "password": "correct-password"},
    )
    assert correct_password.status_code == 401


def test_successful_login_resets_consecutive_failures() -> None:
    for _ in range(4):
        client.post(
            "/api/auth/login",
            json={"email": "user@example.com", "password": "wrong-password"},
        )

    response = client.post(
        "/api/auth/login",
        json={"email": "user@example.com", "password": "correct-password"},
    )

    assert response.status_code == 200
    with TestSession() as db:
        user = db.query(User).filter_by(email="user@example.com").one()
        assert user.failed_attempts == 0
        assert user.locked_until is None


def test_refresh_renews_active_session() -> None:
    login_response = client.post(
        "/api/auth/login",
        json={"email": "user@example.com", "password": "correct-password"},
    )
    token = login_response.json()["access_token"]
    with TestSession() as db:
        session = db.query(LoginSession).one()
        session.expires_at = int(time.time()) + 5
        db.commit()

    refresh_response = client.post(
        "/api/auth/refresh",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert refresh_response.status_code == 200
    refreshed = refresh_response.json()
    assert refreshed["access_token"]
    assert refreshed["expires_in"] > 5
    me_response = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {refreshed['access_token']}"},
    )
    assert me_response.status_code == 200
    assert me_response.json()["expires_in"] > 0


def test_logout_revokes_server_session() -> None:
    login_response = client.post(
        "/api/auth/login",
        json={"email": "user@example.com", "password": "correct-password"},
    )
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    logout_response = client.post("/api/auth/logout", headers=headers)

    assert logout_response.status_code == 204
    assert client.get("/api/auth/me", headers=headers).status_code == 401
    assert client.post("/api/auth/refresh", headers=headers).status_code == 401
    with TestSession() as db:
        assert db.query(LoginSession).count() == 0


def test_expired_server_session_is_rejected() -> None:
    login_response = client.post(
        "/api/auth/login",
        json={"email": "user@example.com", "password": "correct-password"},
    )
    token = login_response.json()["access_token"]

    with TestSession() as db:
        session = db.query(LoginSession).one()
        session.expires_at = int(time.time()) - 1
        db.commit()

    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/auth/me", headers=headers).status_code == 401
    assert client.post("/api/auth/refresh", headers=headers).status_code == 401

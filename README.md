# Customer Management Backend

FastAPI API for EP-01 sign-in. User accounts are created by an administrator using the CLI; public registration is intentionally disabled.

## Run locally (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `SECRET_KEY` in `.env` to a unique value, for example:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Copy that output into `.env`, then initialize a user and start the API:

```powershell
python -m app.create_user
uvicorn app.main:app --reload
```

The API is available at `http://localhost:8000`; interactive API docs are at `http://localhost:8000/docs`.

## API

- `POST /api/auth/login` — accepts `{ "email": "...", "password": "..." }`; returns a bearer token, its lifetime, and the user's role.
- `GET /api/auth/me` — returns the authenticated user's id, email, role, and remaining session lifetime. Send `Authorization: Bearer <token>`.
- `POST /api/auth/refresh` — renews an active session and returns a replacement bearer token. The frontend calls this only while the user has recently interacted with the page.
- `POST /api/auth/logout` — revokes the active server-side session immediately.

The session lifetime is controlled by `ACCESS_TOKEN_MINUTES` (60 minutes by default). The frontend renews it shortly before expiry only when browser activity occurred in the last five minutes; otherwise the session expires and the user must sign in again.

### Frontend API contract

Both repositories use the same contract:

| Request | Authentication | Success response |
| --- | --- | --- |
| `POST /api/auth/login` with `{ "email": "...", "password": "..." }` | None | `{ "access_token": "...", "token_type": "bearer", "expires_in": 3600, "user": { "id": 1, "email": "...", "role": "..." } }` |
| `GET /api/auth/me` | `Authorization: Bearer <token>` | `{ "id": 1, "email": "...", "role": "...", "expires_in": 3600 }` |
| `POST /api/auth/refresh` | `Authorization: Bearer <token>` | `{ "access_token": "...", "token_type": "bearer", "expires_in": 3600 }` |
| `POST /api/auth/logout` | `Authorization: Bearer <token>` | `204 No Content` |

An invalid or expired session returns `401` with a JSON `detail` message.
- `GET /api/health` — liveness check.

Five consecutive failed password attempts temporarily lock an account for 15 minutes. Failed sign-in responses use a shared message and do not disclose whether an email is registered.

Configure `CORS_ORIGINS` in `.env` to include the deployed frontend origin. Keep `.env`, the database file, and production secrets out of Git.

Run tests with `pytest`.

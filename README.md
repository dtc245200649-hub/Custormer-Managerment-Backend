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

- `POST /api/auth/login` — accepts `{ "email": "...", "password": "..." }`; returns a bearer token and the user's role.
- `GET /api/auth/me` — returns the authenticated user's id, email, and role. Send `Authorization: Bearer <token>`.
- `GET /api/health` — liveness check.

Five consecutive failed password attempts temporarily lock an account for 15 minutes. Failed sign-in responses use a shared message and do not disclose whether an email is registered.

Configure `CORS_ORIGINS` in `.env` to include the deployed frontend origin. Keep `.env`, the database file, and production secrets out of Git.

Run tests with `pytest`.

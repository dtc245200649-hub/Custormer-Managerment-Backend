from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import CORS_ORIGINS
from app.database import Base, engine
from app.models import User  # noqa: F401
from app.routers.auth import router as auth_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Customer Management API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(auth_router)


@app.get("/api/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}

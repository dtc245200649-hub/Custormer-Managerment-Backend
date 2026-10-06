import os

from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY or SECRET_KEY == "replace-with-a-long-random-secret":
    raise RuntimeError("Set a unique SECRET_KEY in the backend .env file.")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./customer_management.db")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    if origin.strip()
]

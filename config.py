"""Application configuration."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.environ.get("SENTINELSOC_SECRET", "dev-only-change-this-secret")
    DATABASE = os.environ.get("SENTINELSOC_DATABASE", str(BASE_DIR / "data" / "sentinelsoc.db"))
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    UPLOAD_FOLDER = str(BASE_DIR / "uploads")
    ALLOWED_EXTENSIONS = {"log", "txt"}
    DETECTION = {"brute_force_threshold": 5, "window_minutes": 5,
                 "multi_username_threshold": 4, "invalid_user_threshold": 3,
                 "burst_threshold": 8}

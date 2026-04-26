"""
Application configuration.
Settings control security features and can be overridden via environment variables.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings:
    APP_NAME: str = "Secure Chat Demo - CNS Lab"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Paths
    DATABASE_PATH: str = str(BASE_DIR / "database" / "chat.db")
    UPLOAD_DIR: str = str(BASE_DIR / "uploads")
    LOG_FILE: str = str(BASE_DIR / "logs" / "security_events.log")
    FRONTEND_DIR: str = str(BASE_DIR / "frontend")

    # File limits
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10 MB

    # Nonce lifetime – messages older than this are rejected as replays
    NONCE_TTL_SECONDS: int = 300  # 5 minutes

    # ── Runtime security toggles (defaults; overridden by SecurityConfig at runtime) ──
    TLS_ENABLED: bool = False
    E2E_ENABLED: bool = True
    REPLAY_PROTECTION_ENABLED: bool = True
    SIMULATE_MITM: bool = False
    SIMULATE_REPLAY: bool = False


settings = Settings()

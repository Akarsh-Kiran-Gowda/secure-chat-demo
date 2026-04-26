"""
SQLite database initialisation.
Creates all required tables if they do not exist.
All I/O is synchronous (sqlite3) – the FastAPI endpoint handlers
call blocking DB code inside run_in_executor where necessary,
but for a single-server demo direct calls are acceptable.
"""
import sqlite3
import logging
from pathlib import Path
from app.config import settings

logger = logging.getLogger(__name__)


def get_connection() -> sqlite3.Connection:
    """Open a new SQLite connection with row-factory enabled."""
    conn = sqlite3.connect(settings.DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrent read performance
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create schema on first run."""
    Path(settings.DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)

    ddl = """
    -- ── Rooms ──────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS rooms (
        room_id     TEXT PRIMARY KEY,
        owner       TEXT NOT NULL,
        invite_hash TEXT NOT NULL,          -- SHA-256 of raw invite token
        group_key   TEXT NOT NULL,          -- Base64 AES key
        created_at  TEXT NOT NULL
    );

    -- ── Messages ────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS messages (
        message_id  TEXT PRIMARY KEY,
        room_id     TEXT NOT NULL REFERENCES rooms(room_id),
        sender      TEXT NOT NULL,
        ciphertext  TEXT NOT NULL,
        timestamp   TEXT NOT NULL,
        nonce       TEXT NOT NULL,
        hash        TEXT NOT NULL,
        is_file     INTEGER NOT NULL DEFAULT 0,
        filename    TEXT NOT NULL DEFAULT ''
    );

    -- ── Nonces ──────────────────────────────────────────────────────────
    -- Used for replay-attack detection; nonces are retained for NONCE_TTL seconds.
    CREATE TABLE IF NOT EXISTS nonces (
        nonce       TEXT PRIMARY KEY,
        timestamp   TEXT NOT NULL
    );
    """

    with get_connection() as conn:
        conn.executescript(ddl)

    logger.info("Database initialised at %s", settings.DATABASE_PATH)

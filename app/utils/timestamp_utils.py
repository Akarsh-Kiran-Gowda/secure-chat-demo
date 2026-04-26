"""
Timestamp utilities for replay-attack protection.
Messages are timestamped in UTC ISO-8601 format; freshness is checked
against a configurable TTL window.
"""
from datetime import datetime, timezone
from app.config import settings


def utc_now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 string into an aware datetime (UTC)."""
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_timestamp_fresh(ts: str, ttl_seconds: int | None = None) -> bool:
    """
    Return True if *ts* is within the allowed TTL window.
    Stale timestamps indicate a replay attempt.
    """
    ttl = ttl_seconds if ttl_seconds is not None else settings.NONCE_TTL_SECONDS
    try:
        msg_time = parse_iso(ts)
        now = datetime.now(timezone.utc)
        delta = abs((now - msg_time).total_seconds())
        return delta <= ttl
    except Exception:
        return False

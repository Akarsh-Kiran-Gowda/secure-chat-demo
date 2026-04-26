"""
Nonce repository – store and look up used nonces.
Expired nonces are purged periodically to keep the table small.
"""
from app.storage.database import get_connection
from app.utils.timestamp_utils import utc_now_iso, is_timestamp_fresh
from app.config import settings


class NonceRepository:

    def exists(self, nonce: str) -> bool:
        """Return True if the nonce has already been seen (replay candidate)."""
        with get_connection() as conn:
            row = conn.execute(
                "SELECT nonce FROM nonces WHERE nonce = ?", (nonce,)
            ).fetchone()
        return row is not None

    def store(self, nonce: str, timestamp: str) -> None:
        """Persist a nonce so future duplicates are rejected."""
        with get_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO nonces (nonce, timestamp) VALUES (?, ?)",
                (nonce, timestamp),
            )

    def purge_expired(self) -> int:
        """Delete nonces whose associated message is older than NONCE_TTL.
        Returns the number of rows removed."""
        with get_connection() as conn:
            rows = conn.execute("SELECT nonce, timestamp FROM nonces").fetchall()
            expired = [
                r["nonce"] for r in rows
                if not is_timestamp_fresh(r["timestamp"], settings.NONCE_TTL_SECONDS)
            ]
            if expired:
                conn.executemany(
                    "DELETE FROM nonces WHERE nonce = ?",
                    [(n,) for n in expired],
                )
        return len(expired)


nonce_repository = NonceRepository()

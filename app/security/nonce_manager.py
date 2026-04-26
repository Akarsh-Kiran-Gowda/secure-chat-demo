"""
Nonce Manager – generates and validates message nonces.

A nonce (number used once) combined with a timestamp ensures that:
  • Each message can only be accepted once (prevents replay attacks).
  • Messages with stale timestamps are rejected even with fresh nonces.

Flow:
  Sender  → generate_nonce() → attach to message
  Receiver → validate_nonce() → accepts or rejects
"""
import secrets
import logging
from app.storage.nonce_repository import nonce_repository
from app.utils.timestamp_utils import is_timestamp_fresh

logger = logging.getLogger(__name__)


class NonceManager:

    @staticmethod
    def generate_nonce() -> str:
        """Return a 32-byte cryptographic random hex string."""
        return secrets.token_hex(32)

    def validate_nonce(self, nonce: str, timestamp: str) -> tuple[bool, str]:
        """
        Validate a nonce + timestamp pair.

        Returns (is_valid: bool, reason: str).
        Failures indicate a replay attack or a tampered message.
        """
        # 1. Check timestamp freshness
        if not is_timestamp_fresh(timestamp):
            reason = f"Stale timestamp – message too old (replay attack suspected)"
            logger.warning("[SECURITY] %s | nonce=%s", reason, nonce[:8])
            return False, reason

        # 2. Check nonce uniqueness
        if nonce_repository.exists(nonce):
            reason = "Duplicate nonce – replay attack detected and BLOCKED"
            logger.warning("[SECURITY] %s | nonce=%s", reason, nonce[:8])
            return False, reason

        # 3. Store nonce to prevent future reuse
        nonce_repository.store(nonce, timestamp)
        return True, "OK"

    @staticmethod
    def purge_expired() -> int:
        """Remove expired nonces from storage; call periodically."""
        removed = nonce_repository.purge_expired()
        if removed:
            logger.debug("[NONCE] Purged %d expired nonces", removed)
        return removed


nonce_manager = NonceManager()

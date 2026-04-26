"""
ReplayProtectionService – thin facade over NonceManager.

Provides explicit service-layer methods for the replay attack
demonstration use-case (capturing and re-submitting messages).
"""
import logging
from app.security.nonce_manager import nonce_manager
from app.utils.timestamp_utils import utc_now_iso

logger = logging.getLogger(__name__)


class ReplayProtectionService:

    def generate_nonce(self) -> str:
        """Generate a fresh nonce for outgoing messages."""
        return nonce_manager.generate_nonce()

    def validate_nonce(self, nonce: str, timestamp: str) -> tuple[bool, str]:
        """
        Validate nonce + timestamp.
        Returns (valid, reason).
        """
        return nonce_manager.validate_nonce(nonce, timestamp)

    def check_timestamp(self, timestamp: str) -> bool:
        from app.utils.timestamp_utils import is_timestamp_fresh
        return is_timestamp_fresh(timestamp)

    def store_nonce(self, nonce: str, timestamp: str) -> None:
        from app.storage.nonce_repository import nonce_repository
        nonce_repository.store(nonce, timestamp)

    def simulate_replay(self, captured_payload: dict) -> dict:
        """
        Return the captured payload unmodified – simulating an attacker
        who re-sends a previously intercepted message.
        The timestamp and nonce are intentionally left stale/duplicate
        so that replay protection can detect and reject it.
        """
        logger.warning(
            "[ATTACK] Replay simulation – re-sending captured message | nonce=%s",
            captured_payload.get("nonce", "?")[:8],
        )
        return captured_payload


replay_protection_service = ReplayProtectionService()

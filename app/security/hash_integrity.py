"""
Hash Integrity – SHA-256 message and file integrity checks.

Each message carries a hash computed over its core fields.
Before delivery the hash is recomputed and compared; a mismatch
indicates the message was modified in transit (MITM tampering).
"""
import hashlib
import base64
import logging

logger = logging.getLogger(__name__)


class HashIntegrity:

    @staticmethod
    def compute_message_hash(sender: str, ciphertext: str,
                              timestamp: str, nonce: str) -> str:
        """
        Compute SHA-256 over the canonical message string.
        Returns hex digest.
        """
        canonical = f"{sender}|{ciphertext}|{timestamp}|{nonce}"
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def verify_message_hash(sender: str, ciphertext: str,
                             timestamp: str, nonce: str, expected_hash: str) -> bool:
        """
        Recompute hash and compare.  Returns False if tampered.
        """
        actual = HashIntegrity.compute_message_hash(sender, ciphertext, timestamp, nonce)
        if actual != expected_hash:
            logger.warning(
                "[SECURITY] Integrity violation – hash mismatch | sender=%s", sender
            )
            return False
        return True

    @staticmethod
    def compute_file_hash(data: bytes) -> str:
        """Return SHA-256 hex digest of file bytes."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def verify_file_hash(data: bytes, expected_hash: str) -> bool:
        """Return False if the file was corrupted or tampered with."""
        actual = HashIntegrity.compute_file_hash(data)
        if actual != expected_hash:
            logger.warning("[SECURITY] File integrity check FAILED – hash mismatch")
            return False
        return True


hash_integrity = HashIntegrity()

"""
CryptoService – high-level encryption / decryption interface.

Delegates to E2EEManager for AES-256-GCM operations.
When E2E encryption is disabled (demo mode) messages are transmitted as plaintext.
"""
import logging
from app.security.e2ee_manager import e2ee_manager
from app.models.security_config import security_config

logger = logging.getLogger(__name__)


class CryptoService:

    def generate_group_key(self) -> str:
        """Generate a new AES-256 group key for a room."""
        return e2ee_manager.generate_group_key()

    def encrypt_message(self, plaintext: str, group_key: str) -> str:
        """
        Encrypt *plaintext* if E2E is active; otherwise pass through.
        Returning plaintext unencrypted lets the professor demonstrate
        what an attacker sees when encryption is OFF.
        """
        if not security_config.e2e_enabled:
            logger.info("[CRYPTO] E2E disabled – message transmitted as PLAINTEXT")
            return plaintext
        ciphertext = e2ee_manager.encrypt(plaintext, group_key)
        logger.debug("[CRYPTO] Message encrypted (AES-256-GCM)")
        return ciphertext

    def decrypt_message(self, ciphertext: str, group_key: str) -> str:
        """Decrypt if E2E is active; otherwise assume plaintext pass-through."""
        if not security_config.e2e_enabled:
            return ciphertext
        return e2ee_manager.decrypt(ciphertext, group_key)

    def encrypt_file(self, data: bytes, group_key: str) -> bytes:
        if not security_config.e2e_enabled:
            return data
        return e2ee_manager.encrypt_file(data, group_key)

    def decrypt_file(self, encrypted_data: bytes, group_key: str) -> bytes:
        if not security_config.e2e_enabled:
            return encrypted_data
        return e2ee_manager.decrypt_file(encrypted_data, group_key)


crypto_service = CryptoService()

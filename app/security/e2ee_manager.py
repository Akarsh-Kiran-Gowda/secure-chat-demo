"""
E2EE Manager – AES-256-GCM end-to-end encryption.

Each chat room receives a shared AES-256 group key.
Messages are encrypted with AES-GCM which provides both
confidentiality AND authenticity (built-in MAC tag).

Key material is stored in the DB as Base64 for this demo only.
In production, keys would be distributed via a Diffie-Hellman
or Signal-style key exchange.
"""
import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class E2EEManager:

    # --- Key operations ---

    @staticmethod
    def generate_group_key() -> str:
        """Generate a 256-bit AES key; return as Base64 string."""
        raw_key = os.urandom(32)          # 256 bits
        return base64.b64encode(raw_key).decode()

    @staticmethod
    def _load_key(b64_key: str) -> bytes:
        return base64.b64decode(b64_key.encode())

    # --- Encryption ---

    @staticmethod
    def encrypt(plaintext: str, b64_key: str) -> str:
        """
        AES-256-GCM encrypt *plaintext*.
        Returns a Base64-encoded JSON blob: {"iv": ..., "ct": ..., "tag": ...}
        (GCM tag is appended by cryptography library automatically.)
        """
        key = E2EEManager._load_key(b64_key)
        aesgcm = AESGCM(key)
        iv = os.urandom(12)                # 96-bit nonce recommended for GCM
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext.encode(), None)
        payload = {
            "iv": base64.b64encode(iv).decode(),
            "ct": base64.b64encode(ciphertext_with_tag).decode(),
        }
        return base64.b64encode(json.dumps(payload).encode()).decode()

    @staticmethod
    def decrypt(b64_payload: str, b64_key: str) -> str:
        """
        Decrypt the payload produced by encrypt().
        Raises ValueError on ANY failure – covers both AES-GCM tag mismatch
        (content tampered) and malformed base64/JSON (payload corrupted by MITM).
        """
        try:
            key = E2EEManager._load_key(b64_key)
            aesgcm = AESGCM(key)
            payload = json.loads(base64.b64decode(b64_payload.encode()).decode())
            iv = base64.b64decode(payload["iv"])
            ct = base64.b64decode(payload["ct"])
            plaintext = aesgcm.decrypt(iv, ct, None)
            return plaintext.decode()
        except Exception as exc:
            raise ValueError(
                "AES-GCM decryption failed – ciphertext was tampered or corrupted"
            ) from exc

    # --- File encryption (same algorithm) ---

    @staticmethod
    def encrypt_file(data: bytes, b64_key: str) -> bytes:
        """Encrypt raw file bytes; returns IV (12 B) || ciphertext+tag."""
        key = E2EEManager._load_key(b64_key)
        aesgcm = AESGCM(key)
        iv = os.urandom(12)
        encrypted = aesgcm.encrypt(iv, data, None)
        return iv + encrypted             # prepend IV for easy splitting

    @staticmethod
    def decrypt_file(encrypted_data: bytes, b64_key: str) -> bytes:
        """Inverse of encrypt_file; extracts prepended IV then decrypts."""
        key = E2EEManager._load_key(b64_key)
        aesgcm = AESGCM(key)
        iv, ct = encrypted_data[:12], encrypted_data[12:]
        return aesgcm.decrypt(iv, ct, None)


e2ee_manager = E2EEManager()

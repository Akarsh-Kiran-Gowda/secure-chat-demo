"""
ChatService – compose, validate, and persist chat messages.

Orchestrates:
  • Encryption via CryptoService
  • Nonce + timestamp validation via NonceManager
  • Hash computation via HashIntegrity
  • Persistence via MessageRepository
"""
import logging
from typing import Optional
from app.models.message import Message
from app.models.security_config import security_config
from app.services.crypto_service import crypto_service
from app.services.room_service import room_service
from app.security.nonce_manager import nonce_manager
from app.security.hash_integrity import hash_integrity
from app.storage.message_repository import message_repository
from app.utils.token_generator import generate_message_id
from app.utils.timestamp_utils import utc_now_iso

logger = logging.getLogger(__name__)


class ChatService:

    def compose_message(self, room_id: str, sender: str, plaintext: str) -> Optional[dict]:
        """
        Build an outbound message payload (sender side).
        Returns the structured dict ready for WebSocket broadcast.
        """
        group_key = room_service.get_room_key(room_id)
        if not group_key:
            logger.error("[CHAT] Room %s not found", room_id)
            return None

        nonce = nonce_manager.generate_nonce()
        timestamp = utc_now_iso()
        ciphertext = crypto_service.encrypt_message(plaintext, group_key)
        msg_hash = hash_integrity.compute_message_hash(sender, ciphertext, timestamp, nonce)

        payload = {
            "message_id": generate_message_id(),
            "room_id": room_id,
            "sender": sender,
            "ciphertext": ciphertext,
            "timestamp": timestamp,
            "nonce": nonce,
            "hash": msg_hash,
            "is_file": False,
            "filename": "",
        }
        return payload

    def receive_message(self, payload: dict) -> tuple[bool, str, Optional[Message]]:
        """
        Validate and process an inbound message payload (receiver side).

        Returns (accepted: bool, reason: str, message: Message | None).
        """
        sender = payload.get("sender", "")
        ciphertext = payload.get("ciphertext", "")
        timestamp = payload.get("timestamp", "")
        nonce = payload.get("nonce", "")
        msg_hash = payload.get("hash", "")
        room_id = payload.get("room_id", "")

        # ── 1. Integrity check ──────────────────────────────────────────
        if not hash_integrity.verify_message_hash(sender, ciphertext, timestamp, nonce, msg_hash):
            logger.warning("[SECURITY] Integrity check FAILED | sender=%s room=%s", sender, room_id)
            return False, "Integrity check failed – message may be tampered", None

        # ── 2. Replay protection ────────────────────────────────────────
        if security_config.replay_protection_enabled:
            valid, reason = nonce_manager.validate_nonce(nonce, timestamp)
            if not valid:
                logger.warning("[SECURITY] Replay attack BLOCKED | %s", reason)
                return False, reason, None

        # ── 3. Decrypt ──────────────────────────────────────────────────
        group_key = room_service.get_room_key(room_id)
        if not group_key:
            return False, "Room not found", None

        try:
            plaintext = crypto_service.decrypt_message(ciphertext, group_key)
        except ValueError as exc:
            logger.error("[SECURITY] Decryption failed – %s", exc)
            return False, str(exc), None

        # ── 4. Persist ──────────────────────────────────────────────────
        msg = Message(
            message_id=payload.get("message_id", generate_message_id()),
            room_id=room_id,
            sender=sender,
            ciphertext=ciphertext,
            timestamp=timestamp,
            nonce=nonce,
            hash=msg_hash,
        )
        message_repository.save(msg)

        # Attach plaintext for in-memory delivery (not persisted)
        payload["plaintext"] = plaintext
        return True, "OK", msg

    def get_room_history(self, room_id: str) -> list[dict]:
        """Return messages for a room (ciphertext only – clients decrypt)."""
        messages = message_repository.find_by_room(room_id)
        return [
            {
                "message_id": m.message_id,
                "room_id": m.room_id,
                "sender": m.sender,
                "ciphertext": m.ciphertext,
                "timestamp": m.timestamp,
                "nonce": m.nonce,
                "hash": m.hash,
                "is_file": m.is_file,
                "filename": m.filename,
            }
            for m in messages
        ]


chat_service = ChatService()

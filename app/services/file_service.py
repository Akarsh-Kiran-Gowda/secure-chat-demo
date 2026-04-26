"""
FileService – secure file upload, encryption, integrity verification, and download.

Flow (upload):
  1. Client sends file bytes + metadata via HTTP multipart.
  2. FileService computes SHA-256 hash of raw bytes.
  3. Bytes are encrypted with the room's AES group key.
  4. Encrypted file is stored on disk.
  5. A chat message with is_file=True and the hash is broadcast to the room.

Flow (download):
  1. Client requests a file by message_id.
  2. Server loads encrypted blob from disk.
  3. Blob is decrypted and returned.
  4. Client verifies SHA-256 against the stored hash.
"""
import os
import logging
from pathlib import Path
from app.config import settings
from app.services.crypto_service import crypto_service
from app.services.room_service import room_service
from app.security.hash_integrity import hash_integrity
from app.utils.token_generator import generate_message_id
from app.utils.timestamp_utils import utc_now_iso
from app.security.nonce_manager import nonce_manager
from app.storage.message_repository import message_repository
from app.models.message import Message

logger = logging.getLogger(__name__)


class FileService:

    def __init__(self):
        self.upload_dir = Path(settings.UPLOAD_DIR)
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def save_file(self, room_id: str, sender: str, filename: str, data: bytes) -> dict:
        """
        Encrypt and persist an uploaded file.
        Returns a chat-message payload to broadcast to the room.
        """
        if len(data) > settings.MAX_FILE_SIZE:
            raise ValueError(f"File exceeds max size ({settings.MAX_FILE_SIZE} bytes)")

        group_key = room_service.get_room_key(room_id)
        if not group_key:
            raise ValueError(f"Room {room_id} not found")

        # Compute integrity hash BEFORE encryption
        file_hash = hash_integrity.compute_file_hash(data)

        # Encrypt file content
        encrypted = crypto_service.encrypt_file(data, group_key)

        # Persist to disk using message_id as filename
        message_id = generate_message_id()
        dest = self.upload_dir / f"{message_id}.enc"
        dest.write_bytes(encrypted)

        nonce = nonce_manager.generate_nonce()
        timestamp = utc_now_iso()

        # The "ciphertext" field carries the file hash for integrity verification
        msg_hash = hash_integrity.compute_message_hash(sender, file_hash, timestamp, nonce)

        payload = {
            "message_id": message_id,
            "room_id": room_id,
            "sender": sender,
            "ciphertext": file_hash,   # hash acts as integrity reference
            "timestamp": timestamp,
            "nonce": nonce,
            "hash": msg_hash,
            "is_file": True,
            "filename": filename,
        }

        # Persist to DB so the download endpoint can look it up by message_id
        message_repository.save(Message(
            message_id=message_id,
            room_id=room_id,
            sender=sender,
            ciphertext=file_hash,
            timestamp=timestamp,
            nonce=nonce,
            hash=msg_hash,
            is_file=True,
            filename=filename,
        ))

        logger.info("[FILE] Saved encrypted file | room=%s sender=%s file=%s", room_id, sender, filename)
        return payload

    def load_file(self, message_id: str, room_id: str) -> tuple[bytes, str]:
        """
        Decrypt and return the raw file bytes plus the stored hash.
        Raises FileNotFoundError if the file does not exist.
        """
        src = self.upload_dir / f"{message_id}.enc"
        if not src.exists():
            raise FileNotFoundError(f"File for message {message_id} not found")

        group_key = room_service.get_room_key(room_id)
        if not group_key:
            raise ValueError(f"Room {room_id} not found")

        encrypted = src.read_bytes()
        raw = crypto_service.decrypt_file(encrypted, group_key)

        stored_hash = hash_integrity.compute_file_hash(raw)
        logger.info("[FILE] Decrypted file | message=%s", message_id)
        return raw, stored_hash


file_service = FileService()

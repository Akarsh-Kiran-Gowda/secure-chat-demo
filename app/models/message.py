"""
Message model representing a single chat message payload.
Hash field enables SHA-256 integrity verification at the receiver.
"""
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Message:
    message_id: str
    room_id: str
    sender: str
    ciphertext: str      # Base64-encoded AES-encrypted content (or plaintext in insecure mode)
    timestamp: str       # ISO-8601 UTC timestamp
    nonce: str           # Random nonce – prevents replay attacks
    hash: str            # SHA-256 of (sender + ciphertext + timestamp + nonce)
    is_file: bool = False
    filename: str = ""

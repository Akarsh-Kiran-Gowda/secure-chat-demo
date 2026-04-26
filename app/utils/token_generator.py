"""
Secure random token generation for room invite codes.
Uses secrets module to guarantee cryptographic randomness.
"""
import secrets
import hashlib


def generate_invite_token(length: int = 32) -> str:
    """Return a URL-safe cryptographically random token."""
    return secrets.token_urlsafe(length)


def hash_token(token: str) -> str:
    """Return SHA-256 hex digest of the token for safe DB storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_user_id() -> str:
    """Return a random hex user/session identifier."""
    return secrets.token_hex(16)


def generate_room_id() -> str:
    """Return a short random room identifier."""
    return secrets.token_hex(8)


def generate_message_id() -> str:
    """Return a random message identifier."""
    return secrets.token_hex(12)

"""
Data models for Rooms, Messages, Users, and SecurityConfig.
Uses plain dataclasses / Pydantic BaseModel for validation.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────
# Room
# ─────────────────────────────────────────────
@dataclass
class Room:
    room_id: str
    owner: str
    invite_hash: str          # HMAC/hash of invite token stored in DB
    group_key: str            # Base64-encoded AES group key (encrypted or raw for demo)
    created_at: datetime = field(default_factory=datetime.utcnow)
    members: list[str] = field(default_factory=list)

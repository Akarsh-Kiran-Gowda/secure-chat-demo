"""
RoomService – business logic for room lifecycle management.

Rooms are the core security boundary: each room holds a shared AES
group key that is distributed to members via invite tokens.
"""
import logging
from datetime import datetime
from typing import Optional
from app.models.room import Room
from app.storage.room_repository import room_repository
from app.services.crypto_service import crypto_service
from app.utils.token_generator import (
    generate_room_id, generate_invite_token, hash_token
)

logger = logging.getLogger(__name__)


class RoomService:

    def create_room(self, owner: str) -> tuple[Room, str]:
        """
        Create a new room.

        Returns (room, raw_invite_token) – the raw token is shown to the
        creator once and never stored; only its hash is persisted.
        """
        room_id = generate_room_id()
        raw_token = generate_invite_token()
        invite_hash = hash_token(raw_token)
        group_key = crypto_service.generate_group_key()

        room = Room(
            room_id=room_id,
            owner=owner,
            invite_hash=invite_hash,
            group_key=group_key,
            created_at=datetime.utcnow(),
            members=[owner],
        )
        room_repository.save(room)
        logger.info("[ROOM] Created room=%s owner=%s", room_id, owner)
        return room, raw_token

    def join_room(self, raw_token: str, username: str) -> Optional[Room]:
        """
        Validate an invite token and add *username* to the room.
        Returns the Room on success, None on invalid token.
        """
        invite_hash = hash_token(raw_token)
        room = room_repository.find_by_invite_hash(invite_hash)
        if room is None:
            logger.warning("[ROOM] Invalid invite token | user=%s", username)
            return None
        if username not in room.members:
            room.members.append(username)
        logger.info("[ROOM] %s joined room=%s", username, room.room_id)
        return room

    def get_room(self, room_id: str) -> Optional[Room]:
        return room_repository.find_by_id(room_id)

    def get_room_key(self, room_id: str) -> Optional[str]:
        room = room_repository.find_by_id(room_id)
        return room.group_key if room else None

    def list_rooms(self) -> list[Room]:
        return room_repository.list_all()

    def generate_invite_token(self, room_id: str) -> Optional[str]:
        """
        Re-generate an invite token for an existing room.
        Old token is invalidated (hash replaced in DB).
        """
        room = room_repository.find_by_id(room_id)
        if not room:
            return None
        raw_token = generate_invite_token()
        room.invite_hash = hash_token(raw_token)
        room_repository.save(room)
        return raw_token

    def verify_invite_token(self, raw_token: str) -> bool:
        invite_hash = hash_token(raw_token)
        return room_repository.find_by_invite_hash(invite_hash) is not None


room_service = RoomService()

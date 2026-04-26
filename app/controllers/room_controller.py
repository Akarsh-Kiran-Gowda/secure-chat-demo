"""
Room controller – HTTP endpoints for room creation and joining.
"""
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.room_service import room_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/rooms", tags=["rooms"])


class CreateRoomRequest(BaseModel):
    owner: str


class JoinRoomRequest(BaseModel):
    invite_token: str
    username: str


@router.post("/create")
def create_room(req: CreateRoomRequest):
    """Create a new chat room; returns room info and a one-time invite token."""
    if not req.owner.strip():
        raise HTTPException(400, "Owner name required")
    room, token = room_service.create_room(req.owner.strip())
    logger.info("[ROOM] Created room=%s owner=%s", room.room_id, room.owner)
    return {
        "room_id": room.room_id,
        "owner": room.owner,
        "invite_token": token,   # show once – never stored in plain form
        "created_at": room.created_at.isoformat(),
    }


@router.post("/join")
def join_room(req: JoinRoomRequest):
    """Join a room using an invite token.  Returns room_id and group_key."""
    if not req.invite_token.strip() or not req.username.strip():
        raise HTTPException(400, "invite_token and username required")
    room = room_service.join_room(req.invite_token.strip(), req.username.strip())
    if room is None:
        raise HTTPException(403, "Invalid or expired invite token")
    return {
        "room_id": room.room_id,
        "group_key": room.group_key,   # AES key distributed to room members
        "owner": room.owner,
    }


@router.get("/{room_id}/key")
def get_room_key(room_id: str):
    """
    Return the AES group key for a room.
    In a real system this would require authentication; here it's open for demo purposes.
    """
    key = room_service.get_room_key(room_id)
    if not key:
        raise HTTPException(404, "Room not found")
    return {"room_id": room_id, "group_key": key}


@router.get("/{room_id}")
def get_room(room_id: str):
    """Retrieve room metadata."""
    room = room_service.get_room(room_id)
    if not room:
        raise HTTPException(404, "Room not found")
    return {
        "room_id": room.room_id,
        "owner": room.owner,
        "created_at": room.created_at.isoformat(),
        "members": room.members,
    }


@router.get("/")
def list_rooms():
    """List all rooms (demo convenience endpoint)."""
    rooms = room_service.list_rooms()
    return [
        {"room_id": r.room_id, "owner": r.owner, "created_at": r.created_at.isoformat()}
        for r in rooms
    ]

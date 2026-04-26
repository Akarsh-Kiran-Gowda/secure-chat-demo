"""
Chat controller – HTTP endpoint for message history retrieval.
Real-time messaging is handled via WebSocket, not HTTP.
"""
from fastapi import APIRouter, HTTPException
from app.services.chat_service import chat_service
from app.services.room_service import room_service

router = APIRouter(prefix="/api/chat", tags=["chat"])


@router.get("/{room_id}/history")
def get_history(room_id: str, limit: int = 50):
    """
    Return the last *limit* messages for a room.
    Messages are returned as ciphertext; clients decrypt locally using
    the group key obtained at join time.
    """
    room = room_service.get_room(room_id)
    if not room:
        raise HTTPException(404, "Room not found")
    messages = chat_service.get_room_history(room_id)
    return {"room_id": room_id, "messages": messages[-limit:]}

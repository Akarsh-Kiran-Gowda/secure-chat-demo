"""
File controller – HTTP endpoints for secure file upload and download.
"""
import logging
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import Response
from app.services.file_service import file_service
from app.services.room_service import room_service
from app.security.hash_integrity import hash_integrity
from app.storage.message_repository import message_repository
from app.websocket.websocket_manager import ws_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/files", tags=["files"])


@router.post("/upload")
async def upload_file(
    room_id: str = Form(...),
    sender: str = Form(...),
    file: UploadFile = File(...),
):
    """
    Upload an encrypted file to the server.

    Steps:
      1. Compute SHA-256 hash of raw bytes
      2. Encrypt with room AES key
      3. Store encrypted blob on disk
      4. Broadcast a file-message to the room via WebSocket
    """
    if not room_service.get_room(room_id):
        raise HTTPException(404, "Room not found")

    data = await file.read()
    if len(data) == 0:
        raise HTTPException(400, "Empty file")

    try:
        payload = file_service.save_file(room_id, sender, file.filename or "file", data)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    # Broadcast file-message to room so all members receive the download link
    await ws_manager._broadcast(room_id, {
        "type": "chat",
        **payload,
        "plaintext": f"[FILE] {file.filename}",
    })

    logger.info("[FILE] Uploaded file=%s room=%s sender=%s", file.filename, room_id, sender)
    return {
        "message_id": payload["message_id"],
        "filename": file.filename,
        "hash": payload["ciphertext"],   # SHA-256 of original file
        "status": "uploaded",
    }


@router.get("/download/{message_id}")
def download_file(message_id: str, room_id: str):
    """
    Decrypt and return the raw file bytes.
    The caller should verify SHA-256 against the hash stored in the message.
    """
    msg = message_repository.find_by_id(message_id)
    if not msg or not msg.is_file:
        raise HTTPException(404, "File not found")

    try:
        raw_bytes, computed_hash = file_service.load_file(message_id, room_id)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(404, str(exc))

    # The stored hash is in msg.ciphertext for file messages
    if not hash_integrity.verify_file_hash(raw_bytes, msg.ciphertext):
        raise HTTPException(409, "File integrity check FAILED – file may be corrupted or tampered")

    return Response(
        content=raw_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{msg.filename}"'},
    )

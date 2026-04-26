"""
Message repository – CRUD operations for the messages table.
"""
import sqlite3
from typing import Optional
from app.storage.database import get_connection
from app.models.message import Message


class MessageRepository:

    def save(self, msg: Message) -> None:
        sql = """
        INSERT OR REPLACE INTO messages
            (message_id, room_id, sender, ciphertext, timestamp, nonce, hash, is_file, filename)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with get_connection() as conn:
            conn.execute(sql, (
                msg.message_id, msg.room_id, msg.sender,
                msg.ciphertext, msg.timestamp, msg.nonce, msg.hash,
                int(msg.is_file), msg.filename,
            ))

    def find_by_room(self, room_id: str, limit: int = 100) -> list[Message]:
        sql = """
        SELECT * FROM messages WHERE room_id = ?
        ORDER BY timestamp ASC LIMIT ?
        """
        with get_connection() as conn:
            rows = conn.execute(sql, (room_id, limit)).fetchall()
        return [self._row_to_message(r) for r in rows]

    def find_by_id(self, message_id: str) -> Optional[Message]:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM messages WHERE message_id = ?", (message_id,)
            ).fetchone()
        return self._row_to_message(row) if row else None

    @staticmethod
    def _row_to_message(row: sqlite3.Row) -> Message:
        return Message(
            message_id=row["message_id"],
            room_id=row["room_id"],
            sender=row["sender"],
            ciphertext=row["ciphertext"],
            timestamp=row["timestamp"],
            nonce=row["nonce"],
            hash=row["hash"],
            is_file=bool(row["is_file"]),
            filename=row["filename"],
        )


message_repository = MessageRepository()

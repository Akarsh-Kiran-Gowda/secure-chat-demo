"""
Room repository – CRUD operations for the rooms table.
"""
import sqlite3
from typing import Optional
from app.storage.database import get_connection
from app.models.room import Room


class RoomRepository:

    def save(self, room: Room) -> None:
        sql = """
        INSERT OR REPLACE INTO rooms (room_id, owner, invite_hash, group_key, created_at)
        VALUES (?, ?, ?, ?, ?)
        """
        with get_connection() as conn:
            conn.execute(sql, (
                room.room_id,
                room.owner,
                room.invite_hash,
                room.group_key,
                room.created_at.isoformat(),
            ))

    def find_by_id(self, room_id: str) -> Optional[Room]:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM rooms WHERE room_id = ?", (room_id,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_room(row)

    def find_by_invite_hash(self, invite_hash: str) -> Optional[Room]:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM rooms WHERE invite_hash = ?", (invite_hash,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_room(row)

    def list_all(self) -> list[Room]:
        with get_connection() as conn:
            rows = conn.execute("SELECT * FROM rooms ORDER BY created_at DESC").fetchall()
        return [self._row_to_room(r) for r in rows]

    @staticmethod
    def _row_to_room(row: sqlite3.Row) -> Room:
        from datetime import datetime
        return Room(
            room_id=row["room_id"],
            owner=row["owner"],
            invite_hash=row["invite_hash"],
            group_key=row["group_key"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )


room_repository = RoomRepository()

"""
User model – lightweight; users are identified by a chosen display name
and a session-scoped UUID.  No passwords are required for the demo.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class User:
    user_id: str
    username: str
    current_room: Optional[str] = None

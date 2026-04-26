"""
WebSocket Manager – handles all real-time client connections.

Architecture:
  • Maintains a dict of {room_id: {user_id: WebSocket}}
  • On each inbound message, runs the full security pipeline:
      1. MITM simulation (if enabled)
      2. Chat service validation (integrity + replay + decrypt)
      3. Broadcast to room members

Security pipeline per message:
  Client  →  [MITM intercept?]  →  [integrity check]
          →  [replay check]     →  [decrypt]
          →  [broadcast to room]
"""
import json
import logging
from fastapi import WebSocket
from app.services.chat_service import chat_service
from app.services.mitm_simulation_service import mitm_simulation_service
from app.attack_simulation import mitm_attack, replay_attack
from app.models.security_config import security_config

logger = logging.getLogger(__name__)

# Security Monitor event bus – consumed by SSE or polling endpoint
security_events: list[dict] = []


def _push_event(event: dict) -> None:
    security_events.append(event)
    if len(security_events) > 300:
        security_events.clear()


class WebSocketManager:
    """Manages WebSocket connections grouped by room."""

    def __init__(self):
        # room_id → {user_id: WebSocket}
        self._rooms: dict[str, dict[str, WebSocket]] = {}

    async def connect(self, websocket: WebSocket, room_id: str, user_id: str) -> None:
        await websocket.accept()
        self._rooms.setdefault(room_id, {})[user_id] = websocket
        logger.info("[WS] Connected | room=%s user=%s", room_id, user_id)
        await self._broadcast_system(room_id, f"{user_id} joined the room", exclude=None)

    async def disconnect(self, room_id: str, user_id: str) -> None:
        room = self._rooms.get(room_id, {})
        room.pop(user_id, None)
        logger.info("[WS] Disconnected | room=%s user=%s", room_id, user_id)
        await self._broadcast_system(room_id, f"{user_id} left the room", exclude=None)

    async def handle_message(self, raw: str, room_id: str, sender_id: str) -> None:
        """Process one inbound WebSocket message through the full security pipeline."""
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("[WS] Malformed JSON from %s", sender_id)
            return

        msg_type = payload.get("type", "chat")

        if msg_type == "ping":
            return  # heartbeat – ignore

        if msg_type != "chat":
            logger.debug("[WS] Unknown message type: %s", msg_type)
            return

        is_replay_sim = payload.get("_replay_sim", False)

        # ── Step 1a: Capture original (clean) payload for replay demo ──
        # Must happen BEFORE MITM modifies the ciphertext, otherwise the
        # captured message has a broken hash and can never pass integrity.
        # Also runs when MITM is off – replay simulation is independent.
        if security_config.simulate_replay and not is_replay_sim:
            replay_attack.capture_message(payload)

        # ── Step 1b: MITM interception ─────────────────────────────────
        # Skip for already-replayed messages so MITM does not inject a
        # second time and corrupt the hash before the nonce check runs.
        if security_config.simulate_mitm and not is_replay_sim:
            payload = mitm_attack.intercept_message(payload)
            _push_event({
                "type": "MITM_INTERCEPT",
                "sender": payload.get("sender"),
                "e2e_active": security_config.e2e_enabled,
                "tls_active": security_config.tls_enabled,
            })

        # ── Step 2: Validate + decrypt via ChatService ─────────────────
        accepted, reason, msg = chat_service.receive_message(payload)

        if not accepted:
            # Determine if this was a replay block or integrity failure
            if "replay" in reason.lower() or "nonce" in reason.lower():
                event_type = "REPLAY_BLOCKED"
                replay_attack.record_blocked(payload.get("nonce", ""), reason)
            else:
                event_type = "INTEGRITY_FAILED"

            _push_event({"type": event_type, "reason": reason, "sender": payload.get("sender")})
            logger.warning("[SECURITY] Message rejected: %s", reason)

            # Notify sender of rejection
            await self._send_to_user(room_id, sender_id, {
                "type": "error",
                "reason": reason,
                "event": event_type,
            })
            return

        # ── Step 3: Broadcast to room ──────────────────────────────────
        broadcast_payload = {
            "type": "chat",
            "message_id": payload.get("message_id"),
            "room_id": room_id,
            "sender": payload.get("sender"),
            "ciphertext": payload.get("ciphertext"),
            "plaintext": payload.get("plaintext", ""),  # decrypted content
            "timestamp": payload.get("timestamp"),
            "nonce": payload.get("nonce"),
            "hash": payload.get("hash"),
            "is_file": payload.get("is_file", False),
            "filename": payload.get("filename", ""),
        }
        await self._broadcast(room_id, broadcast_payload)

    async def trigger_replay(self, room_id: str) -> None:
        """
        Trigger a replay attack simulation.
        Takes the most recently captured message and re-submits it.
        """
        captured = replay_attack.get_captured_messages()
        if not captured:
            logger.info("[REPLAY] No captured messages to replay")
            return

        replayed = replay_attack.build_replay_payload(captured[-1])
        # Mark as a replay simulation so handle_message skips MITM injection
        # (the goal is to demonstrate nonce/timestamp rejection, not MITM)
        replayed["_replay_sim"] = True
        _push_event({"type": "REPLAY_ATTEMPT", "sender": replayed.get("sender")})

        # Submit through the normal pipeline – replay protection should block it
        sender_id = replayed.get("sender", "attacker")
        raw = json.dumps(replayed)
        await self.handle_message(raw, room_id, sender_id)

    # ── Internal helpers ───────────────────────────────────────────────

    async def _broadcast(self, room_id: str, payload: dict) -> None:
        dead = []
        for uid, ws in self._rooms.get(room_id, {}).items():
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(uid)
        for uid in dead:
            await self.disconnect(room_id, uid)

    async def _broadcast_system(self, room_id: str, text: str, exclude: str | None) -> None:
        msg = {"type": "system", "text": text}
        for uid, ws in self._rooms.get(room_id, {}).items():
            if uid == exclude:
                continue
            try:
                await ws.send_json(msg)
            except Exception:
                pass

    async def _send_to_user(self, room_id: str, user_id: str, payload: dict) -> None:
        ws = self._rooms.get(room_id, {}).get(user_id)
        if ws:
            try:
                await ws.send_json(payload)
            except Exception:
                pass

    def room_member_count(self, room_id: str) -> int:
        return len(self._rooms.get(room_id, {}))


# Module-level singleton
ws_manager = WebSocketManager()

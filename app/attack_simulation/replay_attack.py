"""
Replay Attack Simulation Module

Demonstrates a replay attack: an attacker captures a legitimate message
and re-transmits it later to trick the server into processing it again.

Real-world examples:
  • Session token replay            • Authentication token replay
  • Financial transaction replay    • Command replay in SCADA systems

Defence:
  • Nonce (number used once) – each message carries a unique random value
  • Timestamp window          – messages older than NONCE_TTL are rejected
  • Server-side nonce store   – duplicate nonces are rejected outright

Security demonstration lessons:
  • Replay without protection:  server processes the same message twice
  • Replay with protection:     server detects duplicate nonce and rejects
"""
import copy
import logging
from app.models.security_config import security_config

logger = logging.getLogger(__name__)

# Buffer of captured message payloads available for replay
_captured: list[dict] = []

# Event log for Security Monitor
replay_log: list[dict] = []


def _log(entry: dict) -> None:
    replay_log.append(entry)
    if len(replay_log) > 500:
        replay_log.clear()


def capture_message(payload: dict) -> None:
    """
    Store a copy of the payload to simulate an attacker capturing it.
    Called automatically in simulation mode.
    """
    if not security_config.simulate_replay:
        return
    captured = copy.deepcopy(payload)
    _captured.append(captured)
    if len(_captured) > 50:
        _captured.pop(0)

    _log({
        "event": "REPLAY_CAPTURE",
        "sender": payload.get("sender"),
        "nonce": payload.get("nonce", "")[:12] + "...",
        "timestamp": payload.get("timestamp"),
    })
    logger.warning("[ATTACK/REPLAY] Message captured for replay | nonce=%s", payload.get("nonce", "")[:8])


def get_captured_messages() -> list[dict]:
    """Return all currently captured messages available for replay."""
    return list(_captured)


def build_replay_payload(original: dict) -> dict:
    """
    Build a replay payload from a captured message.
    The nonce and timestamp are left unchanged (stale) so that
    replay protection can detect and reject the message.
    """
    replay = copy.deepcopy(original)
    _log({
        "event": "REPLAY_ATTEMPT",
        "sender": original.get("sender"),
        "nonce": original.get("nonce", "")[:12] + "...",
        "note": "Re-sending captured message with original nonce – should be blocked",
    })
    logger.warning("[ATTACK/REPLAY] Replaying captured message | nonce=%s", original.get("nonce", "")[:8])
    return replay


def record_blocked(nonce: str, reason: str) -> None:
    """Called by the WebSocket manager when a replay is blocked."""
    _log({
        "event": "REPLAY_BLOCKED",
        "nonce": nonce[:12] + "...",
        "reason": reason,
    })
    logger.warning("[SECURITY] Replay attack BLOCKED | reason=%s", reason)


def get_replay_log() -> list[dict]:
    return list(replay_log)

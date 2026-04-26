"""
Security controller – endpoints for toggling security settings and
reading the Security Monitor event log.
"""
import logging
from fastapi import APIRouter
from pydantic import BaseModel
from app.models.security_config import security_config
from app.websocket.websocket_manager import security_events
from app.attack_simulation.mitm_attack import get_attack_log as mitm_log
from app.attack_simulation.replay_attack import get_replay_log, get_captured_messages

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/security", tags=["security"])


class SecurityConfigUpdate(BaseModel):
    tls_enabled: bool | None = None
    e2e_enabled: bool | None = None
    replay_protection_enabled: bool | None = None
    simulate_mitm: bool | None = None
    simulate_replay: bool | None = None


@router.get("/status")
def get_status():
    """Return the current security configuration."""
    return {
        "tls_enabled": security_config.tls_enabled,
        "e2e_enabled": security_config.e2e_enabled,
        "replay_protection_enabled": security_config.replay_protection_enabled,
        "simulate_mitm": security_config.simulate_mitm,
        "simulate_replay": security_config.simulate_replay,
    }


@router.post("/update")
def update_config(req: SecurityConfigUpdate):
    """
    Toggle individual security features.
    Changes take effect immediately for all subsequent messages.
    """
    changed = []

    if req.tls_enabled is not None:
        security_config.tls_enabled = req.tls_enabled
        changed.append(f"tls_enabled={req.tls_enabled}")

    if req.e2e_enabled is not None:
        security_config.e2e_enabled = req.e2e_enabled
        changed.append(f"e2e_enabled={req.e2e_enabled}")

    if req.replay_protection_enabled is not None:
        security_config.replay_protection_enabled = req.replay_protection_enabled
        changed.append(f"replay_protection_enabled={req.replay_protection_enabled}")

    if req.simulate_mitm is not None:
        security_config.simulate_mitm = req.simulate_mitm
        changed.append(f"simulate_mitm={req.simulate_mitm}")

    if req.simulate_replay is not None:
        security_config.simulate_replay = req.simulate_replay
        changed.append(f"simulate_replay={req.simulate_replay}")

    if changed:
        logger.info("[SECURITY] Config updated: %s", ", ".join(changed))

    cfg = get_status()
    return {"status": "ok", "changed": changed, **cfg}


@router.get("/events")
def get_events(limit: int = 50):
    """Return recent Security Monitor events (MITM, replay, integrity failures)."""
    all_events = security_events + mitm_log() + get_replay_log()
    return {"events": all_events[-limit:]}


@router.post("/trigger-replay/{room_id}")
async def trigger_replay(room_id: str):
    """
    Immediately replay the most recently captured message in the given room.
    Used by the demo UI 'Simulate Replay Attack' button.
    """
    from app.websocket.websocket_manager import ws_manager
    captured = get_captured_messages()
    if not captured:
        return {"status": "no_captured_messages"}
    await ws_manager.trigger_replay(room_id)
    return {"status": "replay_triggered", "room_id": room_id}

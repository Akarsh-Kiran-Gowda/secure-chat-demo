"""
MITMSimulationService – simulates a Man-in-the-Middle attacker.

When enabled, every outgoing message is routed through this service
before being broadcast to other room members.

Behaviour depends on active security settings:
  • E2E disabled  → attacker can READ plaintext content
  • E2E enabled   → attacker sees only ciphertext (unreadable)
  • TLS disabled  → attacker can MODIFY the message in transit
  • TLS enabled   → modifications break the hash → detected by integrity check
"""
import copy
import logging
from app.models.security_config import security_config
from app.security.hash_integrity import hash_integrity

logger = logging.getLogger(__name__)


class MITMSimulationService:

    # In-memory log of intercepted events for the Security Monitor panel
    intercept_log: list[dict] = []

    def intercept_message(self, payload: dict) -> dict:
        """
        Intercept the message payload.
        Logs what the MITM can observe given current security settings.
        Returns the (possibly modified) payload.
        """
        if not security_config.simulate_mitm:
            return payload

        intercepted = copy.deepcopy(payload)

        # What can the attacker read?
        if security_config.e2e_enabled:
            readable = "<encrypted – E2E active, attacker cannot read>"
        else:
            readable = intercepted.get("ciphertext", "")  # plaintext in insecure mode

        event = {
            "event": "MITM_INTERCEPT",
            "sender": intercepted.get("sender"),
            "room_id": intercepted.get("room_id"),
            "readable_content": readable,
            "e2e_active": security_config.e2e_enabled,
            "tls_active": security_config.tls_enabled,
        }
        self.log_intercepted_data(event)

        # Attempt modification only when TLS is OFF (otherwise TLS would prevent it)
        if not security_config.tls_enabled:
            intercepted = self.modify_message(intercepted)

        return intercepted

    def modify_message(self, payload: dict) -> dict:
        """
        Tamper with the message ciphertext to simulate active MITM injection.
        The receiver's integrity check should detect this modification
        when hash verification is performed.
        """
        original_ct = payload.get("ciphertext", "")
        # Append a marker to the ciphertext to simulate tampering
        payload["ciphertext"] = original_ct + "__MITM_TAMPERED__"

        event = {
            "event": "MITM_MODIFY",
            "sender": payload.get("sender"),
            "room_id": payload.get("room_id"),
            "note": "Ciphertext tampered – integrity check should FAIL at receiver",
        }
        self.log_intercepted_data(event)
        logger.warning(
            "[ATTACK] MITM modified message | sender=%s room=%s",
            payload.get("sender"), payload.get("room_id"),
        )
        return payload

    def log_intercepted_data(self, event: dict) -> None:
        self.intercept_log.append(event)
        # Keep log bounded
        if len(self.intercept_log) > 200:
            self.intercept_log = self.intercept_log[-200:]

        logger.warning(
            "[SECURITY] MITM intercepted message | sender=%s room=%s e2e=%s",
            event.get("sender"), event.get("room_id"), event.get("e2e_active"),
        )

    def get_log(self) -> list[dict]:
        return list(self.intercept_log)


mitm_simulation_service = MITMSimulationService()

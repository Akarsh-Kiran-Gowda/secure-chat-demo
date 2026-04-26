"""
MITM Attack Simulation Module

Demonstrates a Man-in-the-Middle attack at the application layer.
In a real network scenario, MITM occurs at the network layer (ARP spoofing,
rogue Wi-Fi, BGP hijacking).  Here we instrument the message pipeline
to show the same observable effects.

Security demonstration lessons:
  • TLS OFF + E2E OFF  → MITM reads plaintext, modifies it, reforges hash
                         → receiver SEES the tampered message (attacker wins)
  • TLS ON  + E2E OFF  → MITM can still read, but cannot forge the hash
                         → integrity check FAILS, message rejected
  • TLS OFF + E2E ON   → MITM cannot read (encrypted), modifies ciphertext,
                         reforges outer hash → server decrypts → AES-GCM tag fails
  • TLS ON  + E2E ON   → Full protection: MITM can neither read nor modify
"""
import copy
import logging
from app.models.security_config import security_config

logger = logging.getLogger(__name__)

attack_log: list[dict] = []


def _append_log(entry: dict) -> None:
    attack_log.append(entry)
    if len(attack_log) > 500:
        attack_log.clear()


def intercept_message(payload: dict) -> dict:
    """
    Route a message through the simulated MITM proxy.
    Returns the (potentially tampered) payload.
    """
    if not security_config.simulate_mitm:
        return payload

    observed = copy.deepcopy(payload)

    # ── What can the attacker read? ────────────────────────────
    if security_config.e2e_enabled:
        readable_content = "[ENCRYPTED – E2E active: attacker cannot read content]"
    else:
        readable_content = observed.get("ciphertext", "")
        logger.warning(
            "[ATTACK/MITM] Plaintext intercepted | sender=%s | content=%s",
            observed.get("sender"), readable_content[:60],
        )

    _append_log({
        "event": "MITM_INTERCEPT",
        "sender": observed.get("sender"),
        "e2e_active": security_config.e2e_enabled,
        "tls_active": security_config.tls_enabled,
        "readable_content": readable_content,
    })
    logger.warning("[SECURITY] MITM intercepted message | sender=%s", observed.get("sender"))

    # ── Attempt modification ───────────────────────────────────
    # TLS OFF → MITM controls the channel; it can tamper AND reforge the hash.
    #           The receiver sees the injected content (attack succeeds).
    # TLS ON  → MITM can tamper bytes but cannot forge the TLS-protected hash.
    #           Integrity check fails and the message is rejected.
    observed = modify_message(observed, forge_hash=not security_config.tls_enabled)

    return observed


def modify_message(payload: dict, forge_hash: bool = False) -> dict:
    """
    Inject content into the ciphertext field.

    forge_hash=True  (TLS OFF): recompute SHA-256 over the tampered payload
                                so integrity check passes → receiver sees injected text.
    forge_hash=False (TLS ON):  leave the original hash → integrity check fails
                                → message is rejected before delivery.
    """
    from app.security.hash_integrity import hash_integrity

    payload["ciphertext"] = payload.get("ciphertext", "") + "||MITM_INJECTED||"

    if forge_hash:
        # MITM reforges the hash – simulates a fully active attacker on an
        # unprotected channel.  The receiver has no way to detect tampering.
        payload["hash"] = hash_integrity.compute_message_hash(
            payload.get("sender", ""),
            payload["ciphertext"],
            payload.get("timestamp", ""),
            payload.get("nonce", ""),
        )
        note = "TLS OFF – MITM forged hash + injected content → message delivered tampered"
    else:
        note = "TLS ON – MITM injected content but cannot forge hash → integrity check will FAIL"

    _append_log({
        "event": "MITM_MODIFY",
        "sender": payload.get("sender"),
        "forge_hash": forge_hash,
        "note": note,
    })
    logger.warning("[SECURITY] MITM modified message | forge_hash=%s | sender=%s", forge_hash, payload.get("sender"))
    return payload


def log_intercepted_data(event: dict) -> None:
    _append_log(event)


def get_attack_log() -> list[dict]:
    return list(attack_log)

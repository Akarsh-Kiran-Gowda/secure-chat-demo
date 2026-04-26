"""
SecurityConfig – runtime security settings toggled from the frontend.
A single instance is held in memory; changes propagate immediately.
"""
from dataclasses import dataclass


@dataclass
class SecurityConfig:
    # Transport-level encryption (Nginx TLS in production)
    tls_enabled: bool = False

    # AES end-to-end encryption of message content
    e2e_enabled: bool = True

    # Nonce + timestamp replay protection
    replay_protection_enabled: bool = True

    # Demo flags – simulate attacks
    simulate_mitm: bool = False
    simulate_replay: bool = False


# Module-level singleton shared across the application
security_config = SecurityConfig()

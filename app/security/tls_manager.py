"""
TLS Manager – helper for TLS status reporting and self-signed cert generation.

In production, Nginx terminates TLS before traffic reaches the Python app.
This module:
  1. Reports whether TLS is active (based on SecurityConfig toggles).
  2. Can generate a self-signed certificate for development/demo use.
"""
import os
import datetime
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class TLSManager:

    CERT_DIR = Path("certs")
    CERT_FILE = CERT_DIR / "server.crt"
    KEY_FILE = CERT_DIR / "server.key"

    def is_tls_active(self) -> bool:
        from app.models.security_config import security_config
        return security_config.tls_enabled

    def generate_self_signed_cert(self) -> tuple[str, str]:
        """
        Generate a self-signed RSA certificate for demo/development.
        Returns (cert_path, key_path).

        Requires the 'cryptography' library (already in requirements).
        """
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.CERT_DIR.mkdir(exist_ok=True)

        # Generate 2048-bit RSA key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CNS Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Write PEM files
        self.KEY_FILE.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        self.CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        logger.info("Self-signed TLS certificate written to %s", self.CERT_DIR)
        return str(self.CERT_FILE), str(self.KEY_FILE)

    def get_tls_info(self) -> dict:
        return {
            "tls_active": self.is_tls_active(),
            "cert_exists": self.CERT_FILE.exists(),
            "note": (
                "TLS terminates at Nginx in production. "
                "Enable via security panel toggle for demonstration."
            ),
        }


tls_manager = TLSManager()

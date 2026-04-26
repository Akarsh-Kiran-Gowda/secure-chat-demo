"""
Application entry point.

Usage:
    python run_server.py                  # HTTP (development)
    python run_server.py --tls            # HTTPS with self-signed cert (demo)
    python run_server.py --host 0.0.0.0 --port 8443 --tls
"""
import argparse
import sys
import uvicorn
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Secure Chat Demo Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--tls", action="store_true", help="Enable TLS with self-signed cert")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes")
    return parser.parse_args()


def main():
    args = parse_args()

    ssl_keyfile = None
    ssl_certfile = None

    if args.tls:
        # Generate / reuse self-signed certificate
        from app.security.tls_manager import tls_manager
        cert, key = tls_manager.generate_self_signed_cert()
        ssl_certfile = cert
        ssl_keyfile = key
        print(f"[TLS] Self-signed certificate: {cert}")
        print(f"[TLS] Access via: https://{args.host}:{args.port}")
    else:
        print(f"[INFO] Access via: http://{args.host}:{args.port}")
        print("[INFO] Use --tls to enable HTTPS")

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        log_level="info",
    )


if __name__ == "__main__":
    main()

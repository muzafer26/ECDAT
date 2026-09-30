"""
ECDAT Demo Server Entrypoint.

Starts the local development server for the ECDAT demo application.
Usage:
    python -m demo.backend.server [--port 8080] [--host 127.0.0.1]
"""

import argparse
import os
from demo.backend.app import create_app


def main() -> None:
    default_host = os.environ.get("HOST", "127.0.0.1")
    default_port = int(os.environ.get("PORT", "8080"))

    parser = argparse.ArgumentParser(description="ECDAT Demo Server")
    parser.add_argument("--host", default=default_host, help=f"Host interface (default: {default_host})")
    parser.add_argument("--port", type=int, default=default_port, help=f"Port (default: {default_port})")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    app = create_app()
    print(f"[*] Starting ECDAT Demo Server on http://{args.host}:{args.port}")
    print("[*] Consuming frozen core at product/core/")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()

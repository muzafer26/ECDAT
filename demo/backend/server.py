"""
ECDAT Demo Server Entrypoint.

Starts the local development server for the ECDAT demo application.
Usage:
    python -m demo.backend.server [--port 8080] [--host 127.0.0.1]
"""

import argparse
from demo.backend.app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="ECDAT Demo Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    app = create_app()
    print(f"[*] Starting ECDAT Demo Server on http://{args.host}:{args.port}")
    print("[*] Consuming frozen core at product/core/")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()

"""sbp-dispatcher: SBP relay.

- ``/ws`` (legacy): HMAC + plaintext JSON frames, for trusted LAN / old clients.
- ``/ws-e2ee`` (new): public-key auth + opaque-tag pub/sub. The relay never holds a
  secret and cannot read payloads. See sbp-spec/spec/SBP-0.4-e2ee.md.
"""
from __future__ import annotations

import logging
import os

from aiohttp import web

from . import legacy
from .e2ee import E2EERelay, e2ee_handler
from .pubkey import load_trusted_keys

log = logging.getLogger("sbp.dispatcher")


def make_app(data_dir: str | None = None) -> web.Application:
    app = legacy.make_app(data_dir)
    trusted = load_trusted_keys()
    app["e2ee_trusted"] = trusted
    app["e2ee_relay"] = E2EERelay(trusted)
    app.router.add_get("/ws-e2ee", e2ee_handler)
    app.router.add_get("/sbp-e2ee", e2ee_handler)
    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    app = make_app()
    port = int(os.environ.get("SBP_PORT", "8787"))
    host = os.environ.get("SBP_HOST", "127.0.0.1")
    web.run_app(app, host=host, port=port, print=None)


if __name__ == "__main__":
    main()

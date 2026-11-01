"""E2EE relay endpoint: public-key auth + opaque-tag pub/sub.

This handler is the entire "untrusted relay". It:
  1. authenticates each connection with an Ed25519 signature (never a secret);
  2. routes frames purely by an opaque HMAC tag it cannot invert (no `rk`);
  3. verifies each frame's signature with the trusted public key (rejects forgeries)
     but never decrypts the ciphertext (no `box_sk`).

It does NOT parse or store any SBP payload. The inner frame only exists at the
two trusted endpoints.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from typing import Dict, Set

from aiohttp import WSMsgType, web

from sbp_client.crypto import b64d, verify_sig, VERSION as E2EE_VERSION

log = logging.getLogger("sbp.e2ee")

CHALLENGE_PREFIX = "sbp1|"


class _Conn:
    __slots__ = ("ws", "kid")

    def __init__(self, ws, kid: str):
        self.ws = ws
        self.kid = kid


class E2EERelay:
    """Shared tag -> subscribers registry for one dispatcher process."""

    def __init__(self, trusted: Dict[str, object]):
        self.trusted = trusted
        self.tag_subs: Dict[str, Set[_Conn]] = defaultdict(set)

    def _sub(self, conn: _Conn, tag: str) -> None:
        self.tag_subs[tag].add(conn)

    def _unsub(self, conn: _Conn, tag: str) -> None:
        self.tag_subs[tag].discard(conn)

    def _drop(self, conn: _Conn) -> None:
        for s in self.tag_subs.values():
            s.discard(conn)

    async def _deliver(self, sender: _Conn, envelope: dict) -> None:
        for c in list(self.tag_subs.get(envelope.get("tag", ""), ())):
            if c is sender:
                continue
            try:
                await c.ws.send_json(envelope)
            except Exception:
                self.tag_subs[envelope.get("tag", "")].discard(c)


def _verify_challenge(sign_pk, key_id: str, ts, nonce, sig_b64: str) -> bool:
    msg = f"{CHALLENGE_PREFIX}{key_id}|{ts}|{nonce}".encode()
    try:
        sign_pk.verify(msg, b64d(sig_b64))
    except Exception:
        return False
    try:
        if abs(int(time.time() * 1000) - int(ts)) > 5 * 60 * 1000:
            return False
    except (TypeError, ValueError):
        return False
    return True


async def e2ee_handler(req: web.Request) -> web.WebSocketResponse:
    trusted = req.app.get("e2ee_trusted", {})
    relay: E2EERelay = req.app["e2ee_relay"]
    ws = web.WebSocketResponse(heartbeat=25, protocols=(E2EE_VERSION,))
    await ws.prepare(req)

    try:
        first = await asyncio.wait_for(ws.receive(), timeout=8)
    except asyncio.TimeoutError:
        await ws.close(code=4408, message=b"hello timeout")
        return ws
    if first.type is not WSMsgType.TEXT:
        await ws.close(code=4401, message=b"need hello")
        return ws
    try:
        hello = json.loads(first.data or "{}")
    except Exception:
        await ws.close(code=4401, message=b"bad hello")
        return ws
    hp = (hello.get("payload") or {}) if hello.get("name") == "hello" else {}
    kid = str(hp.get("keyId") or "")
    sign_pk = trusted.get(kid)
    if not sign_pk or not _verify_challenge(sign_pk, kid, hp.get("ts"), hp.get("nonce"), hp.get("sig", "")):
        await ws.close(code=4401, message=b"bad signature")
        return ws

    conn = _Conn(ws, kid)
    role = hp.get("role", "client")
    await ws.send_json({
        "v": E2EE_VERSION, "type": "res", "ref": hello.get("id"), "name": "hello.ok",
        "ok": True, "ts": int(time.time() * 1000),
        "payload": {"scope": "e2ee", "kid": kid, "role": role},
    })
    log.info("e2ee %s online: %s", role, kid)

    try:
        async for msg in ws:
            if msg.type is not WSMsgType.TEXT:
                continue
            try:
                frame = json.loads(msg.data or "{}")
            except Exception:
                continue
            if frame.get("kid") != kid:
                continue  # frame must come from the authenticated identity
            if frame.get("ctl"):
                tag = frame.get("tag", "")
                if not verify_sig(sign_pk, tag, "", "", frame.get("sig", "")):
                    continue
                if frame["ctl"] == "sub":
                    relay._sub(conn, tag)
                elif frame["ctl"] == "unsub":
                    relay._unsub(conn, tag)
                continue
            # data envelope: verify signature, then route by tag
            if not verify_sig(sign_pk, frame.get("tag", ""), frame.get("eph", ""),
                              frame.get("cipher", ""), frame.get("sig", "")):
                continue
            await relay._deliver(conn, frame)
    finally:
        relay._drop(conn)
        log.info("e2ee %s offline: %s", role, kid)
    return ws


__all__ = ["e2ee_handler", "E2EERelay"]

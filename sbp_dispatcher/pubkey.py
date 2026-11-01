"""Trusted public-key directory for the E2EE relay.

The relay holds ONLY signing public keys (`sign_pk`). It uses them to verify the
Ed25519 signature on every frame, so it can reject forgeries — but it can never
decrypt a payload (no `box_sk`) and never learns which session a tag maps to
(no `rk`). See sbp-spec/spec/SBP-0.4-e2ee.md.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Dict

from nacl.signing import VerifyKey


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def load_trusted_keys() -> Dict[str, VerifyKey]:
    """Build keyId -> VerifyKey from config.

    Sources (first wins per keyId):
      - SBP_TRUSTED_KEYS = "id1:signB64[:boxB64],id2:..."  (comma separated)
      - SBP_TRUSTED_KEYS_FILE = path to JSON {"id": "signB64[:boxB64]", ...}

    The relay only needs the signing public key; the optional box public key is
    ignored here (it is used by endpoints to seal frames, never by the relay).
    """
    out: Dict[str, VerifyKey] = {}
    raw: Dict[str, str] = {}

    env = os.environ.get("SBP_TRUSTED_KEYS", "").strip()
    if env:
        for part in env.split(","):
            if ":" not in part:
                continue
            kid, val = part.split(":", 1)
            kid, val = kid.strip(), val.strip()
            if kid and val:
                raw[kid] = val
    fpath = os.environ.get("SBP_TRUSTED_KEYS_FILE", "").strip()
    if fpath and Path(fpath).exists():
        try:
            for kid, val in json.loads(Path(fpath).read_text()).items():
                raw.setdefault(kid, val)
        except Exception:
            pass

    for kid, val in raw.items():
        sign_b64 = val.split(":")[0].strip()
        try:
            out[kid] = VerifyKey(_b64d(sign_b64))
        except Exception:
            continue
    return out


__all__ = ["load_trusted_keys"]

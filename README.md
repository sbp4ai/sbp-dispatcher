# sbp4ai-dispatcher

The SBP (Session Bridge Protocol) **relay**. It forwards frames between clients and
devices over WebSocket. Two modes coexist:

| Mode | Endpoint | Trust | Use |
|---|---|---|---|
| Legacy | `/ws` | HMAC shared secret, plaintext JSON | trusted LAN / old clients |
| **E2EE** | `/ws-e2ee` | Ed25519 pubkey auth, opaque-tag pub/sub | untrusted relay |

In **E2EE mode** the relay holds *only public keys* and routes frames by an opaque
`HMAC(rk, scope)` tag it cannot invert. It verifies each frame's Ed25519 signature
(rejecting forgeries) but **never decrypts payloads** — there is no secret key on the
relay. See [`sbp-spec/spec/SBP-0.4-e2ee.md`](https://github.com/sbp4ai/sbp-spec/blob/main/spec/SBP-0.4-e2ee.md).

## Run

```bash
pip install sbp4ai-dispatcher
export SBP_TRUSTED_KEYS="dev:<signPkB64>[:<boxPkB64>],cli:<signPkB64>[:<boxPkB64>]"
sbp-dispatcher                # listens on 127.0.0.1:8787 by default (alias: sbp4ai-dispatcher)
```

### Standard usage (3 steps)

```bash
pip install sbp4ai-agents                      # on the controlled machine
sbp-agents --relay wss://relay.example.com/ws-e2ee
cat .copy2client
```

**`cat .copy2client` → copy the whole block → paste it into the console / mini-program
「粘贴导入」(paste-import) box — it imports both clients at once
(`cli-web` web console + `cli-minis` WeChat mini program).**

### The two-line setup with sbp4ai-agents

`sbp4ai-agents` writes the public-key directory for you into `.copy4relay` (public keys
only — safe to send over any channel):

```bash
# on the device
cat .copy4relay
# SBP_TRUSTED_KEYS=dev-mac-1a2b:<signPk>:<boxPk>,cli-web:<signPk>:<boxPk>,cli-minis:...

# on the relay
export SBP_TRUSTED_KEYS="$(sed -n 's/^SBP_TRUSTED_KEYS=//p' .copy4relay)"
sbp-dispatcher
```

Then paste the device's `.copy2client` into the console / mini-program import box — done.

- `SBP_TRUSTED_KEYS` — comma-separated `keyId:signPublicKeyB64[:boxPublicKeyB64]`. The
  relay uses only the **signing** public key (to verify sigs). The box public key is
  ignored by the relay (endpoints use it to seal frames).
- `SBP_PORT`, `SBP_HOST` — bind address.
- Legacy mode additionally reads `SBP_HMAC_KEYS` / `SBP_OPEN` (see legacy docs).

## Note on the legacy code

The legacy `/ws` handler lives in `legacy.py` (copied from the original
`tmux-ai-coder-panel` server). It is kept for backward compatibility on trusted
networks. New deployments should use `/ws-e2ee` exclusively.

## Related

- [`sbp4ai-client`](https://pypi.org/project/sbp4ai-client/) — the E2EE crypto core both endpoints import.
- [`sbp4ai-agents`](https://pypi.org/project/sbp4ai-agents/) — the device/panel that reports local tmux / CLI sessions.

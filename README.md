# TrustGate

**Agent identity, attenuated delegation, and audit for MCP / A2A.**

IdP proves *who the human is*. TrustGate proves *what an agent is allowed to do*, *how authority narrows across hops*, and *what happened*.

**GitHub:** https://github.com/easonphys/trustgate

[Quickstart](docs/QUICKSTART.md) · [Positioning](docs/POSITIONING.md) · [Threat model](docs/THREAT_MODEL.md) · [Competitors](docs/COMPETITORS.md)

## Status

`v0.1.0` — open-source kernel MVP:

- Ed25519 agent identities
- Compact tokens (JWT / EdDSA)
- Chained attenuated delegation
- MCP HTTP auth proxy (`X-TrustGate-Token` / `X-AIP-Token`)
- Audit events + jti/agent revocation
- Adversarial test suite

## Install

```bash
uv sync --extra dev
uv run trustgate version
```

## 60-second demo

```bash
uv run python examples/demo_flow.py
```

## CLI

```bash
trustgate identity gen -o root.json
trustgate token issue -i root.json -s user:alice -a mcp:tools --scope "tools.read" -o t.tok
trustgate token verify t.tok -a mcp:tools --scope tools.read
trustgate proxy --upstream http://127.0.0.1:9000 --audience mcp:tools --port 8080
```

## Design rules

1. Delegation may **only narrow** scopes, never expand.
2. Credentials stay out of the LLM context; the proxy strips bearer/tokens.
3. Production should resolve keys via a **trust map / registry**, not only embedded `pk`.

## License

Apache-2.0

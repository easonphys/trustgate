"""Adversarial cases TrustGate must reject."""

from __future__ import annotations

import base64
import json
import time

import jwt
import pytest

from trustgate.errors import ErrorCode, TrustGateError
from trustgate.identity import generate_identity
from trustgate.token import IssueRequest, delegate, issue_compact, verify


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_reject_tampered_compact_payload():
    root = generate_identity("tg:web:example.com/root")
    token = issue_compact(
        root,
        IssueRequest(subject="user:alice", audience="mcp:tools", scopes="tools.read"),
    )
    header, payload, sig = token.split(".")
    data = json.loads(base64.urlsafe_b64decode(payload + "=="))
    data["scope"] = "tools.admin"
    evil_payload = _b64url(json.dumps(data, separators=(",", ":")).encode())
    evil = f"{header}.{evil_payload}.{sig}"
    with pytest.raises(TrustGateError) as exc:
        verify(evil, audience="mcp:tools")
    assert exc.value.code == ErrorCode.SIGNATURE_INVALID


def test_reject_forged_signature_with_other_key():
    root = generate_identity("tg:web:example.com/root")
    attacker = generate_identity("tg:web:evil.com/attacker")
    now = int(time.time())
    forged = jwt.encode(
        {
            "tg": "compact",
            "iss": root.agent_id,
            "sub": "user:alice",
            "aud": "mcp:tools",
            "scope": "tools.admin",
            "iat": now,
            "exp": now + 3600,
            "jti": "forged",
            "pk": attacker.public_key_b64,
        },
        attacker.private_key,
        algorithm="EdDSA",
    )
    # Trust only the real root key — embedded attacker pk must not win over trust map
    with pytest.raises(TrustGateError) as exc:
        verify(
            forged,
            audience="mcp:tools",
            trust_keys={root.agent_id: root.public_key_b64},
        )
    assert exc.value.code in {ErrorCode.SIGNATURE_INVALID, ErrorCode.TOKEN_MALFORMED}


def test_reject_scope_expansion_in_chain():
    root = generate_identity("tg:web:example.com/root")
    worker = generate_identity("tg:web:example.com/worker")
    parent = issue_compact(
        root,
        IssueRequest(subject="user:alice", audience="orch", scopes="tools.read"),
    )
    with pytest.raises(TrustGateError) as exc:
        delegate(parent, worker, audience="mcp", scopes="tools.read tools.write")
    assert exc.value.code == ErrorCode.ATTENUATION_VIOLATION


def test_reject_missing_token_semantics_via_empty():
    with pytest.raises(TrustGateError) as exc:
        verify("   ", audience="mcp")
    assert exc.value.code == ErrorCode.TOKEN_MISSING


def test_reject_depth_bypass_attempt():
    root = generate_identity("tg:web:example.com/root")
    a = generate_identity("tg:web:example.com/a")
    parent = issue_compact(
        root,
        IssueRequest(
            subject="user:alice",
            audience="orch",
            scopes="tools.*",
            max_depth=0,
        ),
    )
    with pytest.raises(TrustGateError) as exc:
        delegate(parent, a, audience="mcp", scopes="tools.read")
    assert exc.value.code == ErrorCode.DEPTH_EXCEEDED

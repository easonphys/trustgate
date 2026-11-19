from __future__ import annotations

import time

import pytest

from trustgate.errors import ErrorCode, TrustGateError
from trustgate.identity import generate_identity
from trustgate.token import IssueRequest, delegate, issue_chained_root, issue_compact, verify


def test_compact_issue_and_verify():
    root = generate_identity("tg:web:example.com/root")
    token = issue_compact(
        root,
        IssueRequest(
            subject="user:alice",
            audience="mcp:tools",
            scopes="tools.read tools.search",
            ttl_seconds=60,
        ),
    )
    claims = verify(token, audience="mcp:tools", required_scope="tools.read")
    assert claims.issuer == root.agent_id
    assert claims.subject == "user:alice"
    assert "tools.read" in claims.scopes
    assert claims.mode == "compact"


def test_audience_mismatch():
    root = generate_identity("tg:web:example.com/root")
    token = issue_compact(
        root,
        IssueRequest(subject="user:alice", audience="mcp:tools", scopes="tools.read"),
    )
    with pytest.raises(TrustGateError) as exc:
        verify(token, audience="mcp:other")
    assert exc.value.code == ErrorCode.AUDIENCE_MISMATCH


def test_scope_insufficient():
    root = generate_identity("tg:web:example.com/root")
    token = issue_compact(
        root,
        IssueRequest(subject="user:alice", audience="mcp:tools", scopes="tools.read"),
    )
    with pytest.raises(TrustGateError) as exc:
        verify(token, audience="mcp:tools", required_scope="tools.write")
    assert exc.value.code == ErrorCode.SCOPE_INSUFFICIENT


def test_delegate_attenuates():
    root = generate_identity("tg:web:example.com/root")
    worker = generate_identity("tg:web:example.com/worker")
    parent = issue_compact(
        root,
        IssueRequest(
            subject="user:alice",
            audience="mcp:orchestrator",
            scopes="tools.*",
            max_depth=3,
        ),
    )
    child = delegate(
        parent,
        worker,
        audience="mcp:tools",
        scopes="tools.read",
    )
    claims = verify(child, audience="mcp:tools", required_scope="tools.read")
    assert claims.mode == "chained"
    assert claims.depth == 1
    assert claims.issuer == worker.agent_id
    assert claims.scopes == frozenset({"tools.read"})


def test_delegate_cannot_expand_scope():
    root = generate_identity("tg:web:example.com/root")
    worker = generate_identity("tg:web:example.com/worker")
    parent = issue_compact(
        root,
        IssueRequest(subject="user:alice", audience="orch", scopes="tools.read"),
    )
    with pytest.raises(TrustGateError) as exc:
        delegate(parent, worker, audience="mcp:tools", scopes="tools.write")
    assert exc.value.code == ErrorCode.ATTENUATION_VIOLATION


def test_depth_exceeded():
    root = generate_identity("tg:web:example.com/root")
    a = generate_identity("tg:web:example.com/a")
    b = generate_identity("tg:web:example.com/b")
    parent = issue_chained_root(
        root,
        IssueRequest(
            subject="user:alice",
            audience="orch",
            scopes="tools.*",
            max_depth=1,
        ),
    )
    mid = delegate(parent, a, audience="mid", scopes="tools.read")
    with pytest.raises(TrustGateError) as exc:
        delegate(mid, b, audience="leaf", scopes="tools.read")
    assert exc.value.code == ErrorCode.DEPTH_EXCEEDED


def test_expired_token():
    root = generate_identity("tg:web:example.com/root")
    token = issue_compact(
        root,
        IssueRequest(
            subject="user:alice",
            audience="mcp:tools",
            scopes="tools.read",
            ttl_seconds=1,
        ),
    )
    time.sleep(2)
    with pytest.raises(TrustGateError) as exc:
        verify(token, audience="mcp:tools")
    assert exc.value.code == ErrorCode.TOKEN_EXPIRED


def test_replay_detection():
    root = generate_identity("tg:web:example.com/root")
    token = issue_compact(
        root,
        IssueRequest(subject="user:alice", audience="mcp:tools", scopes="tools.read"),
    )
    seen: set[str] = set()
    verify(token, audience="mcp:tools", seen_jti=seen)
    with pytest.raises(TrustGateError) as exc:
        verify(token, audience="mcp:tools", seen_jti=seen)
    assert exc.value.code == ErrorCode.REPLAY_DETECTED

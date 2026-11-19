from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from trustgate.identity import generate_identity
from trustgate.proxy import create_app, extract_token
from trustgate.token import IssueRequest, issue_compact


def test_extract_token_headers():
    assert extract_token({"X-TrustGate-Token": "abc"}) == "abc"
    assert extract_token({"X-AIP-Token": "abc"}) == "abc"
    assert extract_token({"Authorization": "Bearer abc"}) == "abc"
    assert extract_token({}) is None


def test_proxy_denies_without_token(monkeypatch):
    app = create_app(upstream="http://127.0.0.1:9", audience="mcp:tools")
    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200

    resp = client.post("/mcp")
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_missing"


def test_proxy_allows_valid_token(httpx_mock=None):
    # Lightweight: only check auth decision path using a local ASGI upstream mock via httpx
    pytest.importorskip("httpx")
    from unittest.mock import AsyncMock, patch

    root = generate_identity("tg:web:example.com/root")
    token = issue_compact(
        root,
        IssueRequest(subject="user:alice", audience="mcp:tools", scopes="tools.read"),
    )
    app = create_app(
        upstream="http://upstream.test",
        audience="mcp:tools",
        required_scope="tools.read",
        trust_keys={root.agent_id: root.public_key_b64},
    )

    class FakeResp:
        status_code = 200
        content = b'{"ok":true}'
        headers = {"content-type": "application/json"}

    async def fake_request(self, method, url, content=None, headers=None):
        assert headers["x-trustgate-agent"] == root.agent_id
        return FakeResp()

    with patch("httpx.AsyncClient.request", new=fake_request):
        # Also need to patch the context manager
        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            request = fake_request

        with patch("httpx.AsyncClient", return_value=FakeClient()):
            client = TestClient(app)
            resp = client.post(
                "/call",
                headers={"X-TrustGate-Token": token},
                content=b"{}",
            )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

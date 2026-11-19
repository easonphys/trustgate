#!/usr/bin/env python3
"""End-to-end demo: root issues → worker delegates → verify attenuated token."""

from __future__ import annotations

from trustgate.identity import generate_identity
from trustgate.token import IssueRequest, delegate, issue_compact, verify


def main() -> None:
    root = generate_identity("tg:web:acme.com/orchestrator")
    worker = generate_identity("tg:web:acme.com/research-agent")

    parent = issue_compact(
        root,
        IssueRequest(
            subject="user:alice",
            audience="tg:orchestrator",
            scopes="tools.search tools.fetch tools.summarize",
            ttl_seconds=600,
            max_depth=2,
        ),
    )
    print("parent (compact) issued")

    child = delegate(
        parent,
        worker,
        audience="mcp:search-server",
        scopes="tools.search",
    )
    print("child (chained) delegated with attenuated scope")

    claims = verify(
        child,
        audience="mcp:search-server",
        required_scope="tools.search",
        trust_keys={
            root.agent_id: root.public_key_b64,
            worker.agent_id: worker.public_key_b64,
        },
    )
    print(
        {
            "issuer": claims.issuer,
            "subject": claims.subject,
            "audience": claims.audience,
            "scopes": sorted(claims.scopes),
            "depth": claims.depth,
        }
    )


if __name__ == "__main__":
    main()

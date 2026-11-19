from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from trustgate.token import TokenClaims, fingerprint_token


@dataclass
class AuditEvent:
    event_id: str
    ts: int
    action: str
    decision: str
    agent_id: str
    subject: str
    audience: str
    scopes: list[str]
    depth: int
    token_fp: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))


def make_event(
    *,
    action: str,
    decision: str,
    claims: TokenClaims | None = None,
    detail: dict[str, Any] | None = None,
    raw_token: str | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_id=str(uuid.uuid4()),
        ts=int(time.time()),
        action=action,
        decision=decision,
        agent_id=claims.issuer if claims else "",
        subject=claims.subject if claims else "",
        audience=claims.audience if claims else "",
        scopes=sorted(claims.scopes) if claims else [],
        depth=claims.depth if claims else -1,
        token_fp=fingerprint_token(raw_token or (claims.raw_token if claims else "")),
        detail=detail or {},
    )


class AuditLog:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else None
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self._events.append(event)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(event.to_json() + "\n")

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

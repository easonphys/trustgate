from __future__ import annotations

import json
import time
from pathlib import Path


class RevocationList:
    """Simple jti/agent revocation store (file-backed optional)."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else None
        self._jtis: set[str] = set()
        self._agents: set[str] = set()
        if self.path and self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._jtis = set(data.get("jtis", []))
            self._agents = set(data.get("agents", []))

    def revoke_jti(self, jti: str) -> None:
        self._jtis.add(jti)
        self._persist()

    def revoke_agent(self, agent_id: str) -> None:
        self._agents.add(agent_id)
        self._persist()

    def is_revoked(self, *, jti: str | None = None, agent_id: str | None = None) -> bool:
        if jti and jti in self._jtis:
            return True
        if agent_id and agent_id in self._agents:
            return True
        return False

    def _persist(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": int(time.time()),
            "jtis": sorted(self._jtis),
            "agents": sorted(self._agents),
        }
        self.path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

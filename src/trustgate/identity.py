from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


@dataclass
class AgentIdentity:
    """Cryptographic agent identity with Ed25519 keys."""

    agent_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @property
    def public_key_b64(self) -> str:
        raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _b64url(raw)

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    def export_public(self) -> dict[str, str]:
        return {
            "agent_id": self.agent_id,
            "public_key": self.public_key_b64,
            "alg": "EdDSA",
        }

    def save(self, path: Path | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        payload = {
            "agent_id": self.agent_id,
            "private_key_pem": private_bytes.decode("ascii"),
            "public_key": self.public_key_b64,
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        path.chmod(0o600)

    @classmethod
    def load(cls, path: Path | str) -> AgentIdentity:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        private_key = serialization.load_pem_private_key(
            data["private_key_pem"].encode("ascii"),
            password=None,
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("identity file must contain an Ed25519 private key")
        return cls(
            agent_id=data["agent_id"],
            private_key=private_key,
            public_key=private_key.public_key(),
        )


def generate_identity(agent_id: str | None = None, *, domain: str = "local") -> AgentIdentity:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    if agent_id is None:
        pub = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        agent_id = f"tg:web:{domain}/{_b64url(pub)[:16]}"
    return AgentIdentity(agent_id=agent_id, private_key=private_key, public_key=public_key)


def public_key_from_b64(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(value))


def verify_signature(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False

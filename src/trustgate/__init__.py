"""TrustGate: agent identity, attenuated delegation, and audit."""

from trustgate.errors import TrustGateError, ErrorCode
from trustgate.identity import AgentIdentity, generate_identity
from trustgate.token import (
    IssueRequest,
    TokenClaims,
    delegate,
    issue_compact,
    verify,
)

__all__ = [
    "AgentIdentity",
    "ErrorCode",
    "IssueRequest",
    "TokenClaims",
    "TrustGateError",
    "delegate",
    "generate_identity",
    "issue_compact",
    "verify",
]

__version__ = "0.1.0"

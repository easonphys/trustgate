from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    TOKEN_MISSING = "token_missing"
    TOKEN_MALFORMED = "token_malformed"
    TOKEN_EXPIRED = "token_expired"
    SIGNATURE_INVALID = "signature_invalid"
    IDENTITY_UNRESOLVABLE = "identity_unresolvable"
    KEY_REVOKED = "key_revoked"
    SCOPE_INSUFFICIENT = "scope_insufficient"
    BUDGET_EXCEEDED = "budget_exceeded"
    DEPTH_EXCEEDED = "depth_exceeded"
    AUDIENCE_MISMATCH = "audience_mismatch"
    ATTENUATION_VIOLATION = "attenuation_violation"
    REPLAY_DETECTED = "replay_detected"


class TrustGateError(Exception):
    def __init__(self, code: ErrorCode, message: str, *, http_status: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        if http_status is not None:
            self.http_status = http_status
        elif code in {
            ErrorCode.SCOPE_INSUFFICIENT,
            ErrorCode.BUDGET_EXCEEDED,
            ErrorCode.DEPTH_EXCEEDED,
            ErrorCode.ATTENUATION_VIOLATION,
            ErrorCode.AUDIENCE_MISMATCH,
        }:
            self.http_status = 403
        else:
            self.http_status = 401

    def to_dict(self) -> dict[str, str | int]:
        return {
            "error": self.code.value,
            "message": self.message,
            "status": self.http_status,
        }

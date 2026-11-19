from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from trustgate.errors import ErrorCode, TrustGateError
from trustgate.identity import AgentIdentity, public_key_from_b64, verify_signature
from trustgate.scope import attenuate, format_scopes, normalize_scopes, scope_allows


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _canonical(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


KeyResolver = Callable[[str], Ed25519PublicKey | None]


@dataclass
class IssueRequest:
    subject: str
    audience: str
    scopes: str | list[str]
    ttl_seconds: int = 3600
    budget: int | None = None
    max_depth: int = 4
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TokenClaims:
    mode: str
    issuer: str
    subject: str
    audience: str
    scopes: frozenset[str]
    expires_at: int
    issued_at: int
    jti: str
    depth: int
    max_depth: int
    budget: int | None
    chain: tuple[dict[str, Any], ...] = ()
    raw_token: str = ""

    def requires(self, required_scope: str | list[str]) -> None:
        if not scope_allows(self.scopes, required_scope):
            raise TrustGateError(
                ErrorCode.SCOPE_INSUFFICIENT,
                f"token scopes {format_scopes(self.scopes)!r} do not allow {required_scope!r}",
            )


def issue_compact(identity: AgentIdentity, req: IssueRequest) -> str:
    now = int(time.time())
    scopes = normalize_scopes(req.scopes)
    if not scopes:
        raise ValueError("scopes must not be empty")
    payload = {
        "tg": "compact",
        "iss": identity.agent_id,
        "sub": req.subject,
        "aud": req.audience,
        "scope": format_scopes(scopes),
        "iat": now,
        "exp": now + req.ttl_seconds,
        "jti": str(uuid.uuid4()),
        "depth": 0,
        "max_depth": req.max_depth,
        "pk": identity.public_key_b64,
    }
    if req.budget is not None:
        payload["budget"] = req.budget
    payload.update(req.extra)
    return jwt.encode(payload, identity.private_key, algorithm="EdDSA")


def _sign_block(private_key: Ed25519PrivateKey, body: dict[str, Any]) -> dict[str, Any]:
    sig = private_key.sign(_canonical(body))
    return {**body, "sig": _b64url(sig)}


def issue_chained_root(identity: AgentIdentity, req: IssueRequest) -> str:
    """Create a depth-0 chained token (single block)."""
    now = int(time.time())
    scopes = normalize_scopes(req.scopes)
    if not scopes:
        raise ValueError("scopes must not be empty")
    body = {
        "tg": "chain",
        "iss": identity.agent_id,
        "sub": req.subject,
        "aud": req.audience,
        "scope": format_scopes(scopes),
        "iat": now,
        "exp": now + req.ttl_seconds,
        "jti": str(uuid.uuid4()),
        "depth": 0,
        "max_depth": req.max_depth,
        "pk": identity.public_key_b64,
    }
    if req.budget is not None:
        body["budget"] = req.budget
    block = _sign_block(identity.private_key, body)
    return _b64url(json.dumps([block], separators=(",", ":")).encode("utf-8"))


def delegate(
    parent_token: str,
    identity: AgentIdentity,
    *,
    audience: str,
    scopes: str | list[str],
    ttl_seconds: int | None = None,
    subject: str | None = None,
    trust_keys: Mapping[str, str] | KeyResolver | None = None,
) -> str:
    """Append an attenuated delegation block. Parent may be compact or chained."""
    parent = verify(parent_token, audience=None, trust_keys=trust_keys, require_audience=False)
    if parent.depth + 1 > parent.max_depth:
        raise TrustGateError(
            ErrorCode.DEPTH_EXCEEDED,
            f"delegation depth {parent.depth + 1} exceeds max_depth {parent.max_depth}",
        )
    try:
        child_scopes = attenuate(parent.scopes, scopes)
    except ValueError as exc:
        raise TrustGateError(ErrorCode.ATTENUATION_VIOLATION, str(exc)) from exc

    now = int(time.time())
    exp = parent.expires_at if ttl_seconds is None else min(parent.expires_at, now + ttl_seconds)
    if exp <= now:
        raise TrustGateError(ErrorCode.TOKEN_EXPIRED, "parent token is expired")

    # Normalize parent into chain blocks
    if parent.mode == "compact":
        root = {
            "tg": "chain",
            "iss": parent.issuer,
            "sub": parent.subject,
            "aud": parent.audience,
            "scope": format_scopes(parent.scopes),
            "iat": parent.issued_at,
            "exp": parent.expires_at,
            "jti": parent.jti,
            "depth": 0,
            "max_depth": parent.max_depth,
            "pk": _extract_pk_from_compact(parent_token),
        }
        if parent.budget is not None:
            root["budget"] = parent.budget
        # Re-sign is impossible without root key; embed compact as sealed root instead
        chain_blocks = [
            {
                "tg": "chain",
                "sealed": "compact",
                "compact": parent_token,
                "iss": parent.issuer,
                "sub": parent.subject,
                "aud": parent.audience,
                "scope": format_scopes(parent.scopes),
                "iat": parent.issued_at,
                "exp": parent.expires_at,
                "jti": parent.jti,
                "depth": 0,
                "max_depth": parent.max_depth,
                "pk": root["pk"],
                **({"budget": parent.budget} if parent.budget is not None else {}),
            }
        ]
    else:
        chain_blocks = [dict(b) for b in parent.chain]

    block_body = {
        "tg": "chain",
        "iss": identity.agent_id,
        "sub": subject or parent.subject,
        "aud": audience,
        "scope": format_scopes(child_scopes),
        "iat": now,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        "depth": parent.depth + 1,
        "max_depth": parent.max_depth,
        "pk": identity.public_key_b64,
        "parent_jti": parent.jti,
    }
    if parent.budget is not None:
        block_body["budget"] = parent.budget
    chain_blocks.append(_sign_block(identity.private_key, block_body))
    return _b64url(json.dumps(chain_blocks, separators=(",", ":")).encode("utf-8"))


def _extract_pk_from_compact(token: str) -> str:
    header_payload = token.split(".")[1]
    payload = json.loads(_b64url_decode(header_payload))
    pk = payload.get("pk")
    if not pk:
        raise TrustGateError(ErrorCode.TOKEN_MALFORMED, "compact token missing pk claim")
    return pk


def verify(
    token: str,
    *,
    audience: str | None,
    required_scope: str | list[str] | None = None,
    trust_keys: Mapping[str, str] | KeyResolver | None = None,
    require_audience: bool = True,
    allow_embedded_pk: bool = True,
    now: int | None = None,
    seen_jti: set[str] | None = None,
) -> TokenClaims:
    if not token or not token.strip():
        raise TrustGateError(ErrorCode.TOKEN_MISSING, "token is missing")
    token = token.strip()
    now = int(time.time()) if now is None else now

    if token.count(".") == 2:
        claims = _verify_compact(
            token,
            trust_keys=trust_keys,
            now=now,
            allow_embedded_pk=allow_embedded_pk,
        )
    else:
        claims = _verify_chained(
            token,
            trust_keys=trust_keys,
            now=now,
            allow_embedded_pk=allow_embedded_pk,
        )

    if require_audience:
        if not audience:
            raise ValueError("audience is required when require_audience=True")
        if claims.audience != audience and claims.audience != "*":
            raise TrustGateError(
                ErrorCode.AUDIENCE_MISMATCH,
                f"token audience {claims.audience!r} does not match {audience!r}",
            )

    if required_scope is not None:
        claims.requires(required_scope)

    if seen_jti is not None:
        if claims.jti in seen_jti:
            raise TrustGateError(ErrorCode.REPLAY_DETECTED, f"jti {claims.jti} already seen")
        seen_jti.add(claims.jti)

    return claims


def _resolve_key(
    agent_id: str,
    embedded_pk: str | None,
    trust_keys: Mapping[str, str] | KeyResolver | None,
    *,
    allow_embedded_pk: bool = True,
) -> Ed25519PublicKey:
    if callable(trust_keys):
        key = trust_keys(agent_id)
        if key is not None:
            return key
    elif isinstance(trust_keys, Mapping) and agent_id in trust_keys:
        return public_key_from_b64(trust_keys[agent_id])
    if allow_embedded_pk and embedded_pk:
        # Dev convenience only — production proxy should disable this.
        return public_key_from_b64(embedded_pk)
    raise TrustGateError(
        ErrorCode.IDENTITY_UNRESOLVABLE,
        f"cannot resolve public key for agent {agent_id!r}",
    )


def _verify_compact(
    token: str,
    *,
    trust_keys: Mapping[str, str] | KeyResolver | None,
    now: int,
    allow_embedded_pk: bool = True,
) -> TokenClaims:
    try:
        unverified = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False},
            algorithms=["EdDSA"],
        )
    except Exception as exc:
        raise TrustGateError(ErrorCode.TOKEN_MALFORMED, f"compact token malformed: {exc}") from exc

    if unverified.get("tg") not in {None, "compact"}:
        raise TrustGateError(ErrorCode.TOKEN_MALFORMED, "not a compact TrustGate token")

    iss = unverified.get("iss")
    pk = unverified.get("pk")
    if not iss:
        raise TrustGateError(ErrorCode.TOKEN_MALFORMED, "missing iss")
    key = _resolve_key(iss, pk, trust_keys, allow_embedded_pk=allow_embedded_pk)
    try:
        payload = jwt.decode(
            token,
            key=key,
            algorithms=["EdDSA"],
            options={"verify_aud": False, "require": ["exp", "iat", "jti", "iss", "sub", "aud"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TrustGateError(ErrorCode.TOKEN_EXPIRED, "token expired") from exc
    except jwt.InvalidSignatureError as exc:
        raise TrustGateError(ErrorCode.SIGNATURE_INVALID, "invalid signature") from exc
    except Exception as exc:
        raise TrustGateError(ErrorCode.TOKEN_MALFORMED, f"compact verify failed: {exc}") from exc

    if int(payload["exp"]) < now:
        raise TrustGateError(ErrorCode.TOKEN_EXPIRED, "token expired")

    return TokenClaims(
        mode="compact",
        issuer=payload["iss"],
        subject=payload["sub"],
        audience=payload["aud"],
        scopes=normalize_scopes(payload.get("scope", "")),
        expires_at=int(payload["exp"]),
        issued_at=int(payload["iat"]),
        jti=payload["jti"],
        depth=int(payload.get("depth", 0)),
        max_depth=int(payload.get("max_depth", 4)),
        budget=payload.get("budget"),
        raw_token=token,
    )


def _verify_chained(
    token: str,
    *,
    trust_keys: Mapping[str, str] | KeyResolver | None,
    now: int,
    allow_embedded_pk: bool = True,
) -> TokenClaims:
    try:
        blocks = json.loads(_b64url_decode(token))
    except Exception as exc:
        raise TrustGateError(ErrorCode.TOKEN_MALFORMED, f"chained token malformed: {exc}") from exc
    if not isinstance(blocks, list) or not blocks:
        raise TrustGateError(ErrorCode.TOKEN_MALFORMED, "chained token must be a non-empty list")

    parent_scopes: frozenset[str] | None = None
    parent_jti: str | None = None
    max_depth = 4
    root_subject = ""
    budget: int | None = None

    for idx, block in enumerate(blocks):
        if not isinstance(block, dict):
            raise TrustGateError(ErrorCode.TOKEN_MALFORMED, f"block {idx} is not an object")

        if block.get("sealed") == "compact":
            compact = block.get("compact")
            if not isinstance(compact, str):
                raise TrustGateError(ErrorCode.TOKEN_MALFORMED, "sealed compact missing")
            sealed = _verify_compact(
                compact,
                trust_keys=trust_keys,
                now=now,
                allow_embedded_pk=allow_embedded_pk,
            )
            parent_scopes = sealed.scopes
            parent_jti = sealed.jti
            max_depth = sealed.max_depth
            root_subject = sealed.subject
            budget = sealed.budget
            if idx != 0:
                raise TrustGateError(ErrorCode.TOKEN_MALFORMED, "sealed compact must be root")
            continue

        depth = int(block.get("depth", -1))
        if depth != idx:
            raise TrustGateError(
                ErrorCode.TOKEN_MALFORMED,
                f"block depth {depth} does not match index {idx}",
            )

        body = {k: v for k, v in block.items() if k != "sig"}
        sig_b64 = block.get("sig")
        if not sig_b64:
            raise TrustGateError(ErrorCode.TOKEN_MALFORMED, f"block {idx} missing sig")
        iss = body.get("iss")
        pk = body.get("pk")
        if not iss:
            raise TrustGateError(ErrorCode.TOKEN_MALFORMED, f"block {idx} missing iss")
        key = _resolve_key(iss, pk, trust_keys, allow_embedded_pk=allow_embedded_pk)
        if not verify_signature(key, _canonical(body), _b64url_decode(sig_b64)):
            raise TrustGateError(ErrorCode.SIGNATURE_INVALID, f"invalid signature on block {idx}")

        if int(body.get("exp", 0)) < now:
            raise TrustGateError(ErrorCode.TOKEN_EXPIRED, f"block {idx} expired")

        scopes = normalize_scopes(body.get("scope", ""))
        if parent_scopes is None:
            parent_scopes = scopes
            root_subject = str(body.get("sub", ""))
            max_depth = int(body.get("max_depth", 4))
            budget = body.get("budget")
        else:
            if not scope_allows(parent_scopes, scopes):
                raise TrustGateError(
                    ErrorCode.ATTENUATION_VIOLATION,
                    f"block {idx} expands scopes beyond parent",
                )
            expected_parent = body.get("parent_jti")
            if parent_jti and expected_parent and expected_parent != parent_jti:
                raise TrustGateError(
                    ErrorCode.TOKEN_MALFORMED,
                    f"block {idx} parent_jti mismatch",
                )
            parent_scopes = scopes

        parent_jti = str(body.get("jti"))
        max_depth = int(body.get("max_depth", max_depth))
        if depth > max_depth:
            raise TrustGateError(
                ErrorCode.DEPTH_EXCEEDED,
                f"block depth {depth} exceeds max_depth {max_depth}",
            )

    last = blocks[-1]
    if last.get("sealed") == "compact":
        # single sealed compact only
        compact_claims = _verify_compact(
            last["compact"],
            trust_keys=trust_keys,
            now=now,
            allow_embedded_pk=allow_embedded_pk,
        )
        return TokenClaims(
            mode="chained",
            issuer=compact_claims.issuer,
            subject=compact_claims.subject,
            audience=compact_claims.audience,
            scopes=compact_claims.scopes,
            expires_at=compact_claims.expires_at,
            issued_at=compact_claims.issued_at,
            jti=compact_claims.jti,
            depth=0,
            max_depth=compact_claims.max_depth,
            budget=compact_claims.budget,
            chain=tuple(blocks),
            raw_token=token,
        )

    return TokenClaims(
        mode="chained",
        issuer=str(last["iss"]),
        subject=str(last.get("sub", root_subject)),
        audience=str(last["aud"]),
        scopes=normalize_scopes(last.get("scope", "")),
        expires_at=int(last["exp"]),
        issued_at=int(last["iat"]),
        jti=str(last["jti"]),
        depth=int(last["depth"]),
        max_depth=int(last.get("max_depth", max_depth)),
        budget=last.get("budget", budget),
        chain=tuple(blocks),
        raw_token=token,
    )


def fingerprint_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]

from __future__ import annotations

from typing import Mapping

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from trustgate.audit import AuditLog, make_event
from trustgate.errors import ErrorCode, TrustGateError
from trustgate.revoke import RevocationList
from trustgate.token import verify

HEADER_CANDIDATES = ("x-trustgate-token", "x-aip-token", "authorization")


def extract_token(headers: Mapping[str, str]) -> str | None:
    lower = {k.lower(): v for k, v in headers.items()}
    for name in HEADER_CANDIDATES:
        raw = lower.get(name)
        if not raw:
            continue
        if name == "authorization":
            if raw.lower().startswith("bearer "):
                return raw[7:].strip()
            continue
        return raw.strip()
    return None


def create_app(
    *,
    upstream: str,
    audience: str,
    required_scope: str | None = None,
    trust_keys: Mapping[str, str] | None = None,
    audit_log: AuditLog | None = None,
    revocation: RevocationList | None = None,
    seen_jti: set[str] | None = None,
) -> Starlette:
    audit = audit_log or AuditLog()
    rev = revocation or RevocationList()
    replay = seen_jti if seen_jti is not None else set()
    upstream = upstream.rstrip("/")

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "service": "trustgate-mcp-proxy", "audience": audience})

    async def proxy(request: Request) -> Response:
        token = extract_token(request.headers)
        path = request.url.path
        if request.url.query:
            path = f"{path}?{request.url.query}"

        try:
            if not token:
                raise TrustGateError(ErrorCode.TOKEN_MISSING, "missing TrustGate/AIP token")
            claims = verify(
                token,
                audience=audience,
                required_scope=required_scope,
                trust_keys=trust_keys,
                # Prefer registry keys when provided; still allow embedded pk for local demos.
                allow_embedded_pk=trust_keys is None,
                seen_jti=replay,
            )
            if rev.is_revoked(jti=claims.jti, agent_id=claims.issuer):
                raise TrustGateError(ErrorCode.KEY_REVOKED, "token or agent has been revoked")
        except TrustGateError as err:
            audit.append(
                make_event(
                    action=f"mcp:{request.method}:{request.url.path}",
                    decision="deny",
                    detail=err.to_dict(),
                    raw_token=token or "",
                )
            )
            return JSONResponse(err.to_dict(), status_code=err.http_status)

        body = await request.body()
        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower()
            not in {
                "host",
                "content-length",
                "x-trustgate-token",
                "x-aip-token",
                "authorization",
            }
        }
        # Forward identity context to upstream (never forward raw secrets beyond token strip)
        headers["x-trustgate-agent"] = claims.issuer
        headers["x-trustgate-subject"] = claims.subject
        headers["x-trustgate-scope"] = " ".join(sorted(claims.scopes))
        headers["x-trustgate-depth"] = str(claims.depth)

        async with httpx.AsyncClient(timeout=60.0) as client:
            upstream_resp = await client.request(
                request.method,
                f"{upstream}{path}",
                content=body,
                headers=headers,
            )

        audit.append(
            make_event(
                action=f"mcp:{request.method}:{request.url.path}",
                decision="allow",
                claims=claims,
                detail={"upstream_status": upstream_resp.status_code},
            )
        )
        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers={
                k: v
                for k, v in upstream_resp.headers.items()
                if k.lower() not in {"content-encoding", "transfer-encoding", "content-length"}
            },
            media_type=upstream_resp.headers.get("content-type"),
        )

    routes = [
        Route("/healthz", health, methods=["GET"]),
        Route("/{path:path}", proxy, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]),
    ]
    return Starlette(routes=routes)

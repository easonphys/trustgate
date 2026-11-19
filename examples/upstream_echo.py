#!/usr/bin/env python3
"""Tiny upstream server for proxy demos."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn


async def echo(request: Request) -> JSONResponse:
    body = await request.body()
    return JSONResponse(
        {
            "ok": True,
            "path": request.url.path,
            "agent": request.headers.get("x-trustgate-agent"),
            "subject": request.headers.get("x-trustgate-subject"),
            "scope": request.headers.get("x-trustgate-scope"),
            "body_len": len(body),
        }
    )


app = Starlette(routes=[Route("/{path:path}", echo, methods=["GET", "POST"])])

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9000)

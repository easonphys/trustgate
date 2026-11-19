from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
import uvicorn
from rich import print as rprint

from trustgate import __version__
from trustgate.audit import AuditLog
from trustgate.errors import TrustGateError
from trustgate.identity import generate_identity, AgentIdentity
from trustgate.proxy import create_app
from trustgate.revoke import RevocationList
from trustgate.token import IssueRequest, delegate, issue_chained_root, issue_compact, verify

app = typer.Typer(
    name="trustgate",
    help="TrustGate: agent identity, attenuated delegation, MCP auth proxy",
    no_args_is_help=True,
)
identity_app = typer.Typer(help="Manage agent identities")
token_app = typer.Typer(help="Issue, delegate, and verify tokens")
app.add_typer(identity_app, name="identity")
app.add_typer(token_app, name="token")


@app.command("version")
def version() -> None:
    rprint(f"trustgate {__version__}")


@identity_app.command("gen")
def identity_gen(
    out: Path = typer.Option(..., "--out", "-o", help="Path to write identity JSON"),
    agent_id: Optional[str] = typer.Option(None, help="Optional agent id"),
    domain: str = typer.Option("local", help="Domain used when auto-generating id"),
) -> None:
    ident = generate_identity(agent_id, domain=domain)
    ident.save(out)
    rprint({"agent_id": ident.agent_id, "public_key": ident.public_key_b64, "path": str(out)})


@identity_app.command("show")
def identity_show(path: Path = typer.Argument(..., help="Identity file")) -> None:
    ident = AgentIdentity.load(path)
    rprint(ident.export_public())


@token_app.command("issue")
def token_issue(
    identity: Path = typer.Option(..., "--identity", "-i"),
    subject: str = typer.Option(..., "--subject", "-s"),
    audience: str = typer.Option(..., "--audience", "-a"),
    scope: str = typer.Option(..., "--scope", help="Space-separated scopes"),
    ttl: int = typer.Option(3600, "--ttl"),
    mode: str = typer.Option("compact", "--mode", help="compact|chained"),
    max_depth: int = typer.Option(4, "--max-depth"),
    budget: Optional[int] = typer.Option(None, "--budget"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
) -> None:
    ident = AgentIdentity.load(identity)
    req = IssueRequest(
        subject=subject,
        audience=audience,
        scopes=scope,
        ttl_seconds=ttl,
        max_depth=max_depth,
        budget=budget,
    )
    token = issue_chained_root(ident, req) if mode == "chained" else issue_compact(ident, req)
    if out:
        out.write_text(token + "\n", encoding="utf-8")
        rprint({"written": str(out), "mode": mode})
    else:
        print(token)


@token_app.command("delegate")
def token_delegate(
    parent: Path = typer.Option(..., "--parent", "-p", help="Parent token file"),
    identity: Path = typer.Option(..., "--identity", "-i"),
    audience: str = typer.Option(..., "--audience", "-a"),
    scope: str = typer.Option(..., "--scope"),
    ttl: Optional[int] = typer.Option(None, "--ttl"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
) -> None:
    ident = AgentIdentity.load(identity)
    parent_token = parent.read_text(encoding="utf-8").strip()
    try:
        token = delegate(
            parent_token,
            ident,
            audience=audience,
            scopes=scope,
            ttl_seconds=ttl,
        )
    except TrustGateError as err:
        rprint(err.to_dict())
        raise typer.Exit(code=1) from err
    if out:
        out.write_text(token + "\n", encoding="utf-8")
        rprint({"written": str(out)})
    else:
        print(token)


@token_app.command("verify")
def token_verify(
    token_file: Path = typer.Argument(..., help="Token file"),
    audience: Optional[str] = typer.Option(None, "--audience", "-a"),
    scope: Optional[str] = typer.Option(None, "--scope"),
    trust: Optional[Path] = typer.Option(
        None, "--trust", help="JSON map of agent_id -> public_key"
    ),
) -> None:
    raw = token_file.read_text(encoding="utf-8").strip()
    trust_keys = json.loads(trust.read_text(encoding="utf-8")) if trust else None
    try:
        claims = verify(
            raw,
            audience=audience,
            required_scope=scope,
            trust_keys=trust_keys,
            require_audience=audience is not None,
        )
    except TrustGateError as err:
        rprint(err.to_dict())
        raise typer.Exit(code=1) from err
    rprint(
        {
            "mode": claims.mode,
            "iss": claims.issuer,
            "sub": claims.subject,
            "aud": claims.audience,
            "scope": sorted(claims.scopes),
            "depth": claims.depth,
            "max_depth": claims.max_depth,
            "exp": claims.expires_at,
            "jti": claims.jti,
        }
    )


@app.command("proxy")
def proxy_cmd(
    upstream: str = typer.Option(..., "--upstream", "-u", help="Upstream MCP/HTTP base URL"),
    audience: str = typer.Option(..., "--audience", "-a"),
    scope: Optional[str] = typer.Option(None, "--scope"),
    trust: Optional[Path] = typer.Option(None, "--trust"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port"),
    audit: Optional[Path] = typer.Option(None, "--audit"),
    revoke_file: Optional[Path] = typer.Option(None, "--revoke-file"),
) -> None:
    trust_keys = json.loads(trust.read_text(encoding="utf-8")) if trust else None
    application = create_app(
        upstream=upstream,
        audience=audience,
        required_scope=scope,
        trust_keys=trust_keys,
        audit_log=AuditLog(audit),
        revocation=RevocationList(revoke_file),
    )
    rprint(f"[green]TrustGate proxy[/green] audience={audience} -> {upstream}")
    uvicorn.run(application, host=host, port=port, log_level="info")


@app.command("revoke")
def revoke_cmd(
    revoke_file: Path = typer.Option(..., "--revoke-file", "-f"),
    jti: Optional[str] = typer.Option(None, "--jti"),
    agent: Optional[str] = typer.Option(None, "--agent"),
) -> None:
    if not jti and not agent:
        raise typer.BadParameter("provide --jti and/or --agent")
    store = RevocationList(revoke_file)
    if jti:
        store.revoke_jti(jti)
    if agent:
        store.revoke_agent(agent)
    rprint({"revoked_jti": jti, "revoked_agent": agent, "file": str(revoke_file)})


if __name__ == "__main__":
    app()

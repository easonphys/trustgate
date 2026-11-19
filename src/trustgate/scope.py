from __future__ import annotations

import re

_SCOPE_RE = re.compile(r"^[a-zA-Z0-9_.:*/-]+$")


def normalize_scopes(scopes: str | list[str] | set[str] | None) -> frozenset[str]:
    if scopes is None:
        return frozenset()
    if isinstance(scopes, str):
        items = [s for s in scopes.replace(",", " ").split() if s]
    else:
        items = list(scopes)
    cleaned: set[str] = set()
    for item in items:
        item = item.strip()
        if not item:
            continue
        if not _SCOPE_RE.match(item):
            raise ValueError(f"invalid scope token: {item!r}")
        cleaned.add(item)
    return frozenset(cleaned)


def scope_allows(granted: frozenset[str], required: frozenset[str] | str) -> bool:
    need = normalize_scopes(required)
    if not need:
        return True
    for req in need:
        if not _one_allows(granted, req):
            return False
    return True


def _one_allows(granted: frozenset[str], required: str) -> bool:
    if required in granted or "*" in granted:
        return True
    # prefix wildcards: tools.* covers tools.read
    for g in granted:
        if g.endswith(".*"):
            prefix = g[:-2]
            if required == prefix or required.startswith(prefix + "."):
                return True
        if g.endswith(":*"):
            prefix = g[:-1]
            if required.startswith(prefix):
                return True
    return False


def attenuate(parent: frozenset[str], child: frozenset[str] | str) -> frozenset[str]:
    """Return child scopes only if every child scope is allowed by parent."""
    child_set = normalize_scopes(child)
    if not scope_allows(parent, child_set):
        raise ValueError("child scopes are not a subset (attenuation) of parent scopes")
    # Keep the more specific child set (narrower)
    return child_set


def format_scopes(scopes: frozenset[str]) -> str:
    return " ".join(sorted(scopes))

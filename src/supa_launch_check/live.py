"""Owner-only, read-only live check against a Supabase project's REST API.

What it does (and nothing else):
  1. GET {url}/rest/v1/            -> the PostgREST OpenAPI document (table + RPC names)
  2. GET {url}/rest/v1/<table>?select=*&limit=1   for each table, as the anon role

It never sends POST/PATCH/PUT/DELETE, never calls RPC functions, never prints row data,
and waits between requests. It refuses to run with a service_role / secret key, because
the point is to see exactly what an anonymous visitor sees.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from .findings import Finding
from .static_scan import decode_jwt_payload

USER_AGENT = "supa-launch-check (owner-authorised read-only check)"
MAX_TABLES_DEFAULT = 200


class LiveCheckError(Exception):
    pass


@dataclass
class TableResult:
    table: str
    status: int | None
    rows_visible: bool
    note: str = ""


@dataclass
class LiveResult:
    url: str
    tables: list[TableResult] = field(default_factory=list)
    rpc_functions: list[str] = field(default_factory=list)
    requests_made: int = 0
    truncated: bool = False
    findings: list[Finding] = field(default_factory=list)


def validate_key(key: str) -> str:
    """Return the key kind ('anon-jwt' or 'publishable') or raise if it is a secret key."""
    key = key.strip()
    if key.startswith("sb_secret_"):
        raise LiveCheckError("That is a secret key (sb_secret_). Use the anon / publishable key only.")
    if key.startswith("sb_publishable_"):
        return "publishable"
    payload = decode_jwt_payload(key)
    if payload is None:
        raise LiveCheckError("Key is not a Supabase anon JWT or sb_publishable_ key.")
    role = payload.get("role")
    if role != "anon":
        raise LiveCheckError(
            f"Key has role '{role}'. This check must run with the anon key so it sees exactly what "
            "an anonymous visitor sees. Never paste a service_role key into tools."
        )
    return "anon-jwt"


def validate_url(url: str) -> str:
    url = url.strip().rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise LiveCheckError(f"Not a valid project URL: {url!r}")
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme == "http" and not local:
        raise LiveCheckError("Refusing plain http for a non-local URL; use https.")
    if parsed.path not in ("", "/"):
        raise LiveCheckError("Pass the project base URL, e.g. https://abcd1234.supabase.co")
    return url


Opener = Callable[[urllib.request.Request, float], object]


def _default_opener(req: urllib.request.Request, timeout: float):
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 (scheme validated)


def run_live_check(
    url: str,
    anon_key: str,
    *,
    delay: float = 0.5,
    max_tables: int = MAX_TABLES_DEFAULT,
    timeout: float = 10.0,
    opener: Opener | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> LiveResult:
    url = validate_url(url)
    kind = validate_key(anon_key)
    opener = opener or _default_opener
    res = LiveResult(url=url)

    headers = {"apikey": anon_key, "User-Agent": USER_AGENT}
    if kind == "anon-jwt":
        headers["Authorization"] = f"Bearer {anon_key}"

    def get(path: str, accept: str) -> tuple[int, bytes]:
        if res.requests_made:
            sleep(delay)
        res.requests_made += 1
        req = urllib.request.Request(url + path, method="GET", headers={**headers, "Accept": accept})
        try:
            with opener(req, timeout) as resp:  # type: ignore[attr-defined]
                return resp.status, resp.read(5_000_000)
        except urllib.error.HTTPError as e:
            return e.code, e.read(65536) if e.fp else b""
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise LiveCheckError(f"Could not reach {url}: {e}") from e

    status, body = get("/rest/v1/", "application/openapi+json")
    if status != 200:
        raise LiveCheckError(
            f"Could not read the API schema (HTTP {status}). The OpenAPI endpoint may be disabled "
            "for the anon role, or the URL/key is wrong."
        )
    try:
        spec = json.loads(body)
    except ValueError as e:
        raise LiveCheckError("API schema response was not JSON.") from e

    tables: list[str] = []
    for p in sorted((spec.get("paths") or {}).keys()):
        if p == "/" or not p.startswith("/"):
            continue
        if p.startswith("/rpc/"):
            res.rpc_functions.append(p[len("/rpc/") :])
        else:
            tables.append(p[1:])

    if len(tables) > max_tables:
        res.truncated = True
        tables = tables[:max_tables]

    for t in tables:
        q = f"/rest/v1/{urllib.parse.quote(t, safe='')}?select=*&limit=1"
        status, body = get(q, "application/json")
        rows_visible, note = False, ""
        if status in (200, 206):
            try:
                data = json.loads(body or b"[]")
            except ValueError:
                data = []
            rows_visible = isinstance(data, list) and len(data) > 0
            note = "rows visible to anon" if rows_visible else "no rows visible (RLS filtering, or empty)"
        elif status in (401, 403):
            note = "permission denied for anon"
        elif status == 404:
            note = "not found"
        else:
            note = f"HTTP {status}"
        res.tables.append(TableResult(t, status, rows_visible, note))
        if rows_visible:
            res.findings.append(
                Finding(
                    "SLC201",
                    "high",
                    f"Table '{t}' returned data to an anonymous request "
                    f"(GET /rest/v1/{t}?select=*&limit=1). Confirm this table is meant to be public.",
                    file=f"{url}/rest/v1/{t}",
                    extra={"table": t, "http_status": status},
                )
            )

    if res.rpc_functions:
        names = ", ".join(res.rpc_functions[:15]) + (" ..." if len(res.rpc_functions) > 15 else "")
        res.findings.append(
            Finding(
                "SLC202",
                "low",
                f"{len(res.rpc_functions)} RPC function(s) are listed for the anon key: {names}. "
                "Not called; review that each is safe for anonymous callers.",
                file=f"{url}/rest/v1/rpc",
                extra={"functions": res.rpc_functions},
            )
        )
    return res

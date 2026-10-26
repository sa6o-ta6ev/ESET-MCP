"""``eset-mcp-check``: which ESET endpoints work for which tenant.

Logs in as every configured tenant and calls each list endpoint (every GET
tool without path parameters) once with ``pageSize=1``, then prints a matrix
of HTTP status codes::

    endpoint                                   acme  globex  same?
    GET /v1/devices                             200     200
    GET /v1/quarantined-objects                 404     200   differs
    GET /v2/edr-rules                           501     501

An error that every tenant gets points at the API or the server; one that
only some tenants get points at that tenant's licence or permission set.

Read-only: GET requests only. Takes roughly (number of endpoints) / 10
seconds per tenant because of ESET's 10 req/s limit; tenants run in parallel.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from .config import Settings
from .credentials import TenantError, build_provider
from .errors import EsetApiError
from .http_client import EsetHttpClient
from .tools_loader import ToolDef, load_all_tools


def list_endpoints() -> list[ToolDef]:
    """GET tools callable without arguments: no path parameters, no required
    query parameters, and no ``:batchGet`` (needs a list of uuids to mean anything)."""
    return [
        t for t in load_all_tools()
        if not t.path_params and not _required_query(t) and ":batch" not in t.path
    ]


def _required_query(tool: ToolDef) -> list[str]:
    required = set(tool.input_schema.get("required", []))
    return [p for p in tool.query_params if p in required]


async def probe_tenant(provider, tenant_id: str, endpoints: list[ToolDef]) -> dict[str, str]:
    """Status per endpoint path for one tenant ('login: <status>' if login fails)."""
    try:
        creds = provider.resolve(tenant_id)
    except TenantError as e:
        return {"_login": f"config error: {e}"}
    results: dict[str, str] = {}
    async with EsetHttpClient(creds) as http:
        for tool in endpoints:
            query = {"pageSize": 1} if "pageSize" in tool.query_params else None
            try:
                await http.request("GET", tool.service, tool.path, query=query)
                results[tool.path] = "200"
            except EsetApiError as e:
                if e.endpoint and "oauth/token" in e.endpoint:  # the login itself failed
                    return {"_login": f"login failed ({e.status}): check user/password/region"}
                results[tool.path] = str(e.status)
            except Exception as e:  # network errors etc. - report, keep going
                results[tool.path] = type(e).__name__
    return results


async def run(tenant_filter: list[str] | None = None) -> tuple[list[str], list[ToolDef], dict[str, dict[str, str]]]:
    settings = Settings.from_env()
    provider = build_provider(settings)
    tenant_ids = [t.id for t in provider.tenants() if not tenant_filter or t.id in tenant_filter]
    endpoints = list_endpoints()
    results = await asyncio.gather(*(probe_tenant(provider, t, endpoints) for t in tenant_ids))
    return tenant_ids, endpoints, dict(zip(tenant_ids, results, strict=True))


def render(tenant_ids: list[str], endpoints: list[ToolDef], results: dict[str, dict[str, str]]) -> str:
    lines = []
    for tenant_id in tenant_ids:
        if "_login" in results[tenant_id]:
            lines.append(f"!! {tenant_id}: {results[tenant_id]['_login']}")
    usable = [t for t in tenant_ids if "_login" not in results[t]]
    if not usable:
        lines.append("No tenant could log in - nothing to compare.")
        return "\n".join(lines)
    width = max(len(f"{e.method} {e.path}") for e in endpoints)
    cols = [max(len(t), 4) for t in usable]
    header = f"{'endpoint':<{width}}  " + "  ".join(f"{t:>{c}}" for t, c in zip(usable, cols, strict=True))
    lines.append(header + ("  same?" if len(usable) > 1 else ""))
    for e in endpoints:
        statuses = [results[t].get(e.path, "-") for t in usable]
        row = f"{e.method + ' ' + e.path:<{width}}  " + "  ".join(
            f"{s:>{c}}" for s, c in zip(statuses, cols, strict=True)
        )
        if len(usable) > 1 and len(set(statuses)) > 1:
            row += "  differs"
        lines.append(row)
    if usable:
        failing_all = [e.path for e in endpoints if all(results[t].get(e.path) != "200" for t in usable)]
        lines.append(
            f"\n{len(endpoints)} endpoints x {len(usable)} tenants; "
            f"{len(failing_all)} fail for every tenant."
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Which ESET endpoints work for which tenant (read-only).")
    parser.add_argument("tenants", nargs="*", help="tenant ids to check (default: all)")
    parser.add_argument("--json", action="store_true", help="print raw results as JSON")
    args = parser.parse_args()
    # Retry/rate-limit warnings would interleave with the table.
    logging.getLogger("eset_mcp").setLevel(logging.ERROR)
    try:
        tenant_ids, endpoints, results = asyncio.run(run(args.tenants or None))
    except (TenantError, RuntimeError) as e:
        sys.exit(str(e))
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(render(tenant_ids, endpoints, results))

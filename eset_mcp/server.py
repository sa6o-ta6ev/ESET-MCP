"""MCP server - registers tools, resources and prompts.

Uses the low-level ``Server`` from the official `mcp` Python SDK (2.x).
Every tool is read-only: generated tools wrap ESET GET endpoints, and the
composite tools only fan out GET requests.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any
from urllib.parse import quote

from jsonschema.validators import validator_for
from mcp.server import Server, ServerRequestContext
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    GetPromptRequestParams,
    GetPromptResult,
    ListPromptsResult,
    ListResourcesResult,
    ListToolsResult,
    PaginatedRequestParams,
    Prompt,
    PromptArgument,
    PromptMessage,
    ReadResourceRequestParams,
    ReadResourceResult,
    Resource,
    TextContent,
    TextResourceContents,
    Tool,
    ToolAnnotations,
)

from . import __version__
from .client_pool import ClientPool
from .composite_tools import (
    ALL_KINDS,
    device_full_profile,
    eset_search,
    incident_full_context,
    latest_detections,
    policy_settings,
)
from .config import Settings
from .errors import EsetApiError
from .http_client import EsetHttpClient
from .observability import (
    inc_capped,
    inc_tool_call,
    log_event,
    observe_response_bytes,
    observe_tool_duration,
    record_usage,
)
from .policy_decode import omit_policy_blobs
from .response_shaping import apply_fields_projection, cap_response_size
from .tools_loader import ToolDef, load_all_tools

# Resolver protocol - anything with a no-arg `resolve()` returning Credentials.
# We don't import the protocol class to keep server.py decoupled; duck typing
# is enough and avoids a circular import.

_LOG = logging.getLogger("eset_mcp.server")

_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,  # external API (ESET)
)

_COMPOSITE_TOOLS: list[Tool] = [
    Tool(
        name="eset_search",
        description=(
            "Case-insensitive substring search across devices, users, policies and groups. "
            "Returns matching items with their UUIDs and which field matched. Use this instead "
            "of list_* + manual filtering when you have a name fragment (e.g. 'jeff', 'laptop-23', "
            "'finance')."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Substring to look for (case-insensitive). Plain text, not regex.",
                },
                "kinds": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(ALL_KINDS)},
                    "description": (
                        "Resource kinds to search. Defaults to all four. Pick a subset to "
                        "narrow scope and save quota: e.g. ['user'] when looking for a person, "
                        "['device'] for hostnames/IPs."
                    ),
                },
                "limit_per_kind": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 20,
                    "description": "Max matches returned per kind (default 20).",
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        annotations=_READ_ONLY.model_copy(update={"title": "ESET cross-resource substring search"}),
    ),
    Tool(
        name="device_full_profile",
        description=(
            "One call → device record + its recent detections (last 30 days) + detection "
            "groups + vulnerabilities + recent scans. Use when answering 'what do you know "
            "about this machine'. Each sub-section degrades gracefully if the tenant lacks "
            "a module."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceUuid": {"type": "string", "description": "UUID of the device."},
            },
            "required": ["deviceUuid"],
            "additionalProperties": False,
        },
        annotations=_READ_ONLY.model_copy(update={"title": "ESET device full profile (composite)"}),
    ),
    Tool(
        name="incident_full_context",
        description=(
            "One call → incident + comments + related detections + affected devices. "
            "Detections and devices are capped at 10 each to stay within rate limits; "
            "the response carries a 'truncated' flag if more exist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "incidentUuid": {"type": "string", "description": "UUID of the incident."},
            },
            "required": ["incidentUuid"],
            "additionalProperties": False,
        },
        annotations=_READ_ONLY.model_copy(update={"title": "ESET incident full context (composite)"}),
    ),
    Tool(
        name="latest_detections",
        description=(
            "Newest detections in a time window, sorted by occurTime descending. "
            "Use this - NOT the raw list_detections tools - when answering "
            "'what's the latest detection / what happened recently'. The raw list endpoints "
            "do NOT sort by date, so a first-page sort silently returns stale rows. "
            "This composite does v2→v1 fallback, paginates the time window, and sorts locally."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 24 * 365,
                    "default": 24,
                    "description": "Time window in hours back from now (default 24).",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 10,
                    "description": "Number of newest detections to return (default 10).",
                },
                "severity_min": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH"],
                    "description": "Optional: filter to severity at or above this level.",
                },
            },
            "additionalProperties": False,
        },
        annotations=_READ_ONLY.model_copy(update={"title": "ESET latest detections (composite)"}),
    ),
    Tool(
        name="policy_settings",
        description=(
            "A policy's settings decoded to plain JSON. ESET's get/list policy endpoints only "
            "return the settings as an encoded blob (omitted from their output) - use this "
            "tool to read what a policy actually configures. Returns policy metadata, the "
            "product it targets, console/product version info, and the settings per settings "
            "file (several documents = the same settings written for different product "
            "versions). Setting wrappers {ce_value, ce_flags} are unwrapped to the value; "
            "credential-looking values are redacted. Large policies return a section outline - "
            "then call again with `path` or `search`."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "policyUuid": {"type": "string", "description": "UUID of the policy."},
                "path": {
                    "type": "string",
                    "description": (
                        "Optional dotted path inside each settings document, e.g. "
                        "'policy.data.Settings.Firewall' or 'list[0].name'."
                    ),
                },
                "search": {
                    "type": "string",
                    "description": (
                        "Optional case-insensitive text to find in setting names or values; "
                        "returns matching paths and values only (max 100)."
                    ),
                },
                "include_history": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include the change log (who changed which section, when).",
                },
                "raw_flags": {
                    "type": "boolean",
                    "default": False,
                    "description": "Keep the raw {ce_value, ce_flags} wrappers instead of unwrapping.",
                },
            },
            "required": ["policyUuid"],
            "additionalProperties": False,
        },
        annotations=_READ_ONLY.model_copy(update={"title": "ESET policy settings, decoded (composite)"}),
    ),
]

_POLICY_BLOB_HINT = "call policy_settings with this policy's uuid to read the decoded settings"

_RESOURCES: list[Resource] = [
    Resource(
        uri="eset://config/region",
        name="ESET region",
        description="API region (eu/de/us/ca/jpn). Only meaningful for cloud deployments.",
        mime_type="text/plain",
    ),
    Resource(
        uri="eset://config/deployment",
        name="ESET deployment kind",
        description="'cloud' (ESET Connect API) or 'onprem' (customer-hosted ESET PROTECT console).",
        mime_type="text/plain",
    ),
    Resource(
        uri="eset://config/tools-catalog",
        name="Tools catalog",
        description="List of all tools with their mapping to ESET endpoints.",
        mime_type="application/json",
    ),
    Resource(
        uri="eset://docs/rate-limits",
        name="ESET API rate limits",
        description="10 req/s per credential/IP. Bursts subject to the Fair Use Policy.",
        mime_type="text/markdown",
    ),
]

_PROMPTS: list[Prompt] = [
    Prompt(
        name="audit_inactive_devices",
        description="List devices that have not checked in for X days - offboarding candidates.",
        arguments=[
            PromptArgument(name="days", description="Inactivity threshold in days (default 30).", required=False),
        ],
    ),
    Prompt(
        name="vulnerability_report",
        description="Build a CVE report: which devices have unpatched vulnerabilities, sorted by severity.",
        arguments=[],
    ),
    Prompt(
        name="incident_triage",
        description="Show open incidents + related detections. Suggest priorities.",
        arguments=[],
    ),
]


class _ToolError(Exception):
    """A tool call failed in a way the agent should see as ``is_error``."""

    def __init__(self, message: str, status: str = "error"):
        super().__init__(message)
        self.status = status


def build_server(settings: Settings, pool: ClientPool, resolver: Any) -> Server:
    """Build an mcp Server instance with every capability wired up.

    `resolver` is anything with a no-arg ``resolve() -> Credentials`` method
    (see eset_mcp.credentials). `pool` is the shared ClientPool.
    """
    tools = load_all_tools()
    tools_by_name = {t.name: t for t in tools}
    mcp_tools = [*_COMPOSITE_TOOLS, *(_tool_to_mcp(t) for t in tools)]
    schemas = {t.name: t.input_schema for t in mcp_tools}
    # The low-level Server does not validate tool arguments, so we do. Unknown
    # OpenAPI keywords (nullable, readOnly, ...) are ignored by jsonschema.
    validators = {name: validator_for(schema)(schema) for name, schema in schemas.items()}

    async def _http() -> EsetHttpClient:
        """Resolve current request's credentials → fetch a pooled client."""
        return await pool.get(resolver.resolve())

    # --- TOOLS ---
    async def on_list_tools(
        _ctx: ServerRequestContext, _params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        return ListToolsResult(tools=mcp_tools)

    async def on_call_tool(_ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
        name = params.name
        t0 = time.monotonic()
        deployment = settings.deployment
        status = "error"
        bytes_out = 0
        try:
            text = await _dispatch(name, dict(params.arguments or {}))
            status = "ok"
            bytes_out = len(text.encode("utf-8"))
            return CallToolResult(content=[TextContent(type="text", text=text)])
        except _ToolError as e:
            status = e.status
            return CallToolResult(content=[TextContent(type="text", text=str(e))], is_error=True)
        except Exception as e:
            # Unexpected bug or transport failure (timeout, DNS, ...). Report
            # it as a tool error the agent can read instead of a bare JSON-RPC
            # "Internal server error"; the traceback goes to the log.
            status = "exception"
            _LOG.exception("tool %s failed", name)
            text = f"Internal error while running {name}: {type(e).__name__}: {e}"
            return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)
        finally:
            # Telemetry must NEVER kill a tool call. Wrap defensively so
            # that a misbehaving metrics registry or formatter cannot
            # turn a successful tool call into an error for the agent.
            try:
                _emit_tool_call_telemetry(settings, name, deployment, status, t0, bytes_out)
            except Exception:  # observability MUST be best-effort
                _LOG.exception("telemetry emission failed for tool=%s", name)

    async def _dispatch(name: str, arguments: dict[str, Any]) -> str:
        if name not in schemas:
            raise _ToolError(f"Unknown tool: {name}", status="unknown_tool")
        errors = sorted(validators[name].iter_errors(arguments), key=lambda e: list(e.path))
        if errors:
            details = "; ".join(
                f"{'/'.join(map(str, e.path)) or '(arguments)'}: {e.message}" for e in errors[:5]
            )
            raise _ToolError(f"Invalid arguments for {name}: {details}", status="invalid_arguments")
        http = await _http()

        # `fields` is a *synthetic* parameter we add to every generated tool
        # (see tools_loader._build_input_schema). It is a server-side
        # projection, never forwarded to ESET - so we pop it before dispatch.
        fields = arguments.pop("fields", None)
        max_bytes = settings.response_bytes_max

        try:
            composite = await _dispatch_composite(http, name, arguments, max_bytes)
            if composite is not None:
                if isinstance(composite, dict) and "error" in composite:
                    # Composites report a failed primary fetch as {"error": ...}.
                    raise _ToolError(_to_text(composite), status="eset_error")
                return _to_text(_shape(composite, fields, max_bytes))
            tool = tools_by_name[name]
            result = await _execute_tool(http, tool, arguments)
        except EsetApiError as e:
            raise _ToolError(f"ESET API error: {e}", status=str(e.status)) from e

        if tool.service == "policy-management":
            # The encoded settings blob is thousands of useless tokens to the
            # agent; point it at the decoding tool instead.
            result = omit_policy_blobs(result, _POLICY_BLOB_HINT)
        shaped = _shape(result, fields, max_bytes)
        if isinstance(shaped, dict) and "_capped" in shaped:
            inc_capped(tool=name)
        return _to_text(shaped)

    # --- RESOURCES ---
    async def on_list_resources(
        _ctx: ServerRequestContext, _params: PaginatedRequestParams | None
    ) -> ListResourcesResult:
        return ListResourcesResult(resources=_RESOURCES)

    async def on_read_resource(
        _ctx: ServerRequestContext, params: ReadResourceRequestParams
    ) -> ReadResourceResult:
        uri = str(params.uri)
        mime_type = "text/plain"
        if uri == "eset://config/region":
            text = resolver.resolve().region
        elif uri == "eset://config/deployment":
            # For on-prem credentials we surface the server URL too - it's
            # the only useful "where am I" hint the agent has.
            creds = resolver.resolve()
            text = f"onprem ({creds.server_url})" if creds.deployment == "onprem" else "cloud"
        elif uri == "eset://config/tools-catalog":
            catalog = [
                {
                    "name": t.name,
                    "method": t.method,
                    "path": t.path,
                    "service": t.service,
                    "description": t.description,
                }
                for t in tools
            ]
            text = json.dumps(catalog, indent=2, ensure_ascii=False)
            mime_type = "application/json"
        elif uri == "eset://docs/rate-limits":
            text = (
                "# ESET Connect - rate limits\n\n"
                "- **10 req/s** per credential / account / originating IP.\n"
                "- 429 Too Many Requests on exceedance - the MCP server retries with backoff.\n"
                "- Bursts >1000 requests trip the Fair Use Policy: some get 202, "
                "some 50x (must be retried later).\n"
            )
            mime_type = "text/markdown"
        else:
            raise ValueError(f"Unknown resource URI: {uri}")
        return ReadResourceResult(contents=[TextResourceContents(uri=uri, mime_type=mime_type, text=text)])

    # --- PROMPTS ---
    async def on_list_prompts(
        _ctx: ServerRequestContext, _params: PaginatedRequestParams | None
    ) -> ListPromptsResult:
        return ListPromptsResult(prompts=_PROMPTS)

    # Tool names are derived from ESET's operationIds, which ESET renames
    # between spec versions - so prompts look tools up by path, not by name.
    tool_for_path = {t.path: t.name for t in tools}

    async def on_get_prompt(_ctx: ServerRequestContext, params: GetPromptRequestParams) -> GetPromptResult:
        name = params.name
        args = params.arguments or {}
        if name == "audit_inactive_devices":
            days = args.get("days", "30")
            text = (
                f"Use the ESET MCP tools to list devices inactive for at least {days} days.\n"
                f"Steps:\n"
                f"1. `{tool_for_path['/v1/devices']}` - fetch all (follow nextPageToken).\n"
                f"2. Filter by `lastSyncTime` < now - {days}d.\n"
                f"3. Present as a table: name, OS, last seen, group.\n"
            )
        elif name == "vulnerability_report":
            text = (
                "Build a vulnerability report:\n"
                f"1. `{tool_for_path['/v1/vulnerable-devices']}` - list of devices.\n"
                "2. For the top-N (e.g. 10) by severity → "
                f"`{tool_for_path['/v1/device-vulnerabilities']}` with deviceUuid.\n"
                "3. Group by CVE, sort by severity, show top 10.\n"
            )
        elif name == "incident_triage":
            text = (
                "Open incident review:\n"
                f"1. `{tool_for_path['/v2/incidents']}` - list incidents, keep the open ones.\n"
                "2. For each → `incident_full_context` (incident + comments + detections + devices).\n"
                "3. Sort by severity and first-detection time. Propose priorities.\n"
            )
        else:
            raise ValueError(f"Unknown prompt: {name}")
        return GetPromptResult(
            description=name,
            messages=[PromptMessage(role="user", content=TextContent(type="text", text=text))],
        )

    return Server(
        "eset-mcp",
        version=__version__,
        get_tool_input_schema=schemas.get,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
        on_list_resources=on_list_resources,
        on_read_resource=on_read_resource,
        on_list_prompts=on_list_prompts,
        on_get_prompt=on_get_prompt,
    )


def _tool_to_mcp(t: ToolDef) -> Tool:
    """Convert ToolDef -> mcp.types.Tool with read-only annotations."""
    return Tool(
        name=t.name,
        description=t.description,
        input_schema=t.input_schema,
        annotations=_READ_ONLY.model_copy(update={"title": f"{t.method} {t.path}"}),
    )


def _path_segment(value: Any) -> str:
    """Encode one path parameter so it stays a single URL path segment.

    Without this, a value such as ``../v1/users`` (e.g. injected through
    data the agent read from ESET) would walk to a different endpoint.
    """
    raw = str(value)
    if raw in ("", ".", ".."):
        raise _ToolError(f"Invalid path parameter value: {raw!r}", status="bad_request")
    return quote(raw, safe="")


async def _execute_tool(
    http: EsetHttpClient,
    tool: ToolDef,
    arguments: dict[str, Any],
) -> Any:
    """Turn (ToolDef + arguments) into an HTTP request against ESET.

    For on-prem credentials we pick :attr:`ToolDef.onprem_path` when one is
    registered for this tool - see ``openapi/onprem-path-overrides.json``.
    """
    args = dict(arguments)
    # Pick cloud or on-prem variant of the path before placeholder substitution.
    path = tool.path_for(http.credentials.deployment)
    for pname in tool.path_params:
        if pname not in args:
            raise _ToolError(f"Missing required path parameter: {pname}", status="bad_request")
        path = path.replace("{" + pname + "}", _path_segment(args.pop(pname)))

    # Query params: keep only the declared ones, leave the rest in args (e.g. body).
    query = {pname: args.pop(pname) for pname in tool.query_params if pname in args}

    body = args.pop("body", None) if tool.has_body else None
    if args:
        # Unknown parameters - silently drop, but log for debugging.
        _LOG.debug("Dropped unknown parameters for %s: %s", tool.name, list(args))

    return await http.request(tool.method, tool.service, path, query=query, json=body)


def _to_text(result: Any) -> str:
    """Render as JSON text - pretty-printed for readability."""
    try:
        return json.dumps(result, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(result)


def _emit_tool_call_telemetry(
    settings: Settings, name: str, deployment: str, status: str, t0: float, bytes_out: int
) -> None:
    """Emit the metric, log and usage-file records for a finished tool call."""
    duration_s = time.monotonic() - t0
    inc_tool_call(tool=name, deployment=deployment, status=status)
    observe_tool_duration(tool=name, deployment=deployment, seconds=duration_s)
    if bytes_out > 0:
        observe_response_bytes(tool=name, deployment=deployment, n_bytes=bytes_out)
    log_event(
        _LOG, "tool_call",
        tool=name,
        deployment=deployment,
        status=status,
        duration_ms=int(duration_s * 1000),
        response_bytes=bytes_out,
    )
    if settings.usage_log_path:
        record_usage(
            settings.usage_log_path,
            tool=name,
            ok=status == "ok",
            status=status,
            duration_ms=int(duration_s * 1000),
        )


def _shape(result: Any, fields: list[str] | None, max_bytes: int) -> Any:
    """Apply field projection (if requested) and the global byte cap.

    Projection happens first so the cap, when it kicks in, kicks in on
    already-skinnier rows - giving the agent more items per call.
    """
    if fields:
        result = apply_fields_projection(result, fields)
    if max_bytes > 0:
        result, _ = cap_response_size(result, max_bytes)
    return result


async def _dispatch_composite(
    http: EsetHttpClient,
    name: str,
    arguments: dict[str, Any],
    max_bytes: int,
) -> Any:
    """If `name` is one of the composite tools, run it and return its result.

    Returns None when `name` is not a composite - caller falls through to the
    OpenAPI-derived tool registry.
    """
    if name == "eset_search":
        return await eset_search(
            http,
            query=arguments["query"],
            kinds=arguments.get("kinds"),
            limit_per_kind=int(arguments.get("limit_per_kind", 20)),
        )
    if name == "device_full_profile":
        return await device_full_profile(http, device_uuid=arguments["deviceUuid"])
    if name == "incident_full_context":
        return await incident_full_context(http, incident_uuid=arguments["incidentUuid"])
    if name == "latest_detections":
        return await latest_detections(
            http,
            hours=int(arguments.get("hours", 24)),
            limit=int(arguments.get("limit", 10)),
            severity_min=arguments.get("severity_min"),
        )
    if name == "policy_settings":
        return await policy_settings(
            http,
            arguments["policyUuid"],
            path=arguments.get("path"),
            search=arguments.get("search"),
            include_history=bool(arguments.get("include_history", False)),
            raw_flags=bool(arguments.get("raw_flags", False)),
            max_bytes=max_bytes,
        )
    return None

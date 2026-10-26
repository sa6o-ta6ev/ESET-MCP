"""Configuration loaded from .env / environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from dotenv import load_dotenv

Transport = Literal["stdio", "http"]
Region = Literal["eu", "de", "us", "ca", "jpn"]
Deployment = Literal["cloud", "onprem"]

VALID_REGIONS: tuple[Region, ...] = ("eu", "de", "us", "ca", "jpn")


@dataclass(frozen=True)
class Settings:
    user: str
    password: str
    region: Region
    transport: Transport
    http_host: str
    http_port: int
    log_level: str
    # Per-call response byte cap applied AFTER fields projection and BEFORE
    # serialising to the MCP client. 0 disables the cap entirely (not
    # recommended in production - single calls can consume the whole LLM
    # context window). Default ≈25 k tokens on a 4-chars/token heuristic.
    response_bytes_max: int

    # --- On-prem ESET PROTECT support ---
    # Which ESET API the credentials belong to: ``cloud`` (ESET Connect) or
    # ``onprem`` (a customer-hosted ESET PROTECT console).
    deployment: Deployment
    # Required when deployment="onprem". Must be a fully qualified
    # ``https://host[:port]`` URL.
    onprem_server_url: str
    # On-prem PROTECT consoles almost always ship with self-signed certs.
    # Default keeps TLS verification on; operators of intranet deployments
    # opt out with ``ESET_ONPREM_VERIFY_SSL=false``.
    onprem_verify_ssl: bool
    # On-prem only: the API user is an Active Directory account. Sent to
    # ``POST /GetTokens`` as ``is_domain_user``.
    onprem_domain_user: bool
    # Optional Cloudflare Access Service Token, used when the on-prem PROTECT
    # console sits behind Cloudflare Access (zero-trust ingress). When both
    # values are set, the HTTP client adds ``CF-Access-Client-Id`` /
    # ``CF-Access-Client-Secret`` headers to every request - both the
    # ``POST /GetTokens`` auth call and every subsequent API call.
    # Cloud credentials always ignore these (ESET Connect is a public SaaS
    # and is not fronted by anyone's Cloudflare Access).
    onprem_cf_access_client_id: str
    onprem_cf_access_client_secret: str

    # --- Observability ---
    # ``text`` (default) - human-readable single line per record, ideal for
    # local dev. ``json`` - JSON Lines, ideal for log shippers in prod.
    log_format: str
    # Opt-in Prometheus /metrics endpoint (HTTP transport only). When
    # enabled, the metrics route is mounted alongside /mcp on the same
    # uvicorn server. /metrics carries no secrets; protect it at the network
    # layer like the rest of the HTTP endpoint.
    metrics_enabled: bool
    metrics_path: str
    # Append-only JSON Lines file with one record per tool call (tool name,
    # success/failure, duration - never arguments or results). Empty string
    # disables it. Summarise with ``eset-mcp-stats``.
    usage_log_path: str

    @classmethod
    def from_env(cls, env_file: Path | None = None) -> Settings:
        if env_file is None:
            # Prefer .env in the current working directory, then in the repo root,
            # so this works both for `python -m eset_mcp` and docker-compose.
            for candidate in (Path.cwd() / ".env", Path(__file__).resolve().parent.parent / ".env"):
                if candidate.exists():
                    env_file = candidate
                    break
        if env_file:
            load_dotenv(env_file, override=False)

        transport = _parse_transport(os.getenv("ESET_MCP_TRANSPORT", "stdio"))

        user = os.getenv("ESET_USER", "")
        password = os.getenv("ESET_PASSWORD", "")
        if not user or not password:
            raise RuntimeError("ESET_USER and ESET_PASSWORD are required in .env.")

        deployment = _parse_deployment(os.getenv("ESET_DEPLOYMENT", "cloud"))
        onprem_server_url_raw = os.getenv("ESET_ONPREM_SERVER_URL", "").strip()
        onprem_server_url = _normalize_server_url(onprem_server_url_raw) if onprem_server_url_raw else ""
        # Cloudflare Access Service Token (optional). Both values must be set
        # together - half a token pair is useless and almost always a typo.
        cf_id = os.getenv("ESET_ONPREM_CF_ACCESS_CLIENT_ID", "").strip()
        cf_secret = os.getenv("ESET_ONPREM_CF_ACCESS_CLIENT_SECRET", "").strip()
        if bool(cf_id) != bool(cf_secret):
            raise RuntimeError(
                "ESET_ONPREM_CF_ACCESS_CLIENT_ID and "
                "ESET_ONPREM_CF_ACCESS_CLIENT_SECRET must be set together "
                "(both or neither)."
            )
        if deployment == "onprem" and not onprem_server_url:
            raise RuntimeError(
                "ESET_DEPLOYMENT=onprem requires "
                "ESET_ONPREM_SERVER_URL (e.g. https://protect.example.com:9443)."
            )

        return cls(
            user=user,
            password=password,
            region=_parse_region(os.getenv("ESET_REGION", "eu")),
            transport=transport,
            http_host=os.getenv("ESET_MCP_HTTP_HOST", "127.0.0.1"),
            http_port=int(os.getenv("ESET_MCP_HTTP_PORT", "8765")),
            log_level=os.getenv("ESET_LOG_LEVEL", "INFO").upper(),
            response_bytes_max=_parse_int(
                os.getenv("ESET_MCP_RESPONSE_BYTES_MAX", "100000"),
                "ESET_MCP_RESPONSE_BYTES_MAX",
            ),
            deployment=deployment,
            onprem_server_url=onprem_server_url,
            onprem_verify_ssl=_parse_bool(
                os.getenv("ESET_ONPREM_VERIFY_SSL", "true"),
                "ESET_ONPREM_VERIFY_SSL",
            ),
            onprem_domain_user=_parse_bool(
                os.getenv("ESET_ONPREM_DOMAIN_USER", "false"),
                "ESET_ONPREM_DOMAIN_USER",
            ),
            onprem_cf_access_client_id=cf_id,
            onprem_cf_access_client_secret=cf_secret,
            log_format=_parse_log_format(os.getenv("ESET_MCP_LOG_FORMAT", "text")),
            metrics_enabled=_parse_bool(
                os.getenv("ESET_MCP_METRICS_ENABLED", "false"),
                "ESET_MCP_METRICS_ENABLED",
            ),
            metrics_path=os.getenv("ESET_MCP_METRICS_PATH", "/metrics"),
            usage_log_path=os.path.expanduser(
                os.getenv("ESET_MCP_USAGE_LOG", "").split("#", 1)[0].strip()
            ),
        )


def _parse_region(raw: str) -> Region:
    val = raw.split("#", 1)[0].strip().lower()
    if val not in VALID_REGIONS:
        raise RuntimeError(f"ESET_REGION must be one of {VALID_REGIONS}, got {raw!r}")
    return val  # type: ignore[return-value]


def _parse_transport(raw: str) -> Transport:
    val = raw.split("#", 1)[0].strip().lower()
    if val not in ("stdio", "http"):
        raise RuntimeError(f"ESET_MCP_TRANSPORT must be 'stdio' or 'http', got {raw!r}")
    return val  # type: ignore[return-value]


def _parse_deployment(raw: str) -> Deployment:
    val = raw.split("#", 1)[0].strip().lower()
    if val not in ("cloud", "onprem"):
        raise RuntimeError(f"ESET_DEPLOYMENT must be 'cloud' or 'onprem', got {raw!r}")
    return val  # type: ignore[return-value]


def _parse_int(raw: str, var: str) -> int:
    cleaned = raw.split("#", 1)[0].strip()
    try:
        n = int(cleaned)
    except ValueError as e:
        raise RuntimeError(f"{var} must be an integer, got {raw!r}") from e
    if n < 0:
        raise RuntimeError(f"{var} must be >= 0 (0 disables), got {n}")
    return n


def _parse_log_format(raw: str) -> str:
    val = raw.split("#", 1)[0].strip().lower()
    if val not in ("text", "json"):
        raise RuntimeError(f"ESET_MCP_LOG_FORMAT must be 'text' or 'json', got {raw!r}")
    return val


def _parse_bool(raw: str, var: str) -> bool:
    cleaned = raw.split("#", 1)[0].strip().lower()
    if cleaned in ("true", "1", "yes", "on"):
        return True
    if cleaned in ("false", "0", "no", "off"):
        return False
    raise RuntimeError(f"{var} must be a boolean (true/false), got {raw!r}")


def _normalize_server_url(raw: str) -> str:
    """Validate and normalise an on-prem PROTECT server URL.

    Accepts: ``https://host[:port]`` with no path/query/fragment.
    Strips any trailing slash so callers can safely concatenate ``"/path"``.
    HTTPS is mandatory - on-prem PROTECT consoles default to port 9443 over
    TLS, and the login call carries the API user's password.
    """
    parts = urlsplit(raw)
    if parts.scheme != "https":
        raise RuntimeError(
            f"ESET on-prem server URL must use https://, got {raw!r}. "
            "On-prem PROTECT consoles default to port 9443 over TLS; "
            "plain HTTP would leak the API password."
        )
    if not parts.hostname:
        raise RuntimeError(f"ESET on-prem server URL is missing a hostname: {raw!r}")
    if parts.path and parts.path != "/":
        raise RuntimeError(
            f"ESET on-prem server URL must not include a path; got {raw!r}. "
            "Use just the origin (e.g. https://protect.example.com:9443)."
        )
    if parts.query or parts.fragment:
        raise RuntimeError(f"ESET on-prem server URL must not include query/fragment: {raw!r}")
    # Rebuild with no path, no trailing slash.
    netloc = parts.netloc
    return f"https://{netloc}"

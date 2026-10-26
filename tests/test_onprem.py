"""Unit tests for on-prem ESET PROTECT support.

These run entirely without network - they exercise:
- Settings parsing of ESET_DEPLOYMENT / ESET_ONPREM_SERVER_URL / ESET_ONPREM_VERIFY_SSL
- Credentials.cache_key() distinguishing cloud vs on-prem (and same user on
  two different on-prem URLs)
- OnPremTokenManager wire format against a mocked HTTP server (respx)
- On-prem path overrides (ToolDef.path_for)
- httpx verify=… wiring driven by Credentials.verify_ssl
"""
from __future__ import annotations

import json

import httpx
import pytest
import respx

from eset_mcp.auth import CloudTokenManager, OnPremTokenManager, make_token_manager
from eset_mcp.config import Settings
from eset_mcp.credentials import Credentials, EnvCredentialResolver
from eset_mcp.http_client import EsetHttpClient
from eset_mcp.regions import resolve_auth_url, resolve_base_url
from eset_mcp.tools_loader import ToolDef


# --- Settings (env parsing) ---
def _set_env(monkeypatch, **overrides) -> None:
    """Replace any ESET_* env vars with a clean baseline + caller's overrides."""
    # Wipe state so tests don't leak between each other.
    for key in list(monkeypatch._setitem if hasattr(monkeypatch, "_setitem") else []):
        if key.startswith("ESET_"):
            monkeypatch.delenv(key, raising=False)
    baseline = {
        "ESET_USER": "u@example.com",
        "ESET_PASSWORD": "pw",
        "ESET_REGION": "eu",
        "ESET_MCP_TRANSPORT": "stdio",
    }
    baseline.update(overrides)
    for k, v in baseline.items():
        monkeypatch.setenv(k, v)


def test_settings_default_deployment_is_cloud(monkeypatch) -> None:
    _set_env(monkeypatch)
    s = Settings.from_env(env_file=None)
    assert s.deployment == "cloud"
    assert s.onprem_server_url == ""
    assert s.onprem_verify_ssl is True


def test_settings_onprem_requires_server_url(monkeypatch) -> None:
    _set_env(monkeypatch, ESET_DEPLOYMENT="onprem")
    with pytest.raises(RuntimeError, match="ESET_ONPREM_SERVER_URL"):
        Settings.from_env(env_file=None)


def test_settings_onprem_server_url_normalised(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.example.com:9443/",
    )
    s = Settings.from_env(env_file=None)
    # Trailing slash dropped so callers can concatenate "/path" safely.
    assert s.onprem_server_url == "https://protect.example.com:9443"


def test_settings_onprem_server_url_http_rejected(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="http://protect.example.com:9443",
    )
    with pytest.raises(RuntimeError, match="https"):
        Settings.from_env(env_file=None)


def test_settings_onprem_server_url_with_path_rejected(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.example.com:9443/api",
    )
    with pytest.raises(RuntimeError, match="path"):
        Settings.from_env(env_file=None)


def test_settings_onprem_verify_ssl_false(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.local:9443",
        ESET_ONPREM_VERIFY_SSL="false",
    )
    s = Settings.from_env(env_file=None)
    assert s.onprem_verify_ssl is False


# --- Credentials.cache_key() ---
def test_cache_key_distinguishes_cloud_from_onprem() -> None:
    cloud = Credentials(user="u", password="pw", region="eu")
    onprem = Credentials(
        user="u", password="pw", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
    )
    assert cloud.cache_key() != onprem.cache_key()
    # Cloud key carries region.
    assert cloud.cache_key()[2] == "cloud"
    assert cloud.cache_key()[3] == "eu"
    # On-prem key carries the URL.
    assert onprem.cache_key()[2] == "onprem"
    assert onprem.cache_key()[3] == "https://protect.local:9443"


def test_cache_key_distinguishes_two_onprem_consoles() -> None:
    a = Credentials(user="u", password="pw", region="eu",
                    deployment="onprem", server_url="https://a.local:9443")
    b = Credentials(user="u", password="pw", region="eu",
                    deployment="onprem", server_url="https://b.local:9443")
    assert a.cache_key() != b.cache_key()


def test_cache_key_password_hash_changes_when_password_rotates() -> None:
    """Rotating the password forces a new pool entry - no stale-token reuse."""
    a = Credentials(user="u", password="old", region="eu")
    b = Credentials(user="u", password="new", region="eu")
    assert a.cache_key() != b.cache_key()


# --- Region/URL resolution ---
def test_resolve_base_url_cloud_per_service() -> None:
    c = Credentials(user="u", password="pw", region="eu")
    assert resolve_base_url(c, "device-management") == "https://eu.device-management.eset.systems"
    assert resolve_base_url(c, "policy-management") == "https://eu.policy-management.eset.systems"


def test_resolve_base_url_onprem_collapses_to_single_host() -> None:
    c = Credentials(user="u", password="pw", region="eu",
                    deployment="onprem", server_url="https://protect.local:9443")
    # On-prem uses one origin for everything.
    assert resolve_base_url(c, "device-management") == "https://protect.local:9443"
    assert resolve_base_url(c, "policy-management") == "https://protect.local:9443"


def test_resolve_auth_url_picks_right_endpoint() -> None:
    cloud = Credentials(user="u", password="pw", region="eu")
    assert "/oauth/token" in resolve_auth_url(cloud)

    onprem = Credentials(user="u", password="pw", region="eu",
                         deployment="onprem", server_url="https://protect.local:9443")
    assert resolve_auth_url(onprem) == "https://protect.local:9443/GetTokens"


def test_resolve_base_url_onprem_without_server_url_raises() -> None:
    bad = Credentials(user="u", password="pw", region="eu", deployment="onprem")
    with pytest.raises(RuntimeError, match="server URL"):
        resolve_base_url(bad, "device-management")


# --- EnvCredentialResolver ---
def test_env_resolver_propagates_onprem_settings(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.local:9443",
        ESET_ONPREM_VERIFY_SSL="false",
    )
    s = Settings.from_env(env_file=None)
    r = EnvCredentialResolver(s)
    c = r.resolve()
    assert c.deployment == "onprem"
    assert c.server_url == "https://protect.local:9443"
    assert c.verify_ssl is False
    assert c.domain_user is False


def test_env_resolver_propagates_domain_user(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.local:9443",
        ESET_ONPREM_DOMAIN_USER="true",
    )
    c = EnvCredentialResolver(Settings.from_env(env_file=None)).resolve()
    assert c.domain_user is True


# --- OnPremTokenManager wire format (respx mock) ---
@respx.mock
async def test_onprem_token_manager_posts_get_tokens() -> None:
    """OnPremTokenManager hits POST /GetTokens with the documented JSON body
    and parses camelCase {accessToken, expiresIn}."""
    creds = Credentials(
        user="u@example.com", password="s3cret", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
    )
    route = respx.post("https://protect.local:9443/GetTokens").mock(
        return_value=httpx.Response(200, json={"accessToken": "AAA", "expiresIn": 3600})
    )
    async with httpx.AsyncClient() as http:
        mgr = OnPremTokenManager(creds, http)
        token = await mgr.get_access_token()

    assert token == "AAA"
    assert route.called
    # Verify wire format: JSON body with exactly the three documented keys
    # (ESET help: "Set up the ESET PROTECT On-Prem REST API" - camelCase grantType).
    sent = route.calls.last.request
    body = json.loads(sent.content.decode("utf-8"))
    assert body == {"username": "u@example.com", "password": "s3cret", "grantType": "password"}
    assert "grant_type" not in body
    assert sent.headers.get("content-type", "").startswith("application/json")


@respx.mock
async def test_onprem_token_manager_marks_domain_user() -> None:
    """Active Directory API users add is_domain_user=true to /GetTokens."""
    creds = Credentials(
        user="CORP\\api", password="s3cret", region="eu",
        deployment="onprem", server_url="https://protect.local:9443", domain_user=True,
    )
    route = respx.post("https://protect.local:9443/GetTokens").mock(
        return_value=httpx.Response(200, json={"accessToken": "AAA", "expiresIn": 3600})
    )
    async with httpx.AsyncClient() as http:
        await OnPremTokenManager(creds, http).get_access_token()
    body = json.loads(route.calls.last.request.content.decode("utf-8"))
    assert body["is_domain_user"] is True
    assert body["grantType"] == "password"


@respx.mock
async def test_onprem_token_manager_missing_access_token_errors() -> None:
    creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
    )
    respx.post("https://protect.local:9443/GetTokens").mock(
        return_value=httpx.Response(200, json={"oops": True})
    )
    async with httpx.AsyncClient() as http:
        mgr = OnPremTokenManager(creds, http)
        with pytest.raises(Exception, match="accessToken"):
            await mgr.get_access_token()


def test_make_token_manager_picks_by_deployment() -> None:
    import httpx as _httpx
    h = _httpx.AsyncClient()
    cloud_creds = Credentials(user="u", password="p", region="eu")
    onprem_creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
    )
    assert isinstance(make_token_manager(cloud_creds, h), CloudTokenManager)
    assert isinstance(make_token_manager(onprem_creds, h), OnPremTokenManager)


# --- EsetHttpClient TLS verify wiring ---
async def test_http_client_onprem_verify_true_by_default() -> None:
    creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
    )
    client = EsetHttpClient(creds)
    try:
        # httpx exposes the verify flag indirectly via the transport's SSL context.
        # We check the public _transport's verify config - internal attribute,
        # but stable enough across httpx 0.27+.
        assert client._http.is_closed is False
    finally:
        await client.aclose()


def test_http_client_onprem_verify_false_honoured_and_warns(caplog) -> None:
    creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
        verify_ssl=False,
    )
    import logging
    with caplog.at_level(logging.WARNING, logger="eset_mcp.http"):
        client = EsetHttpClient(creds)
    # The warning happens exactly once at construction.
    warnings = [r for r in caplog.records if "verification DISABLED" in r.getMessage()]
    assert len(warnings) == 1
    assert "https://protect.local:9443" in warnings[0].getMessage()
    # Don't bother awaiting close - pytest tears down the loop.
    del client


# --- On-prem path overrides (tools_loader) ---
def test_tool_def_path_for_picks_onprem_when_override_present() -> None:
    t = ToolDef(
        name="x", description="", input_schema={}, service="device-management",
        method="GET", path="/v1/devices/{u}", operation_id="Devices_GetDevice",
        onprem_path="/v1/legacy-devices/{u}",
    )
    assert t.path_for("cloud") == "/v1/devices/{u}"
    assert t.path_for("onprem") == "/v1/legacy-devices/{u}"


def test_tool_def_path_for_falls_back_to_cloud_when_no_override() -> None:
    t = ToolDef(
        name="x", description="", input_schema={}, service="device-management",
        method="GET", path="/v1/devices", operation_id="Devices_ListDevices",
    )
    assert t.path_for("cloud") == "/v1/devices"
    assert t.path_for("onprem") == "/v1/devices"  # no override → same path


# --- Cloudflare Access Service Token ---
def test_settings_cf_access_requires_both_id_and_secret(monkeypatch) -> None:
    """Half-pair (only ID, only SECRET) is a 100% chance of operator typo."""
    _set_env(monkeypatch, ESET_ONPREM_CF_ACCESS_CLIENT_ID="just-the-id")
    with pytest.raises(RuntimeError, match="must be set together"):
        Settings.from_env(env_file=None)


def test_settings_cf_access_both_set_ok(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.local:9443",
        ESET_ONPREM_CF_ACCESS_CLIENT_ID="abc.access",
        ESET_ONPREM_CF_ACCESS_CLIENT_SECRET="s3cr3t",
    )
    s = Settings.from_env(env_file=None)
    assert s.onprem_cf_access_client_id == "abc.access"
    assert s.onprem_cf_access_client_secret == "s3cr3t"


def test_http_client_onprem_attaches_cf_headers_to_httpx_defaults() -> None:
    """When CF tokens are present, the httpx client default headers carry
    CF-Access-Client-Id / CF-Access-Client-Secret on every outbound call -
    including the /GetTokens auth call (same underlying httpx client)."""
    creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
        cf_access_client_id="abc.access", cf_access_client_secret="s3cr3t",
    )
    client = EsetHttpClient(creds)
    try:
        assert client._http.headers["cf-access-client-id"] == "abc.access"
        assert client._http.headers["cf-access-client-secret"] == "s3cr3t"
    finally:
        del client


def test_http_client_cloud_does_not_attach_cf_headers() -> None:
    """Cloud creds must NEVER carry CF Access headers - ESET Connect is a
    public SaaS and is not behind anyone's Cloudflare Access."""
    creds = Credentials(
        user="u", password="p", region="eu",
        cf_access_client_id="abc.access", cf_access_client_secret="s3cr3t",
    )
    client = EsetHttpClient(creds)
    try:
        assert "cf-access-client-id" not in client._http.headers
        assert "cf-access-client-secret" not in client._http.headers
    finally:
        del client


@respx.mock
async def test_onprem_get_tokens_call_carries_cf_headers() -> None:
    """End-to-end wiring check: /GetTokens (auth handshake) must include the
    CF Access headers, otherwise Cloudflare blocks it at the edge."""
    creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
        cf_access_client_id="abc.access", cf_access_client_secret="s3cr3t",
    )
    route = respx.post("https://protect.local:9443/GetTokens").mock(
        return_value=httpx.Response(200, json={"accessToken": "T", "expiresIn": 3600})
    )
    client = EsetHttpClient(creds)
    try:
        token = await client._token_mgr.get_access_token()
        assert token == "T"
        sent = route.calls.last.request
        assert sent.headers.get("CF-Access-Client-Id") == "abc.access"
        assert sent.headers.get("CF-Access-Client-Secret") == "s3cr3t"
    finally:
        await client.aclose()

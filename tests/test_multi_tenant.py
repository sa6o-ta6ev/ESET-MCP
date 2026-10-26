"""Multi-tenant mode: tenants file, tenant argument, per-tenant credentials (no network)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest
import respx
from mcp import Client

from eset_mcp.check_tenants import list_endpoints, probe_tenant, render
from eset_mcp.client_pool import ClientPool
from eset_mcp.config import Settings
from eset_mcp.credentials import FileCredentialProvider, TenantError, build_provider
from eset_mcp.server import build_server
from eset_mcp.tools_loader import load_all_tools

LIST_DEVICES = {t.path: t.name for t in load_all_tools()}["/v1/devices"]

TENANTS_TOML = """
[[tenant]]
id = "acme"
name = "ACME Ltd"
region = "eu"
user = "api@acme.example"
password_file = "acme.password"

[[tenant]]
id = "globex"
name = "Globex"
region = "us"
user = "api@globex.example"
password_file = "globex.password"
"""


def write_tenants(tmp_path: Path, toml: str = TENANTS_TOML, passwords: dict | None = None) -> Path:
    folder = tmp_path / "tenants"
    folder.mkdir()
    (folder / "tenants.toml").write_text(toml)
    for tenant_id, password in (passwords or {"acme": "pw-acme", "globex": "pw-globex"}).items():
        f = folder / f"{tenant_id}.password"
        f.write_text(password + "\n")
        os.chmod(f, 0o600)
    return folder / "tenants.toml"


# --- provider ---
def test_file_provider_lists_tenants_and_resolves_credentials(tmp_path) -> None:
    provider = FileCredentialProvider(write_tenants(tmp_path))
    assert [(t.id, t.name, t.region) for t in provider.tenants()] == [
        ("acme", "ACME Ltd", "eu"), ("globex", "Globex", "us")]
    creds = provider.resolve("globex")
    assert (creds.user, creds.password, creds.region) == ("api@globex.example", "pw-globex", "us")


def test_password_rotation_needs_no_restart(tmp_path) -> None:
    path = write_tenants(tmp_path)
    provider = FileCredentialProvider(path)
    (path.parent / "acme.password").write_text("rotated")
    assert provider.resolve("acme").password == "rotated"


@pytest.mark.parametrize("bad, message", [
    ('[[tenant]]\nid="a"\nregion="eu"\nuser="u"\npassword="secret"\n', "not allowed in the tenants file"),
    ('[[tenant]]\nid="Bad Id"\nregion="eu"\nuser="u"\npassword_file="x"\n', "lowercase"),
    ('[[tenant]]\nid="a"\nregion="mars"\nuser="u"\npassword_file="x"\n', "region"),
    ('[[tenant]]\nid="a"\nregion="eu"\nuser="u"\npassword_file="missing.password"\n', "cannot read password file"),
    ('[[tenant]]\nid="a"\nregion="eu"\nuser="u"\npassword_file="a.password"\ndeployment="onprem"\n', "only cloud"),
    ("", r"no \[\[tenant\]\]"),
])
def test_invalid_tenants_file_fails_at_startup(tmp_path, bad, message) -> None:
    path = write_tenants(tmp_path, bad, {"a": "pw"})
    with pytest.raises(TenantError, match=message):
        FileCredentialProvider(path)


def test_duplicate_tenant_ids_rejected(tmp_path) -> None:
    toml = TENANTS_TOML.replace('id = "globex"', 'id = "acme"')
    with pytest.raises(TenantError, match="defined twice"):
        FileCredentialProvider(write_tenants(tmp_path, toml))


def test_unknown_or_missing_tenant_rejected(tmp_path) -> None:
    provider = FileCredentialProvider(write_tenants(tmp_path))
    with pytest.raises(TenantError, match="Unknown tenant"):
        provider.resolve("initech")
    with pytest.raises(TenantError, match="required"):
        provider.resolve(None)


def test_settings_accept_tenants_file_without_env_credentials(tmp_path, monkeypatch) -> None:
    path = write_tenants(tmp_path)
    monkeypatch.delenv("ESET_USER", raising=False)
    monkeypatch.delenv("ESET_PASSWORD", raising=False)
    monkeypatch.setenv("ESET_TENANTS_FILE", str(path))
    provider = build_provider(Settings.from_env(env_file=None))
    assert provider.multi_tenant and len(provider.tenants()) == 2


# --- server ---
@pytest.fixture
def multi_settings(tmp_path, monkeypatch) -> Settings:
    monkeypatch.setenv("ESET_TENANTS_FILE", str(write_tenants(tmp_path)))
    monkeypatch.setenv("ESET_MCP_USAGE_LOG", str(tmp_path / "usage.jsonl"))
    monkeypatch.setenv("ESET_MCP_TRANSPORT", "stdio")
    return Settings.from_env(env_file=None)


async def test_tools_require_tenant_and_route_to_its_account(multi_settings) -> None:
    with respx.mock(assert_all_called=False) as mock:
        eu_token = mock.post("https://eu.business-account.iam.eset.systems/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "EU", "expires_in": 3600}))
        mock.post("https://us.business-account.iam.eset.systems/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "US", "expires_in": 3600}))
        us_devices = mock.get("https://us.device-management.eset.systems/v1/devices").mock(
            return_value=httpx.Response(200, json={"devices": [{"uuid": "g1", "tags": [""]}]}))
        pool = ClientPool(multi_settings)
        provider = build_provider(multi_settings)
        try:
            async with Client(build_server(multi_settings, pool, provider)) as client:
                tools = {t.name: t for t in (await client.list_tools()).tools}
                listed = await client.call_tool("list_tenants", {})
                missing = await client.call_tool(LIST_DEVICES, {})
                wrong = await client.call_tool(LIST_DEVICES, {"tenant": "initech"})
                ok = await client.call_tool(LIST_DEVICES, {"tenant": "globex"})
        finally:
            await pool.close()

    assert "list_tenants" in tools
    schema = tools[LIST_DEVICES].input_schema
    assert "tenant" in schema["required"]
    assert schema["properties"]["tenant"]["enum"] == ["acme", "globex"]
    assert "tenant" not in tools["list_tenants"].input_schema["properties"]
    assert json.loads(listed.content[0].text)["tenants"][1] == {
        "id": "globex", "name": "Globex", "region": "us", "deployment": "cloud"}
    assert "password" not in listed.content[0].text
    assert missing.is_error and "tenant" in missing.content[0].text
    assert wrong.is_error  # rejected by the schema enum
    assert not ok.is_error
    assert json.loads(ok.content[0].text)["devices"][0]["uuid"] == "g1"
    # Globex (us) was called with its own token; ACME (eu) was never logged into.
    assert us_devices.calls.last.request.headers["authorization"] == "Bearer US"
    assert not eu_token.called
    records = [json.loads(line) for line in open(multi_settings.usage_log_path)]
    assert records[-1]["tenant"] == "globex" and records[-1]["ok"] is True


# --- check-tenants ---
async def test_check_tenants_matrix(tmp_path) -> None:
    provider = FileCredentialProvider(write_tenants(tmp_path))
    endpoints = [e for e in list_endpoints() if e.path in ("/v1/devices", "/v1/quarantined-objects")]
    with respx.mock(assert_all_called=False) as mock:
        mock.post("https://eu.business-account.iam.eset.systems/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "EU", "expires_in": 3600}))
        mock.post("https://us.business-account.iam.eset.systems/oauth/token").mock(
            return_value=httpx.Response(401))
        mock.get("https://eu.device-management.eset.systems/v1/devices").mock(
            return_value=httpx.Response(200, json={"devices": []}))
        mock.get("https://eu.quarantine-management.eset.systems/v1/quarantined-objects").mock(
            return_value=httpx.Response(404))
        acme = await probe_tenant(provider, "acme", endpoints)
        globex = await probe_tenant(provider, "globex", endpoints)
    assert acme == {"/v1/devices": "200", "/v1/quarantined-objects": "404"}
    assert globex["_login"].startswith("login failed (401)")
    text = render(["acme", "globex"], endpoints, {"acme": acme, "globex": globex})
    assert "!! globex: login failed" in text
    assert "GET /v1/quarantined-objects" in text


def test_check_tenants_render_when_no_tenant_logs_in() -> None:
    endpoints = [e for e in list_endpoints() if e.path == "/v1/devices"]
    text = render(["acme"], endpoints, {"acme": {"_login": "login failed (401)"}})
    assert text.splitlines() == ["!! acme: login failed (401)", "No tenant could log in - nothing to compare."]

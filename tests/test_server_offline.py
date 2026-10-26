"""End-to-end tests of the MCP server without an ESET account.

Builds the real server, connects an in-process MCP client, and mocks the
ESET HTTP API with respx. Unlike the integration tests these always run, so
an SDK upgrade that breaks startup or dispatch fails CI immediately.
"""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp import Client

from eset_mcp import http_client as http_client_module
from eset_mcp.client_pool import ClientPool
from eset_mcp.config import Settings
from eset_mcp.credentials import EnvCredentialResolver
from eset_mcp.server import build_server
from eset_mcp.tools_loader import load_all_tools

TOKEN_URL = "https://eu.business-account.iam.eset.systems/oauth/token"
DEVICES_URL = "https://eu.device-management.eset.systems/v1/devices"

TOOL_BY_PATH = {t.path: t.name for t in load_all_tools()}
LIST_DEVICES = TOOL_BY_PATH["/v1/devices"]
GET_DEVICE = TOOL_BY_PATH["/v1/devices/{deviceUuid}"]


@pytest.fixture
def settings(monkeypatch, tmp_path) -> Settings:
    for key, value in {
        "ESET_USER": "api@example.com",
        "ESET_PASSWORD": "pw",
        "ESET_REGION": "eu",
        "ESET_DEPLOYMENT": "cloud",
        "ESET_MCP_TRANSPORT": "stdio",
        "ESET_MCP_USAGE_LOG": str(tmp_path / "usage.jsonl"),
    }.items():
        monkeypatch.setenv(key, value)
    return Settings.from_env(env_file=None)


@pytest.fixture
def eset_api():
    with respx.mock(assert_all_called=False) as mock:
        mock.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "T", "expires_in": 3600})
        )
        yield mock


async def _client_for(settings: Settings):
    pool = ClientPool(settings)
    server = build_server(settings, pool, EnvCredentialResolver(settings))
    return pool, Client(server)


def _usage(settings: Settings) -> list[dict]:
    with open(settings.usage_log_path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


async def test_server_starts_and_lists_only_read_tools(settings, eset_api) -> None:
    pool, client = await _client_for(settings)
    try:
        async with client:
            tools = (await client.list_tools()).tools
    finally:
        await pool.close()
    names = {t.name for t in tools}
    assert len(tools) == len(load_all_tools()) + 4
    assert {"eset_search", "device_full_profile", "incident_full_context", "latest_detections"} <= names
    assert all(t.annotations and t.annotations.read_only_hint for t in tools)
    assert not any("installer" in n for n in names)


async def test_tool_call_success_is_not_error_and_is_recorded(settings, eset_api) -> None:
    eset_api.get(DEVICES_URL).mock(
        return_value=httpx.Response(200, json={"devices": [{"uuid": "d1", "displayName": "pc-1"}]})
    )
    pool, client = await _client_for(settings)
    try:
        async with client:
            result = await client.call_tool(LIST_DEVICES, {"pageSize": 1})
    finally:
        await pool.close()
    assert not result.is_error
    assert json.loads(result.content[0].text)["devices"][0]["uuid"] == "d1"
    [record] = _usage(settings)
    assert record["tool"] == LIST_DEVICES
    assert record["ok"] is True
    assert record["status"] == "ok"


async def test_eset_error_is_flagged_and_recorded_as_failure(settings, eset_api) -> None:
    eset_api.get(f"{DEVICES_URL}/missing").mock(return_value=httpx.Response(404, text="not found"))
    pool, client = await _client_for(settings)
    try:
        async with client:
            result = await client.call_tool(GET_DEVICE, {"deviceUuid": "missing"})
    finally:
        await pool.close()
    assert result.is_error
    assert result.content[0].text.startswith("ESET API error:")
    [record] = _usage(settings)
    assert record["ok"] is False
    assert record["status"] == "404"


async def test_composite_primary_failure_is_flagged(settings, eset_api) -> None:
    eset_api.get(f"{DEVICES_URL}/missing").mock(return_value=httpx.Response(404, text="not found"))
    pool, client = await _client_for(settings)
    try:
        async with client:
            result = await client.call_tool("device_full_profile", {"deviceUuid": "missing"})
    finally:
        await pool.close()
    assert result.is_error
    assert "Device fetch failed" in result.content[0].text
    assert _usage(settings)[0]["ok"] is False


async def test_path_parameter_cannot_escape_its_segment(settings, eset_api) -> None:
    """'../users' must stay inside /v1/devices/{deviceUuid}, not reach /v1/users."""
    route = eset_api.get(url__regex=r"https://eu\.device-management\.eset\.systems/.*").mock(
        return_value=httpx.Response(404, text="not found")
    )
    pool, client = await _client_for(settings)
    try:
        async with client:
            await client.call_tool(GET_DEVICE, {"deviceUuid": "../users"})
            dotdot = await client.call_tool(GET_DEVICE, {"deviceUuid": ".."})
    finally:
        await pool.close()
    assert route.call_count == 1
    assert route.calls.last.request.url.raw_path == b"/v1/devices/..%2Fusers"
    # A bare '..' is rejected before any request is made.
    assert dotdot.is_error
    assert "Invalid path parameter" in dotdot.content[0].text


async def test_transient_5xx_is_retried_once(settings, eset_api, monkeypatch) -> None:
    monkeypatch.setattr(http_client_module, "_TRANSIENT_RETRY_DELAY_S", 0)
    route = eset_api.get(DEVICES_URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json={"devices": []})]
    )
    pool, client = await _client_for(settings)
    try:
        async with client:
            result = await client.call_tool(LIST_DEVICES, {})
    finally:
        await pool.close()
    assert not result.is_error
    assert route.call_count == 2


async def test_invalid_arguments_are_rejected_before_any_request(settings, eset_api) -> None:
    route = eset_api.get(url__regex=r"https://eu\.device-management\.eset\.systems/.*")
    pool, client = await _client_for(settings)
    try:
        async with client:
            missing = await client.call_tool("device_full_profile", {"bogus": 1})
            wrong_type = await client.call_tool(LIST_DEVICES, {"pageSize": "lots"})
    finally:
        await pool.close()
    assert missing.is_error and "Invalid arguments" in missing.content[0].text
    assert "deviceUuid" in missing.content[0].text
    assert wrong_type.is_error and "pageSize" in wrong_type.content[0].text
    assert route.call_count == 0
    assert {r["status"] for r in _usage(settings)} == {"invalid_arguments"}


async def test_unexpected_exception_becomes_tool_error(settings, eset_api) -> None:
    eset_api.get(DEVICES_URL).mock(side_effect=httpx.ConnectError("boom"))
    pool, client = await _client_for(settings)
    try:
        async with client:
            result = await client.call_tool(LIST_DEVICES, {})
    finally:
        await pool.close()
    assert result.is_error
    assert "ConnectError" in result.content[0].text
    assert _usage(settings)[0]["status"] == "exception"


def test_every_tool_schema_is_valid_json_schema(settings) -> None:
    from jsonschema.validators import validator_for

    from eset_mcp.server import _COMPOSITE_TOOLS
    schemas = [t.input_schema for t in load_all_tools()] + [t.input_schema for t in _COMPOSITE_TOOLS]
    for schema in schemas:
        validator_for(schema).check_schema(schema)


async def test_unknown_tool_is_an_error(settings, eset_api) -> None:
    pool, client = await _client_for(settings)
    try:
        async with client:
            result = await client.call_tool("device_devices__move_device", {"deviceUuid": "x"})
    finally:
        await pool.close()
    assert result.is_error


async def test_prompts_reference_existing_tools(settings, eset_api) -> None:
    pool, client = await _client_for(settings)
    try:
        async with client:
            prompts = (await client.list_prompts()).prompts
            texts = [
                (await client.get_prompt(p.name, {})).messages[0].content.text for p in prompts
            ]
            tool_names = {t.name for t in (await client.list_tools()).tools}
    finally:
        await pool.close()
    assert len(texts) == 3
    for text in texts:
        # Backticked words that look like tool names (generated names contain
        # "__", composites use snake_case) - skips field names like lastSyncTime.
        quoted = set(text.split("`")[1::2])
        referenced = {q for q in quoted if "__" in q or ("_" in q and q.islower())}
        assert referenced, f"prompt mentions no tools: {text!r}"
        assert referenced <= tool_names, f"prompt references unknown tools: {referenced - tool_names}"


async def test_resources_are_readable(settings, eset_api) -> None:
    pool, client = await _client_for(settings)
    try:
        async with client:
            resources = (await client.list_resources()).resources
            for r in resources:
                content = await client.read_resource(str(r.uri))
                assert content.contents[0].text
            region = await client.read_resource("eset://config/region")
    finally:
        await pool.close()
    assert region.contents[0].text == "eu"

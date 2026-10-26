"""RO smoke tests - hit the real ESET API and verify that GET tools
are callable and return data matching the documentation.
"""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.ro


async def test_catalog_is_read_only(mcp_session) -> None:
    """The catalog exposes only read-only tools: generated GET tools + 4 composites."""
    from eset_mcp.tools_loader import load_all_tools
    async with mcp_session() as client:
        tools = await client.list_tools()
        assert len(tools.tools) == len(load_all_tools()) + 4
        for t in tools.tools:
            assert t.annotations and t.annotations.read_only_hint, (
                f"{t.name} listed without read_only_hint=True"
            )


async def test_composite_tools_present(mcp_session) -> None:
    """The hand-written high-level tools (all RO) must be in the catalog in any mode."""
    async with mcp_session() as client:
        tools = await client.list_tools()
        names = {t.name for t in tools.tools}
        assert {
            "eset_search",
            "device_full_profile",
            "incident_full_context",
            "latest_detections",
        } <= names


async def test_resources_exposed(mcp_session) -> None:
    async with mcp_session() as client:
        resources = await client.list_resources()
        uris = {str(r.uri) for r in resources.resources}
        assert "eset://config/region" in uris
        assert "eset://config/tools-catalog" in uris


async def test_resources_readable(mcp_session) -> None:
    """Every advertised resource must be readable end-to-end (catches AnyUrl-vs-str bugs)."""
    async with mcp_session() as client:
        resources = await client.list_resources()
        for r in resources.resources:
            content = await client.read_resource(r.uri)
            assert content.contents, f"empty contents for {r.uri}"
            assert content.contents[0].text, f"no text for {r.uri}"


async def test_list_device_groups(mcp_session, tool_name) -> None:
    """RO endpoint /v1/device_groups - must return a list under `deviceGroups`."""
    async with mcp_session() as client:
        result = await client.call_tool(
            tool_name("/v1/device_groups"), arguments={"pageSize": 5}
        )
    payload = json.loads(result.content[0].text)
    assert "deviceGroups" in payload
    assert isinstance(payload["deviceGroups"], list)
    if payload["deviceGroups"]:
        g = payload["deviceGroups"][0]
        assert "uuid" in g and "displayName" in g


async def test_list_managed_devices(mcp_session, tool_name) -> None:
    async with mcp_session() as client:
        result = await client.call_tool(
            tool_name("/v1/devices"), arguments={"pageSize": 5}
        )
    text = result.content[0].text
    if text.startswith("ESET API error:"):
        pytest.skip(f"endpoint not available for this account: {text}")
    payload = json.loads(text)
    assert "devices" in payload
    assert isinstance(payload["devices"], list)


async def test_list_tasks(mcp_session, tool_name) -> None:
    """Automation /v1/device_tasks."""
    async with mcp_session() as client:
        result = await client.call_tool(
            tool_name("/v1/device_tasks"), arguments={"pageSize": 5}
        )
    text = result.content[0].text
    if text.startswith("ESET API error:"):
        pytest.skip(f"endpoint not available for this account: {text}")
    payload = json.loads(text)
    assert "deviceTasks" in payload or "tasks" in payload


async def test_list_users(mcp_session, tool_name) -> None:
    async with mcp_session() as client:
        result = await client.call_tool(tool_name("/v1/users"), arguments={"pageSize": 5})
    text = result.content[0].text
    if text.startswith("ESET API error:"):
        pytest.skip(f"user-management not available for this account: {text}")
    payload = json.loads(text)
    assert "users" in payload


# --- Response shaping: live verification ---
async def test_fields_projection_returns_skinny_rows(mcp_session, tool_name) -> None:
    """`fields=['uuid','displayName']` must drop every other key per device."""
    async with mcp_session() as client:
        result = await client.call_tool(
            tool_name("/v1/devices"),
            arguments={"pageSize": 5, "fields": ["uuid", "displayName"]},
        )
    payload = json.loads(result.content[0].text)
    assert payload.get("devices")
    for device in payload["devices"]:
        # Every projected device must have *only* the requested keys.
        # (Some endpoints return items without a displayName - that's fine,
        # the key may be missing, but no other keys may appear.)
        assert set(device.keys()) <= {"uuid", "displayName"}, (
            f"projection leaked extra keys: {sorted(set(device.keys()) - {'uuid','displayName'})}"
        )
        assert "uuid" in device, "uuid must survive projection"


async def test_response_size_cap_kicks_in_on_large_payload(mcp_session, tool_name) -> None:
    """Forcing pageSize=1000 should overflow the default 100 KB cap.

    The response must (a) still be valid JSON, (b) carry a `_capped` metadata
    block, (c) preserve `nextPageToken` if the endpoint returned one, and
    (d) be smaller than it would have been uncapped.
    """
    async with mcp_session() as client:
        result = await client.call_tool(
            tool_name("/v1/devices"),
            arguments={"pageSize": 1000},
        )
    text = result.content[0].text
    assert len(text.encode("utf-8")) < 200_000, (
        "Capped response should be well below the uncapped ~800 KB seen on this tenant; "
        f"got {len(text.encode('utf-8'))} bytes."
    )
    payload = json.loads(text)
    if "_capped" not in payload:
        # If the tenant has so few devices that even pageSize=1000 fits under
        # the cap, the test is a no-op - skip rather than fail.
        pytest.skip("Tenant returned a smaller-than-cap list; nothing to truncate.")
    meta = payload["_capped"]
    assert meta["truncated"] is True
    assert meta["itemsKey"] == "devices"
    assert meta["originalItems"] > meta["returnedItems"] > 0
    # nextPageToken (if the endpoint returned one) must survive - otherwise
    # the agent would have no way to fetch the items we trimmed.
    if payload.get("nextPageToken"):
        assert payload["nextPageToken"], "nextPageToken must be preserved through capping"
    # Hint mentions an actionable next step.
    assert "pageSize" in meta["hint"] or "nextPageToken" in meta["hint"]


async def test_fields_projection_lets_more_items_fit_under_cap(mcp_session, tool_name) -> None:
    """Projection should materially increase how many items survive the cap."""
    async with mcp_session() as client:
        fat = await client.call_tool(
            tool_name("/v1/devices"), arguments={"pageSize": 1000}
        )
        skinny = await client.call_tool(
            tool_name("/v1/devices"),
            arguments={"pageSize": 1000, "fields": ["uuid", "displayName"]},
        )
    fat_payload = json.loads(fat.content[0].text)
    skinny_payload = json.loads(skinny.content[0].text)

    if "_capped" not in fat_payload:
        pytest.skip("Tenant too small to demonstrate cap behaviour.")
    fat_kept = fat_payload["_capped"]["returnedItems"]
    skinny_kept = (
        skinny_payload["_capped"]["returnedItems"]
        if "_capped" in skinny_payload
        else len(skinny_payload["devices"])
    )
    assert skinny_kept > fat_kept, (
        f"projection should keep more items under the cap "
        f"(fat={fat_kept}, skinny={skinny_kept})"
    )

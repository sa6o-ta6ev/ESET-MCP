"""Test "MCP vs docs": every exposed read operation MUST be backed by exactly one tool.

This is the safety net after large changes (e.g. refreshing the specs from
ESET): it ensures nothing has vanished and nothing extra has appeared compared
with the official ESET specification - and that no write operation slipped in.
"""
from __future__ import annotations

import json
from importlib import resources

import pytest

from eset_mcp.tools_loader import _EXCLUDED_SERVICES, _NON_SPEC_FILES, is_deprecated, load_all_tools

pytestmark = pytest.mark.ro


def _count_get_operations_in_specs() -> int:
    total = 0
    pkg = resources.files("eset_mcp") / "openapi"
    for entry in sorted(pkg.iterdir()):
        if entry.suffix != ".json" or entry.name in _NON_SPEC_FILES:
            continue
        if entry.stem in _EXCLUDED_SERVICES:
            continue
        spec = json.loads(entry.read_text(encoding="utf-8"))
        for _, ops in spec.get("paths", {}).items():
            total += sum(1 for m, op in ops.items() if m.lower() == "get" and not is_deprecated(op))
    return total


def test_one_tool_per_openapi_get_operation() -> None:
    tools = load_all_tools()
    spec_op_count = _count_get_operations_in_specs()
    assert len(tools) == spec_op_count, (
        f"Tool count ({len(tools)}) != OpenAPI GET operation count ({spec_op_count}). "
        "Something is drifting from the API documentation."
    )


def test_only_get_tools_are_loaded() -> None:
    methods = {t.method for t in load_all_tools()}
    assert methods == {"GET"}, f"Non-GET tools loaded: {methods - {'GET'}}"


def test_excluded_services_are_not_loaded() -> None:
    services = {t.service for t in load_all_tools()}
    assert not services & _EXCLUDED_SERVICES


def test_tool_names_are_unique() -> None:
    tools = load_all_tools()
    names = [t.name for t in tools]
    assert len(names) == len(set(names)), f"Duplicates: {sorted({n for n in names if names.count(n) > 1})}"


def test_every_tool_has_inputschema() -> None:
    for t in load_all_tools():
        assert t.input_schema.get("type") == "object", f"{t.name}: object schema missing"
        # `properties` may be empty (e.g. /oauth/token without query params),
        # but the key must exist.
        assert "properties" in t.input_schema, f"{t.name}: properties key missing"


def test_deprecated_operations_are_not_loaded() -> None:
    paths = {t.path for t in load_all_tools()}
    assert "/v2/role-assignments" not in paths  # iam "List roles", @deprecated by ESET

"""Shared fixtures for ESET-MCP integration tests.

Tests hit the **real** ESET Connect API (using the credentials from .env).
If credentials are missing, integration tests are skipped automatically so
that nobody's CI/local environment breaks just because they have no setup.
"""
from __future__ import annotations

import contextlib
import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from dotenv import load_dotenv

from eset_mcp.client_pool import ClientPool
from eset_mcp.config import Settings
from eset_mcp.credentials import Credentials, EnvCredentialResolver
from eset_mcp.http_client import EsetHttpClient
from eset_mcp.server import build_server

# Load .env from repo root before anything reads os.getenv.
load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)

def _have_credentials() -> bool:
    return bool(os.getenv("ESET_USER") and os.getenv("ESET_PASSWORD"))


# Without credentials, skip every integration test (we still keep the unit-level
# `test_catalog_vs_openapi.py`, which doesn't talk to the network).
collect_ignore_glob = []
if not _have_credentials():
    collect_ignore_glob = ["test_smoke_ro.py", "test_pagination.py"]


@pytest.fixture(scope="session")
def settings() -> Settings:
    if not _have_credentials():
        pytest.skip("ESET_USER/ESET_PASSWORD missing - integration tests skipped.")
    return Settings.from_env()


def _creds_from_settings(settings: Settings) -> Credentials:
    return Credentials(user=settings.user, password=settings.password, region=settings.region)


@pytest_asyncio.fixture
async def http(settings: Settings) -> AsyncIterator[EsetHttpClient]:
    """Direct HTTP client - for testing the http_client layer (e.g. pagination)."""
    async with EsetHttpClient(_creds_from_settings(settings)) as c:
        yield c


@pytest.fixture
def mcp_session(settings: Settings):
    """Factory returning an async context manager that yields a connected MCP ClientSession.

    Used as:

        async def test_x(mcp_session):
            async with mcp_session() as client:
                tools = await client.list_tools()

    Why a factory instead of an async fixture: MCP's memory transport uses anyio
    task groups, and a yield-style async fixture in pytest-asyncio runs __aenter__
    and __aexit__ in different tasks → RuntimeError("cancel scope in different task").
    Keeping the entire `async with` inside one test task keeps the scope consistent.
    """

    @contextlib.asynccontextmanager
    async def _factory():
        from mcp import Client
        pool = ClientPool(settings)
        resolver = EnvCredentialResolver(settings)
        try:
            server = build_server(settings, pool, resolver)
            async with Client(server) as client:
                yield client
        finally:
            await pool.close()

    return _factory


@pytest.fixture(scope="session")
def tool_name():
    """Map an ESET endpoint path to its generated tool name.

    Tool names come from ESET's operationIds, which ESET renames between spec
    versions - tests look tools up by path so a spec refresh can't silently
    break them.
    """
    from eset_mcp.tools_loader import load_all_tools
    by_path = {t.path: t.name for t in load_all_tools()}
    return by_path.__getitem__

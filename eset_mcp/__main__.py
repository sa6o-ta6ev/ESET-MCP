"""Server entrypoint - stdio or Streamable HTTP transport."""
from __future__ import annotations

import asyncio
import logging

from .client_pool import ClientPool
from .config import Settings
from .credentials import EnvCredentialResolver
from .observability import configure_logging, log_event
from .server import build_server


def main() -> None:
    settings = Settings.from_env()
    configure_logging(level=settings.log_level, fmt=settings.log_format)
    log = logging.getLogger("eset_mcp")
    log_event(
        log, "server_starting",
        region=settings.region,
        transport=settings.transport,
        deployment=settings.deployment,
        metrics_enabled=settings.metrics_enabled,
        usage_log=settings.usage_log_path or "(disabled)",
        log_format=settings.log_format,
    )
    if settings.deployment == "onprem":
        log_event(
            log, "onprem_default",
            server_url=settings.onprem_server_url,
            verify_ssl=settings.onprem_verify_ssl,
        )

    asyncio.run(_run(settings))


async def _run(settings: Settings) -> None:
    pool = ClientPool(settings)
    resolver = EnvCredentialResolver(settings)

    server = build_server(settings, pool, resolver)
    try:
        if settings.transport == "stdio":
            from mcp.server.stdio import stdio_server
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
        elif settings.transport == "http":
            await _serve_http(settings, server)
        else:
            raise RuntimeError(f"Unknown transport: {settings.transport!r}")
    finally:
        await pool.close()


async def _serve_http(settings: Settings, server) -> None:
    """Streamable HTTP transport.

    The endpoint has NO authentication of its own - it serves the tenant in
    ``.env`` to anyone who can reach it. Keep ``ESET_MCP_HTTP_HOST`` on
    127.0.0.1, or put an authenticating proxy in front.

    Stateless: every request gets a fresh transport and no ``Mcp-Session-Id``
    is issued, so there is no server-side session to hijack or to leak
    between clients.

    NOTE: StreamableHTTPSessionManager owns an anyio task group that MUST be
    entered via `async with manager.run()` BEFORE any request hits
    `manager.handle_request`.
    """
    import contextlib

    import uvicorn
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Mount

    manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    @contextlib.asynccontextmanager
    async def _lifespan(_app):
        async with manager.run():
            yield

    routes = [Mount("/mcp", app=manager.handle_request)]
    # Optional /metrics endpoint. It carries no secrets and is intended to
    # be protected at the network layer (private subnet / VPN / proxy ACL).
    if settings.metrics_enabled:
        from .observability.metrics import metrics_asgi_app, metrics_available
        routes.append(Mount(settings.metrics_path, app=metrics_asgi_app()))
        if not metrics_available():
            logging.getLogger("eset_mcp").warning(
                "ESET_MCP_METRICS_ENABLED=true but prometheus_client is not "
                "installed - %s will return 503. Install via "
                "'pip install eset-mcp[metrics]'.",
                settings.metrics_path,
            )

    app = Starlette(routes=routes, lifespan=_lifespan)

    config = uvicorn.Config(
        app, host=settings.http_host, port=settings.http_port, log_level=settings.log_level.lower()
    )
    await uvicorn.Server(config).serve()


if __name__ == "__main__":
    main()

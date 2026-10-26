# syntax=docker/dockerfile:1.7
FROM python:3.13-slim

LABEL org.opencontainers.image.title="ESET-MCP" \
      org.opencontainers.image.description="Read-only MCP server for ESET (Connect cloud + PROTECT On-Prem)" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# uv installs exactly the versions pinned in uv.lock.
COPY --from=ghcr.io/astral-sh/uv:0.11.23 /uv /usr/local/bin/uv

WORKDIR /app

# Deps layer: only the lockfile and project metadata, so code-only changes
# keep this layer cached.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --extra metrics --no-install-project

# Source layer.
COPY eset_mcp ./eset_mcp
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --extra metrics

ENV PATH="/app/.venv/bin:$PATH"

# Defaults: stdio. For HTTP, expose the port (override in docker-compose).
ENV ESET_MCP_TRANSPORT=stdio \
    ESET_MCP_HTTP_HOST=0.0.0.0 \
    ESET_MCP_HTTP_PORT=8765

EXPOSE 8765

# Drop privileges. Non-root by uid 10001 so it never collides with a
# host user. /data holds the usage log; a named volume mounted there
# inherits this ownership on first use.
RUN useradd --create-home --uid 10001 esetmcp \
    && mkdir -p /data \
    && chown -R esetmcp:esetmcp /app /data
USER esetmcp

ENTRYPOINT ["eset-mcp"]

# ESET-MCP - container workflow.
#
#   make build      build the image
#   make up         start the server in the background (127.0.0.1:8765)
#   make register   add it to Claude Code (user scope)
#
# Run `make` or `make help` for every target.

SHELL := /bin/bash

ESET_MCP_PORT ?= 8765
MCP_NAME      ?= eset
MCP_URL       := http://127.0.0.1:$(ESET_MCP_PORT)/mcp/
COMPOSE       := ESET_MCP_PORT=$(ESET_MCP_PORT) docker compose
SERVICE       := eset-mcp

.DEFAULT_GOAL := help

.PHONY: help build up down restart logs ps stats stats-by-tenant check-tenants secure-tenants register unregister test lint check-specs env-check

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

env-check:
	@test -f .env || { echo "Missing .env - run: cp .env.example .env  and fill in ESET_USER / ESET_PASSWORD / ESET_REGION"; exit 1; }

build: ## Build the Docker image (eset-mcp:local)
	$(COMPOSE) build

up: env-check ## Start the server in the background and wait until it is healthy
	@mkdir -p tenants   # mounted read-only; Docker would create it as root otherwise
	$(COMPOSE) up -d --wait
	@echo "ESET MCP server running at $(MCP_URL)"
	@echo "Register it with Claude Code (once): make register"

down: ## Stop and remove the container (keeps the usage-log volume)
	$(COMPOSE) down

restart: env-check ## Restart the container (picks up .env and tenant changes)
	@mkdir -p tenants
	$(COMPOSE) up -d --wait --force-recreate

logs: ## Follow the server logs
	$(COMPOSE) logs -f $(SERVICE)

ps: ## Show container status
	$(COMPOSE) ps

stats: ## Print tool-usage statistics (calls, failures, durations)
	@$(COMPOSE) exec -T $(SERVICE) eset-mcp-stats /data/usage.jsonl

stats-by-tenant: ## Usage statistics per tenant and tool
	@$(COMPOSE) exec -T $(SERVICE) eset-mcp-stats --by-tenant /data/usage.jsonl

check-tenants: ## Which ESET endpoints work for which tenant (read-only GETs)
	@$(COMPOSE) exec -T $(SERVICE) eset-mcp-check

secure-tenants: ## Make tenants/ readable only by the container user (uid 10001); needs sudo
	sudo chown -R 10001:10001 tenants
	sudo chmod 700 tenants
	sudo find tenants -type f -exec chmod 600 {} +

register: ## Add the server to Claude Code (user scope)
	claude mcp add --scope user --transport http $(MCP_NAME) $(MCP_URL)

unregister: ## Remove the server from Claude Code
	claude mcp remove --scope user $(MCP_NAME)

test: ## Run the test suite locally (needs uv; integration tests use .env)
	uv sync --locked --extra dev
	uv run pytest

lint: ## Lint the code locally (needs uv)
	uv run ruff check eset_mcp tests scripts

check-specs: ## Report drift between bundled specs and ESET's published Swagger
	uv run python scripts/update_specs.py --check

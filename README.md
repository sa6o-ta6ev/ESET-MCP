# ESET-MCP (read-only fork)

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server
for ESET: [ESET Connect](https://help.eset.com/eset_connect/en-US/) (ESET
PROTECT Cloud, ESET Inspect cloud data, Cloud Office Security) and ESET
PROTECT On-Prem. It lets an MCP client such as Claude Code query devices,
detections, incidents, vulnerabilities, patches, policies and users.

This is a fork of [maciekaz/ESET-MCP](https://github.com/maciekaz/ESET-MCP),
cut down to a read-only, single-tenant server. See
[Changes from upstream](#changes-from-upstream).

> Independent project - not affiliated with, supported or endorsed by ESET,
> spol. s r.o. Provided "AS IS", without warranty of any kind.

## Contents

- [What it exposes](#what-it-exposes)
- [Quick start (local, Claude Code)](#quick-start-local-claude-code)
- [Configuration](#configuration)
- [Several tenants](#several-tenants)
- [Usage statistics](#usage-statistics)
- [On-prem ESET PROTECT](#on-prem-eset-protect)
- [HTTP transport](#http-transport)
- [Security notes](#security-notes)
- [Development](#development)
- [Changes from upstream](#changes-from-upstream)
- [License](#license)

## What it exposes

- **Generated tools** - one per GET operation in ESET's published OpenAPI
  specs (bundled under `eset_mcp/openapi/`, refreshed 2026-10-26). Names
  follow `{service}_{operationId}`, e.g. `device_v1__devices__list_devices`.
  Write operations (POST/PUT/PATCH/DELETE) are never loaded, so they cannot
  be called. Installer endpoints are excluded (they return enrolment links).
- **Composite tools** that combine several calls:

  | Tool | Returns |
  |---|---|
  | `eset_search(query, kinds?, limit_per_kind?)` | Case-insensitive substring matches across devices / users / policies / groups |
  | `device_full_profile(deviceUuid)` | Device record + its detections (last 30 days, newest first) + detection groups + vulnerabilities + recent scans |
  | `incident_full_context(incidentUuid)` | Incident (v2 + v3 merged) + comments + detections (v2, falling back to v1) + devices + indicators + MITRE technique IDs |
  | `latest_detections(hours=24, limit=10, severity_min?)` | Newest detections in a time window, sorted by `occurTime`; v2 → v1 fallback |
  | `policy_settings(policyUuid, path?, search?, include_history?, raw_flags?)` | A policy's settings decoded to plain JSON (see below) |

- **Policy settings.** ESET returns a policy's settings as an undocumented
  encoded blob (base64 → `ar` archive → LZMA → JSON, in three variants).
  `policy_settings` decodes it on the server and normalises every variant
  to the same shape: `decoded[].documents[]`, each `{source, target,
  version, meta, settings}`, so a setting has the same path (e.g.
  `Settings.Firewall`) whichever way ESET stored it. `{ce_value, ce_flags}`
  wrappers are unwrapped, credential-looking values are redacted, `path`
  selects a section, `search` finds settings by name or value, and
  `include_history` adds the change log (who changed which part, when).
  Policies too large for one response come back as a section outline.
  The blob itself is removed from the generated policy tools' output (it
  was up to ~180 KB per policy). Decoder: `eset_mcp/policy_decode.py`.

- Every generated tool accepts a `fields` list (server-side projection) and
  responses are capped at `ESET_MCP_RESPONSE_BYTES_MAX` bytes (compact JSON),
  keeping `nextPageToken` so the client can page on. When a single item is
  larger than the cap (a vulnerable device with 300+ vulnerabilities), the
  lists inside items are shortened instead, with the original counts in
  `_trimmed`.
- Errors that mean "not available for this tenant" carry a `Likely cause`
  line: 403 (permission set), 404 on a whole collection (module/API version
  not offered), 501 (feature not enabled), 400 on IP sets (needs a "Common
  features" policy). Operations ESET marks deprecated are not exposed.
- **Data fixes** (`eset_mcp/enrich.py`), applied to every tool result -
  each verified against a real tenant; original values are kept:
  - version objects with only `name` filled ("13.3.1192.0", major/minor/patch
    all 0) get major/minor/patch from the name, plus `build`, so versions
    can be compared;
  - disk `capacityBytes` is actually KiB - `capacityGB` is added;
  - a SHA-256 in `objectHashSha1` (v1 detections) is moved to
    `objectHashSha256`;
  - durations like `triageDuration: "339664.8s"` get `triageDurationHuman`
    ("3d 22h 21m");
  - incident descriptions with literal `\n` escapes are unescaped (never
    when the text contains other backslashes, e.g. Windows paths);
  - `tags: [""]` becomes `[]`.

  Policy change logs also split `user_id` (`"<uuid>;PR;PW;SR;SW;"`) into
  `user` and `userFlags`.
- **Resources**: `eset://config/tenants`, `eset://config/tools-catalog`,
  `eset://docs/rate-limits`.
- **Prompts**: `audit_inactive_devices(days)`, `vulnerability_report`,
  `incident_triage`.

ESET Inspect data (detections, detection groups, incidents, indicators,
EDR rules and exclusions) is reachable through ESET Connect's
incident-management API, i.e. for cloud tenants. ESET Inspect On-Prem has
its own API, which this server does not cover.

## Quick start (local, Claude Code)

Requirements: Docker with the compose plugin, and `make`.

1. Create a **dedicated read-only API user** in ESET Business Account /
   ESET PROTECT Hub (User management → new user with a read-only
   permission set → enable the **Integrations** toggle). The console
   Administrator account cannot use the API.
2. Configure, build and start:

   ```bash
   cp .env.example .env        # fill in ESET_USER / ESET_PASSWORD / ESET_REGION
   make build
   make up                     # http://127.0.0.1:8765/mcp/, restarts with Docker
   make register               # adds it to Claude Code (user scope), once
   ```

   Check it with `/mcp` inside Claude Code.

| Target | What it does |
|---|---|
| `make build` | Build the image `eset-mcp:local` (dependencies from `uv.lock`) |
| `make up` / `make down` | Start (and wait until healthy) / stop the container |
| `make restart` | Recreate the container, e.g. after editing `.env` |
| `make logs` / `make ps` | Follow logs / show status |
| `make stats` | Tool-usage statistics from the container's volume |
| `make register` / `make unregister` | Add / remove the server in Claude Code |
| `make test` / `make lint` / `make check-specs` | Development tasks (run locally with uv) |

The container runs the HTTP transport, published on `127.0.0.1` only
(override the port with `make up ESET_MCP_PORT=9000`). The usage log lives
in the `eset-mcp-data` volume and survives restarts and rebuilds.

**Without Docker** (Python ≥ 3.11 and [uv](https://docs.astral.sh/uv/)):
`uv sync --locked`, then
`claude mcp add eset --scope user -- "$PWD/.venv/bin/eset-mcp"` - Claude
Code starts the server itself over stdio and it reads `.env` from the
repository root.

## Configuration

All settings live in `.env` (see [`.env.example`](.env.example)).

| Variable | Default | Purpose |
|---|---|---|
| `ESET_USER` / `ESET_PASSWORD` | - | Dedicated API user (single tenant) |
| `ESET_TENANTS_FILE` | - | Tenants file for several tenants (see [Several tenants](#several-tenants)); overrides the three above |
| `ESET_REGION` | `eu` | Cloud region: `eu` / `de` / `us` / `ca` / `jpn` |
| `ESET_DEPLOYMENT` | `cloud` | `cloud` (ESET Connect) or `onprem` (PROTECT On-Prem) |
| `ESET_ONPREM_SERVER_URL` | - | `https://host[:port]` of the on-prem console (required for `onprem`) |
| `ESET_ONPREM_VERIFY_SSL` | `true` | `false` only for a self-signed console cert you trust |
| `ESET_ONPREM_DOMAIN_USER` | `false` | `true` if the on-prem API user is an Active Directory account |
| `ESET_ONPREM_CF_ACCESS_CLIENT_ID` / `_SECRET` | - | Cloudflare Access service token, if the on-prem console sits behind Cloudflare Access |
| `ESET_MCP_USAGE_LOG` | - (off) | File for per-call usage records, e.g. `~/.local/state/eset-mcp/usage.jsonl` |
| `ESET_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `ESET_MCP_HTTP_HOST` / `_PORT` | `127.0.0.1` / `8765` | HTTP bind address |
| `ESET_MCP_RESPONSE_BYTES_MAX` | `100000` | Per-call response byte cap; `0` disables |
| `ESET_LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` (logs go to stderr) |
| `ESET_MCP_LOG_FORMAT` | `text` | `text` or `json` |
| `ESET_MCP_METRICS_ENABLED` / `_PATH` | `false` / `/metrics` | Prometheus endpoint (HTTP transport only) |

## Several tenants

One server can serve several customers' ESET Business Accounts (cloud only
for now). Credentials stay on the server; Claude only ever sees tenant ids
and names.

```bash
mkdir -p tenants
cp tenants.example.toml tenants/tenants.toml      # one [[tenant]] per customer
printf '%s' 'the-api-password' > tenants/acme.password   # one file per tenant
make secure-tenants      # owner = container user (uid 10001), dir 700, files 600
# in .env:  ESET_TENANTS_FILE=/tenants/tenants.toml
make restart
make check-tenants       # which endpoints work for which tenant
```

```toml
[[tenant]]
id = "acme"                       # what Claude passes as `tenant`
name = "ACME Ltd"
region = "eu"
user = "api-mcp@acme.example"     # dedicated read-only API user per customer
password_file = "acme.password"   # relative to tenants.toml
```

- Every tool gets a required `tenant` argument (an enum of the configured
  ids); `list_tenants` returns ids, names and regions. Each tenant has its
  own login, token and 10 req/s rate limit.
- Passwords are refused inside `tenants.toml`; each lives in its own file,
  read on use - rotating a password means replacing its file, no restart.
  Adding or removing tenants needs `make restart`. The server warns if a
  password file is readable by group/others.
- `tenants/` is git- and docker-ignored and mounted read-only.
- `make check-tenants` (`eset-mcp-check`) logs in as every tenant, calls
  each list endpoint once (GET, `pageSize=1`) and prints a status matrix;
  `differs` marks endpoints that work for some tenants but not others
  (licence / permission set), errors in every column point at the API.
- `make stats-by-tenant` breaks usage and failures down per tenant.
- The storage is behind a provider interface
  (`eset_mcp/credentials.py`), so a secrets manager can replace the file
  without touching the rest of the server.

Without `ESET_TENANTS_FILE` the server stays single-tenant (`ESET_USER` /
`ESET_PASSWORD` from `.env`) and tools take no `tenant` argument.

## Usage statistics

Set `ESET_MCP_USAGE_LOG` to record one JSON line per tool call: timestamp,
tool name, success flag, status (`ok`, an ESET HTTP status such as `404`,
or an internal reason) and duration. Arguments and results are never
recorded. With `make up` this is on automatically (`/data/usage.jsonl` in the
container's volume). Summarise with:

```bash
make stats                                               # container
.venv/bin/eset-mcp-stats ~/.local/state/eset-mcp/usage.jsonl   # without Docker
```

```
tool                                     calls      ok  failed   avg_ms  last call (UTC)       failures
latest_detections                           12      12       0     1840  2026-10-27T09:12:03+00:00
device_v1__devices__get_device               7       6       1      420  2026-10-27T08:55:41+00:00  404x1
```

A call counts as failed when the tool result is flagged `is_error` - ESET
API errors, invalid arguments, or a composite whose main fetch failed.
In HTTP mode the same counts are also available as Prometheus metrics
(`esetmcp_tool_calls_total{tool,status}`).

## On-prem ESET PROTECT

```bash
# .env
ESET_DEPLOYMENT=onprem
ESET_ONPREM_SERVER_URL=https://protect.company.local:9443
ESET_ONPREM_VERIFY_SSL=true
ESET_USER=api-user
ESET_PASSWORD=...
```

- Login is `POST /GetTokens` with `{"username", "password", "grantType": "password"}`
  per ESET's [REST API setup page](https://help.eset.com/protect_admin/latest/en-US/using_api.html);
  `"is_domain_user": true` is added for Active Directory users.
- The on-prem REST API (13.0+, full set from 13.1) covers devices, groups,
  policies and most automation. Incident, quarantine, mobile, web/network
  access and most vulnerability endpoints are cloud-only and return 404
  on-prem - the agent sees a normal `ESET API error: 404`.
- ESET's prerequisites: REST API enabled in the console settings, API
  permission set on the user, no 2FA on the API user, SHA-256 certificates.

## HTTP transport

```bash
make up                                        # container, http://127.0.0.1:8765/mcp/
ESET_MCP_TRANSPORT=http .venv/bin/eset-mcp     # or directly, without Docker
```

The HTTP endpoint is **stateless** (no MCP sessions) and has **no
authentication of its own**: anyone who can reach it can query the tenant
in `.env`. Keep it on `127.0.0.1` or put an authenticating proxy in front.

## Security notes

- Read-only by construction: only GET operations become tools. Still give
  the API user a read-only permission set - that is the control ESET enforces.
- Credentials are read from `.env` and kept in memory; they are never
  logged. Tokens are refreshed automatically.
- Path parameters are URL-encoded into a single segment, so a value like
  `../users` cannot reach a different endpoint.
- Data returned by ESET (device names, command lines, file paths) comes from
  endpoints and can contain text written by an attacker. Treat what the
  model reads from it as untrusted.
- `ESET_ONPREM_VERIFY_SSL=false` disables certificate checks (MITM risk).

## Development

```bash
uv sync --locked --extra dev
uv run pytest                 # offline tests always run; integration tests need ESET_USER/ESET_PASSWORD
uv run ruff check eset_mcp tests scripts
```

- `tests/test_server_offline.py` starts the real server with an in-process
  MCP client and a mocked ESET API - it catches SDK upgrades that break
  startup or dispatch.
- Integration tests (`test_smoke_ro.py`, `test_composite_tools.py`,
  `test_pagination.py`) run against the tenant in `.env`.

### Refreshing the OpenAPI specs

ESET changes its specs without notice (new endpoints, renamed operationIds).

```bash
uv run python scripts/update_specs.py --check   # report drift, change nothing
uv run python scripts/update_specs.py           # download and show what changed
uv run pytest
```

Tool names come from ESET's operationIds and change when ESET renames them;
prompts and tests look tools up by endpoint path so a refresh doesn't break
them silently.

## Changes from upstream

Forked from maciekaz/ESET-MCP at `442dcad` (2026-08-17, v1.0.3).

- **Removed**: read-write mode and all write tools; the multi-tenant `basic`
  auth mode with per-request `X-ESET-*` headers (it let callers point the
  server at arbitrary hosts and could forward the operator's Cloudflare
  token there); the Caddy production profile; image/registry publishing.
- **Fixed**:
  - Startup with `mcp` 2.x (`mcp>=1.2.0` resolved to 2.3.0, which removed
    the decorator API - the server crashed on start). Now `mcp>=2.3,<3`,
    with versions pinned in `uv.lock`.
  - On-prem login body uses `grantType` (camelCase) per ESET docs, instead
    of `grant_type`; Active Directory users supported.
  - Tool errors are flagged `is_error` and counted as failures (before,
    ESET errors and failed composites were reported as successes).
  - Path parameters are URL-encoded.
  - `device_full_profile` no longer mixes in other devices' detections.
  - 5xx responses are retried once for GET (documented but not implemented).
  - HTTP transport is stateless.
  - The inactive-devices prompt used a non-existent field (`lastConnected`
    → `lastSyncTime`).
- **Updated**: OpenAPI specs refreshed 2026-10-26 (adds installed
  applications per device, hostname/IP device filters, v3 incidents and
  indicators).
- **Added**: usage log + `eset-mcp-stats`; offline end-to-end tests;
  `scripts/update_specs.py`; `policy_settings` (server-side decoding of
  policy settings, verified against all 84 policies of one tenant).

## License

MIT - see [LICENSE](LICENSE). Original work © 2026 maciekaz.

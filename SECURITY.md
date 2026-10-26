# Security policy

## Reporting a vulnerability

Do not open public issues for security problems. Use a private security
advisory on this repository (Security → Advisories → Report a
vulnerability), or contact the repository owner directly.

Issues in the original project can also be reported upstream:
<https://github.com/maciekaz/ESET-MCP/security/advisories/new>

## Security properties and where they are tested

- **Read-only by construction.** Only GET operations from the OpenAPI specs
  become tools; write operations are never loaded. Installer endpoints
  (enrolment links) are excluded.
  `tests/test_catalog_vs_openapi.py`, `tests/test_server_offline.py`.
- **Tool arguments are validated** against each tool's schema before any
  request is made, and path parameters are URL-encoded into a single path
  segment (`../users` cannot reach another endpoint).
  `tests/test_server_offline.py`.
- **Fixed upstream hosts.** Cloud requests go only to
  `{region}.*.eset.systems`; on-prem requests go only to
  `ESET_ONPREM_SERVER_URL` from `.env` (HTTPS required). Clients cannot
  choose the target host.
- **No secrets in logs.** `eset_mcp/observability/logging.py` drops any
  field whose name matches `password` / `secret` / `token` /
  `authorization` / `cookie` / `api_key` / `bearer` / `credentials` /
  `cf-access-client-*`. `tests/test_observability.py`.
- **Policy credentials are redacted.** Decoded policy settings whose name
  looks like a credential (password, secret, token, private key) are
  replaced with `[redacted]`; ESET stores them encrypted anyway.
  `tests/test_policy_decode.py`.
- **Usage log carries no data.** Records hold tool name, success flag,
  status and duration only - never arguments or results.
  `tests/test_usage.py`.
- **No secrets on disk** beyond `.env` itself. OAuth tokens live in process
  memory only.
- **Stateless HTTP transport.** No MCP sessions, so nothing to hijack or
  leak between clients.

Not in place (do not assume them): authentication on the HTTP endpoint,
dependency or SAST scanning in CI, secret scanning.

## Operator checklist

1. Use a **dedicated** ESET API user with a **read-only** permission set.
   That is the control ESET itself enforces; the server's read-only design
   is a second layer.
2. Keep `.env` readable only by you (`chmod 600 .env`).
3. Keep the HTTP transport on `127.0.0.1`, or put an authenticating proxy
   in front of it. It has no authentication of its own.
4. Leave `ESET_ONPREM_VERIFY_SSL=true` unless the console uses a
   self-signed certificate on a trusted network.
5. Treat data returned from ESET (device names, command lines, file paths)
   as untrusted input to the model: it originates on endpoints and can
   contain attacker-written text.
6. Install with `uv sync --locked` so dependency versions match `uv.lock`.

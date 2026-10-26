"""Credential resolution - one tenant from ``.env``, or many from a tenants file.

Two providers, same interface (:class:`CredentialProvider`):

- :class:`EnvCredentialResolver` - single tenant. Credentials come from
  ``.env`` (``ESET_USER`` / ``ESET_PASSWORD``); tools take no ``tenant``
  argument.
- :class:`FileCredentialProvider` - several tenants (``ESET_TENANTS_FILE``).
  A TOML file lists the tenants; each password lives in its own file next to
  it. Tools take a ``tenant`` argument.

Deployment kind:

- ``cloud``: hits the ESET Connect API at ``{region}.*.eset.systems`` with
             OAuth2 password grant against ``/oauth/token``.
- ``onprem``: hits a customer-hosted ESET PROTECT console at a single
             ``server_url`` with the on-prem auth endpoint ``/GetTokens``
             (camelCase response). Single-tenant only for now
             (``ESET_DEPLOYMENT=onprem``).

The rest of the codebase (:mod:`auth`, :mod:`http_client`,
:mod:`client_pool`) only ever sees :class:`Credentials`, so another provider
(e.g. a secrets manager) can replace the file one without touching them.
"""
from __future__ import annotations

import hashlib
import logging
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .config import VALID_REGIONS, Deployment, Region, Settings

_LOG = logging.getLogger("eset_mcp.credentials")

DEFAULT_TENANT_ID = "default"
_TENANT_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


@dataclass(frozen=True)
class Credentials:
    user: str
    password: str
    region: Region
    deployment: Deployment = "cloud"
    # On-prem only: full origin URL (e.g. "https://protect.example.com:9443").
    # Empty string for cloud credentials.
    server_url: str = ""
    # On-prem only: whether httpx should verify the TLS cert. Always True for
    # cloud (the public ESET endpoints have valid certs).
    verify_ssl: bool = True
    # On-prem only: the API user is an Active Directory account.
    domain_user: bool = False
    # On-prem only: optional Cloudflare Access Service Token used when the
    # console sits behind Cloudflare Access. Both values are sent on every
    # request (auth + API) as CF-Access-Client-Id / CF-Access-Client-Secret.
    # Empty strings mean "no CF Access in front of the origin".
    cf_access_client_id: str = ""
    cf_access_client_secret: str = ""

    def cache_key(self) -> tuple[str, str, str, str, str]:
        """Identity used by the client pool.

        Includes a *hash* of the password so that changing the password (e.g.
        after a rotation) forces a new client + fresh OAuth login, rather
        than reusing a cached client whose token was minted with the old
        password. We hash rather than embed the raw value so the key is safe
        to log / inspect for debugging.

        For cloud credentials the fourth tuple element is the region
        (``"eu"``/``"us"``/…). For on-prem it is the server URL. This way
        cloud and on-prem clients never collide in the pool, and the same
        on-prem console hit via two different URLs (e.g. IP vs hostname)
        gets two pool entries.

        The fifth slot carries a hash of the Cloudflare Access secret (or
        empty string when none is configured), because the CF headers are
        baked into the httpx client's defaults at construction time.
        """
        pw_hash = hashlib.sha256(self.password.encode("utf-8")).hexdigest()[:16]
        # The fourth slot is "region OR server_url" - unique per deployment.
        endpoint = self.server_url if self.deployment == "onprem" else self.region
        cf_hash = ""
        if self.cf_access_client_secret:
            cf_hash = hashlib.sha256(
                self.cf_access_client_secret.encode("utf-8")
            ).hexdigest()[:16]
        return (self.user, pw_hash, self.deployment, endpoint, cf_hash)


@dataclass(frozen=True)
class Tenant:
    """What the agent may know about a tenant - never credentials."""

    id: str
    name: str
    region: Region
    deployment: Deployment = "cloud"


class TenantError(Exception):
    """Unknown tenant, or a tenant whose credentials cannot be loaded."""


class CredentialProvider(Protocol):
    multi_tenant: bool

    def tenants(self) -> list[Tenant]: ...

    def resolve(self, tenant_id: str | None = None) -> Credentials: ...


class EnvCredentialResolver:
    """Single tenant: always returns the credentials baked in at startup."""

    multi_tenant = False

    def __init__(self, settings: Settings):
        self._creds = Credentials(
            user=settings.user,
            password=settings.password,
            region=settings.region,
            deployment=settings.deployment,
            server_url=settings.onprem_server_url,
            verify_ssl=settings.onprem_verify_ssl,
            domain_user=settings.onprem_domain_user,
            cf_access_client_id=settings.onprem_cf_access_client_id,
            cf_access_client_secret=settings.onprem_cf_access_client_secret,
        )
        self._tenant = Tenant(
            id=DEFAULT_TENANT_ID,
            name=DEFAULT_TENANT_ID,
            region=settings.region,
            deployment=settings.deployment,
        )

    def tenants(self) -> list[Tenant]:
        return [self._tenant]

    def resolve(self, tenant_id: str | None = None) -> Credentials:
        if tenant_id not in (None, DEFAULT_TENANT_ID):
            raise TenantError(f"Unknown tenant {tenant_id!r}: this server serves a single tenant.")
        return self._creds


@dataclass(frozen=True)
class _TenantEntry:
    tenant: Tenant
    user: str
    password_file: Path


class FileCredentialProvider:
    """Several cloud tenants from a TOML file; one password file per tenant.

    ::

        [[tenant]]
        id = "acme"                      # lowercase, used as the tool argument
        name = "ACME Ltd"
        region = "eu"
        user = "api-mcp@acme.example"
        password_file = "acme.password"  # relative to the TOML file

    Passwords are refused inside the TOML file, so the tenant list can be
    shared or reviewed without exposing secrets. Password files are read on
    every resolve (a small local read), so rotating a password means
    replacing the file - no restart. Adding or removing tenants needs a
    restart.
    """

    multi_tenant = True

    def __init__(self, path: str | Path):
        self._path = Path(path).expanduser()
        self._warned: set[Path] = set()
        try:
            doc = tomllib.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError as e:
            raise TenantError(f"Tenants file not found: {self._path}") from e
        except tomllib.TOMLDecodeError as e:
            raise TenantError(f"Tenants file {self._path} is not valid TOML: {e}") from e

        entries = doc.get("tenant")
        if not isinstance(entries, list) or not entries:
            raise TenantError(f"Tenants file {self._path} defines no [[tenant]] entries.")
        self._entries: dict[str, _TenantEntry] = {}
        for i, raw in enumerate(entries, start=1):
            entry = self._parse_entry(raw, i)
            if entry.tenant.id in self._entries:
                raise TenantError(f"Tenant id {entry.tenant.id!r} is defined twice in {self._path}.")
            self._entries[entry.tenant.id] = entry
        # Fail at startup, not on the first tool call.
        for entry in self._entries.values():
            self._read_password(entry)

    def tenants(self) -> list[Tenant]:
        return [e.tenant for e in self._entries.values()]

    def resolve(self, tenant_id: str | None = None) -> Credentials:
        if tenant_id is None:
            raise TenantError(f"A tenant is required; one of: {', '.join(self._entries)}.")
        entry = self._entries.get(tenant_id)
        if entry is None:
            raise TenantError(f"Unknown tenant {tenant_id!r}; one of: {', '.join(self._entries)}.")
        return Credentials(
            user=entry.user,
            password=self._read_password(entry),
            region=entry.tenant.region,
        )

    def _parse_entry(self, raw: object, index: int) -> _TenantEntry:
        where = f"{self._path} tenant #{index}"
        if not isinstance(raw, dict):
            raise TenantError(f"{where}: not a table.")
        if "password" in raw:
            raise TenantError(
                f"{where}: put the password in its own file and reference it with "
                "password_file - passwords are not allowed in the tenants file."
            )
        unknown = set(raw) - {"id", "name", "region", "user", "password_file", "deployment"}
        if unknown:
            raise TenantError(f"{where}: unknown keys {sorted(unknown)}.")
        tenant_id = str(raw.get("id", ""))
        if not _TENANT_ID.match(tenant_id):
            raise TenantError(f"{where}: id {tenant_id!r} must be lowercase letters, digits, '-' or '_'.")
        if raw.get("deployment", "cloud") != "cloud":
            raise TenantError(f"{where}: only cloud tenants are supported in the tenants file for now.")
        region = str(raw.get("region", "")).lower()
        if region not in VALID_REGIONS:
            raise TenantError(f"{where}: region must be one of {VALID_REGIONS}, got {region!r}.")
        for key in ("user", "password_file"):
            if not raw.get(key):
                raise TenantError(f"{where}: {key} is required.")
        password_file = Path(str(raw["password_file"])).expanduser()
        if not password_file.is_absolute():
            password_file = self._path.parent / password_file
        return _TenantEntry(
            tenant=Tenant(id=tenant_id, name=str(raw.get("name") or tenant_id), region=region),  # type: ignore[arg-type]
            user=str(raw["user"]),
            password_file=password_file,
        )

    def _read_password(self, entry: _TenantEntry) -> str:
        path = entry.password_file
        try:
            mode = path.stat().st_mode
            password = path.read_text(encoding="utf-8").strip()
        except OSError as e:
            raise TenantError(
                f"Tenant {entry.tenant.id!r}: cannot read password file {path} ({e.strerror})."
            ) from e
        if not password:
            raise TenantError(f"Tenant {entry.tenant.id!r}: password file {path} is empty.")
        if mode & (stat.S_IRWXG | stat.S_IRWXO) and path not in self._warned:
            self._warned.add(path)
            _LOG.warning("password file %s is accessible to group/others; chmod 600 it", path)
        return password


def build_provider(settings: Settings) -> CredentialProvider:
    """Tenants file when ``ESET_TENANTS_FILE`` is set, otherwise the single ``.env`` tenant."""
    if settings.tenants_file:
        return FileCredentialProvider(settings.tenants_file)
    return EnvCredentialResolver(settings)

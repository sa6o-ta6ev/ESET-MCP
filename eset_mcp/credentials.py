"""Credential resolution.

Credentials are read once from ``.env`` and used for every request (one MCP
server, one ESET account).

Deployment kind:

- ``cloud``: hits the ESET Connect API at ``{region}.*.eset.systems`` with
             OAuth2 password grant against ``/oauth/token``.
- ``onprem``: hits a customer-hosted ESET PROTECT console at a single
             ``server_url`` with the on-prem auth endpoint ``/GetTokens``
             (camelCase response). Selected by ``ESET_DEPLOYMENT=onprem``.

The resolver returns a :class:`Credentials` object; the rest of the codebase
(:mod:`auth`, :mod:`http_client`, :mod:`client_pool`) always gets credentials
through a resolver, so a multi-tenant resolver can be added later without
touching them.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .config import Deployment, Region, Settings


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


class EnvCredentialResolver:
    """Always returns the credentials baked in at startup."""

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

    def resolve(self) -> Credentials:
        return self._creds

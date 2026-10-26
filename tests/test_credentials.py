"""Unit tests for credentials and the env resolver (no network)."""
from __future__ import annotations

from eset_mcp.credentials import Credentials, EnvCredentialResolver


def test_env_resolver_always_returns_same_creds() -> None:
    class FakeSettings:
        user = "env-user"
        password = "env-pass"
        region = "eu"
        # On-prem fields - cloud-only setups keep defaults.
        deployment = "cloud"
        onprem_server_url = ""
        onprem_verify_ssl = True
        onprem_domain_user = False
        onprem_cf_access_client_id = ""
        onprem_cf_access_client_secret = ""

    r = EnvCredentialResolver(FakeSettings())  # type: ignore[arg-type]
    creds = r.resolve()
    assert creds == Credentials("env-user", "env-pass", "eu")
    # Resolves to the same identity object every time - important for the
    # client pool cache to hit consistently.
    assert r.resolve() is creds


def test_credentials_cache_key_distinct_per_field() -> None:
    a = Credentials("alice", "x", "eu")
    a_same = Credentials("alice", "x", "eu")
    a_diff_pw = Credentials("alice", "rotated-pw", "eu")
    b = Credentials("bob", "x", "eu")
    c = Credentials("alice", "x", "us")
    assert a.cache_key() == a_same.cache_key()
    # Password rotation forces a new client - we don't want stale tokens
    # served after an account password change.
    assert a.cache_key() != a_diff_pw.cache_key()
    assert a.cache_key() != b.cache_key()
    assert a.cache_key() != c.cache_key()
    # The key never contains the raw password.
    assert "x" not in a.cache_key()

"""tests/api/test_auth_failclosed.py — KCH-30: auth fail-closed tests.

Acceptance criteria:
* App refuses to start with AEGIS_API_KEY unset unless AEGIS_DEV_NO_AUTH=1
* Request with no X-API-Key → 401 on every authenticated route
* Request with wrong key → 401
* No code path resolves an unauthenticated request to a real user identity
* Key comparison uses secrets.compare_digest
* Auth failures emit a structured security-event log line
"""

from __future__ import annotations

import asyncio
import logging
import os

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _set_env(*, api_key: str | None, dev_no_auth: str | None) -> None:
    """Set auth-related env vars (clean existing state first)."""
    if api_key is not None:
        os.environ["AEGIS_API_KEY"] = api_key
    else:
        os.environ.pop("AEGIS_API_KEY", None)

    if dev_no_auth is not None:
        os.environ["AEGIS_DEV_NO_AUTH"] = dev_no_auth
    else:
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)


def _make_app():
    from api.app import create_app

    return create_app()


@pytest.fixture(autouse=True)
def _clean_env():
    """Strip auth-related env vars before/after every test."""
    for k in ("AEGIS_API_KEY", "AEGIS_DEV_NO_AUTH", "AEGIS_USER_ID", "DATABASE_URL"):
        os.environ.pop(k, None)
    yield
    for k in ("AEGIS_API_KEY", "AEGIS_DEV_NO_AUTH", "AEGIS_USER_ID", "DATABASE_URL"):
        os.environ.pop(k, None)


# ---------------------------------------------------------------------------
# Startup: fail-closed (lifespan check runs when TestClient is used as ctx mgr)
# ---------------------------------------------------------------------------


def _start_app(*, api_key: str | None, dev_no_auth: str | None):
    """Set env, create app, and trigger lifespan startup via TestClient context."""
    from fastapi.testclient import TestClient

    _set_env(api_key=api_key, dev_no_auth=dev_no_auth)
    app = _make_app()
    # Entering the context manager fires the lifespan startup event.
    with TestClient(app, raise_server_exceptions=True):
        pass


class TestStartupFailClosed:
    def test_startup_fails_without_key_or_dev_mode(self):
        """Lifespan raises RuntimeError when AEGIS_API_KEY and AEGIS_DEV_NO_AUTH are both unset."""
        with pytest.raises(RuntimeError, match="AEGIS_API_KEY"):
            _start_app(api_key=None, dev_no_auth=None)

    def test_startup_succeeds_with_api_key(self):
        """Lifespan passes when AEGIS_API_KEY is set."""
        _start_app(api_key="secret-key", dev_no_auth=None)  # no exception

    def test_startup_succeeds_with_dev_no_auth(self):
        """Lifespan passes when AEGIS_DEV_NO_AUTH=1, even without a key."""
        _start_app(api_key=None, dev_no_auth="1")  # no exception

    def test_startup_fails_when_dev_no_auth_is_not_one(self):
        """AEGIS_DEV_NO_AUTH=0 is not the opt-out; app must still refuse."""
        with pytest.raises(RuntimeError, match="AEGIS_API_KEY"):
            _start_app(api_key=None, dev_no_auth="0")


# ---------------------------------------------------------------------------
# Request-level: 401 on missing / wrong key
# ---------------------------------------------------------------------------


class TestRequestAuth:
    """HTTP-level auth checks via FastAPI TestClient (no DB required)."""

    _ENDPOINTS = [
        ("GET", "/scans/00000000-0000-4000-8000-000000000001"),
        ("GET", "/scans/00000000-0000-4000-8000-000000000001/report"),
        ("GET", "/scans/00000000-0000-4000-8000-000000000001/aibom"),
    ]

    def _client(self, api_key: str):
        from fastapi.testclient import TestClient

        _set_env(api_key=api_key, dev_no_auth=None)
        app = _make_app()
        return TestClient(app, raise_server_exceptions=False)

    def test_no_key_returns_401_on_get_scan(self):
        """No X-API-Key header → 401."""
        client = self._client("real-secret")
        resp = client.get("/scans/00000000-0000-4000-8000-000000000001")
        assert resp.status_code == 401

    def test_wrong_key_returns_401_on_get_scan(self):
        """Wrong X-API-Key header → 401."""
        client = self._client("real-secret")
        resp = client.get(
            "/scans/00000000-0000-4000-8000-000000000001",
            headers={"X-API-Key": "wrong-key"},
        )
        assert resp.status_code == 401

    def test_correct_key_does_not_return_401(self):
        """Correct key passes auth (may 404 for missing scan, but not 401)."""
        client = self._client("real-secret")
        resp = client.get(
            "/scans/00000000-0000-4000-8000-000000000001",
            headers={"X-API-Key": "real-secret"},
        )
        assert resp.status_code != 401

    def test_no_key_returns_401_on_post_scans(self):
        """POST /scans with no key → 401."""
        client = self._client("real-secret")
        resp = client.post("/scans", json={"mcp_json": {"mcpServers": {}}})
        assert resp.status_code == 401

    def test_no_key_returns_401_on_post_gate(self):
        """POST /gate with no key → 401."""
        client = self._client("real-secret")
        resp = client.post(
            "/gate",
            json={"scan_id": "00000000-0000-4000-8000-000000000001", "min_score": 70},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# No anonymous identity on authenticated paths
# ---------------------------------------------------------------------------


class TestNoAnonIdentity:
    """No unauthenticated request should resolve to a real user UUID."""

    def test_missing_key_raises_401_not_anon(self):
        """get_current_user with no key and no dev mode → 401, not _ANON_USER_ID."""
        from fastapi import HTTPException

        from api.deps import get_current_user

        os.environ["AEGIS_API_KEY"] = "some-key"
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(get_current_user(None))
        assert exc_info.value.status_code == 401

    def test_no_configured_key_and_no_dev_mode_raises_401(self):
        """If startup check were bypassed and AEGIS_API_KEY is absent, still 401."""
        from fastapi import HTTPException

        from api.deps import get_current_user

        os.environ.pop("AEGIS_API_KEY", None)
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(get_current_user("any-key"))
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# secrets.compare_digest usage
# ---------------------------------------------------------------------------


class TestConstantTimeCompare:
    """Verify correct constant-time key comparison behaviour."""

    def test_correct_key_accepted(self):
        """Exact match → no exception."""
        from api.deps import get_current_user

        key = "my-secure-key"
        os.environ["AEGIS_API_KEY"] = key
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)
        # Should not raise
        result = asyncio.run(get_current_user(key))
        assert result is not None

    def test_prefix_of_correct_key_rejected(self):
        """Prefix of the correct key must not pass (non-trivial compare)."""
        from fastapi import HTTPException

        from api.deps import get_current_user

        os.environ["AEGIS_API_KEY"] = "my-secure-key"
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(get_current_user("my-secure-ke"))
        assert exc_info.value.status_code == 401

    def test_key_with_extra_char_rejected(self):
        """Key with one extra char appended must be rejected."""
        from fastapi import HTTPException

        from api.deps import get_current_user

        os.environ["AEGIS_API_KEY"] = "my-secure-key"
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(get_current_user("my-secure-keyX"))
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Security-event logging
# ---------------------------------------------------------------------------


class TestSecurityEventLogging:
    """Auth failures must emit a structured security-event log line."""

    def test_wrong_key_logs_security_event(self, caplog):
        from fastapi import HTTPException

        from api.deps import get_current_user

        os.environ["AEGIS_API_KEY"] = "real-key"
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)

        with caplog.at_level(logging.WARNING, logger="api.deps"), pytest.raises(HTTPException):
            asyncio.run(get_current_user("wrong-key"))

        assert any("security_event=auth_failure" in r.message for r in caplog.records)

    def test_missing_key_logs_security_event(self, caplog):
        from fastapi import HTTPException

        from api.deps import get_current_user

        os.environ["AEGIS_API_KEY"] = "real-key"
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)

        with caplog.at_level(logging.WARNING, logger="api.deps"), pytest.raises(HTTPException):
            asyncio.run(get_current_user(None))

        assert any("security_event=auth_failure" in r.message for r in caplog.records)

    def test_no_key_configured_logs_security_event(self, caplog):
        from fastapi import HTTPException

        from api.deps import get_current_user

        os.environ.pop("AEGIS_API_KEY", None)
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)

        with caplog.at_level(logging.WARNING, logger="api.deps"), pytest.raises(HTTPException):
            asyncio.run(get_current_user("some-key"))

        assert any("security_event=auth_failure" in r.message for r in caplog.records)

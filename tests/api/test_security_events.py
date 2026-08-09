"""tests/api/test_security_events.py — KCH-21: security event logging + spike detection.

Tests:
  - log_auth_failure / log_permission_denied / log_rate_limit_hit emit
    structured log records under the ``aegis.security`` logger.
  - Spike detection: 20 auth failures from the same IP within the window
    triggers a ``security_event=spike_alert`` CRITICAL record.
  - IP extraction in CorrelationIdMiddleware (unit test).
  - Sentry init is skipped gracefully when SENTRY_DSN is unset.
  - configure_structlog() does not break stdlib caplog.
"""

from __future__ import annotations

import logging
import os
import uuid

import pytest  # noqa: F401 (used as decorator + skip)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _flush_redis_key(key: str) -> None:
    """Delete a Redis key if Redis is reachable (best-effort, test cleanup)."""
    try:
        import redis as redis_lib  # type: ignore[import-untyped]

        r = redis_lib.Redis.from_url("redis://localhost:6379", socket_connect_timeout=1)
        r.delete(key)
        r.close()
    except Exception:  # noqa: BLE001
        pass


@pytest.fixture()
def redis_available() -> bool:
    """True if local Redis is reachable."""
    try:
        import redis as redis_lib  # type: ignore[import-untyped]

        r = redis_lib.Redis(host="localhost", port=6379, socket_connect_timeout=1)
        r.ping()
        r.close()
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# log_auth_failure
# ---------------------------------------------------------------------------


class TestLogAuthFailure:
    def test_emits_structured_record(self, caplog):
        from api.security_events import log_auth_failure

        with caplog.at_level(logging.WARNING, logger="aegis.security"):
            log_auth_failure(ip="1.2.3.4", actor="testkey", reason="bad_key")

        msgs = [r.getMessage() for r in caplog.records if r.name == "aegis.security"]
        assert any("security_event=auth_failure" in m for m in msgs), msgs

    def test_includes_ip_in_extra(self, caplog):
        from api.security_events import log_auth_failure

        with caplog.at_level(logging.WARNING, logger="aegis.security"):
            log_auth_failure(ip="10.0.0.1", actor="testkey", reason="bad_key", correlation_id="c1")

        records = [r for r in caplog.records if r.name == "aegis.security"]
        assert records, "Expected at least one aegis.security log record"
        # Extra fields are available on the LogRecord (structlog stdlib integration).
        rec = records[0]
        assert getattr(rec, "ip", None) == "10.0.0.1" or "10.0.0.1" in rec.getMessage()

    def test_log_level_is_warning(self, caplog):
        from api.security_events import log_auth_failure

        with caplog.at_level(logging.DEBUG, logger="aegis.security"):
            log_auth_failure(ip="1.2.3.4", actor="a", reason="bad_key")

        records = [r for r in caplog.records if r.name == "aegis.security"]
        assert records
        assert records[0].levelno == logging.WARNING


# ---------------------------------------------------------------------------
# log_permission_denied
# ---------------------------------------------------------------------------


class TestLogPermissionDenied:
    def test_emits_structured_record(self, caplog):
        from api.security_events import log_permission_denied

        with caplog.at_level(logging.WARNING, logger="aegis.security"):
            log_permission_denied(ip="1.2.3.4", actor="user", resource="scan:abc")

        msgs = [r.getMessage() for r in caplog.records if r.name == "aegis.security"]
        assert any("security_event=permission_denied" in m for m in msgs), msgs


# ---------------------------------------------------------------------------
# log_rate_limit_hit
# ---------------------------------------------------------------------------


class TestLogRateLimitHit:
    def test_emits_structured_record(self, caplog):
        from api.security_events import log_rate_limit_hit

        with caplog.at_level(logging.WARNING, logger="aegis.security"):
            log_rate_limit_hit(ip="1.2.3.4", actor="user")

        msgs = [r.getMessage() for r in caplog.records if r.name == "aegis.security"]
        assert any("security_event=rate_limit_hit" in m for m in msgs), msgs


# ---------------------------------------------------------------------------
# Spike detection — requires real Redis
# ---------------------------------------------------------------------------


class TestSpikeDetection:
    """Integration tests that use a real local Redis instance."""

    _IP = f"test-spike-{uuid.uuid4().hex[:8]}"

    def setup_method(self):
        _flush_redis_key(f"aegis:auth_fail:{self._IP}")

    def teardown_method(self):
        _flush_redis_key(f"aegis:auth_fail:{self._IP}")

    def test_no_spike_below_threshold(self, redis_available, caplog):
        if not redis_available:
            pytest.skip("Redis not available")

        from api.security_events import log_auth_failure

        with caplog.at_level(logging.DEBUG, logger="aegis.security"):
            for _ in range(19):
                log_auth_failure(ip=self._IP, actor="attacker", reason="bad_key")

        critical = [
            r
            for r in caplog.records
            if r.name == "aegis.security" and r.levelno == logging.CRITICAL
        ]
        assert not critical, "Should not emit spike_alert below threshold"

    def test_spike_alert_at_threshold(self, redis_available, caplog):
        if not redis_available:
            pytest.skip("Redis not available")

        from api.security_events import log_auth_failure

        with caplog.at_level(logging.DEBUG, logger="aegis.security"):
            for _ in range(20):
                log_auth_failure(ip=self._IP, actor="attacker", reason="bad_key")

        critical = [
            r
            for r in caplog.records
            if r.name == "aegis.security" and r.levelno == logging.CRITICAL
        ]
        assert critical, "Expected spike_alert CRITICAL record at threshold"
        assert any("security_event=spike_alert" in r.getMessage() for r in critical)

    def test_spike_alert_above_threshold(self, redis_available, caplog):
        if not redis_available:
            pytest.skip("Redis not available")

        from api.security_events import log_auth_failure

        with caplog.at_level(logging.DEBUG, logger="aegis.security"):
            for _ in range(25):
                log_auth_failure(ip=self._IP, actor="attacker", reason="bad_key")

        critical = [
            r
            for r in caplog.records
            if r.name == "aegis.security" and r.levelno == logging.CRITICAL
        ]
        assert critical, "Expected spike_alert above threshold too"

    def test_separate_ips_do_not_cross_contaminate(self, redis_available, caplog):
        if not redis_available:
            pytest.skip("Redis not available")

        ip_b = f"test-spike-other-{uuid.uuid4().hex[:8]}"
        _flush_redis_key(f"aegis:auth_fail:{ip_b}")
        try:
            from api.security_events import log_auth_failure

            with caplog.at_level(logging.DEBUG, logger="aegis.security"):
                # IP A: 10 failures (below threshold)
                for _ in range(10):
                    log_auth_failure(ip=self._IP, actor="a", reason="bad_key")
                # IP B: 10 failures (also below threshold)
                for _ in range(10):
                    log_auth_failure(ip=ip_b, actor="b", reason="bad_key")

            critical = [
                r
                for r in caplog.records
                if r.name == "aegis.security" and r.levelno == logging.CRITICAL
            ]
            assert not critical, "IPs should not contaminate each other's counters"
        finally:
            _flush_redis_key(f"aegis:auth_fail:{ip_b}")


# ---------------------------------------------------------------------------
# configure_structlog — does not break stdlib caplog
# ---------------------------------------------------------------------------


class TestConfigureStructlog:
    def test_configure_does_not_raise(self):
        from api.logging_config import configure_structlog

        configure_structlog()  # idempotent

    def test_stdlib_caplog_still_works_after_configure(self, caplog):
        from api.logging_config import configure_structlog

        configure_structlog()
        log = logging.getLogger("test.structlog.compat")
        with caplog.at_level(logging.WARNING, logger="test.structlog.compat"):
            log.warning("hello from stdlib")

        assert any("hello from stdlib" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# Sentry init — skipped gracefully without DSN
# ---------------------------------------------------------------------------


class TestSentryInit:
    def test_sentry_init_skipped_without_dsn(self):
        """_init_sentry() must not raise when SENTRY_DSN is absent."""
        os.environ.pop("SENTRY_DSN", None)
        from api.app import _init_sentry

        _init_sentry()  # no exception

    def test_sentry_init_skipped_with_invalid_dsn(self):
        """_init_sentry() must not raise (or surface) a bad DSN."""
        os.environ["SENTRY_DSN"] = "https://invalid@sentry.example.com/0"
        try:
            from api.app import _init_sentry

            _init_sentry()  # swallows any init error
        finally:
            os.environ.pop("SENTRY_DSN", None)


# ---------------------------------------------------------------------------
# IP extraction in CorrelationIdMiddleware
# ---------------------------------------------------------------------------


class TestClientIpExtraction:
    def test_forwarded_for_header_takes_priority(self):
        from unittest.mock import MagicMock

        from api.app import _client_ip

        req = MagicMock()
        req.headers = {"X-Forwarded-For": "203.0.113.1, 10.0.0.1"}
        req.client = MagicMock(host="10.0.0.1")
        assert _client_ip(req) == "203.0.113.1"

    def test_falls_back_to_direct_peer(self):
        from unittest.mock import MagicMock

        from api.app import _client_ip

        req = MagicMock()
        req.headers = {}
        req.client = MagicMock(host="192.168.1.5")
        assert _client_ip(req) == "192.168.1.5"

    def test_returns_unknown_with_no_client(self):
        from unittest.mock import MagicMock

        from api.app import _client_ip

        req = MagicMock()
        req.headers = {}
        req.client = None
        assert _client_ip(req) == "unknown"

    def test_middleware_extracts_ip_via_dispatch(self):
        """CorrelationIdMiddleware stores client_ip on request.state (unit-level)."""
        import asyncio
        from unittest.mock import MagicMock

        from api.app import CorrelationIdMiddleware, _client_ip

        # Verify _client_ip is called and result stored on request.state
        req = MagicMock()
        req.headers = {"X-Forwarded-For": "5.6.7.8"}
        req.client = MagicMock(host="10.0.0.2")

        assert _client_ip(req) == "5.6.7.8"

        # Verify CorrelationIdMiddleware.dispatch sets client_ip on state
        mw = CorrelationIdMiddleware(app=MagicMock())  # type: ignore[arg-type]
        state = MagicMock()
        state.client_ip = None
        req2 = MagicMock()
        req2.headers = {"X-Forwarded-For": "9.8.7.6"}
        req2.client = MagicMock(host="10.0.0.1")
        req2.state = state
        req2.url = MagicMock(path="/test")
        req2.method = "GET"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}

        async def _call_next(_r):  # noqa: ANN001
            return mock_response

        asyncio.run(mw.dispatch(req2, _call_next))
        assert state.client_ip == "9.8.7.6"


# ---------------------------------------------------------------------------
# Auth failure security events propagate to aegis.security logger via HTTP
# ---------------------------------------------------------------------------


class TestAuthFailureHTTP:
    """End-to-end: wrong API key → 401 + aegis.security log record."""

    def test_wrong_key_emits_auth_failure_event(self, caplog):
        import os

        os.environ["AEGIS_API_KEY"] = "correct-key"
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)
        try:
            from fastapi.testclient import TestClient

            from api.app import create_app

            app = create_app()
            client = TestClient(app, raise_server_exceptions=False)

            with caplog.at_level(logging.WARNING, logger="aegis.security"):
                resp = client.get(
                    "/scans/00000000-0000-4000-8000-000000000001",
                    headers={"X-API-Key": "wrong-key"},
                )

            assert resp.status_code == 401
            msgs = [r.getMessage() for r in caplog.records if r.name == "aegis.security"]
            assert any("security_event=auth_failure" in m for m in msgs), msgs
        finally:
            os.environ.pop("AEGIS_API_KEY", None)
            os.environ.pop("AEGIS_DEV_NO_AUTH", None)

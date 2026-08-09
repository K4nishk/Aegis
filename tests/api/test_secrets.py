"""tests/api/test_secrets.py — Secret redaction unit tests (KCH-22).

Covers:
  - redact_secrets(): value replacement, keyword preservation, non-matching text
  - redact_dict(): key-name sensitivity, recursive dicts, non-string values
  - structlog_redact_processor(): event field, extra fields, nested dicts
  - logging_config integration: processor is wired into the structlog chain
  - Gitleaks config: .gitleaks.toml exists and passes on current history
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from api.redact import (
    _REDACTED,
    redact_dict,
    redact_secrets,
    structlog_redact_processor,
)

# ---------------------------------------------------------------------------
# redact_secrets
# ---------------------------------------------------------------------------


class TestRedactSecrets:
    def test_api_key_equals(self) -> None:
        result = redact_secrets("api_key=ABCDEF1234567890")
        assert _REDACTED in result
        assert "ABCDEF1234567890" not in result
        assert "api_key=" in result

    def test_token_colon(self) -> None:
        result = redact_secrets("token: eyJhbGciOiJSUzI1NiJ9long_token_value_here")
        assert _REDACTED in result
        assert "eyJhbGciOiJSUzI1NiJ9" not in result

    def test_password_with_quotes(self) -> None:
        result = redact_secrets("password='supersecretpass123'")
        assert _REDACTED in result
        assert "supersecretpass123" not in result
        assert "password=" in result

    def test_secret_standalone(self) -> None:
        result = redact_secrets("secret=abcdefgh12345678")
        assert _REDACTED in result
        assert "abcdefgh12345678" not in result

    def test_api_dot_key(self) -> None:
        result = redact_secrets("api.key=xyzxyzxyz12345678abcd")
        assert _REDACTED in result

    def test_no_match_plain_text(self) -> None:
        text = "This is a normal log message with no secrets."
        assert redact_secrets(text) == text

    def test_short_value_not_redacted(self) -> None:
        # Values < 8 chars are not redacted (too short to be a real secret).
        text = "api_key=short"
        assert redact_secrets(text) == text

    def test_multiple_secrets_in_one_string(self) -> None:
        text = "api_key=ABCDEF1234567890 password=supersecretpass123"
        result = redact_secrets(text)
        assert "ABCDEF1234567890" not in result
        assert "supersecretpass123" not in result
        assert result.count(_REDACTED) == 2

    def test_preserves_surrounding_text(self) -> None:
        text = "prefix api_key=ABCDEF1234567890 suffix"
        result = redact_secrets(text)
        assert result.startswith("prefix ")
        assert result.endswith(" suffix")

    def test_empty_string(self) -> None:
        assert redact_secrets("") == ""


# ---------------------------------------------------------------------------
# redact_dict
# ---------------------------------------------------------------------------


class TestRedactDict:
    def test_sensitive_key_fully_redacted(self) -> None:
        d: dict[str, Any] = {"api_key": "ABCDEF1234567890", "other": "normal"}
        result = redact_dict(d)
        assert result["api_key"] == _REDACTED
        assert result["other"] == "normal"

    def test_case_insensitive_key(self) -> None:
        d: dict[str, Any] = {"AEGIS_API_KEY": "secret_value_here_12345"}
        result = redact_dict(d)
        assert result["AEGIS_API_KEY"] == _REDACTED

    def test_non_sensitive_string_value_scanned(self) -> None:
        d: dict[str, Any] = {"message": "api_key=ABCDEF1234567890 logged here"}
        result = redact_dict(d)
        assert "ABCDEF1234567890" not in result["message"]

    def test_nested_dict_redacted(self) -> None:
        d: dict[str, Any] = {"nested": {"password": "supersecretpass123"}}
        result = redact_dict(d)
        assert result["nested"]["password"] == _REDACTED

    def test_non_string_values_preserved(self) -> None:
        d: dict[str, Any] = {"count": 42, "flag": True, "items": [1, 2, 3]}
        result = redact_dict(d)
        assert result["count"] == 42
        assert result["flag"] is True
        assert result["items"] == [1, 2, 3]

    def test_dsn_key_redacted(self) -> None:
        d: dict[str, Any] = {"dsn": "postgresql://user:pass@host/db"}
        result = redact_dict(d)
        assert result["dsn"] == _REDACTED

    def test_database_url_key_redacted(self) -> None:
        d: dict[str, Any] = {"database_url": "postgresql://user:pass@host/db"}
        result = redact_dict(d)
        assert result["database_url"] == _REDACTED

    def test_original_dict_not_mutated(self) -> None:
        d: dict[str, Any] = {"api_key": "ABCDEF1234567890"}
        redact_dict(d)
        assert d["api_key"] == "ABCDEF1234567890"


# ---------------------------------------------------------------------------
# structlog_redact_processor
# ---------------------------------------------------------------------------


class TestStructlogRedactProcessor:
    def _call(self, event_dict: dict[str, Any]) -> dict[str, Any]:
        return structlog_redact_processor(None, "info", event_dict)

    def test_event_field_redacted(self) -> None:
        ed = {"event": "Connecting with api_key=ABCDEF1234567890"}
        result = self._call(ed)
        assert "ABCDEF1234567890" not in result["event"]
        assert _REDACTED in result["event"]

    def test_sensitive_extra_field_redacted(self) -> None:
        ed = {"event": "auth ok", "api_key": "mysecretkey1234567"}
        result = self._call(ed)
        assert result["api_key"] == _REDACTED

    def test_non_sensitive_field_value_scanned(self) -> None:
        ed = {"event": "ok", "detail": "token: eyJhbGciOiJSUzI1NiJ9verylongtoken"}
        result = self._call(ed)
        assert "eyJhbGciOiJSUzI1NiJ9" not in result["detail"]

    def test_nested_dict_field_redacted(self) -> None:
        ed = {"event": "ok", "context": {"password": "supersecretpass123"}}
        result = self._call(ed)
        assert result["context"]["password"] == _REDACTED

    def test_non_string_fields_preserved(self) -> None:
        ed = {"event": "metrics", "count": 42, "latency_ms": 3.14}
        result = self._call(ed)
        assert result["count"] == 42
        assert result["latency_ms"] == 3.14

    def test_clean_event_unchanged(self) -> None:
        ed = {"event": "scan completed", "scan_id": "abc-123", "score": 85}
        result = self._call(ed)
        assert result["event"] == "scan completed"
        assert result["scan_id"] == "abc-123"

    def test_mutates_in_place_and_returns(self) -> None:
        ed: dict[str, Any] = {"event": "ok", "api_key": "ABCDEF1234567890"}
        result = self._call(ed)
        assert result is ed  # structlog convention: mutate + return same dict


# ---------------------------------------------------------------------------
# Integration: processor is in the structlog chain
# ---------------------------------------------------------------------------


class TestStructlogIntegration:
    def test_redact_processor_in_chain(self) -> None:
        """Verify structlog_redact_processor appears in the configured chain."""
        import structlog

        from api.logging_config import configure_structlog

        configure_structlog()
        config = structlog.get_config()
        # Our processor is a plain function; check by function name.
        func_names = [getattr(p, "__name__", type(p).__name__) for p in config["processors"]]
        assert "structlog_redact_processor" in func_names, (
            f"structlog_redact_processor not found in chain: {func_names}"
        )


# ---------------------------------------------------------------------------
# Gitleaks clean-history check
# ---------------------------------------------------------------------------


class TestGitleaksCleanHistory:
    @pytest.mark.skipif(
        not Path("/usr/local/bin/gitleaks").exists()
        and not Path("/usr/bin/gitleaks").exists()
        and not any(
            (Path(p) / "gitleaks").exists()
            for p in __import__("os").environ.get("PATH", "").split(":")
        ),
        reason="gitleaks not installed",
    )
    def test_no_secrets_in_history(self) -> None:
        """Full git-history scan must find zero leaks (allowlist applied)."""
        repo_root = Path(__file__).parents[2]
        result = subprocess.run(
            [
                "gitleaks",
                "detect",
                "--source",
                str(repo_root),
                "--log-opts=--all",
                "--config",
                str(repo_root / ".gitleaks.toml"),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"gitleaks found leaks:\n{result.stdout}\n{result.stderr}"

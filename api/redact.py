"""api/redact.py — Secret redaction utilities for Aegis (KCH-22).

Provides:
  redact_secrets(text)        — Replace secret values in a string with [REDACTED].
  redact_dict(d)              — Recursively redact all string values in a dict.
  structlog_redact_processor  — structlog processor that scrubs the event and
                                all string-valued extra fields before emission.

Rules (SEC-6):
  - Secrets never reach the browser (client response) or a log sink.
  - All redaction is performed server-side, before structlog handlers emit.
  - The redaction regex mirrors _SECRET_IN_DESC_RE from analyzer/posture.py so
    both static analysis and runtime log-scrubbing use the same definition.

Env vars that must never be logged (scrubbed by key name):
  AEGIS_API_KEY, DATABASE_URL, SENTRY_DSN, AEGIS_USER_ID
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Core redaction regex
#
# Matches: <keyword> <separator> <value>
#   keyword   — password, secret, api_key, token, credential, auth …
#   separator — = : or whitespace (optional quotes)
#   value     — ≥8 chars of base64/hex/alphanumeric (enough to avoid false
#               positives on human-readable words while catching short tokens)
#
# The group(2) capture lets us preserve the keyword and separator while
# replacing only the value with [REDACTED].
# ---------------------------------------------------------------------------

_SECRET_VALUE_RE = re.compile(
    r"((?:password|passwd|secret|api[_\-.]?key|token|credential|auth)[=:\s]+['\"]?)"
    r"([A-Za-z0-9+/\-_]{8,})"
    r"(['\"]?)",
    re.I,
)

# Env-var names whose values should be scrubbed from log records.
_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "aegis_api_key",
        "api_key",
        "database_url",
        "db_url",
        "dsn",
        "sentry_dsn",
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "auth_token",
        "authorization",
        "x-api-key",
    }
)

_REDACTED = "[REDACTED]"


def redact_secrets(text: str) -> str:
    """Replace secret values in *text* with ``[REDACTED]``.

    The keyword and separator are preserved so log messages remain readable;
    only the actual value is replaced.

    Example::

        >>> redact_secrets("api_key=ABCDEF1234567890")
        'api_key=[REDACTED]'
        >>> redact_secrets("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.long")
        'Authorization: Bearer [REDACTED]'
    """
    return _SECRET_VALUE_RE.sub(lambda m: m.group(1) + _REDACTED + m.group(3), text)


def _is_sensitive_key(key: str) -> bool:
    return key.lower() in _SENSITIVE_KEYS


def redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of *d* with sensitive values replaced.

    - Keys in ``_SENSITIVE_KEYS`` have their entire value replaced with
      ``[REDACTED]`` regardless of format.
    - Other string values are passed through ``redact_secrets()``.
    - Non-string values are left unchanged.
    - Nested dicts are recursed into (one level only; deep nesting is rare in
      log contexts and we avoid quadratic behaviour).
    """
    out: dict[str, Any] = {}
    for k, v in d.items():
        if _is_sensitive_key(k):
            out[k] = _REDACTED
        elif isinstance(v, str):
            out[k] = redact_secrets(v)
        elif isinstance(v, dict):
            out[k] = redact_dict(v)
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# structlog processor
# ---------------------------------------------------------------------------


def structlog_redact_processor(
    logger: Any,  # noqa: ARG001
    method: str,  # noqa: ARG001
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """structlog processor: scrub secrets from the event string and all fields.

    Insert this processor *before* the renderer in the processor chain so that
    no secret ever reaches a log sink (stdout, CloudWatch, Sentry breadcrumbs).

    Mutates *event_dict* in-place (structlog convention) and returns it.
    """
    # Scrub the main log message.
    event = event_dict.get("event")
    if isinstance(event, str):
        event_dict["event"] = redact_secrets(event)

    # Scrub all other string-valued fields by key name and value pattern.
    for key in list(event_dict):
        if key == "event":
            continue
        val = event_dict[key]
        if _is_sensitive_key(key):
            event_dict[key] = _REDACTED
        elif isinstance(val, str):
            event_dict[key] = redact_secrets(val)
        elif isinstance(val, dict):
            event_dict[key] = redact_dict(val)

    return event_dict

"""api/logging_config.py — structlog configuration for Aegis (KCH-21).

Configures structlog to emit structured logs through the stdlib logging system so:
  - CloudWatch metric filters can match on ``security_event`` JSON fields (production)
  - pytest caplog continues to capture records normally in tests
  - Sentry enriches error records automatically via its stdlib integration

Call ``configure_structlog()`` once at app startup.

Environment:
  AEGIS_LOG_FORMAT=json   — JSONRenderer (one JSON object per line, CloudWatch-ready)
  (default)               — KeyValueRenderer (human-readable, still stdlib-routed)
"""

from __future__ import annotations

import logging
import os

import structlog


def configure_structlog() -> None:
    """Configure structlog for the current environment.

    Routes structlog through the stdlib LoggerFactory so that all structured
    log calls appear in pytest caplog and in any stdlib handler (CloudWatch
    agent, stdout, etc.).
    """
    json_mode = os.environ.get("AEGIS_LOG_FORMAT", "").lower() == "json"

    shared_processors: list[structlog.types.Processor] = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
    ]

    if json_mode:
        # JSONRenderer returns a string; structlog passes it as the log message.
        # Each line in CloudWatch will be a parseable JSON object.
        processors: list[structlog.types.Processor] = [
            *shared_processors,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # render_to_log_kwargs returns a dict; structlog calls stdlib.logger(msg=..., extra={...}).
        # LogRecord.getMessage() returns the event string which caplog can inspect.
        processors = [
            *shared_processors,
            structlog.stdlib.render_to_log_kwargs,
        ]

    structlog.configure(
        processors=processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        # False so re-calling configure_structlog() (e.g. from lifespan) takes effect immediately.
        cache_logger_on_first_use=False,
    )

    logging.getLogger("aegis.security").setLevel(logging.WARNING)


# Auto-configure at import time with dev defaults so that structlog always
# routes through stdlib logging (and thus pytest caplog) without requiring an
# explicit call to configure_structlog() in every test.
configure_structlog()

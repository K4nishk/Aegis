# Dockerfile — Aegis Security API (KCH-33)
# Multi-stage: reproducible deps via uv + lean runtime image.
# Runs as non-root user (UID 1000) — required for a security product.

# ---------------------------------------------------------------------------
# Stage 1: dependency installer
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

RUN pip install --no-cache-dir "uv==0.7.20"

WORKDIR /build

# Copy only the files uv needs to resolve the lockfile.
# Doing this before copying source keeps this layer cached on source changes.
COPY pyproject.toml uv.lock ./

# Sync production deps into /build/.venv; skip installing the project itself.
RUN uv sync --frozen --no-dev --no-install-project

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Create a dedicated non-root user.
RUN useradd -m -u 1000 -s /bin/bash aegis

WORKDIR /app

# Copy the pre-built virtualenv from the builder stage.
COPY --from=builder /build/.venv /app/.venv

# Copy only the application packages that are actually needed at runtime.
# Tests, docs, and dev tooling are intentionally excluded.
COPY --chown=aegis:aegis api/       api/
COPY --chown=aegis:aegis analyzer/  analyzer/
COPY --chown=aegis:aegis parser/    parser/
COPY --chown=aegis:aegis db/        db/

USER aegis

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# Default command: run uvicorn.
# In docker-compose.yml the command is overridden to run migrations first.
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]

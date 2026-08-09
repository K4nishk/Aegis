# Running Aegis locally with Docker

From a clean checkout to a live posture score in under ten commands.

## Prerequisites

- Docker 24+ with Compose V2 (`docker compose` not `docker-compose`)
- No other services bound to port 5432, 6379, or 8000

## 1. Clone and configure

```bash
git clone https://github.com/K4nishk/Aegis.git
cd Aegis
cp .env.example .env
```

Open `.env` and set `AEGIS_API_KEY` to a secret value:

```bash
# generate a key
python3 -c "import secrets; print(secrets.token_hex(32))"
# paste the output into .env as AEGIS_API_KEY=<value>
```

## 2. Start the stack

```bash
docker compose up -d
```

This builds the image, starts Postgres and Redis, waits for their healthchecks,
runs all DDL migrations (idempotent), then starts uvicorn.

## 3. Verify all services are healthy

```bash
docker compose ps
# Expected: all three services show "healthy" within ~60 s
```

## 4. Confirm migrations applied

```bash
docker compose exec db psql -U aegis -d aegis -c "\dt"
# Expected tables: tool_graph_nodes, tool_graph_edges, findings, scan_runs, audit_log, ...
```

## 5. Health endpoint (no auth required)

```bash
curl -fsS localhost:8000/health
# {"status":"ok","db":"ok","redis":"ok"}
```

## 6. Auth is enforced

```bash
# No key → 401
curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8000/scans

# With key → 201
export AEGIS_API_KEY=$(grep AEGIS_API_KEY .env | cut -d= -f2)
curl -s -o /dev/null -w '%{http_code}' \
     -H "X-API-Key: $AEGIS_API_KEY" \
     -H "Content-Type: application/json" \
     -X POST localhost:8000/scans \
     -d @tests/fixtures/mcp/github_brave.json
```

## 7. Run a real scan and get a posture score

```bash
# Submit the scan
SCAN_ID=$(curl -s \
  -H "X-API-Key: $AEGIS_API_KEY" \
  -H "Content-Type: application/json" \
  -X POST localhost:8000/scans \
  -d @tests/fixtures/mcp/github_brave.json \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

# Fetch the report
curl -s -H "X-API-Key: $AEGIS_API_KEY" \
     "localhost:8000/scans/${SCAN_ID}/report?fmt=text"
```

Expected output includes a posture score between 0 and 100, triggered rules,
and any trifecta findings.

## 8. Restart without losing data

```bash
docker compose down && docker compose up -d
```

The named volume `pgdata` preserves all scan data.  Migrations are idempotent —
re-running them on restart does not double-apply or error.

## 9. Confirm the container is non-root

```bash
docker compose exec api whoami
# aegis  (must NOT be root)
```

## 10. Confirm no secrets in image layers

```bash
docker history --no-trunc aegis-api | grep -iE "key|secret|token"
# Expected: no output
```

---

## Stopping and cleaning up

```bash
docker compose down          # stop and remove containers
docker compose down -v       # also remove the pgdata volume (destroys all data)
```

## Environment variables

See `.env.example` for the full list of tunables with descriptions.

Key variables:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AEGIS_API_KEY` | yes | — | API authentication key |
| `DATABASE_URL` | yes | auto-built | Postgres DSN |
| `AEGIS_REDIS_URL` | no | `redis://redis:6379` | Redis DSN |
| `API_PORT` | no | `8000` | Host port for the API |
| `SENTRY_DSN` | no | — | Sentry error tracking |

## Notes

- The `aegis` database user is a superuser in the local Docker setup, which
  means RLS policies are bypassed.  In production, connect as the `aegis_app`
  role (created automatically by V1 migration) so that Row-Level Security
  is enforced.  Secret provisioning is covered in KCH-34.
- Cloud deployment is covered in KCH-35.
- Backup/restore procedures are in `docs/RUNBOOK.md`.

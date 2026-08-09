#!/usr/bin/env bash
# ops/backup.sh — nightly pg_dump → S3 offsite backup (KCH-23 / SEC-7)
#
# Required env vars:
#   PGDATABASE        — database name to back up
#   PGHOST            — Postgres host (default: localhost)
#   PGPORT            — Postgres port (default: 5432)
#   PGUSER            — Postgres user
#   S3_BUCKET         — S3 bucket name (versioned, SSE-KMS)
#
# Optional:
#   S3_PREFIX         — key prefix inside bucket (default: aegis/backups)
#   PGPASSWORD        — password (prefer ~/.pgpass or IAM instance-profile auth)
#   S3_STORAGE_CLASS  — STANDARD | STANDARD_IA | GLACIER (default: STANDARD_IA)
#   BACKUP_DIR        — local temp dir for dump file (default: /tmp/aegis_backup)
#   AWS_REGION        — AWS region (default: us-east-1)

set -euo pipefail

PGDATABASE="${PGDATABASE:?PGDATABASE is required}"
PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:?PGUSER is required}"
S3_BUCKET="${S3_BUCKET:?S3_BUCKET is required}"
S3_PREFIX="${S3_PREFIX:-aegis/backups}"
S3_STORAGE_CLASS="${S3_STORAGE_CLASS:-STANDARD_IA}"
BACKUP_DIR="${BACKUP_DIR:-/tmp/aegis_backup}"
AWS_REGION="${AWS_REGION:-us-east-1}"

TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
DUMP_BASENAME="aegis_${PGDATABASE}_${TIMESTAMP}.pgdump"
DUMP_FILE="${BACKUP_DIR}/${DUMP_BASENAME}"
GZ_FILE="${DUMP_FILE}.gz"
S3_KEY="${S3_PREFIX}/${TIMESTAMP}/${DUMP_BASENAME}.gz"

log() { echo "[backup $(date -u +%H:%M:%SZ)] $*"; }

log "starting: db=${PGDATABASE} host=${PGHOST}:${PGPORT} ts=${TIMESTAMP}"

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

# pg_dump in custom (binary) format for selective / parallel restore support
log "running pg_dump"
pg_dump \
  --host="${PGHOST}" \
  --port="${PGPORT}" \
  --username="${PGUSER}" \
  --format=custom \
  --compress=0 \
  --no-password \
  --file="${DUMP_FILE}" \
  "${PGDATABASE}"

DUMP_BYTES=$(stat -c '%s' "${DUMP_FILE}" 2>/dev/null || stat -f '%z' "${DUMP_FILE}")
log "dump size: ${DUMP_BYTES} bytes; compressing"

gzip -9 "${DUMP_FILE}"

GZ_BYTES=$(stat -c '%s' "${GZ_FILE}" 2>/dev/null || stat -f '%z' "${GZ_FILE}")
log "compressed size: ${GZ_BYTES} bytes"

log "uploading → s3://${S3_BUCKET}/${S3_KEY}"
aws s3 cp \
  "${GZ_FILE}" \
  "s3://${S3_BUCKET}/${S3_KEY}" \
  --region "${AWS_REGION}" \
  --storage-class "${S3_STORAGE_CLASS}" \
  --sse aws:kms \
  --no-progress

log "verifying upload"
aws s3 ls "s3://${S3_BUCKET}/${S3_KEY}" --region "${AWS_REGION}" > /dev/null

log "removing local temp file"
rm -f "${GZ_FILE}"

log "done: s3://${S3_BUCKET}/${S3_KEY} (${GZ_BYTES} bytes)"
echo "BACKUP_S3_URI=s3://${S3_BUCKET}/${S3_KEY}"

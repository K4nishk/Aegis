#!/usr/bin/env bash
# ops/restore.sh — download pg_dump from S3 and restore to target DB (KCH-23 / SEC-7)
#
# Usage:
#   S3_BACKUP_URI=s3://bucket/prefix/ts/file.pgdump.gz \
#   TARGET_PGDATABASE=aegis_restored \
#   TARGET_PGUSER=aegis_app \
#   ./ops/restore.sh
#
# Required env vars:
#   S3_BACKUP_URI       — full s3:// URI of the .pgdump.gz backup file
#   TARGET_PGDATABASE   — target database name
#   TARGET_PGUSER       — target Postgres user
#
# Optional:
#   TARGET_PGHOST       — target host (default: localhost)
#   TARGET_PGPORT       — target port (default: 5432)
#   CREATE_DB           — set to 1 to createdb before restoring (default: 0)
#   RESTORE_DIR         — local temp dir (default: /tmp/aegis_restore)
#   AWS_REGION          — AWS region (default: us-east-1)
#
# Post-restore:
#   Run smoke-checks per docs/RUNBOOK.md §4 before switching traffic.

set -euo pipefail

S3_BACKUP_URI="${S3_BACKUP_URI:?S3_BACKUP_URI is required}"
TARGET_PGDATABASE="${TARGET_PGDATABASE:?TARGET_PGDATABASE is required}"
TARGET_PGUSER="${TARGET_PGUSER:?TARGET_PGUSER is required}"
TARGET_PGHOST="${TARGET_PGHOST:-localhost}"
TARGET_PGPORT="${TARGET_PGPORT:-5432}"
CREATE_DB="${CREATE_DB:-0}"
RESTORE_DIR="${RESTORE_DIR:-/tmp/aegis_restore}"
AWS_REGION="${AWS_REGION:-us-east-1}"

TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
FILENAME=$(basename "${S3_BACKUP_URI}")
LOCAL_GZ="${RESTORE_DIR}/${FILENAME}"
LOCAL_DUMP="${LOCAL_GZ%.gz}"

log() { echo "[restore $(date -u +%H:%M:%SZ)] $*"; }

log "ts=${TIMESTAMP}"
log "source: ${S3_BACKUP_URI}"
log "target: ${TARGET_PGUSER}@${TARGET_PGHOST}:${TARGET_PGPORT}/${TARGET_PGDATABASE}"

mkdir -p "${RESTORE_DIR}"
chmod 700 "${RESTORE_DIR}"

log "downloading dump from S3"
aws s3 cp "${S3_BACKUP_URI}" "${LOCAL_GZ}" \
  --region "${AWS_REGION}" \
  --no-progress

GZ_BYTES=$(stat -c '%s' "${LOCAL_GZ}" 2>/dev/null || stat -f '%z' "${LOCAL_GZ}")
log "downloaded: ${GZ_BYTES} bytes; decompressing"

gunzip -f "${LOCAL_GZ}"

DUMP_BYTES=$(stat -c '%s' "${LOCAL_DUMP}" 2>/dev/null || stat -f '%z' "${LOCAL_DUMP}")
log "decompressed: ${DUMP_BYTES} bytes"

if [[ "${CREATE_DB}" == "1" ]]; then
  log "creating database ${TARGET_PGDATABASE}"
  createdb \
    --host="${TARGET_PGHOST}" \
    --port="${TARGET_PGPORT}" \
    --username="${TARGET_PGUSER}" \
    "${TARGET_PGDATABASE}" \
    || log "database already exists, continuing"
fi

log "running pg_restore"
pg_restore \
  --host="${TARGET_PGHOST}" \
  --port="${TARGET_PGPORT}" \
  --username="${TARGET_PGUSER}" \
  --dbname="${TARGET_PGDATABASE}" \
  --no-owner \
  --no-privileges \
  --exit-on-error \
  --verbose \
  "${LOCAL_DUMP}"

log "cleaning up temp files"
rm -f "${LOCAL_DUMP}"

log "done: ${TARGET_PGDATABASE} restored from ${S3_BACKUP_URI}"
log "IMPORTANT: run smoke-checks per docs/RUNBOOK.md §4 before switching traffic"

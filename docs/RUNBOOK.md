# Aegis Backup & Recovery Runbook

**Ref:** ARD.md §6.1 SEC-7, ADR-4 · **Issue:** KCH-23

---

## 1. Backup architecture

```
EC2 host (02:00 UTC)
  └── ops/backup.sh
        ├── pg_dump --format=custom → /tmp/aegis_backup/*.pgdump
        ├── gzip -9
        └── aws s3 cp --sse aws:kms → s3://aegis-pg-backups-primary/<ts>/
                                            └── (CRR) → s3://aegis-pg-backups-replica/<ts>/
```

- **Versioning:** enabled on both buckets.
- **Encryption:** SSE-KMS with bucket-level key.
- **Cross-region replication:** primary (us-east-1) → replica (us-west-2).
- **Retention:** objects transition to STANDARD_IA after 30 days, expire after 90 days.
- **Scheduling:** systemd timer `aegis-backup.timer` fires at 02:00 UTC with up to 5-minute jitter.

---

## 2. Deploying the backup cron

```bash
# Copy scripts and units to the EC2 host
sudo cp ops/backup.sh  /opt/aegis/ops/backup.sh
sudo chmod 750         /opt/aegis/ops/backup.sh
sudo chown aegis:aegis /opt/aegis/ops/backup.sh

# Create /etc/aegis/backup.env (mode 0600, owned by aegis)
# Contents (adjust values):
#   PGDATABASE=aegis_prod
#   PGHOST=localhost
#   PGPORT=5432
#   PGUSER=aegis_app
#   S3_BUCKET=aegis-pg-backups-primary
#   AWS_REGION=us-east-1

sudo cp ops/aegis-backup.service /etc/systemd/system/
sudo cp ops/aegis-backup.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-backup.timer

# Verify next trigger
systemctl list-timers aegis-backup.timer
```

---

## 3. Initiating a restore

### 3a. List available backups

```bash
aws s3 ls s3://aegis-pg-backups-primary/aegis/backups/ --recursive \
  | sort | tail -20
```

### 3b. Restore to a scratch database (rehearsal / staging)

```bash
export S3_BACKUP_URI=s3://aegis-pg-backups-primary/aegis/backups/<ts>/aegis_<db>_<ts>.pgdump.gz
export TARGET_PGDATABASE=aegis_restore_<ts>
export TARGET_PGUSER=ishq_kan       # use a superuser for scratch restores
export CREATE_DB=1
bash ops/restore.sh
```

### 3c. Restore to production (disaster recovery)

> WARNING: restoring to production overwrites live data. Follow the promotion
> steps in §5 (rollback) before switching traffic.

```bash
# 1. Put application into maintenance mode (update load balancer / DNS)
# 2. Restore to a new database
export S3_BACKUP_URI=s3://aegis-pg-backups-primary/aegis/backups/<latest-ts>/...
export TARGET_PGDATABASE=aegis_prod_recovered
export TARGET_PGUSER=aegis_app
export CREATE_DB=1
bash ops/restore.sh

# 3. Run smoke-checks (§4)
# 4. Swap DATABASE_URL to point at the recovered DB
# 5. Restart the API containers
```

---

## 4. Smoke-checks after restore

Run all of the following before promoting a restored DB:

```sql
-- Row counts must be non-zero
SELECT COUNT(*) FROM scan_runs;
SELECT COUNT(*) FROM tool_graph_nodes;

-- Confirm most recent scan_run timestamp is within expected range
SELECT MAX(created_at) FROM scan_runs;

-- Confirm no RLS bypass (should return 0 unless superuser)
SET ROLE aegis_app;
SET app.user_id = '00000000-0000-0000-0000-000000000000';
SELECT COUNT(*) FROM scan_runs;  -- expect 0 rows (different owner_id)
RESET ROLE;
```

```bash
# API health-check (set DATABASE_URL to the restored DB)
DATABASE_URL=postgresql://aegis_app@localhost:5432/aegis_prod_recovered \
  python3 -c "from api.app import create_app; app = create_app(); print('ok')"
```

---

## 5. Deploy rollback (docker-compose)

```bash
# List available image tags
docker images aegis-api --format '{{.Tag}}' | sort -r | head -10

# Roll back to the previous tag
PREVIOUS_TAG=<tag>
docker-compose down
IMAGE_TAG=${PREVIOUS_TAG} docker-compose up -d

# Verify
docker-compose ps
docker-compose logs api | tail -30
```

---

## 6. RDS PITR (production design target)

When Aegis migrates to RDS, point-in-time recovery (PITR) replaces `pg_dump`:

```hcl
# terraform
resource "aws_db_instance" "aegis" {
  backup_retention_period   = 7          # days of PITR
  backup_window             = "02:00-03:00"
  delete_automated_backups  = false
  copy_tags_to_snapshot     = true
}
```

Restore: AWS Console → RDS → Restore to point in time → choose timestamp.

---

## 7. Rehearsal schedule

The restore rehearsal test (`tests/ops/test_backup_rehearsal.py`) must pass before
every production deployment. The last rehearsal receipt is written to
`ops/rehearsal_receipt.txt` — check it into git when running the rehearsal manually.

Rehearsal cadence: **monthly minimum**, or after any Postgres major version upgrade.

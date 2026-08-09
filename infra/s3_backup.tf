# infra/s3_backup.tf — Aegis offsite S3 backup bucket (KCH-23 / SEC-7)
#
# Requires AWS credentials (not verifiable locally — apply from CI or admin shell).
# terraform apply -var="primary_region=us-east-1" -var="replica_region=us-west-2"

variable "primary_region" {
  description = "AWS region for the primary backup bucket"
  default     = "us-east-1"
}

variable "replica_region" {
  description = "AWS region for the cross-region replica bucket"
  default     = "us-west-2"
}

variable "bucket_name_prefix" {
  description = "Prefix for both bucket names; append -primary / -replica"
  default     = "aegis-pg-backups"
}

# ---------------------------------------------------------------------------
# Primary bucket (source of truth for nightly dumps)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "backup_primary" {
  provider = aws.primary
  bucket   = "${var.bucket_name_prefix}-primary"

  tags = {
    Project = "Aegis"
    Purpose = "nightly-pg-backup"
    Tier    = "primary"
  }
}

resource "aws_s3_bucket_versioning" "backup_primary" {
  provider = aws.primary
  bucket   = aws_s3_bucket.backup_primary.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backup_primary" {
  provider = aws.primary
  bucket   = aws_s3_bucket.backup_primary.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "backup_primary" {
  provider                = aws.primary
  bucket                  = aws_s3_bucket.backup_primary.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "backup_primary" {
  provider = aws.primary
  bucket   = aws_s3_bucket.backup_primary.id

  rule {
    id     = "transition-and-expire"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# ---------------------------------------------------------------------------
# Replica bucket (cross-region — offsite)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "backup_replica" {
  provider = aws.replica
  bucket   = "${var.bucket_name_prefix}-replica"

  tags = {
    Project = "Aegis"
    Purpose = "nightly-pg-backup"
    Tier    = "replica"
  }
}

resource "aws_s3_bucket_versioning" "backup_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.backup_replica.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backup_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.backup_replica.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "backup_replica" {
  provider                = aws.replica
  bucket                  = aws_s3_bucket.backup_replica.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# Replication: primary → replica (cross-region)
# ---------------------------------------------------------------------------
resource "aws_iam_role" "replication" {
  provider = aws.primary
  name     = "aegis-s3-backup-replication"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "replication" {
  provider = aws.primary
  role     = aws_iam_role.replication.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
        Resource = aws_s3_bucket.backup_primary.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"]
        Resource = "${aws_s3_bucket.backup_primary.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
        Resource = "${aws_s3_bucket.backup_replica.arn}/*"
      }
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "primary_to_replica" {
  provider   = aws.primary
  depends_on = [aws_s3_bucket_versioning.backup_primary]

  bucket = aws_s3_bucket.backup_primary.id
  role   = aws_iam_role.replication.arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.backup_replica.arn
      storage_class = "STANDARD_IA"
    }
  }
}

# ---------------------------------------------------------------------------
# Provider aliases
# ---------------------------------------------------------------------------
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  alias  = "primary"
  region = var.primary_region
}

provider "aws" {
  alias  = "replica"
  region = var.replica_region
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "primary_bucket_name" {
  value = aws_s3_bucket.backup_primary.id
}

output "replica_bucket_name" {
  value = aws_s3_bucket.backup_replica.id
}

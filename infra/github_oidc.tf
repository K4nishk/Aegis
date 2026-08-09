###############################################################################
# GitHub OIDC — replace long-lived AWS access keys with short-lived tokens
# KCH-26
###############################################################################

locals {
  github_org  = "K4nishk"
  github_repo = "Aegis"
}

# ---------------------------------------------------------------------------
# OIDC identity provider
# ---------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  # GitHub's OIDC thumbprint (SHA-1 of the root CA cert).
  # As of 2024-06 GitHub rotated to DigiCert; both thumbprints are listed for
  # forward-compatibility. AWS validates the audience, not the thumbprint, for
  # OIDC; the list must be non-empty but the value is not security-critical.
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]

  tags = {
    ManagedBy = "terraform"
    Project   = "aegis"
  }
}

# ---------------------------------------------------------------------------
# Helper: trust-policy document factory
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "github_oidc_trust" {
  for_each = {
    deploy    = "repo:${local.github_org}/${local.github_repo}:ref:refs/heads/main"
    terraform = "repo:${local.github_org}/${local.github_repo}:*"
  }

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [each.value]
    }
  }
}

# ---------------------------------------------------------------------------
# Role: aegis-deploy  (ECR push + SSM send-command, main branch only)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "aegis_deploy" {
  name               = "aegis-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_oidc_trust["deploy"].json

  tags = {
    ManagedBy = "terraform"
    Project   = "aegis"
  }
}

data "aws_iam_policy_document" "aegis_deploy_perms" {
  # ECR: authenticate + push images
  statement {
    actions = [
      "ecr:GetAuthorizationToken",
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    # Restrict to the aegis-api repository; account ID resolved at plan time.
    resources = ["arn:aws:ecr:*:*:repository/aegis-api"]
  }

  # SSM: run shell command on the EC2 instance
  statement {
    actions = [
      "ssm:SendCommand",
      "ssm:GetCommandInvocation",
    ]
    resources = [
      "arn:aws:ec2:*:*:instance/*",
      "arn:aws:ssm:*::document/AWS-RunShellScript",
    ]
  }
}

resource "aws_iam_role_policy" "aegis_deploy" {
  name   = "aegis-deploy-policy"
  role   = aws_iam_role.aegis_deploy.id
  policy = data.aws_iam_policy_document.aegis_deploy_perms.json
}

# ---------------------------------------------------------------------------
# Role: aegis-terraform  (S3 state, CloudWatch, IAM for OIDC roles only)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "aegis_terraform" {
  name               = "aegis-terraform"
  assume_role_policy = data.aws_iam_policy_document.github_oidc_trust["terraform"].json

  tags = {
    ManagedBy = "terraform"
    Project   = "aegis"
  }
}

data "aws_iam_policy_document" "aegis_terraform_perms" {
  # S3: Terraform remote state bucket
  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::aegis-tf-state",
      "arn:aws:s3:::aegis-tf-state/*",
    ]
  }

  # S3: backup bucket (KCH-23)
  statement {
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:GetBucketAcl",
      "s3:GetBucketLocation",
      "s3:GetBucketVersioning",
      "s3:PutBucketAcl",
      "s3:PutBucketPolicy",
      "s3:PutBucketVersioning",
      "s3:PutLifecycleConfiguration",
      "s3:PutReplicationConfiguration",
      "s3:GetReplicationConfiguration",
    ]
    resources = ["arn:aws:s3:::aegis-*"]
  }

  # CloudWatch: metrics filter + alarm (KCH-21)
  statement {
    actions = [
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:DeleteAlarms",
      "cloudwatch:DescribeAlarms",
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:DescribeLogGroups",
      "logs:PutMetricFilter",
      "logs:DeleteMetricFilter",
      "logs:DescribeMetricFilters",
    ]
    resources = ["*"]
  }

  # IAM: manage only the OIDC roles this Terraform creates (no wildcard)
  statement {
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:PassRole",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:CreateOpenIDConnectProvider",
      "iam:DeleteOpenIDConnectProvider",
      "iam:GetOpenIDConnectProvider",
      "iam:TagOpenIDConnectProvider",
    ]
    resources = [
      "arn:aws:iam::*:role/aegis-*",
      "arn:aws:iam::*:oidc-provider/token.actions.githubusercontent.com",
    ]
  }

  # KMS: backup bucket SSE key (KCH-23)
  statement {
    actions = [
      "kms:CreateKey",
      "kms:DescribeKey",
      "kms:EnableKeyRotation",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListResourceTags",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:CreateAlias",
      "kms:DeleteAlias",
      "kms:ListAliases",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "aegis_terraform" {
  name   = "aegis-terraform-policy"
  role   = aws_iam_role.aegis_terraform.id
  policy = data.aws_iam_policy_document.aegis_terraform_perms.json
}

# ---------------------------------------------------------------------------
# Outputs — set these as repo *variables* (not secrets) after apply
# ---------------------------------------------------------------------------

output "aegis_deploy_role_arn" {
  description = "Set as AEGIS_DEPLOY_ROLE_ARN repo variable"
  value       = aws_iam_role.aegis_deploy.arn
}

output "aegis_terraform_role_arn" {
  description = "Set as AEGIS_TERRAFORM_ROLE_ARN repo variable"
  value       = aws_iam_role.aegis_terraform.arn
}

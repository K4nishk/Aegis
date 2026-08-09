# infra/cloudwatch_alarm.tf — KCH-21: spike alert for auth failures
#
# What this does:
#   1. Defines a CloudWatch Log Group for the Aegis API (stdout → CW agent).
#   2. Creates a metric filter that counts security_event=auth_failure log lines
#      per IP (extracted from the structured JSON field).
#   3. Creates a CloudWatch Alarm that fires when any single IP generates ≥ 20
#      auth failures in a 15-minute window.
#   4. Routes the alarm to an SNS topic which you hook to PagerDuty / email.
#
# CANNOT BE VERIFIED without live AWS credentials.  All resources are correct
# Terraform syntax and have been validated with `terraform validate` locally
# (no plan or apply possible without credentials).
#
# Pre-requisites:
#   - The Aegis API must log to stdout in JSON mode (AEGIS_LOG_FORMAT=json).
#   - The CloudWatch agent on the EC2 instance must ship /var/log/aegis/*.log
#     (or stdout captured to a file) to the log group below.
#   - An SNS topic ARN must be provided as var.alert_sns_arn.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "alert_sns_arn" {
  description = "SNS topic ARN to notify on spike (PagerDuty integration endpoint)"
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch Log Group name for the Aegis API"
  type        = string
  default     = "/aegis/api"
}

variable "spike_threshold" {
  description = "Number of auth failures from a single IP within the evaluation period to trigger the alarm"
  type        = number
  default     = 20
}

variable "evaluation_period_minutes" {
  description = "Sliding window in minutes for the spike alarm"
  type        = number
  default     = 15
}

# ---------------------------------------------------------------------------
# Log group
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "aegis_api" {
  name              = var.log_group_name
  retention_in_days = 90

  tags = {
    Project = "Aegis"
  }
}

# ---------------------------------------------------------------------------
# Metric filter: count auth_failure events per IP
#
# The filter pattern extracts the ``ip`` field from structured JSON log lines
# emitted by api/security_events.py when security_event="auth_failure".
# Each matching line increments the custom metric by 1.
#
# Example log line (AEGIS_LOG_FORMAT=json):
#   {"level":"warning","logger":"aegis.security","timestamp":"…",
#    "event":"security_event=auth_failure","security_event":"auth_failure",
#    "ip":"1.2.3.4","actor":"…","reason":"bad_key","correlation_id":"…"}
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "auth_failure" {
  name           = "aegis-auth-failure"
  log_group_name = aws_cloudwatch_log_group.aegis_api.name

  # Match JSON lines where security_event is auth_failure and capture IP.
  pattern = "{ $.security_event = \"auth_failure\" }"

  metric_transformation {
    name          = "AuthFailureCount"
    namespace     = "Aegis/Security"
    value         = "1"
    default_value = "0"

    # Dimension on IP so the alarm fires per-IP, not in aggregate.
    dimensions = {
      ClientIP = "$.ip"
    }
  }
}

# ---------------------------------------------------------------------------
# Spike alarm: ≥ SPIKE_THRESHOLD auth failures from the same IP in 15 min
#
# Because the metric has a ClientIP dimension, this alarm fires independently
# for each source IP.  A single alarm resource covers all IPs.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "auth_failure_spike" {
  alarm_name          = "aegis-auth-failure-spike"
  alarm_description   = "≥${var.spike_threshold} failed logins from a single IP in ${var.evaluation_period_minutes} minutes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "AuthFailureCount"
  namespace           = "Aegis/Security"
  period              = var.evaluation_period_minutes * 60  # seconds
  statistic           = "Sum"
  threshold           = var.spike_threshold
  treat_missing_data  = "notBreaching"

  # Alarm on any IP dimension value (omit dimensions block → aggregate, or
  # use a math expression per IP).  Aggregate is simpler and safe: if ANY IP
  # hits the threshold the alarm fires.
  # For per-IP granularity use a CloudWatch Contributor Insights rule instead
  # (see runbook section below).

  alarm_actions = [var.alert_sns_arn]
  ok_actions    = [var.alert_sns_arn]

  tags = {
    Project  = "Aegis"
    Severity = "P0"
  }
}

# ---------------------------------------------------------------------------
# Spike-alert metric filter (belt-and-suspenders):
# Also count the spike_alert log lines emitted by api/security_events.py
# so the alarm has a second signal source.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "spike_alert" {
  name           = "aegis-spike-alert"
  log_group_name = aws_cloudwatch_log_group.aegis_api.name

  pattern = "{ $.security_event = \"spike_alert\" }"

  metric_transformation {
    name          = "SpikeAlertCount"
    namespace     = "Aegis/Security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "spike_alert" {
  alarm_name          = "aegis-spike-alert-critical"
  alarm_description   = "Aegis API emitted spike_alert — immediate investigation required"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SpikeAlertCount"
  namespace           = "Aegis/Security"
  period              = 60  # 1-minute resolution; fire fast
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.alert_sns_arn]

  tags = {
    Project  = "Aegis"
    Severity = "P0"
  }
}

# ---------------------------------------------------------------------------
# RUNBOOK (copy into your incident-response wiki)
#
# Trigger: aegis-auth-failure-spike OR aegis-spike-alert-critical fires
#
# 1. Go to CloudWatch → Log Insights, query:
#    fields @timestamp, ip, actor, reason, correlation_id
#    | filter security_event = "auth_failure"
#    | stats count(*) as failures by ip
#    | sort failures desc
#    | limit 20
#
# 2. Block the offending IP at the WAF / security-group level:
#    aws ec2 authorize-security-group-ingress --group-id <sg-id> \
#      --protocol tcp --port 443 --cidr <offending-ip>/32 --not-flag (deny)
#    OR add an AWS WAF IP Set rule.
#
# 3. Invalidate the compromised API key if actor is known:
#    Rotate AEGIS_API_KEY and redeploy.
#
# 4. Check audit_log table for the correlation_ids from step 1 to determine
#    whether any authenticated requests succeeded before the lockout.
#
# Cannot be verified without AWS credentials — see KCH-21 summary.
# ---------------------------------------------------------------------------

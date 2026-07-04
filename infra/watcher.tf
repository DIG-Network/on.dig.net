# Chain-change watcher (#33): a 1-minute EventBridge-scheduled Lambda that detects when a served
# store's on-chain singleton lineage advances and invalidates the resolver's two DYNAMIC CloudFront
# paths (`/` + `/__dig/config.json`) the moment a change is seen, instead of waiting out their
# passive max-age (300s / 30s, see cloudfront.tf). See src/watcher.rs module docs + SPEC.md §10 for
# the full design (why a coin-lineage tip rather than a decoded root, why this never writes
# `pinned_root`, why a single-subdomain-scoped invalidation isn't achievable on this distribution).
#
# READ-ONLY on the shared `dighub` table (Scan, like the resolver's GetItem — never a write). ALL
# state this service itself needs to remember (the last-known tip per store) lives in its OWN
# dedicated table below, never the shared one.

# This service's OWN last-known-tip ledger. Tiny: one item per distinct store id backing an
# active domain. PAY_PER_REQUEST — negligible at this scale (pre-release, §3.7).
resource "aws_dynamodb_table" "watcher_state" {
  name         = "on-dig-net-watcher-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "store_id"

  attribute {
    name = "store_id"
    type = "S"
  }
}

data "aws_iam_policy_document" "watcher_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "watcher" {
  name               = "on-dig-net-watcher-role"
  assume_role_policy = data.aws_iam_policy_document.watcher_assume.json
}

resource "aws_iam_role_policy_attachment" "watcher_basic" {
  role       = aws_iam_role.watcher.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Least-privilege: read-only Scan on the shared table (never Get/Put/Update/Delete — this service
# never writes a domain row), full read/write on its OWN state table, and CreateInvalidation scoped
# to exactly the resolver distribution (never wildcarded to every distribution in the account).
data "aws_iam_policy_document" "watcher" {
  statement {
    sid       = "ScanSharedDighubTableReadOnly"
    actions   = ["dynamodb:Scan"]
    resources = [data.aws_dynamodb_table.dighub.arn]
  }
  statement {
    sid       = "DecryptSharedTableCmk"
    actions   = ["kms:Decrypt"]
    resources = [var.table_kms_key_arn]
  }
  statement {
    sid       = "OwnStateTableReadWrite"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [aws_dynamodb_table.watcher_state.arn]
  }
  statement {
    sid       = "InvalidateResolverDistributionOnly"
    actions   = ["cloudfront:CreateInvalidation"]
    resources = ["arn:aws:cloudfront::${local.acct}:distribution/${aws_cloudfront_distribution.resolver.id}"]
  }
}

resource "aws_iam_role_policy" "watcher" {
  name   = "on-dig-net-watcher-scoped"
  role   = aws_iam_role.watcher.id
  policy = data.aws_iam_policy_document.watcher.json
}

resource "aws_cloudwatch_log_group" "watcher" {
  name              = "/aws/lambda/on-dig-net-watcher"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "watcher" {
  function_name = "on-dig-net-watcher"
  role          = aws_iam_role.watcher.arn
  package_type  = "Zip"
  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 60 # a lineage walk is a handful of small HTTP calls per tracked store

  filename         = var.watcher_lambda_package_path
  source_code_hash = var.watcher_lambda_source_code_hash

  environment {
    variables = {
      DIGHUB_TABLE        = var.dighub_table_name
      WATCHER_STATE_TABLE = aws_dynamodb_table.watcher_state.name
      DISTRIBUTION_ID     = aws_cloudfront_distribution.resolver.id
      LOG_LEVEL           = "info"
    }
  }

  depends_on = [aws_cloudwatch_log_group.watcher]
}

# 1-minute tick — matches hub.dig.net's own anchor-watcher cadence for the identical class of
# problem (a lightweight, cheap, scheduled chain-state check).
data "aws_iam_policy_document" "watcher_scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "watcher_scheduler" {
  name               = "on-dig-net-watcher-scheduler-role"
  assume_role_policy = data.aws_iam_policy_document.watcher_scheduler_assume.json
}

data "aws_iam_policy_document" "watcher_scheduler_invoke" {
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.watcher.arn]
  }
}

resource "aws_iam_role_policy" "watcher_scheduler_invoke" {
  name   = "invoke-watcher"
  role   = aws_iam_role.watcher_scheduler.id
  policy = data.aws_iam_policy_document.watcher_scheduler_invoke.json
}

resource "aws_scheduler_schedule" "watcher" {
  name = "on-dig-net-watcher"
  flexible_time_window {
    mode = "OFF"
  }
  schedule_expression = "rate(1 minute)"

  target {
    arn      = aws_lambda_function.watcher.arn
    role_arn = aws_iam_role.watcher_scheduler.arn
  }
}

# GitHub Actions OIDC deploy role for this repo's CI (deploy.yml). Reuses the account's EXISTING
# GitHub OIDC provider (only one per URL per account — created by the hub bootstrap). The role is
# assumable ONLY from this repo's `production` environment (the gated apply) or its main branch (the
# build-artifacts job), never arbitrary PR refs. No long-lived keys.

data "aws_caller_identity" "current" {}

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

locals {
  acct = data.aws_caller_identity.current.account_id
}

data "aws_iam_policy_document" "trust_deploy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_repo}:environment:${var.deploy_environment}",
        "repo:${var.github_repo}:ref:refs/heads/main",
      ]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name               = "on-dig-net-ci-deploy"
  assume_role_policy = data.aws_iam_policy_document.trust_deploy.json
}

# Scoped-write policy: exactly the services this stack manages. CloudFront + API Gateway actions
# cannot be resource-scoped (no resource-level ARNs for most actions), so they are granted on "*";
# everything else is scoped to this service's own resources.
data "aws_iam_policy_document" "deploy" {
  statement {
    sid       = "TerraformStateBucket"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.state_bucket}", "arn:aws:s3:::${var.state_bucket}/on.dig.net/*"]
  }
  statement {
    sid       = "TerraformStateKms"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.state_kms_key_arn]
  }
  statement {
    sid       = "TerraformStateLock"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
    resources = ["arn:aws:dynamodb:${var.region}:${local.acct}:table/${var.lock_table}"]
  }
  statement {
    # The aws_dynamodb_table data source reads the table + its continuous-backups, TTL, and tags.
    sid = "ReadSharedTable"
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:DescribeContinuousBackups",
      "dynamodb:DescribeTimeToLive",
      "dynamodb:ListTagsOfResource",
    ]
    resources = ["arn:aws:dynamodb:${var.region}:${local.acct}:table/${var.dighub_table_name}"]
  }
  statement {
    sid = "AssetBucket"
    actions = [
      "s3:CreateBucket", "s3:PutBucketPolicy", "s3:GetBucketPolicy", "s3:DeleteBucketPolicy",
      "s3:PutEncryptionConfiguration", "s3:GetEncryptionConfiguration",
      "s3:PutBucketVersioning", "s3:GetBucketVersioning",
      "s3:PutBucketPublicAccessBlock", "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketOwnershipControls", "s3:GetBucketOwnershipControls",
      "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketLogging", "s3:GetBucketTagging",
      "s3:GetBucketWebsite", "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration",
      "s3:GetAccelerateConfiguration", "s3:GetBucketRequestPayment", "s3:GetBucketObjectLockConfiguration",
      "s3:GetBucketLocation", "s3:ListBucket",
      "s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:GetObjectTagging", "s3:PutObjectTagging"
    ]
    resources = ["arn:aws:s3:::${var.asset_bucket_name}", "arn:aws:s3:::${var.asset_bucket_name}/*"]
  }
  statement {
    sid     = "Lambda"
    actions = ["lambda:*"]
    resources = [
      "arn:aws:lambda:${var.region}:${local.acct}:function:on-dig-net-resolver",
      "arn:aws:lambda:${var.region}:${local.acct}:function:on-dig-net-watcher",
    ]
  }
  statement {
    # The chain-change watcher's OWN state table (#33, watcher.tf) — a dedicated resource this
    # service owns and manages, distinct from the shared (hub-owned, read-only) dighub table.
    sid = "WatcherStateTable"
    actions = [
      "dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:DescribeTable",
      "dynamodb:UpdateTable", "dynamodb:TagResource", "dynamodb:UntagResource",
      "dynamodb:ListTagsOfResource", "dynamodb:DescribeContinuousBackups",
      "dynamodb:DescribeTimeToLive", "dynamodb:UpdateContinuousBackups",
    ]
    resources = ["arn:aws:dynamodb:${var.region}:${local.acct}:table/on-dig-net-watcher-state"]
  }
  statement {
    # EventBridge Scheduler driving the watcher's 1-minute tick (#33, watcher.tf).
    sid = "WatcherSchedule"
    actions = [
      "scheduler:CreateSchedule", "scheduler:GetSchedule", "scheduler:UpdateSchedule",
      "scheduler:DeleteSchedule", "scheduler:TagResource", "scheduler:UntagResource",
      "scheduler:ListTagsForResource",
    ]
    resources = ["arn:aws:scheduler:${var.region}:${local.acct}:schedule/default/on-dig-net-watcher"]
  }
  statement {
    sid = "IamForServiceRoles"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:TagRole", "iam:UntagRole",
      "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy", "iam:ListRolePolicies",
      "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:ListAttachedRolePolicies",
      "iam:UpdateAssumeRolePolicy", "iam:ListInstanceProfilesForRole",
    ]
    resources = ["arn:aws:iam::${local.acct}:role/on-dig-net-*"]
  }
  statement {
    sid       = "IamPassRoleToLambda"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.acct}:role/on-dig-net-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }
  statement {
    sid       = "ReadOidcProvider"
    actions   = ["iam:GetOpenIDConnectProvider"]
    resources = [data.aws_iam_openid_connect_provider.github.arn]
  }
  statement {
    # The aws_iam_openid_connect_provider data source resolves the provider BY URL, which lists all
    # providers first (a list op with no resource-level scoping).
    sid       = "ListOidcProviders"
    actions   = ["iam:ListOpenIDConnectProviders"]
    resources = ["*"]
  }
  statement {
    # DescribeLogGroups is a prefix-list op that AWS evaluates against `log-group::log-stream:`, so it
    # cannot be scoped to a specific group ARN. It is a read-only list; the WRITE log actions above
    # stay scoped to this service's groups.
    sid       = "LogsDescribe"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }
  statement {
    # CloudFront + API Gateway have no resource-level ARNs for most create/get actions.
    sid       = "EdgeAndApi"
    actions   = ["cloudfront:*", "apigateway:GET", "apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE"]
    resources = ["*"]
  }
  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:DescribeLogGroups",
      "logs:PutRetentionPolicy", "logs:TagResource", "logs:UntagResource",
      "logs:ListTagsForResource", "logs:TagLogGroup", "logs:ListTagsLogGroup",
    ]
    resources = [
      "arn:aws:logs:${var.region}:${local.acct}:log-group:/aws/lambda/on-dig-net-resolver*",
      "arn:aws:logs:${var.region}:${local.acct}:log-group:/aws/apigw/on-dig-net-resolver*",
      "arn:aws:logs:${var.region}:${local.acct}:log-group:/aws/lambda/on-dig-net-watcher*",
    ]
  }
  statement {
    sid       = "Route53"
    actions   = ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets", "route53:GetHostedZone"]
    resources = ["arn:aws:route53:::hostedzone/${var.zone_id}"]
  }
  statement {
    sid       = "Route53Change"
    actions   = ["route53:GetChange"]
    resources = ["arn:aws:route53:::change/*"]
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "deploy"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}

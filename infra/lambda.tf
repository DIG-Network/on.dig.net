# The resolver Lambda: a Rust custom-runtime (provided.al2023, arm64) zip built by cargo-lambda.
# It looks up a *.on.dig.net subdomain (or an attached custom host) in the SHARED dighub DynamoDB
# table and serves the branded loader shell / status config. READ-ONLY on the table.

data "aws_dynamodb_table" "dighub" {
  name = var.dighub_table_name
}

# Least-privilege: exactly GetItem on the shared table (+ its GSIs, for the same ARN shape the hub
# resolver role carried) and kms:Decrypt on the table's CMK so SSE-KMS rows can be read.
data "aws_iam_policy_document" "resolver" {
  statement {
    sid       = "ReadDighubTable"
    actions   = ["dynamodb:GetItem"]
    resources = [data.aws_dynamodb_table.dighub.arn, "${data.aws_dynamodb_table.dighub.arn}/index/*"]
  }
  statement {
    sid       = "DecryptTableCmk"
    actions   = ["kms:Decrypt"]
    resources = [var.table_kms_key_arn]
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "resolver" {
  name               = "on-dig-net-resolver-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "basic" {
  role       = aws_iam_role.resolver.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "resolver" {
  name   = "on-dig-net-resolver-scoped"
  role   = aws_iam_role.resolver.id
  policy = data.aws_iam_policy_document.resolver.json
}

resource "aws_cloudwatch_log_group" "resolver" {
  name              = "/aws/lambda/on-dig-net-resolver"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "resolver" {
  function_name = "on-dig-net-resolver"
  role          = aws_iam_role.resolver.arn
  package_type  = "Zip"
  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 15

  filename         = var.lambda_package_path
  source_code_hash = var.lambda_source_code_hash

  environment {
    variables = {
      # The ONLY env the resolver reads (bootstrap.rs). Points at the shared table.
      DIGHUB_TABLE = var.dighub_table_name
      LOG_LEVEL    = "warn"
    }
  }

  depends_on = [aws_cloudwatch_log_group.resolver]
}

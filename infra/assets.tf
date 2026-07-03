# This service's OWN dedicated S3 asset bucket for the static loader assets served straight from the
# nearest CloudFront PoP (ZERO Lambda on the /__dig/*, /__dig_sw.js, /dig-client/* paths).
#
# CRITICAL (the outage this split eliminates): these assets must live in a bucket OWNED by this
# service — NEVER the shared hub web bucket. Sharing that bucket meant hub's `deploy-web`
# `s3 sync --delete` wiped the resolver's assets. A dedicated bucket ends that coupling.

resource "aws_s3_bucket" "assets" {
  bucket = var.asset_bucket_name
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "assets" {
  bucket = aws_s3_bucket.assets.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "assets" {
  bucket = aws_s3_bucket.assets.id
  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3 (AES256): the loader assets are PUBLIC content (served to any visitor), so no CMK is needed
# and a KMS grant on the CloudFront OAC principal is avoided.
resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Only THIS distribution may read the bucket, via OAC (SigV4).
data "aws_iam_policy_document" "assets_oac" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.assets.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.resolver.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "assets" {
  bucket = aws_s3_bucket.assets.id
  policy = data.aws_iam_policy_document.assets_oac.json
}

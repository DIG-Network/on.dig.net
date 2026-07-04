variable "region" {
  description = "AWS region. Single-region us-east-1 (CloudFront cert + the shared dighub table live there)."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (all point at Chia mainnet / the live dighub table)."
  type        = string
  default     = "prod"
}

variable "resolver_wildcard" {
  description = "The wildcard host this service resolves. Attached to the CloudFront distribution ONLY when var.attach_wildcard_alias is true (see the zero-downtime cutover in runbooks/deploy.md)."
  type        = string
  default     = "*.on.dig.net"
}

variable "rpc_host" {
  description = "The DIG content-read RPC host the loader's service worker fetches ciphertext from (baked into the loader CSP + the response-headers CSP)."
  type        = string
  default     = "rpc.dig.net"
}

variable "app_host" {
  description = "The hub app host allowlisted in the CONTENT-sandbox CSP baseline for the sanctioned first-party tip widget (kept byte-identical to the hub resolver policy this service was split from)."
  type        = string
  default     = "hub.dig.net"
}

variable "certificate_arn" {
  description = "ACM cert (us-east-1) covering *.on.dig.net. Defaults to the existing shared *.on.dig.net cert (a cert may back multiple distributions)."
  type        = string
  default     = "arn:aws:acm:us-east-1:873139760123:certificate/3966954e-faab-4c81-86cf-adf91dccb93f"
}

variable "zone_id" {
  description = "Route53 hosted zone id for dig.net."
  type        = string
  default     = "Z09143862Q3QQA5P9F8QY"
}

variable "dighub_table_name" {
  description = "Name of the SHARED DynamoDB table the hub control plane writes domain registrations to; this resolver only reads it (GetItem)."
  type        = string
  default     = "dighub"
}

variable "table_kms_key_arn" {
  description = "The CMK that encrypts the shared dighub table (SSE-KMS). The resolver Lambda role needs kms:Decrypt on it to read rows via GetItem. Distinct from the state-bucket key."
  type        = string
  default     = "arn:aws:kms:us-east-1:873139760123:key/d56a99ab-4a0c-4ea0-9f2d-c15750b488ea"
}

variable "price_class" {
  description = "CloudFront price class. PriceClass_All — the visitor path is heavily edge-cache-driven, so global PoP reach is the widest-effect latency win (matches the distribution this was split from)."
  type        = string
  default     = "PriceClass_All"
}

variable "asset_bucket_name" {
  description = "This service's OWN dedicated S3 asset bucket for the static loader assets (/__dig/*, /__dig_sw.js, /dig-client/*). MUST NOT be the shared hub web bucket — that coupling was the outage this split eliminates."
  type        = string
  default     = "on-dig-net-assets"
}

variable "attach_wildcard_alias" {
  description = "Whether to attach *.on.dig.net to THIS distribution + publish the Route53 wildcard A/AAAA alias to it. Now TRUE: the zero-downtime cutover completed (the alias was moved here via `aws cloudfront update-domain-association` and the Route53 A/AAAA aliases point at this distribution). It was false only for the very first apply, while the alias still lived on the old hub distribution (avoiding a CNAMEAlreadyExists conflict). Keep it true — flipping it back to false would DETACH the live production alias and cause an outage."
  type        = bool
  default     = true
}

variable "github_repo" {
  description = "owner/repo permitted to assume the CI deploy role via GitHub OIDC."
  type        = string
  default     = "DIG-Network/on.dig.net"
}

variable "deploy_environment" {
  description = "GitHub Actions environment that may assume the apply role."
  type        = string
  default     = "production"
}

variable "state_bucket" {
  description = "Terraform remote-state bucket (granted to the CI deploy role for state access)."
  type        = string
  default     = "dighub-tfstate"
}

variable "state_kms_key_arn" {
  description = "KMS key encrypting the remote-state bucket (granted to the CI deploy role)."
  type        = string
  default     = "arn:aws:kms:us-east-1:873139760123:key/8a67b736-b5a7-4195-bf7d-e16ed34de90e"
}

variable "lock_table" {
  description = "Terraform state-lock DynamoDB table."
  type        = string
  default     = "dighub-tflock"
}

variable "log_retention_days" {
  description = "CloudWatch log retention for the Lambda + APIGW access logs."
  type        = number
  default     = 30
}

# CI computes the cargo-lambda zip path and its base64 sha256 and passes them in (`-var`).
# Empty defaults keep `terraform validate`/`plan` clean without a built artifact.
variable "lambda_package_path" {
  description = "Path to the built cargo-lambda bootstrap.zip."
  type        = string
  default     = ""
}

variable "lambda_source_code_hash" {
  description = "Base64 sha256 of the zip (computed in CI)."
  type        = string
  default     = ""
}

# Same pattern as lambda_package_path/lambda_source_code_hash, for the chain-change watcher
# Lambda (#33, `watcher.tf`) built from the same crate's `watcher` binary target.
variable "watcher_lambda_package_path" {
  description = "Path to the built cargo-lambda watcher bootstrap.zip."
  type        = string
  default     = ""
}

variable "watcher_lambda_source_code_hash" {
  description = "Base64 sha256 of the watcher zip (computed in CI)."
  type        = string
  default     = ""
}

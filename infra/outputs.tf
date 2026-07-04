output "distribution_id" {
  description = "CloudFront distribution id for the resolver."
  value       = aws_cloudfront_distribution.resolver.id
}

output "distribution_domain" {
  description = "The distribution's *.cloudfront.net domain (used to test pre-cutover with a Host header, and as the Route53 alias target)."
  value       = aws_cloudfront_distribution.resolver.domain_name
}

output "asset_bucket" {
  description = "This service's dedicated S3 asset bucket."
  value       = aws_s3_bucket.assets.id
}

output "resolver_origin_domain" {
  description = "The API Gateway execute-api host fronting the resolver Lambda."
  value       = local.resolver_origin_domain
}

output "lambda_function_name" {
  value = aws_lambda_function.resolver.function_name
}

output "watcher_function_name" {
  description = "The chain-change watcher Lambda (#33)."
  value       = aws_lambda_function.watcher.function_name
}

output "watcher_state_table" {
  description = "This service's OWN last-known-tip ledger table (never the shared dighub table)."
  value       = aws_dynamodb_table.watcher_state.name
}

output "ci_deploy_role_arn" {
  description = "Set the repo variable CI_DEPLOY_ROLE_ARN to this."
  value       = aws_iam_role.deploy.arn
}

# API Gateway HTTP API ($default catch-all → the resolver Lambda, AWS_PROXY payload v2) used as the
# CloudFront custom origin. Mirrors the ecosystem apigw-http pattern the hub resolver used: OAC →
# Function-URL is incompatible with an HTTP API behind CloudFront (AWS requires the viewer to sign
# payloads), so API Gateway forwards plain requests to the Lambda and CloudFront fronts it.

resource "aws_apigatewayv2_api" "resolver" {
  name          = "on-dig-net-resolver"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "resolver" {
  api_id                 = aws_apigatewayv2_api.resolver.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.resolver.arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.resolver.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.resolver.id}"
}

# Access logs: retained CloudWatch group capturing every request.
resource "aws_cloudwatch_log_group" "apigw_access" {
  name              = "/aws/apigw/on-dig-net-resolver"
  retention_in_days = var.log_retention_days
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.resolver.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 100
    throttling_rate_limit  = 50
  }
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_access.arn
    format = jsonencode({
      requestId         = "$context.requestId"
      ip                = "$context.identity.sourceIp"
      method            = "$context.httpMethod"
      path              = "$context.path"
      status            = "$context.status"
      latency           = "$context.responseLatency"
      userAgent         = "$context.identity.userAgent"
      responseLen       = "$context.responseLength"
      integrationStatus = "$context.integrationStatus"
    })
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.resolver.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.resolver.execution_arn}/*/*"
}

locals {
  # execute-api host (no scheme/trailing slash) for the CloudFront origin.
  resolver_origin_domain = replace(aws_apigatewayv2_api.resolver.api_endpoint, "https://", "")
}

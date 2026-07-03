# *.on.dig.net resolver CloudFront distribution + its cache/response-headers policies + the
# viewer-request host-preserving function. Split verbatim (behaviourally) out of hub.dig.net's
# `on_resolver` distribution — same 5 behaviors, same two CSP trust contexts, same host-key cache,
# NO WAF (arbitrary per-subdomain user content), IPv6 enabled. Policy + function names are prefixed
# `on-dig-net-` because CloudFront policy/function names are account-global (the hub's `dighub-*`
# copies still exist until the hub-side removal lands).

# OAC for the S3 asset origin — SigV4 always.
resource "aws_cloudfront_origin_access_control" "s3" {
  name                              = "on-dig-net-s3-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Managed origin-request policy: forwards the full viewer request EXCEPT Host (CloudFront rewrites
# Host to the execute-api origin; the viewer host is preserved in x-dig-host by the function below).
data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

# Edge cache for the resolver's document + /__dig/config.json.
#
# The `/` document is a STATIC branded loader shell (no per-request DynamoDB lookup, no baked pin —
# it resolves status + pin async from /__dig/config.json), byte-identical for every subdomain and
# every Active store, so it is EDGE-CACHEABLE. CloudFront honours each response's own Cache-Control
# within [min_ttl, max_ttl]: the document `max-age=300` caches ~300s; /__dig/config.json `max-age=30`
# caches ~30s.
#
# CACHE KEY includes `x-dig-host` (the viewer host, captured by the function below BEFORE the cache
# lookup) so EACH subdomain caches under its OWN key — REQUIRED for config.json correctness (pin/
# status differ per subdomain). MUST key on `x-dig-host`, NOT `Host`: the behavior uses the managed
# AllViewerExceptHostHeader origin-request policy which rewrites Host to the execute-api origin;
# putting `Host` in the cache key forwards the VIEWER Host to API Gateway → 403 Forbidden.
resource "aws_cloudfront_cache_policy" "resolver_doc" {
  name        = "on-dig-net-resolver-doc"
  default_ttl = 300
  max_ttl     = 300
  min_ttl     = 0
  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "whitelist"
      headers {
        items = ["x-dig-host"]
      }
    }
    query_strings_config {
      query_string_behavior = "all"
    }
  }
}

# Long-TTL immutable cache for the STATIC loader assets (/__dig/*, /__dig_sw.js, /dig-client/*).
# CACHE KEY: path + query only — NO host header (the assets are byte-identical across every
# subdomain, so one cached copy per PoP serves all). Query strings ARE in the key (the SW self-host
# registration passes ?store=&root=…; content-hashed asset URLs carry a ?v= cache-buster).
resource "aws_cloudfront_cache_policy" "static_immutable" {
  name        = "on-dig-net-static-immutable"
  default_ttl = 31536000
  max_ttl     = 31536000
  min_ttl     = 31536000
  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "all"
    }
  }
}

# Security headers for the resolver document behaviors. The resolver serves TWO DISTINCT DOCUMENT
# trust contexts (#206): the LOADER SHELL (loader.html — first-party inline branding + bootstrap +
# same-origin embed snippet, reaching ONLY rpc.dig.net) and the STORE CONTENT the service worker
# synthesizes after decrypt (untrusted third-party HTML, sandboxed by sw.js STORE_CSP, which
# allowlists the sanctioned tip-widget origins). To let each document carry the CORRECT policy, the
# resolver Lambda attaches the document CSP PER RESPONSE, so this edge policy sets
# `content_security_policy { override = false }` — the Lambda's per-response CSP WINS while the edge
# still applies HSTS + nosniff + frame-options + referrer-policy. The CSP string below is the
# SANCTIONED-CONTENT baseline (the content-sandbox allowlist) kept for documentation; with
# override=false it never clobbers the Lambda's loader-shell CSP.
resource "aws_cloudfront_response_headers_policy" "resolver" {
  name = "on-dig-net-resolver-headers"
  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 63072000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    content_security_policy {
      override = false
      content_security_policy = join("; ", [
        "default-src 'self' blob: data:",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' blob: https://${var.app_host} https://esm.sh",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob: https://${var.app_host}",
        "font-src 'self' data:",
        "media-src 'self' blob:",
        "connect-src 'self' https://${var.rpc_host} https://${var.app_host} https://api.coinset.org wss://relay.walletconnect.com wss://relay.walletconnect.org https://esm.sh",
        "worker-src 'self' blob:",
        "frame-src https://${var.app_host}",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
      ])
    }
  }
}

# Response headers for the STATIC /__dig/* + /__dig_sw.js + /dig-client/* assets served from S3. A
# browser SW registered at scope `/` from `/__dig_sw.js` requires `Service-Worker-Allowed: /` on the
# SW script response (S3 does not set it), so this policy adds it. Plus HSTS + nosniff.
resource "aws_cloudfront_response_headers_policy" "resolver_static" {
  name = "on-dig-net-resolver-static"
  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 63072000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_type_options {
      override = true
    }
  }
  custom_headers_config {
    items {
      header   = "Service-Worker-Allowed"
      value    = "/"
      override = true
    }
  }
}

# The origin-request policy (AllViewerExceptHostHeader) rewrites Host to the execute-api origin, so
# the Lambda can't see which *.on.dig.net subdomain was requested. This viewer-request function
# preserves the original viewer host in x-dig-host BEFORE CloudFront rewrites Host; the Lambda reads
# x-dig-host to extract the subdomain.
resource "aws_cloudfront_function" "resolver_host" {
  name    = "on-dig-net-resolver-host"
  runtime = "cloudfront-js-2.0"
  comment = "Preserve the viewer Host in x-dig-host so the resolver Lambda can read the subdomain."
  publish = true
  code    = <<-EOT
    function handler(event) {
      var request = event.request;
      if (request.headers.host) {
        request.headers['x-dig-host'] = { value: request.headers.host.value };
      }
      return request;
    }
  EOT
}

resource "aws_cloudfront_distribution" "resolver" {
  enabled      = true
  price_class  = var.price_class
  http_version = "http2and3"
  # *.on.dig.net attaches ONLY when the cutover flips var.attach_wildcard_alias true — keeping it off
  # for the initial apply avoids a CNAMEAlreadyExists conflict with the live hub distribution.
  aliases = var.attach_wildcard_alias ? [var.resolver_wildcard] : []
  # NO WAF (deliberate): each subdomain serves arbitrary user-published content, so we cannot assume a
  # request-shape policy without risking breaking someone's app. (Ecosystem rule: no WAF on the
  # user-content resolver.)
  is_ipv6_enabled = true

  # API Gateway HTTP API origin (execute-api) → the resolver Lambda.
  origin {
    origin_id   = "resolver"
    domain_name = local.resolver_origin_domain
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }
  # This service's OWN S3 asset bucket (OAC) for the static loader assets.
  origin {
    origin_id                = "web"
    domain_name              = aws_s3_bucket.assets.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }

  # Default → the resolver Lambda (the static branded loader shell). redirect-to-https so a plain
  # http:// navigation to <sub>.on.dig.net lands on the secure origin (not a 403).
  default_cache_behavior {
    target_origin_id           = "resolver"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = aws_cloudfront_cache_policy.resolver_doc.id
    origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.resolver.id
    compress                   = true
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.resolver_host.arn
    }
  }

  # DYNAMIC per-subdomain pin/status — MUST stay on the resolver Lambda (it does the DynamoDB
  # lookup). Listed BEFORE the /__dig/* static behavior so the more-specific exact path wins.
  ordered_cache_behavior {
    path_pattern               = "/__dig/config.json"
    target_origin_id           = "resolver"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = aws_cloudfront_cache_policy.resolver_doc.id
    origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.resolver.id
    compress                   = true
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.resolver_host.arn
    }
  }

  # STATIC loader assets from S3 (OAC), 1-year immutable, ZERO Lambda.
  ordered_cache_behavior {
    path_pattern               = "/__dig/*"
    target_origin_id           = "web"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = aws_cloudfront_cache_policy.static_immutable.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.resolver_static.id
    compress                   = true
  }

  # The module SERVICE WORKER from S3 (OAC), registered at scope `/` (resolver_static adds
  # Service-Worker-Allowed: /).
  ordered_cache_behavior {
    path_pattern               = "/__dig_sw.js"
    target_origin_id           = "web"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = aws_cloudfront_cache_policy.static_immutable.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.resolver_static.id
    compress                   = true
  }

  # The dig-client read-crypto assets under /dig-client/* — the SAME immutable WASM + ES glue as
  # /__dig/*, served from S3 at the path dig-embed.js actually imports (its ASSET_BASE is
  # <origin>/dig-client). WITHOUT this behavior these requests fall to the resolver Lambda and return
  # loader HTML with a text/html MIME, so the browser's import() of the ES-module glue fails.
  ordered_cache_behavior {
    path_pattern               = "/dig-client/*"
    target_origin_id           = "web"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = aws_cloudfront_cache_policy.static_immutable.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.resolver_static.id
    compress                   = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    acm_certificate_arn      = var.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

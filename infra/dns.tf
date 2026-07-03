# The Route53 wildcard alias for *.on.dig.net → THIS distribution. Created ONLY when
# var.attach_wildcard_alias is true (the post-cutover state), so the initial apply leaves the live
# hub-owned record untouched. Both A and AAAA are published (IPv6-first: an AAAA-preferring resolver
# gets a native AAAA instead of falling through to A). `allow_overwrite` adopts the existing record
# on cutover rather than failing on it.
#
# NOTE on zero-downtime: CloudFront edges route by Host/SNI across a SHARED IP pool, so once the
# alias is attached to this distribution (via `aws cloudfront associate-alias`, see the runbook), all
# *.on.dig.net requests route here regardless of which distribution's domain DNS currently resolves
# to. This Route53 flip is therefore correctness/hygiene, not the functional switch.

resource "aws_route53_record" "wildcard_a" {
  count           = var.attach_wildcard_alias ? 1 : 0
  zone_id         = var.zone_id
  name            = var.resolver_wildcard
  type            = "A"
  allow_overwrite = true
  alias {
    name                   = aws_cloudfront_distribution.resolver.domain_name
    zone_id                = aws_cloudfront_distribution.resolver.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "wildcard_aaaa" {
  count           = var.attach_wildcard_alias ? 1 : 0
  zone_id         = var.zone_id
  name            = var.resolver_wildcard
  type            = "AAAA"
  allow_overwrite = true
  alias {
    name                   = aws_cloudfront_distribution.resolver.domain_name
    zone_id                = aws_cloudfront_distribution.resolver.hosted_zone_id
    evaluate_target_health = false
  }
}

# on.dig.net — development log

High-signal realizations from debugging/development. Concise durable facts with context — not a
change diary (CLAUDE.md §4.5).

## CloudFront caches GET and HEAD to the same path under ONE cache entry (#308)

CloudFront's cache key does **not** include the HTTP method by default: a cache behavior with
`cached_methods = ["GET", "HEAD"]` treats a `GET /foo` and a `HEAD /foo` response as the SAME
cached object (method is simply not one of the dimensions CloudFront hashes into the key — only
`OPTIONS` gets its own slot when enabled). In the common case this is fine (HEAD is supposed to
return the same headers as the equivalent GET, minus the body), but it is a real bug the moment an
origin needs `GET` and `HEAD` to the SAME path to answer with **different semantics** — exactly the
`HEAD /` → mapped-URN feature (#308 Part A): `GET /` serves the static branded loader shell (200,
always) while `HEAD /` reports the subdomain's canonical URN (`X-Dig-URN` etc., 200 or 404
depending on domain status). Without a fix, whichever of the two reaches the origin first for a
given subdomain "wins" the cache entry and silently answers the OTHER method's viewers until the
entry's TTL expires.

**Fix**: extend the CloudFront viewer-request function (`infra/cloudfront.tf`
`resolver_host`) to also stamp the viewer's HTTP method into a header (`x-dig-method`), and add
that header to the affected cache policy's (`resolver_doc`) header whitelist. This gives GET and
HEAD their own cache-key slot for the same path — cheap (a CloudFront Function, not Lambda@Edge)
and requires no path/route changes. The Lambda's `HEAD /` response also sets its own
`Cache-Control: no-store` as a second, belt-and-braces guarantee (so even a cache-policy
regression can't make a stale URN answer stick).

**General rule**: whenever a Lambda-backed CloudFront distribution needs `GET` and `HEAD` on the
same path to diverge in anything beyond "same headers, no body", the cache key MUST be split on
method (or one of the two must be made explicitly non-cacheable end-to-end) — don't assume
CloudFront caches them independently.

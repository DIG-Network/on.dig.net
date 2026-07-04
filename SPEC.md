# on.dig.net — resolver service specification

Normative contract for the `*.on.dig.net` subdomain resolver. An independent reimplementation MUST
satisfy every MUST here. Key words (MUST, SHOULD, MAY) are RFC 2119.

## 1. Purpose

The resolver maps a `*.on.dig.net` subdomain (or an attached custom domain) to a pinned DIG URN and
serves a first-party, client-side-decrypting loader. It is a standalone AWS service:

```
viewer ──HTTPS──▶ CloudFront (*.on.dig.net) ──▶ ┌ API Gateway ▶ resolver Lambda   (document + config.json)
                                                └ S3 asset bucket                  (static loader assets)
                       │
                       └ resolver Lambda reads the SHARED `dighub` DynamoDB table (read-only) for the pin.
```

The domain-registration lifecycle is owned by the hub.dig.net control plane, which WRITES domain
rows to the shared `dighub` DynamoDB table. This service only READS them. It never writes any store,
never holds a signing key, and never builds a spend bundle.

## 2. Host resolution

The viewer host is taken from the `x-dig-host` request header (set by the CloudFront viewer-request
function from the original `Host` before CloudFront rewrites `Host` to the origin), falling back to
`Host` for direct/local invocation.

### 2.1 Wildcard subdomain (`subdomain_of`)

Given a host, extract the single label in front of `on.dig.net`:

- Lowercase; strip a `:port` suffix; strip a trailing FQDN dot.
- The host MUST end in `.on.dig.net`, with exactly ONE non-empty label before it (no multi-label).
- That label MUST pass label validation (§2.3). Otherwise resolution yields nothing.

Yields `None` for the apex `on.dig.net`, a multi-label host (`a.b.on.dig.net`), a non-`on.dig.net`
base, an invalid/reserved label.

### 2.2 Custom domain (`custom_host_candidate` + `CUSTOMDOM#` lookup)

Only when §2.1 yields nothing: normalize the host (lowercase, strip `:port` + trailing dot). A
candidate MUST be a real FQDN (≥2 labels) and MUST NOT be `on.dig.net` or any `*.on.dig.net` host
(those are owned exclusively by §2.1 and MUST never be treated as custom). The resolver reads
`CUSTOMDOM#<candidate>` / `sk=CUSTOMDOM`; only a record whose `status == "active"` resolves, mapping
to its linked `<sub>` and serving the SAME content as `<sub>.on.dig.net`.

### 2.3 Label validation

A valid label: 1–63 chars; only `[a-z0-9-]`; MUST NOT start or end with `-`; MUST NOT be a reserved
word. Reserved words (exact set): `www api rpc hub admin dig on mail ftp ns ns1 ns2 cdn static
assets app root support help about status mx smtp imap pop webmail test dev staging`. This set MUST
match the hub registration validator — a label the hub refuses to register MUST NOT resolve.

## 3. Routes

All responses set `x-content-type-options: nosniff`.

| Method/Path | Origin | Response |
|---|---|---|
| `GET /__dig_sw.js` | asset bucket (edge) / Lambda (fallback) | `text/javascript`, `service-worker-allowed: /`, immutable |
| `GET /__dig/dig-embed.js` | asset bucket / Lambda | `text/javascript`, `max-age=300` |
| `GET /__dig/dig_client.js` | asset bucket / Lambda | `text/javascript`, immutable |
| `GET /__dig/dig_client_bg.wasm` | asset bucket / Lambda | `application/wasm`, immutable |
| `GET /dig-client/dig_client.js` | asset bucket | `text/javascript`, immutable |
| `GET /dig-client/dig_client_bg.wasm` | asset bucket | `application/wasm`, immutable |
| `GET /__dig/config.json` | Lambda | `application/json`, `max-age=30`, see §4 |
| `GET /` (and any other path) | Lambda | the STATIC branded loader shell, `text/html`, `max-age=300`, `LOADER_CSP` |
| unresolvable host | Lambda | `404`, the static error page, `no-store`, static-page CSP |

The Lambda bakes every asset in at compile time (so it can serve them for direct/local invocation),
but in production the `/__dig/*`, `/__dig_sw.js`, and `/dig-client/*` paths are served from the S3
asset bucket at the edge (zero Lambda). The bytes in the bucket MUST equal the baked bytes.

`sw.js` imports `/__dig/dig_client.js` and fetches `/__dig/dig_client_bg.wasm`; `dig-embed.js` loads
the read-crypto WASM from `/dig-client/*` (its `ASSET_BASE`). Both path families MUST be served.

## 4. `/__dig/config.json` (authoritative status + pin)

The document `/` is a STATIC branded shell (no per-request table lookup, no baked pin), byte-identical
for every subdomain. The shell fetches this endpoint async to resolve status + pin. The body MUST be
valid JSON carrying a non-empty `status`:

- Active → `{ "status":"active", "storeId":<64-hex>, "root":<64-hex|null>, "salt":<hex|null>,
  "rpc":"https://rpc.dig.net/", "subdomain":<label> }`. `root:null` = track latest; `salt:null` =
  public store. Any `</` in the serialized pin MUST be escaped as `<\/` (script-breakout safety).
- `available` (no row, or a lapsed Reserved hold) / `pending` (Reserved-with-live-hold or Pending) /
  `expired` / `revoked` → `{ "status":"<state>" }` with NO pin leaked.

Status derivation from a row (`now` = unix seconds): a `Reserved` hold with `expires_at` in the past
is reclaimable → `available`. Otherwise map status: `Active`→active, `Reserved`|`Pending`→pending,
`Expired`→expired, `Revoked`→revoked. Missing row → `available`.

## 5. Domain record (DynamoDB read contract)

Read `pk=DOMAIN#<sub>`, `sk=META`, projection `doc` (a JSON string). `doc` MUST deserialize as:

```
subdomain: string          owner_ph: string            pinned_store_id: string (64-hex)
pinned_root: string|null   salt: string|null           status: "reserved"|"pending"|"active"|"expired"|"revoked"
registered_at: u64|null    expires_at: u64|null         renewal_due_at: u64|null
reg_spend_id: string|null  reg_coin_id: string|null     created_at: u64
reg_price_baseunits: u64|null   (optional; absent on legacy rows)
```

This shape is a byte-level cross-repo contract with hub.dig.net's `dighub-data::domain::Domain` (see
SYSTEM.md). `status` is `snake_case`. Field names and the `reg_price_baseunits` default (absent →
`null`) MUST match so existing rows resolve.

The custom-domain pointer: `pk=CUSTOMDOM#<host>`, `sk=CUSTOMDOM`, `doc` a JSON object with `status`
and `sub`; only `status=="active"` resolves.

## 6. Content-Security-Policy — two trust contexts

The Lambda attaches the DOCUMENT CSP per response; the edge response-headers policy sets
`content_security_policy override=false` so the per-response value wins, while the edge still applies
HSTS + nosniff + frame-options + referrer-policy.

- `LOADER_CSP` (the loader shell — first-party): `default-src 'self' blob: data:; script-src 'self'
  'unsafe-inline' 'wasm-unsafe-eval' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data:
  blob:; font-src 'self' data:; connect-src 'self' https://rpc.dig.net; worker-src 'self' blob:;
  object-src 'none'; base-uri 'none'; frame-ancestors 'none'`. It MUST NOT carry the content-sandbox
  tip-widget origins (`esm.sh`, `hub.dig.net`, `coinset`) or full `'unsafe-eval'`.
- Static status/error pages (inert): `default-src 'self'; script-src 'none'; style-src 'self'
  'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'none'; object-src
  'none'; base-uri 'none'; frame-ancestors 'none'`.

The decrypted STORE CONTENT the service worker synthesizes runs under a separate CSP defined in
`sw.js` (`STORE_CSP`), which additionally allowlists the sanctioned tip-widget origins. That is the
CONTENT sandbox's concern and MUST NOT appear in `LOADER_CSP`.

## 7. Edge (CloudFront) contract

- Two origins: the API Gateway HTTP API (custom origin, the resolver Lambda) and the dedicated S3
  asset bucket (OAC). The asset bucket MUST be dedicated to this service — never a shared bucket.
- Behaviors, in order: `/__dig/config.json` → Lambda; `/__dig/*` → S3; `/__dig_sw.js` → S3;
  `/dig-client/*` → S3; default → Lambda. `/__dig/config.json` MUST precede `/__dig/*`.
- The Lambda behaviors use the managed `AllViewerExceptHostHeader` origin-request policy and a
  viewer-request function that copies `Host` → `x-dig-host` BEFORE the cache lookup. The document +
  config cache key MUST include `x-dig-host` (per-subdomain) and MUST NOT include `Host` (forwarding
  the viewer `Host` to API Gateway yields 403). The static-asset cache key is path + query only (no
  host) — the assets are identical across subdomains.
- `viewer_protocol_policy = redirect-to-https` (a plain-http navigation 301s, never 403s).
- IPv6 MUST be enabled. There MUST be NO WAF (each subdomain serves arbitrary user content).
- Exactly ONE wildcard alias `*.on.dig.net` on this distribution; subdomains are resolved solely by
  the Lambda, never by per-subdomain Route53 records. The Route53 wildcard is an alias A **and** AAAA
  to this distribution.

## 8. Backwards compatibility

The loader / service-worker / wire behavior and the `.dig` read path are FIXED contracts (see
docs.dig.net + digstore SPEC). This service is a pure relocation of the resolver: it MUST keep the
loader HTML, `sw.js`, `dig-embed.js`, and the read-crypto WASM byte-identical to the shipped
artifacts, and MUST keep serving every previously-served route identically.

This fixes the EXTERNAL contract — routes, status codes, response headers, the `.dig` read/verify
semantics — not `sw.js`'s internal fetch/decrypt/caching strategy, which MAY evolve (§9) as long as
every route keeps serving identically and no security invariant is weakened.

## 9. Loader performance: parallel range fetch, streaming decrypt, persistent caching

`sw.js` fetches, verifies, and decrypts a resource as follows (the network/decrypt/caching
STRATEGY; the wire formats it talks — the RPC envelope, the GET content-path headers, the AEAD
chunking, the merkle inclusion proof — are unchanged and specified elsewhere, §3, §6, docs.dig.net,
digstore `SPEC.md`):

- **Parallel byte-range fan-out.** A resource is fetched in fixed-size windows (1 MiB over the
  cacheable GET content path §3/§7's edge behavior for `/stores/*/content/*`; 3 MiB over the POST
  JSON-RPC fallback). Window 0 is always fetched alone — it is the only way to learn the resource's
  total length. Every remaining window is independent (a plain byte-range read, not an opaque
  pagination cursor), so once the total is known they are fetched CONCURRENTLY, bounded to at most
  6 in flight at once. This does not change verification: the merkle inclusion proof is still
  checked over the fully-reassembled ciphertext exactly as before (its leaf is a hash of the WHOLE
  resource, so it cannot itself be verified incrementally) — only the round-trips leading up to
  that check are now concurrent instead of sequential.
- **Streaming decrypt.** Once the ciphertext is fetched and merkle-verified, chunk 0 (per the AEAD
  chunk boundaries carried in `X-Dig-Chunk-Lens` / `chunk_lens`) is decrypted EAGERLY, before any
  `Response` is constructed — a decrypt failure here (wrong key / decoy resource) still yields a
  clean `404`, identical to the pre-streaming behavior, because the derived AES key is the same for
  every chunk in a resource: a wrong key fails AEAD authentication on every chunk, so testing chunk
  0 fully covers that case. The `Response` body is then a stream that has already enqueued chunk 0
  and decrypts chunks 1..N LAZILY as the stream is read, so the browser can start consuming a large
  multi-chunk resource before the last chunk is decrypted. Every chunk is still decrypted through
  its own AEAD-authenticated call — no chunk's authentication is skipped.
- **Persisted WASM module.** The dig-client WASM (hash-verified against the pinned SHA-256 exactly
  as before) is stored in the Cache API keyed by that SHA-256 once fetched. A cache hit is reused
  directly (not re-hashed — Cache Storage is same-origin, SW-private storage this worker's own code
  is the only writer of) and passed to the streaming-instantiate path, letting the browser reuse its
  compiled-code cache tied to that Cache Storage entry and skip recompilation. A wasm rebuild (new
  SHA-256) naturally misses the old entry.
- **Persisted decrypted content.** A decrypted resource read under a PINNED (concrete 64-hex) root
  is persisted in the Cache API, keyed by store id + root + resource key, so a later load — even a
  fresh service-worker instance or a new browser session — skips the network fetch and decrypt
  entirely. An unpinned ("latest"/mutable) read is NEVER persisted this way: since "latest" can
  legitimately resolve to different content over time, a persisted entry for it could serve stale
  content forever after the underlying value changes — exactly what the chain-anchored-root pin
  model exists to prevent. Persistence is best-effort (a private-mode/quota failure never blocks
  serving content already handed to the page) and happens AFTER the response has already been sent
  (via `event.waitUntil`), so it never delays the visible response.

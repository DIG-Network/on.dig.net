//! `*.on.dig.net` resolver Lambda entrypoint.
//!
//! Handles HTTP requests routed by API Gateway/CloudFront for every `*.on.dig.net` host.
//! Responsibilities:
//!   - Serve same-origin SW + dig-client assets (baked in at compile time).
//!   - Parse the `Host` header → subdomain → `DOMAIN#<sub>` DynamoDB lookup.
//!   - Delegate the render decision to the pure [`on_dig_net_resolver`] crate.
//!   - Return the appropriate HTML page or loader.
//!
//! This binary only compiles under `--features aws,net`.

use lambda_http::{run, service_fn, Body, Error, Request, Response};
use on_dig_net_resolver::domain::Domain;
use on_dig_net_resolver::{
    config_json_for, custom_host_candidate, is_static_asset_path, subdomain_of, LOADER_CSP,
    STATIC_PAGE_CSP,
};
use std::time::{SystemTime, UNIX_EPOCH};

// Assets baked into the binary at compile time (same-origin; no CORS).
const LOADER_HTML: &str = include_str!("../../assets/loader.html");
const SW_JS: &str = include_str!("../../assets/sw.js");
// The shared embed snippet, served SAME-ORIGIN at /__dig/dig-embed.js. loader.html loads it → Tier 1
// (module SW). This service vendors the canonical bytes (assets/dig-embed.js), committed in-repo.
const EMBED_JS: &str = include_str!("../../assets/dig-embed.js");
const DIG_JS: &str = include_str!("../../assets/dig_client.js");
const DIG_WASM: &[u8] = include_bytes!("../../assets/dig_client_bg.wasm");
// The unknown-host / misconfigured-host fallback (served verbatim, no __SUB__ substitution). The
// four per-status pages (available/pending/expired/revoked) are now rendered CLIENT-SIDE on the
// branded loader shell (#206b — the status resolves from /__dig/config.json); their canonical copy
// lives in assets/pages/*.html and is regression-tested in the on_dig_net_resolver lib wordmark tests.
const PAGE_ERROR: &str = include_str!("../../assets/pages/error.html");

#[derive(Clone)]
struct Ctx {
    ddb: aws_sdk_dynamodb::Client,
    table: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build an HTML document response with an EXPLICIT per-response Content-Security-Policy.
///
/// The resolver Lambda owns the document CSP for its two DISTINCT trust contexts (loader shell vs
/// inert status pages) rather than delegating to the edge — the CloudFront resolver response-headers
/// policy is configured to NOT override document CSP (`content_security_policy { override = false }`),
/// so this per-response header is the authoritative one for the document regardless of edge config.
/// (HSTS / nosniff-at-edge / frame-options / referrer-policy still come from the edge; we also set
/// nosniff here for direct/local invocation.)
fn html_with_csp(status: u16, body: String, cache: &str, csp: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", cache)
        .header("x-content-type-options", "nosniff")
        .header("content-security-policy", csp)
        .body(Body::Text(body))
        .expect("response")
}

/// Status/error pages are inert first-party HTML → the tight static-page CSP.
fn html(status: u16, body: String, cache: &str) -> Response<Body> {
    html_with_csp(status, body, cache, STATIC_PAGE_CSP)
}

async fn read_domain(ctx: &Ctx, sub: &str) -> Option<Domain> {
    if ctx.table.is_empty() {
        return None;
    }
    let got = ctx
        .ddb
        .get_item()
        .table_name(&ctx.table)
        .key(
            "pk",
            aws_sdk_dynamodb::types::AttributeValue::S(format!("DOMAIN#{sub}")),
        )
        .key(
            "sk",
            aws_sdk_dynamodb::types::AttributeValue::S("META".into()),
        )
        .projection_expression("doc")
        .send()
        .await
        .ok()?;
    match got.item().and_then(|it| it.get("doc")) {
        Some(aws_sdk_dynamodb::types::AttributeValue::S(doc)) => {
            serde_json::from_str::<Domain>(doc).ok()
        }
        _ => None,
    }
}

/// Resolve an attached custom host (e.g. `app.example.com`) to its linked `<sub>` via the
/// flat `CUSTOMDOM#<host>` pointer the API writes when a custom domain becomes Active. Returns
/// the `<sub>` so the caller serves the SAME content as `<sub>.on.dig.net`. Only an `active`
/// pointer is honored (pending/failed attachments do not serve), so a custom host that proved
/// DNS ownership but isn't wired/active yet falls through to the error page.
async fn resolve_custom_host(ctx: &Ctx, host: &str) -> Option<String> {
    if ctx.table.is_empty() {
        return None;
    }
    let candidate = custom_host_candidate(host)?;
    let got = ctx
        .ddb
        .get_item()
        .table_name(&ctx.table)
        .key(
            "pk",
            aws_sdk_dynamodb::types::AttributeValue::S(format!("CUSTOMDOM#{candidate}")),
        )
        .key(
            "sk",
            aws_sdk_dynamodb::types::AttributeValue::S("CUSTOMDOM".into()),
        )
        .projection_expression("doc")
        .send()
        .await
        .ok()?;
    let doc = match got.item().and_then(|it| it.get("doc")) {
        Some(aws_sdk_dynamodb::types::AttributeValue::S(doc)) => doc,
        _ => return None,
    };
    let v: serde_json::Value = serde_json::from_str(doc).ok()?;
    // Only serve a custom host whose attachment is active (issued + edge-attached).
    if v["status"].as_str() != Some("active") {
        return None;
    }
    v["sub"].as_str().map(str::to_string)
}

async fn handle(ctx: &Ctx, req: Request) -> Response<Body> {
    let path = req.uri().path().to_string();
    // CloudFront (AllViewerExceptHostHeader) rewrites `Host` to the APIGW origin domain, so the
    // original viewer host is preserved in `x-dig-host` by the resolver-host CloudFront function.
    // Read that first; fall back to `Host` for direct/local invocation.
    let host = req
        .headers()
        .get("x-dig-host")
        .or_else(|| req.headers().get("host"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // Same-origin internal assets (served regardless of subdomain).
    match path.as_str() {
        "/__dig_sw.js" => {
            return Response::builder()
                .status(200)
                .header("content-type", "text/javascript; charset=utf-8")
                .header("cache-control", "public, max-age=300")
                .header("service-worker-allowed", "/")
                .header("x-content-type-options", "nosniff")
                .body(Body::Text(SW_JS.to_string()))
                .expect("response")
        }
        "/__dig/dig-embed.js" => {
            return Response::builder()
                .status(200)
                .header("content-type", "text/javascript; charset=utf-8")
                .header("cache-control", "public, max-age=300")
                .header("x-content-type-options", "nosniff")
                .body(Body::Text(EMBED_JS.to_string()))
                .expect("response")
        }
        "/__dig/dig_client.js" => {
            return Response::builder()
                .status(200)
                .header("content-type", "text/javascript; charset=utf-8")
                .header("cache-control", "public, max-age=31536000, immutable")
                .header("x-content-type-options", "nosniff")
                .body(Body::Text(DIG_JS.to_string()))
                .expect("response")
        }
        "/__dig/dig_client_bg.wasm" => {
            return Response::builder()
                .status(200)
                .header("content-type", "application/wasm")
                .header("cache-control", "public, max-age=31536000, immutable")
                .header("x-content-type-options", "nosniff")
                .body(Body::Binary(DIG_WASM.to_vec()))
                .expect("response")
        }
        _ => {}
    }

    // Resolve the host to a `<sub>`. The PRIMARY path is the wildcard `*.on.dig.net` resolve
    // (subdomain_of) — completely unchanged. ONLY when that yields nothing (a host that is NOT an
    // on.dig.net subdomain, which today already 404s) do we try the additive custom-domain
    // fallback: map the attached custom host back to its linked `<sub>` and serve the SAME content
    // as `<sub>.on.dig.net`. This never alters behavior for any on.dig.net host.
    let sub = match subdomain_of(host) {
        Some(s) => s,
        None => match resolve_custom_host(ctx, host).await {
            Some(s) => s,
            None => {
                // Not an on.dig.net subdomain and not an active custom domain: serve the static
                // error page as-is (no __SUB__ placeholder to substitute).
                return html(404, PAGE_ERROR.to_string(), "no-store");
            }
        },
    };

    // /__dig/config.json — the AUTHORITATIVE status + pin the loader shell resolves ASYNC (#206b).
    // The (single, cheap) DynamoDB lookup happens HERE, OFF the document first-paint path, so the
    // branded loader shell (served on `/` below) never blocks on a backend round-trip. Active carries
    // the full pin; non-active carries just the status. Cacheable 30s (pin/status can change).
    if path == "/__dig/config.json" {
        return Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .header("cache-control", "public, max-age=30")
            .header("x-content-type-options", "nosniff")
            .body(Body::Text(config_json_for(
                read_domain(ctx, &sub).await,
                now(),
            )))
            .expect("response");
    }

    // Asset-looking paths (a KNOWN non-HTML file extension in the FINAL segment — a site's own
    // `service-worker.js`, an `.mjs`/`.css`/`.wasm`/`.json`/image/font/…) MUST NOT receive the
    // branded loader shell. A browser's service-worker REGISTRATION fetch (and an ES-module import)
    // BYPASSES the page's controlling loader SW and hits this origin directly, so answering
    // `/service-worker.js` with the shell's `text/html` made the browser reject registration with a
    // MIME `SecurityError` (#144). The same masquerade would give any bypassing subresource fetch the
    // wrong MIME. The resolver is a blind host — it cannot decrypt an encrypted store asset — so such
    // a path (one the loader SW did not already serve) gets an honest, correctly-typed `404`, never
    // the SPA-fallback shell (which stays only for the navigation/HTML routes below). A `404` also
    // fails the registration cleanly WITHOUT evicting the loader SW (a browser installs a SW only
    // from a 2xx script), so the store's content keeps decrypting.
    if is_static_asset_path(&path) {
        return Response::builder()
            .status(404)
            .header("content-type", "text/plain; charset=utf-8")
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .body(Body::Text("Not found".to_string()))
            .expect("response");
    }

    // Document `/` (and any non-asset path) → serve the STATIC branded loader shell IMMEDIATELY
    // (#206b). CRITICAL: no `read_domain().await` here — the shell is byte-identical for every
    // subdomain and every Active store (the subdomain lives in window.location.hostname), so the
    // branded card paints on Lambda-response latency alone. The shell fetches /__dig/config.json
    // async to learn status + pin, then either loads the content (active) or swaps to the matching
    // status message (pending/expired/revoked/available) — always on the already-painted shell. It
    // carries LOADER_CSP (loader-shell trust context, #206) and is edge-cacheable (see the resolver
    // cache policy in infra/).
    let _ = &sub; // sub validated the host; the shell itself needs no substitution
    html_with_csp(
        200,
        LOADER_HTML.to_string(),
        "public, max-age=300",
        LOADER_CSP,
    )
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .without_time()
        .init();
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb = aws_sdk_dynamodb::Client::new(&config);
    let table = std::env::var("DIGHUB_TABLE").unwrap_or_default();
    let ctx = Ctx { ddb, table };
    run(service_fn(move |req: Request| {
        let ctx = ctx.clone();
        async move { Ok::<Response<Body>, Error>(handle(&ctx, req).await) }
    }))
    .await
}

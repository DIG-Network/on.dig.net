//! Pure resolver logic: subdomain parsing + page/loader templating. No AWS — unit-testable.
//! Subdomain label validation + the reserved-word list live in [`crate::domain`] (a read-only,
//! wire-faithful copy of the hub's `dighub-data::domain`) and are re-exported here.

pub mod domain;
pub mod watcher;

pub use crate::domain::{validate_label, RESERVED_WORDS};
use crate::domain::{Domain, DomainStatus};

/// The base zone every wildcard subdomain hangs off.
pub const BASE_ZONE: &str = "on.dig.net";

/// Extract the single subdomain label from a `Host` header. Lowercases, strips any
/// `:port` and a trailing FQDN dot, requires exactly one label in front of `on.dig.net`.
/// `None` for the apex, multi-label hosts, or a non-`on.dig.net` base.
pub fn subdomain_of(host: &str) -> Option<String> {
    let host = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host); // tolerate a trailing FQDN dot
    let prefix = host.strip_suffix(BASE_ZONE)?;
    let prefix = prefix.strip_suffix('.')?; // require the dot before the base
    if prefix.is_empty() || prefix.contains('.') {
        return None; // apex or multi-label
    }
    // Defense-in-depth: only return a label that passes the same validator the API enforces
    // (charset [a-z0-9-], length, not reserved). A malformed/reserved Host → None → error page.
    if validate_label(prefix).is_err() {
        return None;
    }
    Some(prefix.to_string())
}

/// Normalize an incoming `Host` header into a bare lowercase custom-domain candidate for the
/// `CUSTOMDOM#<host>` reverse lookup: strips `:port`, a trailing FQDN dot, and lowercases.
/// Returns `None` for a host that is empty, the apex, or anything under `on.dig.net` (those
/// are handled by [`subdomain_of`] and must never be treated as a "custom" domain — keeps the
/// wildcard `*.on.dig.net` path completely untouched). The returned value is exactly the key
/// the API persisted in the `custom_domain` field, so a `CUSTOMDOM#<value>` get resolves it.
pub fn custom_host_candidate(host: &str) -> Option<String> {
    let host = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host).to_string();
    if host.is_empty() {
        return None;
    }
    // Never treat an on.dig.net host as a custom domain — that path is owned by subdomain_of.
    if host == BASE_ZONE || host.ends_with(&format!(".{BASE_ZONE}")) {
        return None;
    }
    // Must look like a real FQDN (>=2 labels), otherwise it can't be someone's attached domain.
    if !host.contains('.') {
        return None;
    }
    Some(host)
}

/// Known static-asset file extensions (lowercased, no leading dot). A request path whose FINAL
/// segment ends in one of these names a concrete static asset, never an application/navigation route.
/// `html`/`htm` are deliberately ABSENT: a document/navigation request still gets the loader shell.
/// This mirrors the extension set the loader's `sw.js` / `dig-embed.js` `contentType()` recognise
/// (plus `map`, `wav`, `ogg`) — the resources a store legitimately ships.
const STATIC_ASSET_EXTENSIONS: &[&str] = &[
    "js", "mjs", "css", "json", "wasm", "map", "svg", "png", "jpg", "jpeg", "gif", "webp", "ico",
    "avif", "woff", "woff2", "ttf", "otf", "txt", "pdf", "mp4", "webm", "mp3", "wav", "ogg", "xml",
    "md",
];

/// Whether a request `path`'s final segment names a concrete STATIC ASSET (a known non-HTML file
/// extension) rather than an application/navigation route.
///
/// WHY (issue #144): the resolver serves the branded loader shell (`text/html`) for every navigation
/// route so an SPA deep-link boots the loader. But an asset path — most critically a site's own
/// `service-worker.js` — MUST NOT receive `text/html`: a browser's service-worker *registration*
/// fetch BYPASSES the page's controlling loader service worker and hits this origin directly, so a
/// `text/html` body makes the browser reject the registration with
/// `SecurityError: unsupported MIME type ('text/html')`. The resolver cannot decrypt an encrypted
/// store asset, so an asset path that reaches it (i.e. one the loader SW did not already serve) gets
/// an honest `404` — never the SPA-fallback shell. Only the final path segment's extension decides,
/// and only KNOWN asset extensions match, so an SPA route that merely contains a dot (`/user/john.doe`)
/// stays a navigation route.
pub fn is_static_asset_path(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or("");
    match last.rsplit_once('.') {
        Some((name, ext)) if !name.is_empty() => {
            STATIC_ASSET_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
        }
        _ => false,
    }
}

/// The status decision for a resolved subdomain. Drives the `/__dig/config.json` body ([`config_json_for`]).
///
/// NOTE (#206b): the document `/` request no longer branches on this — it always serves the STATIC
/// branded loader shell (`bootstrap.rs`), which resolves the status + pin ASYNC from
/// `/__dig/config.json`. This enum is the pure decision the config endpoint reports.
#[derive(Debug, PartialEq, Eq)]
pub enum Render {
    /// The subdomain is Active: carries the JSON pin config (storeId/root/salt/rpc/subdomain) the
    /// loader shell uses to build the URN and hand it to dig-embed.js for decrypt + render.
    Loader(String),
    Available,
    Pending,
    Expired,
    Revoked,
}

/// Content-Security-Policy for the LOADER SHELL trust context (`Render::Loader` → loader.html).
///
/// The loader shell is FIRST-PARTY DIG code: an inline `<style>`/`<svg>` branded card, one inline
/// bootstrap `<script>` (fetches `/__dig/config.json` async to resolve status + pin — #206b: the
/// server bakes NO pin, so the branded card paints instantly without a backend round-trip), and one
/// SAME-ORIGIN `<script src>` (dig-embed.js), which registers the module service worker and fetches +
/// verifies the dig-client WASM. It is a
/// DELIBERATELY DISTINCT trust context from the untrusted STORE CONTENT the service worker later
/// synthesizes (that content runs under `sw.js`'s `STORE_CSP`, which additionally allowlists the
/// sanctioned tip-widget origins — esm.sh / hub.dig.net / coinset). Those origins are the CONTENT
/// sandbox's concern and MUST NOT appear here: the shell never talks to them.
///
/// What the shell legitimately needs, and nothing more:
///   • `script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' blob:` — the inline bootstrap, the
///     same-origin embed snippet, `WebAssembly.instantiate` of the read-crypto wasm, and blob:
///     module workers.
///   • `style-src 'self' 'unsafe-inline'` — the inline branded-card CSS.
///   • `img-src 'self' data: blob:` — inline/data-URI brand imagery.
///   • `font-src 'self' data:` — the self-hosted brand font.
///   • `connect-src 'self' https://rpc.dig.net` — the ONLY network leg the shell makes (content RPC).
///   • `worker-src 'self' blob:` — the module service worker registration.
///   • `object-src 'none'; base-uri 'none'; frame-ancestors 'none'` — clickjacking / base-tag / plugin
///     hardening.
///
/// The Lambda attaches this per-response so the loader-shell CSP is correct regardless of the edge
/// response-headers policy (which is set to NOT override document CSP — see the terraform resolver
/// policy). HSTS / nosniff / frame-options / referrer-policy still come from the edge.
pub const LOADER_CSP: &str = "default-src 'self' blob: data:; \
script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' blob:; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data: blob:; \
font-src 'self' data:; \
connect-src 'self' https://rpc.dig.net; \
worker-src 'self' blob:; \
object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

/// Content-Security-Policy for the STATIC STATUS PAGES (`Available`/`Pending`/`Expired`/`Revoked`).
///
/// These pages are fully static first-party HTML with an inline `<style>` + inline `<svg>` wordmark
/// and NO scripting, no network calls, no workers. The policy is therefore maximally tight: only
/// `'self'` + inline styles + inline/data images, everything else denied. (Kept separate from the
/// loader shell, which legitimately needs script/worker/connect capability.)
pub const STATIC_PAGE_CSP: &str = "default-src 'self'; \
script-src 'none'; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; \
font-src 'self' data:; \
connect-src 'none'; \
object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

/// The Content-Security-Policy the resolver Lambda MUST attach to a document `Render`.
///
/// The loader shell and the static status pages are two DISTINCT trust contexts (the shell scripts
/// and reaches rpc.dig.net; the status pages are inert), so each gets its own policy. This mapping
/// is the single source of truth `bootstrap.rs::html_with_csp` consumes.
pub fn csp_for(render: &Render) -> &'static str {
    match render {
        Render::Loader(_) => LOADER_CSP,
        Render::Available | Render::Pending | Render::Expired | Render::Revoked => STATIC_PAGE_CSP,
    }
}

/// Pure render decision for the document request. `domain` is the looked-up row (or None).
pub fn render_for(domain: Option<Domain>, now: u64) -> Render {
    let Some(d) = domain else {
        return Render::Available;
    };
    if d.is_reclaimable(now) {
        // A lapsed Reserved hold (15-min pre-payment window elapsed, name never registered):
        // return the name to the pool.
        return Render::Available;
    }
    match d.effective_status() {
        DomainStatus::Active => Render::Loader(loader_config(&d)),
        DomainStatus::Reserved | DomainStatus::Pending => Render::Pending,
        DomainStatus::Expired => Render::Expired,
        DomainStatus::Revoked => Render::Revoked,
    }
}

/// Build the pin config JSON object (storeId/root/salt/rpc/subdomain) for an Active domain. It is
/// the Active payload of `/__dig/config.json` (see [`config_json_for`]); the loader shell fetches
/// that endpoint and reads this to build the URN. (#206b: no longer inlined into the document.)
pub fn loader_config(d: &Domain) -> String {
    serde_json::json!({
        "storeId": d.pinned_store_id,
        "root": d.pinned_root,         // null = latest
        "salt": d.salt,                // null = public
        "rpc": "https://rpc.dig.net/",
        "subdomain": d.subdomain,
    })
    .to_string()
    .replace("</", "<\\/") // prevent </script> breakout when embedded inline in the loader HTML
}

/// The client-facing status string for a document `Render` (the `status` field of
/// `/__dig/config.json`). This is the single mapping the loader shell keys off after its INSTANT
/// branded paint: `active` proceeds to decrypt + render content; every other value swaps the
/// branded card's message to the matching status copy WITHOUT navigating away.
pub fn status_str(render: &Render) -> &'static str {
    match render {
        Render::Loader(_) => "active",
        Render::Available => "available",
        Render::Pending => "pending",
        Render::Expired => "expired",
        Render::Revoked => "revoked",
    }
}

/// Build the `/__dig/config.json` body for a looked-up domain row (or `None`).
///
/// This is the AUTHORITATIVE source of both the pin AND the status for the loader shell. The
/// document path (`/`) serves a STATIC branded loader shell INSTANTLY without any DynamoDB lookup;
/// the shell then fetches this endpoint ASYNC to learn what to do. So the (single, cheap)
/// `read_domain` lookup happens HERE, off the critical first-paint path — never blocking the branded
/// card.
///
/// Shape:
///   • Active  → `{ "status":"active", storeId, root, salt, rpc, subdomain }` (the loader builds the
///     URN from the pin and lets dig-embed.js decrypt + stream the content).
///   • non-Active (`available`/`pending`/`expired`/`revoked`) → `{ "status":"…" }` (the loader swaps
///     the branded card's message to the matching status copy).
///
/// The status is derived from the SAME [`render_for`] decision the document used to make, so the
/// four non-active states stay identical to the old server-rendered pages.
pub fn config_json_for(domain: Option<Domain>, now: u64) -> String {
    let render = render_for(domain, now);
    match &render {
        // Active: carry the full pin so the client can build the URN. loader_config already emits
        // storeId/root/salt/rpc/subdomain; merge the status in.
        Render::Loader(cfg) => {
            // `cfg` is valid JSON (from loader_config); splice `"status":"active"` in as the first
            // field so the client always sees a status even if it only peeks at the top.
            match cfg.strip_prefix('{') {
                Some(rest) if !rest.trim_start().starts_with('}') => {
                    format!("{{\"status\":\"active\",{rest}")
                }
                // Defensive: empty/degenerate object → just the status.
                _ => "{\"status\":\"active\"}".to_string(),
            }
        }
        other => serde_json::json!({ "status": status_str(other) }).to_string(),
    }
}

/// Regression guard for the "DIG Network" wordmark on the served *.on.dig.net status pages.
///
/// THE BUG (recurring, user-reported): the word "Network" rendered the SAME COLOR AS THE BACKGROUND
/// (invisible), because the wordmark parent uses `background-clip:text` + `color:transparent` to paint
/// "DIG" with a gradient and the "Network" span was left to INHERIT that transparent fill. The fix is
/// that "Network" (`.mark .net`) MUST carry its OWN explicit visible fill. These tests read the ACTUAL
/// asset bytes the Lambda serves (via include_str!), so reintroducing the transparent inheritance fails.
#[cfg(test)]
mod wordmark_tests {
    // Each page renders `DIG<span class="net">&nbsp;Network</span>` and must give `.net` a visible fill.
    const PAGES: &[(&str, &str)] = &[
        ("available", include_str!("../assets/pages/available.html")),
        ("pending", include_str!("../assets/pages/pending.html")),
        ("expired", include_str!("../assets/pages/expired.html")),
        ("revoked", include_str!("../assets/pages/revoked.html")),
        ("error", include_str!("../assets/pages/error.html")),
    ];

    #[test]
    fn network_span_is_present_and_visibly_colored() {
        for (name, html) in PAGES {
            // The wordmark markup renders DIG + a "Network" span.
            assert!(
                html.contains(r#"DIG<span class="net">&nbsp;Network</span>"#),
                "{name}.html must render the DIG + Network wordmark markup"
            );
            // The `.mark .net` rule must exist and set an explicit, NON-transparent fill for "Network"
            // (both -webkit-text-fill-color and color), never inheriting the parent's color:transparent.
            let rule_start = html
                .find(".mark .net")
                .unwrap_or_else(|| panic!("{name}.html must define a .mark .net rule"));
            let rule = &html[rule_start
                ..html[rule_start..]
                    .find('}')
                    .map(|e| rule_start + e)
                    .unwrap()];
            assert!(
                rule.contains("-webkit-text-fill-color"),
                "{name}.html .mark .net must set -webkit-text-fill-color"
            );
            assert!(
                rule.contains("color:"),
                "{name}.html .mark .net must set color"
            );
            assert!(
                !rule.contains("transparent") && !rule.contains("inherit"),
                "{name}.html Network fill must be a visible color (not transparent/inherit): {rule}"
            );
        }
    }
}

/// CSP trust-context tests (#206). The loader shell and the store CONTENT are DELIBERATELY DISTINCT
/// trust contexts: `LOADER_CSP` (this crate, first-party shell) must permit exactly the shell's own
/// inline branding + bootstrap + wasm eval + worker + the single rpc.dig.net leg, and MUST NOT carry
/// the untrusted-content sandbox's tip-widget origins (esm.sh / hub.dig.net / coinset — those live in
/// sw.js STORE_CSP). The loader.html markup must use ONLY features this policy permits.
#[cfg(test)]
mod csp_tests {
    use super::*;

    const LOADER_HTML: &str = include_str!("../assets/loader.html");

    #[test]
    fn loader_csp_permits_the_shells_own_capabilities() {
        // The branded card is inline <style>/<svg>; the bootstrap is inline; the embed snippet is a
        // same-origin <script src>. All of that needs script-src 'self' + 'unsafe-inline'.
        assert!(LOADER_CSP.contains("script-src 'self' 'unsafe-inline'"));
        // The read-crypto wasm is instantiated via WebAssembly.instantiate.
        assert!(LOADER_CSP.contains("'wasm-unsafe-eval'"));
        // The module service worker is registered (and blob: module workers used).
        assert!(LOADER_CSP.contains("worker-src 'self' blob:"));
        // Inline branded-card CSS.
        assert!(LOADER_CSP.contains("style-src 'self' 'unsafe-inline'"));
        // The ONLY network leg the shell makes is the content RPC.
        assert!(LOADER_CSP.contains("connect-src 'self' https://rpc.dig.net"));
        // Inline/data-URI imagery for the brand.
        assert!(LOADER_CSP.contains("img-src 'self' data: blob:"));
        // Hardening.
        assert!(LOADER_CSP.contains("object-src 'none'"));
        assert!(LOADER_CSP.contains("base-uri 'none'"));
        assert!(LOADER_CSP.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn loader_csp_is_distinct_from_the_content_sandbox() {
        // The store-CONTENT sandbox (sw.js STORE_CSP) allowlists the sanctioned tip-widget origins.
        // The loader SHELL never talks to them; keeping them out of LOADER_CSP is the whole point of
        // splitting the two trust contexts. A regression that widens the shell to the content origins
        // must fail here.
        assert!(
            !LOADER_CSP.contains("esm.sh"),
            "shell must not carry esm.sh"
        );
        assert!(
            !LOADER_CSP.contains("hub.dig.net"),
            "shell must not carry hub.dig.net (a content-sandbox tip-widget origin)"
        );
        assert!(
            !LOADER_CSP.contains("coinset"),
            "shell must not carry coinset (a content-sandbox tip-widget origin)"
        );
        // The shell needs no 'unsafe-eval' (only 'wasm-unsafe-eval'); don't widen it.
        assert!(
            !LOADER_CSP.contains("'unsafe-eval'"),
            "shell must not grant full 'unsafe-eval'"
        );
    }

    #[test]
    fn loader_html_uses_only_csp_permitted_features() {
        // Inline <style> + inline <svg> branding (style-src 'unsafe-inline').
        assert!(
            LOADER_HTML.contains("<style>"),
            "branded card uses an inline <style>"
        );
        assert!(LOADER_HTML.contains("<svg"), "wordmark is an inline <svg>");
        // Exactly ONE same-origin <script src> — the embed snippet — and NO cross-origin script.
        let script_src_tags: Vec<&str> = LOADER_HTML
            .match_indices("<script src=")
            .map(|(i, _)| &LOADER_HTML[i..i + 60])
            .collect();
        assert_eq!(
            script_src_tags.len(),
            1,
            "loader.html must have exactly one <script src> (the same-origin embed snippet), got: {script_src_tags:?}"
        );
        assert!(
            LOADER_HTML.contains(r#"<script src="/__dig/dig-embed.js""#),
            "the single <script src> must be the same-origin embed snippet"
        );
        // No cross-origin scheme in any script src (no https:// / http:// / // src).
        assert!(
            !LOADER_HTML.contains("<script src=\"http")
                && !LOADER_HTML.contains("<script src=\"//"),
            "loader.html must not load a cross-origin script (would violate LOADER_CSP)"
        );
    }

    #[test]
    fn render_loader_maps_to_loader_csp_and_carries_branded_sentinels() {
        use crate::domain::{Domain, DomainStatus};
        let d = Domain {
            subdomain: "foo".into(),
            owner_ph: "p".into(),
            pinned_store_id: "aa".repeat(32),
            pinned_root: None,
            salt: None,
            status: DomainStatus::Active,
            registered_at: Some(0),
            expires_at: None,
            renewal_due_at: None,
            reg_spend_id: None,
            reg_coin_id: None,
            created_at: 0,
            reg_price_baseunits: None,
        };
        let render = render_for(Some(d), 100);
        assert!(matches!(render, Render::Loader(_)));
        // The Loader arm MUST select LOADER_CSP (not the static-page or content policy).
        assert_eq!(csp_for(&render), LOADER_CSP);
        // The branded-card sentinels the served loader carries (so a "never blank" first paint is
        // guaranteed): the card class, the wordmark gradient, and the "DIG Network" label.
        assert!(
            LOADER_HTML.contains("dig-card"),
            "branded card class present"
        );
        assert!(
            LOADER_HTML.contains("linearGradient") && LOADER_HTML.contains("#ff00de"),
            "wordmark gradient present"
        );
        assert!(
            LOADER_HTML.contains("DIG Network"),
            "the DIG Network wordmark label is present"
        );
    }

    #[test]
    fn static_pages_get_the_tight_inert_csp() {
        // The status pages are inert (no script/connect/worker): script-src 'none'.
        assert!(STATIC_PAGE_CSP.contains("script-src 'none'"));
        assert!(STATIC_PAGE_CSP.contains("connect-src 'none'"));
        assert_eq!(csp_for(&Render::Available), STATIC_PAGE_CSP);
        assert_eq!(csp_for(&Render::Pending), STATIC_PAGE_CSP);
        assert_eq!(csp_for(&Render::Expired), STATIC_PAGE_CSP);
        assert_eq!(csp_for(&Render::Revoked), STATIC_PAGE_CSP);
    }

    #[test]
    fn loader_embed_script_is_deferred_and_after_the_branded_body() {
        // FIX C: the embed <script> must run AFTER the branded card paints, so a slow/blocked/failed
        // embed leaves the branded loader visible rather than a blank overlay. Enforce that the
        // <script src> is (a) deferred and (b) positioned after the branded <main class="dig-card">.
        let script_pos = LOADER_HTML
            .find(r#"<script src="/__dig/dig-embed.js""#)
            .expect("embed script tag present");
        let card_pos = LOADER_HTML
            .find(r#"class="dig-card""#)
            .expect("branded card present");
        assert!(
            script_pos > card_pos,
            "the embed <script> must come AFTER the branded card so the card paints first"
        );
        // The tag must carry `defer` so it never blocks the branded first paint.
        let tag_end = LOADER_HTML[script_pos..]
            .find('>')
            .map(|e| script_pos + e)
            .unwrap();
        let tag = &LOADER_HTML[script_pos..tag_end];
        assert!(
            tag.contains("defer"),
            "the embed <script> must be deferred; got: {tag}"
        );
    }

    #[test]
    fn loader_bootstrap_marks_the_shell_present() {
        // FIX C: the inline bootstrap sets a flag so dig-embed.js reuses the already-painted shell
        // instead of stacking a second full-screen overlay (the duplicate-branding fragility).
        assert!(
            LOADER_HTML.contains("__digLoaderShellPresent"),
            "loader.html must set window.__digLoaderShellPresent so the embed reuses the shell"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_decision_branches() {
        use crate::domain::{Domain, DomainStatus};
        let base = |status, exp| Domain {
            subdomain: "foo".into(),
            owner_ph: "p".into(),
            pinned_store_id: "aa".repeat(32),
            pinned_root: None,
            salt: None,
            status,
            registered_at: Some(0),
            expires_at: exp,
            renewal_due_at: None,
            reg_spend_id: None,
            reg_coin_id: None,
            created_at: 0,
            reg_price_baseunits: None,
        };
        // missing → available page
        assert_eq!(render_for(None, 100), Render::Available);

        // Active domain is PERMANENT: renders Loader regardless of any now value.
        // expires_at = None (permanent Active).
        assert!(matches!(
            render_for(Some(base(DomainStatus::Active, None)), 100),
            Render::Loader(_)
        ));
        // Still Loader far in the future.
        assert!(matches!(
            render_for(Some(base(DomainStatus::Active, None)), u64::MAX),
            Render::Loader(_)
        ));

        // pending → pending page
        assert_eq!(
            render_for(Some(base(DomainStatus::Pending, None)), 100),
            Render::Pending
        );
        // reserved (with a non-expired hold) → also a pending page
        assert_eq!(
            render_for(Some(base(DomainStatus::Reserved, Some(1000))), 100),
            Render::Pending
        );
        // revoked → takedown
        assert_eq!(
            render_for(Some(base(DomainStatus::Revoked, None)), 100),
            Render::Revoked
        );

        // A lapsed Reserved hold (15-min window expired, never paid) → Available.
        // expires_at = 50, now = 51 → reclaimable → Available.
        assert_eq!(
            render_for(Some(base(DomainStatus::Reserved, Some(50))), 51),
            Render::Available
        );
        // At exactly expires_at: NOT yet reclaimable → still Pending.
        assert_eq!(
            render_for(Some(base(DomainStatus::Reserved, Some(50))), 50),
            Render::Pending
        );
    }

    #[test]
    fn loader_config_embeds_pin() {
        use crate::domain::{Domain, DomainStatus};
        let d = Domain {
            subdomain: "foo".into(),
            owner_ph: "p".into(),
            pinned_store_id: "aa".repeat(32),
            pinned_root: Some("bb".repeat(32)),
            salt: None,
            status: DomainStatus::Active,
            registered_at: Some(0),
            expires_at: None,
            renewal_due_at: None,
            reg_spend_id: None,
            reg_coin_id: None,
            created_at: 0,
            reg_price_baseunits: None,
        };
        let cfg = loader_config(&d);
        let v: serde_json::Value = serde_json::from_str(&cfg).unwrap();
        assert_eq!(v["storeId"], "aa".repeat(32));
        assert_eq!(v["root"], "bb".repeat(32));
        assert_eq!(v["rpc"], "https://rpc.dig.net/");
        assert_eq!(v["subdomain"], "foo");
        assert!(v["salt"].is_null());
    }

    #[test]
    fn extracts_subdomain_from_host() {
        assert_eq!(subdomain_of("foo.on.dig.net"), Some("foo".to_string()));
        assert_eq!(subdomain_of("Foo.On.Dig.Net"), Some("foo".to_string())); // lowercased
        assert_eq!(subdomain_of("foo.on.dig.net:443"), Some("foo".to_string())); // strips port
        assert_eq!(subdomain_of("on.dig.net"), None); // apex, no subdomain
        assert_eq!(subdomain_of("a.b.on.dig.net"), None); // multi-label rejected
        assert_eq!(subdomain_of("hub.dig.net"), None); // wrong base
        assert_eq!(subdomain_of("foo.on.dig.net."), Some("foo".to_string())); // trailing FQDN dot
        assert_eq!(subdomain_of("xon.dig.net"), None); // missing dot separator before base
        assert_eq!(subdomain_of("foo_bad.on.dig.net"), None); // invalid charset (underscore)
        assert_eq!(subdomain_of("www.on.dig.net"), None); // reserved label
    }

    #[test]
    fn custom_host_candidate_only_for_real_external_domains() {
        // A genuine external custom domain → candidate (normalized lowercase, port/dot stripped).
        assert_eq!(
            custom_host_candidate("app.example.com"),
            Some("app.example.com".to_string())
        );
        assert_eq!(
            custom_host_candidate("App.Example.COM:443"),
            Some("app.example.com".to_string())
        );
        assert_eq!(
            custom_host_candidate("app.example.com."),
            Some("app.example.com".to_string())
        );

        // CRITICAL SAFETY: never treat any on.dig.net host as a custom domain — the wildcard
        // resolve path (subdomain_of) owns those, untouched.
        assert_eq!(custom_host_candidate("foo.on.dig.net"), None);
        assert_eq!(custom_host_candidate("on.dig.net"), None);
        assert_eq!(custom_host_candidate("a.b.on.dig.net"), None);

        // Apex / single-label / empty are not attachable custom domains.
        assert_eq!(custom_host_candidate("localhost"), None);
        assert_eq!(custom_host_candidate(""), None);
        assert_eq!(custom_host_candidate("   "), None);
    }

    #[test]
    fn loader_config_escapes_script_breakout() {
        use crate::domain::{Domain, DomainStatus};
        let d = Domain {
            subdomain: "foo".into(),
            owner_ph: "p".into(),
            pinned_store_id: "aa".repeat(32),
            pinned_root: None,
            salt: Some("</script><x>".into()),
            status: DomainStatus::Active,
            registered_at: Some(0),
            expires_at: None,
            renewal_due_at: None,
            reg_spend_id: None,
            reg_coin_id: None,
            created_at: 0,
            reg_price_baseunits: None,
        };
        let cfg = loader_config(&d);
        assert!(
            !cfg.contains("</script>"),
            "must not contain a raw </script>"
        );
        assert!(cfg.contains("<\\/script>"));
        // still valid JSON that round-trips the salt back to the original
        let v: serde_json::Value = serde_json::from_str(&cfg).unwrap();
        assert_eq!(v["salt"], "</script><x>");
    }

    #[test]
    fn is_static_asset_path_classifies_assets_vs_navigation() {
        // Navigation / document routes (no extension, or an HTML extension) are NOT assets — they get
        // the branded loader shell. An SPA client route is a navigation route.
        assert!(!is_static_asset_path("/"));
        assert!(!is_static_asset_path("/about"));
        assert!(!is_static_asset_path("/chat/123"));
        assert!(!is_static_asset_path("/index.html"));
        assert!(!is_static_asset_path("/nested/page.htm"));
        // An SPA route whose last segment contains a dot but not a KNOWN asset extension is still a
        // navigation route (must not be mis-404'd) — e.g. a username or a version-like segment.
        assert!(!is_static_asset_path("/user/john.doe"));
        assert!(!is_static_asset_path("/v1.2"));

        // The load-bearing case (#144): a service worker script + ES modules MUST be classified as
        // assets so the resolver never answers them with the loader shell's text/html.
        assert!(is_static_asset_path("/service-worker.js"));
        assert!(is_static_asset_path("/sw.js"));
        assert!(is_static_asset_path("/firebase-messaging-sw.js"));
        assert!(is_static_asset_path("/assets/app.min.mjs"));

        // Other known static assets that must get a real 404 (not the shell) when they reach the Lambda.
        assert!(is_static_asset_path("/styles/main.css"));
        assert!(is_static_asset_path("/data/config.json"));
        assert!(is_static_asset_path("/_framework/dotnet.wasm"));
        assert!(is_static_asset_path("/img/logo.svg"));
        assert!(is_static_asset_path("/bundle.js.map"));
        assert!(is_static_asset_path("/PHOTO.PNG")); // case-insensitive extension

        // Robustness: only the FINAL path segment's extension decides.
        assert!(is_static_asset_path("/a.b.c/final.js"));
        assert!(!is_static_asset_path("/a.b.c/final"));
    }

    #[test]
    fn shared_validation_is_reexported() {
        // The label validator + reserved list come from the domain module; confirm the re-export
        // surface compiles + behaves here.
        assert!(validate_label("alice").is_ok());
        assert!(validate_label("www").is_err());
        assert!(RESERVED_WORDS.contains(&"rpc"));
    }

    fn domain(status: DomainStatus, exp: Option<u64>) -> Domain {
        use crate::domain::Domain;
        Domain {
            subdomain: "foo".into(),
            owner_ph: "p".into(),
            pinned_store_id: "aa".repeat(32),
            pinned_root: Some("bb".repeat(32)),
            salt: None,
            status,
            registered_at: Some(0),
            expires_at: exp,
            renewal_due_at: None,
            reg_spend_id: None,
            reg_coin_id: None,
            created_at: 0,
            reg_price_baseunits: None,
        }
    }

    // #206b — the loader shell fetches /__dig/config.json ASYNC after its INSTANT branded paint;
    // this endpoint is the AUTHORITATIVE source of status + pin, resolved OFF the document path.
    #[test]
    fn config_json_active_carries_status_and_pin() {
        let cfg = config_json_for(Some(domain(DomainStatus::Active, None)), 100);
        let v: serde_json::Value = serde_json::from_str(&cfg).unwrap();
        assert_eq!(v["status"], "active");
        assert_eq!(v["storeId"], "aa".repeat(32));
        assert_eq!(v["root"], "bb".repeat(32));
        assert_eq!(v["rpc"], "https://rpc.dig.net/");
        assert_eq!(v["subdomain"], "foo");
    }

    #[test]
    fn config_json_non_active_carries_only_status() {
        // Missing row → available (name free).
        let v: serde_json::Value = serde_json::from_str(&config_json_for(None, 100)).unwrap();
        assert_eq!(v["status"], "available");
        assert!(v["storeId"].is_null(), "non-active must not leak a pin");

        // Pending / Expired / Revoked map to their status strings, no pin.
        for (st, want) in [
            (DomainStatus::Pending, "pending"),
            (DomainStatus::Expired, "expired"),
            (DomainStatus::Revoked, "revoked"),
        ] {
            let v: serde_json::Value =
                serde_json::from_str(&config_json_for(Some(domain(st, None)), 100)).unwrap();
            assert_eq!(v["status"], want);
            assert!(v["storeId"].is_null());
        }

        // A lapsed Reserved hold → available (reclaimed).
        let v: serde_json::Value = serde_json::from_str(&config_json_for(
            Some(domain(DomainStatus::Reserved, Some(50))),
            51,
        ))
        .unwrap();
        assert_eq!(v["status"], "available");
    }

    #[test]
    fn config_json_reserved_hold_is_pending() {
        // A non-lapsed Reserved hold serves the "pending" status (an in-flight reservation).
        let v: serde_json::Value = serde_json::from_str(&config_json_for(
            Some(domain(DomainStatus::Reserved, Some(2_000))),
            1_000,
        ))
        .unwrap();
        assert_eq!(v["status"], "pending");
    }

    #[test]
    fn config_json_is_always_valid_json_with_a_status() {
        // Every arm must round-trip as JSON carrying a non-empty status (the client keys off it).
        for cfg in [
            config_json_for(Some(domain(DomainStatus::Active, None)), 0),
            config_json_for(Some(domain(DomainStatus::Pending, None)), 0),
            config_json_for(None, 0),
        ] {
            let v: serde_json::Value = serde_json::from_str(&cfg).unwrap();
            assert!(v
                .get("status")
                .and_then(|s| s.as_str())
                .is_some_and(|s| !s.is_empty()));
        }
    }

    #[test]
    fn config_json_active_escapes_script_breakout() {
        // The Active pin can carry a salt; the endpoint is served as application/json (not inlined
        // in HTML), but the underlying loader_config still escapes </ so a shared pin string is safe
        // to inline anywhere. Confirm the merged status body preserves that + stays valid JSON.
        let mut d = domain(DomainStatus::Active, None);
        d.salt = Some("</script><x>".into());
        let cfg = config_json_for(Some(d), 0);
        assert!(
            !cfg.contains("</script>"),
            "must not contain a raw </script>"
        );
        let v: serde_json::Value = serde_json::from_str(&cfg).unwrap();
        assert_eq!(v["status"], "active");
        assert_eq!(v["salt"], "</script><x>");
    }

    #[test]
    fn status_str_maps_every_render() {
        assert_eq!(status_str(&Render::Loader(String::new())), "active");
        assert_eq!(status_str(&Render::Available), "available");
        assert_eq!(status_str(&Render::Pending), "pending");
        assert_eq!(status_str(&Render::Expired), "expired");
        assert_eq!(status_str(&Render::Revoked), "revoked");
    }
}

/// #206b — the STATIC loader shell contract. The document `/` response is a STATIC branded loader
/// shell served INSTANTLY (no per-request DynamoDB lookup, no baked pin): the branded card paints on
/// Lambda-response latency alone, THEN the shell fetches `/__dig/config.json` async to resolve
/// status + pin. These tests read the ACTUAL served asset bytes so a regression that re-introduces a
/// baked-in pin (blocking first paint on the backend) fails.
#[cfg(test)]
mod static_shell_tests {
    const LOADER_HTML: &str = include_str!("../assets/loader.html");

    #[test]
    fn loader_shell_bakes_no_per_store_config() {
        // The old model baked `window.__DIG__ = __CONFIG_JSON__` server-side (forcing a DynamoDB
        // lookup on the document path). The static shell MUST NOT carry that placeholder — it is
        // identical for every subdomain + every Active store.
        assert!(
            !LOADER_HTML.contains("__CONFIG_JSON__"),
            "the static loader shell must NOT bake a per-store config placeholder"
        );
    }

    #[test]
    fn loader_shell_fetches_config_json_async() {
        // The shell resolves its pin + status by fetching the config endpoint client-side (async),
        // so the branded card never waits on the backend lookup.
        assert!(
            LOADER_HTML.contains("/__dig/config.json"),
            "the loader shell must fetch /__dig/config.json to resolve pin + status"
        );
    }

    #[test]
    fn loader_shell_still_paints_the_branded_card_first() {
        // The branded card + wordmark are still server-rendered inline (first paint branded), and
        // the embed script is still deferred at the end of <body> (never blocks the card).
        let card = LOADER_HTML
            .find(r#"class="dig-card""#)
            .expect("branded card present");
        let script = LOADER_HTML
            .find(r#"<script src="/__dig/dig-embed.js""#)
            .expect("embed script present");
        assert!(
            script > card,
            "embed script must come after the branded card"
        );
        assert!(
            LOADER_HTML.contains("__digLoaderShellPresent"),
            "the shell-present flag must still be set so the embed reuses the shell"
        );
    }

    #[test]
    fn loader_shell_carries_the_non_active_status_copy() {
        // The shell swaps the branded card's message to the matching status text WITHOUT navigating
        // away, so the branded shell stays visible for every non-active state. The status→copy map
        // must be present in the shell for pending / expired / revoked / available.
        for status in ["pending", "expired", "revoked", "available"] {
            assert!(
                LOADER_HTML.contains(status),
                "the loader shell must carry copy for the '{status}' status"
            );
        }
    }
}

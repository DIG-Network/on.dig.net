// services/resolver/assets/sw.js
//
// Service worker for <subdomain>.on.dig.net pinned-URN resolver.
// Intercepts same-origin GET requests, fetches ciphertext via the dig JSON-RPC,
// verifies the merkle inclusion proof, decrypts client-side with the dig-client
// WASM, and returns a Response.  The Lambda (and server) NEVER see plaintext.
//
// INIT MODEL (load-bearing detail):
//   apps/web/public/dig-client/dig_client.js is a wasm-bindgen *ES module*:
//   it uses `import.meta.url` and `export function …`.  It CANNOT be loaded via
//   importScripts() in a classic worker.  This SW therefore MUST be registered
//   with { type:"module" } (see loader.html) so it can use a top-level `import`.
//   The default export is the async init function (takes a URL, Response, or
//   ArrayBuffer).  Named exports — retrievalKey, deriveKey, verifyInclusion,
//   decryptChunk, install_global — are used directly from the module object.
//   No `wasm_bindgen` global; no `parseUrn` export — URN parsing is in JS below.
//
// Mirrors the read flow in apps/web/lib/dig-client.js (fetchVerifiedCiphertext +
// decryptResourceChunks) and the dig-browser-extension service worker model.
//
// #205d/#205e (PERFORMANCE, this file only — see SPEC.md §9):
//   - Network fetch fans the per-window byte-range GETs out in PARALLEL (bounded,
//     `MAX_PARALLEL_RANGES`) instead of one-at-a-time, once the first window has told us the
//     resource's total length. The resource-level merkle inclusion proof still requires the
//     FULL ciphertext (its leaf is a hash of the whole resource), so verification itself is
//     unchanged — only the network round-trips leading up to it are parallelized.
//   - Decrypt output is STREAMED to the Response body: chunk 0 is decrypted eagerly (before any
//     Response exists, preserving the exact prior fail-closed "wrong key/decoy → 404" behavior),
//     then chunks 1..N are decrypted lazily as the stream is pulled, so the browser can start
//     consuming a large multi-chunk resource before the last chunk is decrypted. Every chunk
//     still goes through its own AEAD-authenticated decryptChunk() call — nothing is skipped.
//   - The compiled WASM module + decrypted PINNED-resource output are persisted in the Cache
//     API so a repeat load skips the wasm re-fetch/recompile and the RPC round-trip + decrypt.
//     Only PINNED (concrete-root) reads are persisted — an unpinned "latest" read is mutable, so
//     persisting it could serve stale content after the underlying value changes.

// ---- WASM glue import (ES module worker only) --------------------------------
// The init function and named crypto exports.  The paths are same-origin because
// the Lambda serves /__dig/dig_client.js and /__dig/dig_client_bg.wasm (Task 5).
import initDigClient, {
  retrievalKey,
  deriveKey,
  verifyInclusion,
  decryptChunk,
  install_global,
} from "/__dig/dig_client.js";

// SRI for the read-crypto WASM (parity with apps/web/lib/dig-client.js, audit frontend-152).
// Same artifact, same digest — regenerate BOTH on a wasm rebuild. Fail closed: a mismatch
// (tampered/wrong artifact) refuses to run unverified crypto.
const DIG_CLIENT_WASM_SHA256 = "ff486be806f908a2a90780e499a04dbd34e10e3b97be0470cb9ee841a1e49e77";

// ---- Lifecycle ---------------------------------------------------------------
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

// ---- Module-level state ------------------------------------------------------
// CFG is fetched lazily on first intercepted request.
let CFG = null;   // { storeId, root, salt, rpc, subdomain }
// digReady serialises the one-shot WASM init (memoised promise).
let digReady = null;

// ---- Constants ---------------------------------------------------------------
// The RPC back-end caps each window at 3 MiB; we loop until `complete` on the POST fallback path.
const RPC_CHUNK = 3 * 1024 * 1024;

// #205a — the cacheable GET content path. A ROOT-PINNED resource read is immutable + content-
// addressed, so it is served over a plain GET the CloudFront edge caches for a year (1-year immutable
// Cache-Control, cache key = Host+path+{root,range}). This collapses the dominant B1 cost from
// N×RTT(viewer→us-east-1) to N×RTT(viewer→nearest PoP) on a cold PoP, and to ~0 (browser HTTP cache)
// on repeat. We window the resource in aligned 1-MiB blocks so every PoP request is a cache key a
// neighbour also produces (no fragmentation), and align to the SAME 64-KiB block size the Lambda
// snaps to. The verification metadata (inclusion proof, chunk lengths, program hash, total length)
// rides response HEADERS here (parity with the JSON-RPC envelope) — see the X-Dig-* headers below.
const GET_WINDOW = 1024 * 1024; // 1 MiB aligned windows for the cacheable GET path
const HDR_INCLUSION_PROOF = "x-dig-inclusion-proof";
const HDR_CHUNK_LENS = "x-dig-chunk-lens";
const HDR_PROGRAM_HASH = "x-dig-program-hash";
const HDR_TOTAL_LENGTH = "x-dig-total-length";

// #205d — how many byte-range windows to fetch concurrently once the total length is known (the
// first window must always be fetched alone since it is what TELLS us the total). Bounded so a
// huge resource can't open unbounded concurrent connections; comfortably under both browsers'
// per-origin HTTP/1.1 limits and typical HTTP/2 stream caps, while still collapsing an N-window
// resource from N sequential RTTs to ~N/MAX_PARALLEL_RANGES.
const MAX_PARALLEL_RANGES = 6;

// #205e — Cache Storage names for the persisted WASM module + persisted decrypted PINNED content.
// Versioned suffixes so a future incompatible change to what's stored can start a fresh cache
// without needing manual migration/cleanup logic.
const WASM_CACHE_NAME = "dig-wasm-v1";
const CONTENT_CACHE_NAME = "dig-content-v1";
// Soft cap on the number of persisted decrypted-content entries; oldest-first eviction on overflow
// (mirrors the in-memory CACHE_MAX policy below) so a long-lived origin can't grow this unbounded.
const CONTENT_CACHE_MAX = 200;

// Store-sandbox CSP for the DECRYPTED DOCUMENTS this SW synthesizes (#202, #175 root cause).
//
// WHY the SW must set this itself: an SW-synthesized Response never receives the edge CSP. The
// store document a visitor sees is built here by serveUrn(); without this header the decrypted
// document would run with NO CSP at all — the per-subdomain sandbox would be ABSENT. This constant
// IS that sandbox.
//
// TWO DISTINCT TRUST CONTEXTS (#206): this STORE-CONTENT sandbox is DELIBERATELY DIFFERENT from the
// LOADER-SHELL CSP. The loader shell (loader.html — first-party inline branding + bootstrap + the
// same-origin embed snippet, reaching only rpc.dig.net) is governed by the resolver Lambda's
// LOADER_CSP (services/resolver/src/lib.rs), attached per-response, and stays tight. This STORE_CSP
// governs the decrypted USER SITE — arbitrary, developer-authored web content — and must let it
// behave like a site hosted on any normal static host (Netlify/Vercel/Pages).
//
// SECURITY MODEL (#206e): the REAL isolation boundary is the ORIGIN — every store is served on its
// OWN `<storeId>.on.dig.net` subdomain, so the same-origin policy already prevents one store from
// reading another store's DOM, storage, cookies, or wallet session. That boundary holds regardless
// of how permissive this CSP is. Therefore this CSP MUST NOT restrict which external hosts a user's
// OWN site may talk to — doing so breaks ordinary sites (their API/fetch/websocket backend, CDN
// scripts/styles/fonts, external images/media, embeds). A site deployed to DIG should "just work"
// exactly as it would anywhere else. So we allow the full web surface (https:/wss:/data:/blob:)
// across every fetch directive, keep 'unsafe-inline'/'unsafe-eval' (frameworks need them), and retain
// ONLY the two zero-cost hardening guards that never block a legitimate modern site:
//   • object-src 'none'  — kills the legacy <object>/<embed> (Flash/plugin) XSS vector; no modern site needs it.
//   • base-uri 'self'    — prevents <base href> hijack within the site; near-zero legitimate use.
// frame-ancestors is intentionally UNSET so a DIG-hosted site is embeddable like any normal site.
// (This blanket https:/wss: also subsumes the sanctioned tip-widget origins — hub.dig.net / esm.sh /
// coinset / WalletConnect relay — so they no longer need an explicit allowlist here.)
const STORE_CSP =
  "default-src 'self' https: data: blob:; " +
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' https: data: blob:; " +
  "style-src 'self' 'unsafe-inline' https:; " +
  "img-src 'self' data: blob: https:; " +
  "font-src 'self' data: https:; " +
  "media-src 'self' data: blob: https:; " +
  "connect-src 'self' https: wss: data: blob:; " +
  "worker-src 'self' blob:; " +
  "frame-src 'self' https: blob:; " +
  "child-src 'self' https: blob:; " +
  "object-src 'none'; base-uri 'self'";

/**
 * Build the response headers for a served resource. HTML documents additionally carry the
 * store-sandbox CSP (+ nosniff) so the per-subdomain sandbox is enforced on the SW path (the edge
 * CSP never reaches an SW-synthesized Response — see STORE_CSP). Non-HTML resources (js/css/img/
 * wasm/…) are subresources of that document and inherit its policy, so they need no CSP of their own.
 */
function resourceHeaders(resourceKey, extra) {
  const ct = contentType(resourceKey);
  const headers = { "content-type": ct, ...extra };
  if (ct.startsWith("text/html")) {
    headers["content-security-policy"] = STORE_CSP;
    headers["x-content-type-options"] = "nosniff";
  }
  return headers;
}

// ---- Helpers -----------------------------------------------------------------

/** Decode standard-base64 to Uint8Array. */
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Infer a MIME type from a file extension.
 * SINGLE SOURCE OF TRUTH: apps/web/lib/embed-core.ts `contentType()` (unit-tested). This map MUST stay
 * byte-identical to that one and to apps/web/public/embed/dig-embed.js — a standalone module worker
 * can't import the TS module, so the map is mirrored here. (Previously this copy had drifted and was
 * missing avif/ttf/otf/mp3, so those resources served as application/octet-stream — now in sync.)
 */
function contentType(resourceKey) {
  const ext = (resourceKey.split(".").pop() || "").toLowerCase();
  return (
    {
      html: "text/html; charset=utf-8", htm: "text/html; charset=utf-8",
      js: "text/javascript; charset=utf-8", mjs: "text/javascript; charset=utf-8",
      css: "text/css; charset=utf-8", json: "application/json",
      png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif",
      svg: "image/svg+xml", webp: "image/webp", ico: "image/x-icon", avif: "image/avif",
      woff: "font/woff", woff2: "font/woff2", ttf: "font/ttf", otf: "font/otf",
      txt: "text/plain", pdf: "application/pdf", mp4: "video/mp4", webm: "video/webm",
      mp3: "audio/mpeg", wasm: "application/wasm", xml: "application/xml", md: "text/markdown",
    }[ext] || "application/octet-stream"
  );
}

/**
 * Read the pin baked into the SW registration URL by dig-embed.js Tier 1, if present.
 * The embed snippet registers `/__dig_sw.js?store=…&root=…&salt=…&entry=…` so a SAME-ORIGIN
 * host that self-serves this SW (not just the *.on.dig.net resolver) can pass the pin without a
 * server-side /__dig/config.json. The resolver path leaves the query empty and uses config.json.
 */
function cfgFromRegistration() {
  try {
    const qs = new URL(self.location.href).searchParams;
    const storeId = qs.get("store");
    if (!storeId) return null;
    return {
      storeId,
      root: qs.get("root") || null,
      salt: qs.get("salt") || null,
      rpc: "https://rpc.dig.net/",
      subdomain: null,
    };
  } catch {
    return null;
  }
}

/**
 * Build the Cache Storage key for the verified dig-client WASM artifact. Content-addressed by the
 * expected SHA-256 (query param, not a real endpoint param — this Request is only ever used as a
 * caches.match()/put() key, never actually fetched): a wasm rebuild changes
 * DIG_CLIENT_WASM_SHA256, which naturally MISSES the old entry rather than ever risking a stale or
 * mismatched artifact being served from the persisted cache.
 *
 * Resolved against `self.location` explicitly (rather than a bare relative string) — a real
 * Service Worker's `Request`/`fetch` resolve a relative path against the worker's own script URL
 * automatically, but that implicit base does not exist in every JS host (e.g. plain Node, used by
 * this repo's unit tests), so an absolute URL keeps this key construction environment-independent.
 */
function wasmCacheKey(hash) {
  return new Request(new URL("/__dig/dig_client_bg.wasm?sha256=" + hash, self.location.href));
}

/**
 * Fetch (or reuse from the Cache API) the verified dig-client WASM as a Response, ready to hand to
 * `initDigClient({ module_or_path: … })`.
 *
 * #205e: on a cache hit, the Response comes from `caches.match()` — passing THAT into
 * `WebAssembly.instantiateStreaming` (which is what the wasm-bindgen glue's `__wbg_load` does for
 * any `Response` input) lets the browser reuse the compiled-code cache it automatically associates
 * with a Cache Storage entry, skipping recompilation entirely on this and every subsequent load
 * until the pinned SHA-256 changes (see https://web.dev/articles/wasm-caching). The hash was
 * already verified at write-time below; Cache Storage is same-origin, SW-private storage that only
 * this worker's own code writes to (never network-attacker-controlled), so a cache hit is trusted
 * without re-hashing — exactly as an already-verified, already-instantiated module in memory would
 * be trusted for the rest of a session.
 *
 * On a miss: fetch, hash-verify (fail closed on mismatch — UNCHANGED invariant), persist the
 * verified Response for next time (best-effort; a quota/private-mode failure must not block using
 * the wasm we already verified), and return the original (unconsumed) Response for streaming
 * instantiation.
 */
async function loadDigClientWasmResponse() {
  let cache = null;
  try {
    cache = await caches.open(WASM_CACHE_NAME);
  } catch {
    cache = null; // Cache Storage unavailable (private mode / quota) — fetch every time instead.
  }
  const key = wasmCacheKey(DIG_CLIENT_WASM_SHA256);
  if (cache) {
    const cached = await cache.match(key);
    if (cached) return cached;
  }

  const res = await fetch("/__dig/dig_client_bg.wasm");
  if (!res.ok) throw new Error(`dig-client wasm fetch failed (${res.status})`);
  const bytes = new Uint8Array(await res.clone().arrayBuffer());
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hex = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (hex !== DIG_CLIENT_WASM_SHA256) {
    throw new Error("dig-client wasm integrity check failed — refusing to run unverified crypto");
  }
  if (cache) {
    try {
      await cache.put(key, res.clone());
    } catch {
      // Best-effort persistence only; the already-verified `res` below still works fine.
    }
  }
  return res;
}

/**
 * Ensure the WASM module is initialised (once) and CFG is loaded.
 * Returns nothing; after awaiting this, the imported named functions are ready.
 */
async function ensureDig() {
  if (!CFG) {
    // Prefer a pin embedded in the registration URL (dig-embed.js Tier 1 self-host); otherwise fall
    // back to the resolver's server-served /__dig/config.json (the *.on.dig.net path).
    CFG = cfgFromRegistration();
    if (!CFG) {
      const res = await fetch("/__dig/config.json");
      if (!res.ok) throw new Error("could not load DIG config (" + res.status + ")");
      CFG = await res.json();
    }
  }
  if (!digReady) {
    digReady = (async () => {
      const res = await loadDigClientWasmResponse();
      await initDigClient({ module_or_path: res });
      // Install globalThis.digClient for any non-bundler consumers (no-op here
      // since we use named imports, but keeps the contract consistent).
      if (typeof install_global === "function") install_global();
    })();
  }
  await digReady;
}

/**
 * One JSON-RPC 2.0 call.  Throws on transport failure or a JSON-RPC error.
 */
async function rpcCall(method, params) {
  let res;
  try {
    res = await fetch(CFG.rpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
  } catch {
    throw new Error("Could not reach the content network. Check your connection.");
  }
  if (!res.ok) throw new Error("dig RPC HTTP error " + res.status);
  const j = await res.json();
  if (j && j.error) throw new Error("dig RPC " + method + ": " + (j.error.message || "error"));
  return j ? j.result : null;
}

/** Whether `root` is a concrete, PINNED generation root (a 64-hex string) — the only reads that are
 *  immutable + edge-cacheable. A rootless / "latest" read is mutable and MUST NOT use the cache path.
 */
function rootIsPinned(root) {
  return typeof root === "string" && /^[0-9a-f]{64}$/i.test(root);
}

/** Parse the comma-separated `X-Dig-Chunk-Lens` header value into a number[] (empty ⇒ null). */
function parseChunkLensHeader(v) {
  if (!v) return null;
  const lens = v
    .split(",")
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => Number.isFinite(n) && n >= 0);
  return lens.length ? lens : null;
}

/**
 * Compute the aligned windows (end INCLUSIVE, matching the `range=<start>-<end>` query
 * convention) covering `[0, total)` in steps of `windowSize`. Pure + side-effect-free so it is
 * directly unit-testable without a network/browser environment.
 */
function planWindows(total, windowSize) {
  const windows = [];
  for (let start = 0, index = 0; start < total; start += windowSize, index++) {
    windows.push({ index, start, end: Math.min(start + windowSize, total) - 1 });
  }
  return windows;
}

/**
 * Run `worker(item, i)` over `items` with at most `concurrency` in flight at once (a bounded
 * worker-pool / fan-out). Pure orchestration — no network/crypto dependency — used to fetch
 * multiple byte-range windows in PARALLEL (#205d) instead of the previous one-at-a-time loop.
 * Each lane pulls the next unclaimed index itself (plain `next++`, single-threaded JS — no race),
 * so a slow window never head-of-line-blocks a faster one behind it.
 */
async function runParallel(items, worker, concurrency) {
  let next = 0;
  const lanes = Math.max(1, Math.min(concurrency, items.length));
  async function lane() {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      await worker(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: lanes }, lane));
}

/**
 * Fetch the full ciphertext for a PINNED resource over the CACHEABLE GET content path (#205a),
 * reassembling aligned 1-MiB windows the CloudFront edge caches for a year. Reads the verification
 * metadata from response HEADERS (inclusion proof / chunk lens / program hash / total length) —
 * parity with the JSON-RPC envelope. Returns the same shape as `fetchVerified`. Throws on any
 * non-200 window so the caller can fall back to the POST JSON-RPC path.
 *
 * The GET URL: `<rpcOrigin>/stores/<storeId>/content/<rk>?root=<root>&range=<start>-<end>`. Windows
 * are 1-MiB, aligned to the window size so every PoP request is a shared cache key (the Lambda snaps
 * ranges to 64-KiB blocks; 1 MiB is a multiple, so no fragmentation).
 *
 * #205d: window 0 is fetched alone (it is the only way to learn the resource's total length); every
 * remaining window is independent and edge-cacheable, so once the total is known they are fanned out
 * in PARALLEL (bounded, `MAX_PARALLEL_RANGES`) rather than awaited one at a time. This does not touch
 * verification — the caller still checks the merkle inclusion proof over the fully-reassembled
 * ciphertext exactly as before; only the round-trips leading up to that are now concurrent.
 */
async function fetchVerifiedGet(storeId, rk, root) {
  // The content edge is the SAME origin as the JSON-RPC endpoint (rpc.dig.net) — reuse CFG.rpc.
  const base = (CFG.rpc || "https://rpc.dig.net/").replace(/\/+$/, "");
  const contentUrl = (start, end) =>
    `${base}/stores/${storeId}/content/${rk}?root=${root}&range=${start}-${end}`;

  // `cache: "force-cache"` leans on the browser HTTP cache + the CloudFront edge cache (the
  // response is 1-year immutable), so a repeat/same-session read is local and a warm PoP is fast.
  const first = await fetch(contentUrl(0, GET_WINDOW - 1), { cache: "force-cache" });
  if (!first.ok) throw new Error("dig content GET failed (" + first.status + ")");
  const total = parseInt(first.headers.get(HDR_TOTAL_LENGTH) || "", 10);
  if (!Number.isFinite(total)) throw new Error("content GET missing total length");
  const proof = first.headers.get(HDR_INCLUSION_PROOF) || "";
  const chunkLens = parseChunkLensHeader(first.headers.get(HDR_CHUNK_LENS));

  const buf = new Uint8Array(total >>> 0);
  const firstBytes = new Uint8Array(await first.arrayBuffer());
  buf.set(firstBytes.subarray(0, Math.min(firstBytes.length, buf.length)), 0);

  const remaining = planWindows(buf.length, GET_WINDOW).filter((w) => w.index > 0);
  await runParallel(
    remaining,
    async (w) => {
      const res = await fetch(contentUrl(w.start, w.end), { cache: "force-cache" });
      if (!res.ok) throw new Error("dig content GET failed (" + res.status + ")");
      const bytes = new Uint8Array(await res.arrayBuffer());
      buf.set(bytes.subarray(0, Math.max(0, Math.min(bytes.length, buf.length - w.start))), w.start);
    },
    MAX_PARALLEL_RANGES
  );

  return { ciphertext: buf, proof, chunkLens };
}

/**
 * Fetch the full ciphertext for a resource, reassembling windows.  Mirrors
 * fetchVerifiedCiphertext() in apps/web/lib/dig-client.ts.
 * Returns { ciphertext: Uint8Array, proof: string, chunkLens: number[]|null }.
 *
 * #205a — for a PINNED (concrete-root) read, prefer the CACHEABLE GET content path (edge-cached for a
 * year); fall back to the POST JSON-RPC path on any failure and for rootless / "latest" (mutable)
 * reads. The GET path is the overwhelming majority (every on.dig.net site with a pinned root); the
 * POST path stays for latest + as a robust fallback.
 */
async function fetchVerified(storeId, rk, root) {
  if (rootIsPinned(root)) {
    try {
      return await fetchVerifiedGet(storeId, rk, root);
    } catch (e) {
      // Edge/GET path unavailable (e.g. the cacheable behavior not yet deployed, or a transient
      // failure) — fall back to the always-available POST JSON-RPC path below.
    }
  }
  return fetchVerifiedPost(storeId, rk, root);
}

/**
 * The POST JSON-RPC ciphertext fetch: 3-MiB windows, the always-available fallback + the path for
 * rootless / "latest" (mutable, uncacheable) reads.
 *
 * #205d: exactly like the GET path, window 0 (`offset=0`) is awaited alone to learn the resource's
 * `total_length`; every remaining `offset` is then planned up front and fanned out in PARALLEL
 * (bounded, `MAX_PARALLEL_RANGES`) instead of following the server's `next_offset` one response at a
 * time. This is safe because `dig.getContent` is a plain byte-range read (arbitrary `offset,length`
 * params, not an opaque pagination cursor) — the GET path above already assumes exactly this same
 * fixed-stride-windows contract with no cursor at all.
 */
async function fetchVerifiedPost(storeId, rk, root) {
  const first = await rpcCall("dig.getContent", {
    store_id: storeId,
    root,
    retrieval_key: rk,
    offset: 0,
    length: RPC_CHUNK,
  });
  if (!first) throw new Error("dig RPC returned no data");
  const total = first.total_length >>> 0;
  const buf = new Uint8Array(total);
  let proof = first.inclusion_proof || "";
  const chunkLens = Array.isArray(first.chunk_lens) ? first.chunk_lens.map((n) => n >>> 0) : null;

  const firstBytes = b64ToBytes(first.ciphertext || "");
  const at0 = first.offset >>> 0;
  buf.set(firstBytes.subarray(0, Math.max(0, Math.min(firstBytes.length, total - at0))), at0);

  if (!(first.complete || first.next_offset == null)) {
    const remaining = planWindows(total, RPC_CHUNK).filter((w) => w.index > 0);
    await runParallel(
      remaining,
      async (w) => {
        const r = await rpcCall("dig.getContent", {
          store_id: storeId,
          root,
          retrieval_key: rk,
          offset: w.start,
          length: RPC_CHUNK,
        });
        if (!r) throw new Error("dig RPC returned no data");
        const chunk = b64ToBytes(r.ciphertext || "");
        const at = r.offset >>> 0;
        buf.set(chunk.subarray(0, Math.max(0, Math.min(chunk.length, total - at))), at);
        if (r.inclusion_proof && !proof) proof = r.inclusion_proof;
      },
      MAX_PARALLEL_RANGES
    );
  }

  return { ciphertext: buf, proof, chunkLens };
}

/** Concatenate decrypted parts into one Uint8Array (the full-resource plaintext). */
function concatParts(parts) {
  if (parts.length === 1) return parts[0];
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let q = 0;
  for (const part of parts) {
    out.set(part, q);
    q += part.length;
  }
  return out;
}

/**
 * Build a streamed Response body for an already-verified, already-key-derived resource (#205d
 * "streaming decrypt"). `firstChunk` MUST already be the caller's own `decryptChunk()` result for
 * `lens[0]` — see the fail-closed reasoning below. Returns `{ stream, whenDone }`:
 *   - `stream` is handed straight to `new Response(stream, …)`; chunk 0 is enqueued immediately,
 *     and chunks 1..N are decrypted LAZILY as the stream is pulled, so a large multi-chunk resource
 *     starts flowing to the browser before the LAST chunk has been decrypted.
 *   - `whenDone` resolves with the full reassembled plaintext once every chunk has been decrypted
 *     (used to populate the in-memory + persistent caches, #205e) — or rejects if a later chunk's
 *     AEAD tag fails (see below).
 *
 * SECURITY — nothing here changes WHAT is verified, only WHEN the decrypt compute happens:
 *   - The resource-level merkle inclusion proof (verifyInclusion) is checked over the FULL
 *     ciphertext by the caller BEFORE this function is ever invoked. Its leaf is a hash of the
 *     whole resource, so it fundamentally cannot be verified incrementally — it already gates
 *     everything below, unchanged.
 *   - Every chunk is still decrypted through decryptChunk(), which still authenticates that
 *     specific chunk's AEAD tag — no chunk's authentication is skipped or weakened.
 *   - `firstChunk` decrypting successfully is not a shortcut: the derived AES key is the SAME for
 *     every chunk in a resource (one key per resource, not per chunk), and the ciphertext is
 *     already proven bit-identical to the chain-anchored resource by the merkle check above — so a
 *     wrong-key/decoy resource fails AEAD authentication on EVERY chunk, and a correct-key resource
 *     succeeds on every chunk. Testing chunk 0 therefore fully covers the "wrong key / decoy" case
 *     the pre-streaming code caught by decrypting the whole resource up front, and it does so
 *     BEFORE any Response/status code is committed — preserving the exact prior blind-model
 *     behavior (a decoy still yields a clean 404, never a mid-stream error visible to the page).
 *     A later-chunk failure is therefore unreachable via adversarial input; if it ever occurred
 *     (e.g. an internal fault) the stream errors rather than silently truncating.
 */
function buildDecryptStream(keyHex, ciphertext, lens, firstChunk) {
  const parts = [firstChunk];
  let offset = lens[0];
  let i = 1;
  let resolveDone;
  let rejectDone;
  const whenDone = new Promise((resolve, reject) => {
    resolveDone = resolve;
    rejectDone = reject;
  });

  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(firstChunk);
      if (i >= lens.length) {
        controller.close();
        resolveDone(concatParts(parts));
      }
    },
    pull(controller) {
      if (i >= lens.length) {
        controller.close();
        resolveDone(concatParts(parts));
        return;
      }
      try {
        const len = lens[i++];
        const plain = decryptChunk(keyHex, ciphertext.subarray(offset, offset + len));
        offset += len;
        parts.push(plain);
        controller.enqueue(plain);
      } catch (e) {
        controller.error(e);
        rejectDone(e);
      }
    },
  });

  return { stream, whenDone };
}

/**
 * Parse a chia:// or urn:dig:chia:… string.
 * Handles the forms emitted by the browser extension:
 *   chia://<storeId>[:<root>]/<resourceKey>[?salt=<hex>]
 *   urn:dig:chia:<storeId>[:<root>]/<resourceKey>
 * Returns { storeId, root, resourceKey, salt } or null on parse failure.
 */
function parseDigUrn(raw) {
  // Normalise: strip chia:// prefix or urn:dig:chia: prefix.
  let s = raw.trim();
  if (s.startsWith("chia://")) s = s.slice(7);
  else if (s.startsWith("urn:dig:chia:")) s = s.slice(13);
  else return null;

  // Optional ?salt= query param.
  let salt = null;
  const qi = s.indexOf("?");
  if (qi !== -1) {
    const qs = new URLSearchParams(s.slice(qi + 1));
    salt = qs.get("salt") || null;
    s = s.slice(0, qi);
  }

  // <storeId>[:<root>]/<resourceKey>
  const slash = s.indexOf("/");
  const head = slash === -1 ? s : s.slice(0, slash);
  const resourceKey = slash === -1 ? "index.html" : s.slice(slash + 1) || "index.html";

  const colon = head.indexOf(":");
  const storeId = colon === -1 ? head : head.slice(0, colon);
  const root = colon === -1 ? null : head.slice(colon + 1);

  if (!storeId) return null;
  return { storeId, root: root || null, resourceKey, salt };
}

/**
 * Build a resource path into a { storeId, root, resourceKey } from the pinned
 * CFG (for ordinary relative-path requests on the pinned domain).
 */
function urnForPath(path) {
  const resourceKey = path.replace(/^\/+/, "") || "index.html";
  return {
    storeId: CFG.storeId,
    // For latest-tracking (unpinned-root) domains, verifyInclusion is advisory and
    // x-dig-verified will be false — content still decrypts via GCM-SIV; matches the blind model.
    root: CFG.root || "latest",
    resourceKey,
    salt: CFG.salt || null,
  };
}

// ---- In-memory cache ---------------------------------------------------------
// Keyed by "<storeId>:<root>/<resourceKey>" — caches decrypted bytes only.
// Bounded to 100 entries (evict oldest first) so it can't grow unbounded across a long session.
// This is ephemeral (lost on SW restart) — the persistent Cache API layer below (#205e) is what
// survives a restart/new session for PINNED reads.
const CACHE = new Map();
const CACHE_MAX = 100;

/** Remember decrypted bytes in the ephemeral in-memory cache, evicting the oldest entry if full. */
function rememberInMemory(cacheKey, bytes) {
  if (CACHE.size >= CACHE_MAX) CACHE.delete(CACHE.keys().next().value);
  CACHE.set(cacheKey, bytes);
}

/**
 * Build the persistent Cache Storage key for a decrypted PINNED resource. Same-origin synthetic
 * path (never actually fetched — only ever used as a caches.match()/put() key) so the entry is
 * unambiguously scoped per store + root + resource key; a different pinned root is a different
 * key, so a persisted entry can never accidentally answer for a different generation.
 */
function contentCacheKey(storeId, root, resourceKey) {
  return new Request(
    self.location.origin + "/__dig_content_cache/" + storeId + "/" + root + "/" + encodeURIComponent(resourceKey)
  );
}

/**
 * Look up a decrypted PINNED resource in the persistent Cache API. Returns the cached bytes, or
 * null on a miss (or when Cache Storage itself is unavailable — private mode / quota — in which
 * case the caller falls through to the network path exactly as before this feature existed).
 */
async function matchContentCache(storeId, root, resourceKey) {
  try {
    const cache = await caches.open(CONTENT_CACHE_NAME);
    const hit = await cache.match(contentCacheKey(storeId, root, resourceKey));
    if (!hit) return null;
    return new Uint8Array(await hit.arrayBuffer());
  } catch {
    return null;
  }
}

/**
 * Persist a decrypted PINNED resource's plaintext into the Cache API (#205e), so the next load —
 * even a fresh SW instance / new browser session — skips the RPC round-trip + decrypt entirely.
 * NEVER called for an unpinned ("latest") read — see rootIsPinned() and the module doc comment:
 * persisting a mutable read could serve stale content forever after the underlying value changes,
 * which the chain-anchored-root pin model exists specifically to prevent. Best-effort: a
 * quota/private-mode failure must never break serving content that was already sent to the page.
 */
async function putContentCache(storeId, root, resourceKey, bytes, headers) {
  try {
    const cache = await caches.open(CONTENT_CACHE_NAME);
    await cache.put(contentCacheKey(storeId, root, resourceKey), new Response(bytes, { status: 200, headers }));
    const keys = await cache.keys();
    if (keys.length > CONTENT_CACHE_MAX) {
      await Promise.all(keys.slice(0, keys.length - CONTENT_CACHE_MAX).map((k) => cache.delete(k)));
    }
  } catch {
    // Best-effort persistence only.
  }
}

/**
 * Serve a resource: fetch from RPC, verify, decrypt, return Response.
 * `path` is the URL path (for pinned-domain requests).
 * `digUrl` is the raw chia:// or urn: string (overrides path when present).
 *
 * Returns `{ response, persistPromise }`. `persistPromise`, when present, is the background
 * persistent-cache write (#205e) — the caller MUST pass it to `event.waitUntil()` so the SW isn't
 * torn down before the write completes; it never blocks/delays `response` itself.
 */
async function serveUrn(path, digUrl) {
  await ensureDig();

  let storeId, root, resourceKey, salt;
  if (digUrl) {
    const p = parseDigUrn(digUrl);
    if (!p) return { response: new Response("Invalid DIG URN", { status: 400 }) };
    ({ storeId, root, resourceKey, salt } = p);
    root = root || CFG.root || "latest";
    salt = salt || CFG.salt || null;
  } else {
    ({ storeId, root, resourceKey, salt } = urnForPath(path));
  }

  const cacheKey = storeId + ":" + root + "/" + resourceKey;
  const memHit = CACHE.get(cacheKey);
  if (memHit) {
    return { response: new Response(memHit, { status: 200, headers: resourceHeaders(resourceKey, { "x-dig-cache": "memory" }) }) };
  }

  const pinned = rootIsPinned(root);

  // #205e — a persistent-cache hit skips the network + decrypt entirely. Pinned reads only (see
  // putContentCache doc comment); an unpinned "latest" read always goes to the network below.
  if (pinned) {
    const persisted = await matchContentCache(storeId, root, resourceKey);
    if (persisted) {
      rememberInMemory(cacheKey, persisted);
      return { response: new Response(persisted, { status: 200, headers: resourceHeaders(resourceKey, { "x-dig-cache": "persistent" }) }) };
    }
  }

  // Retrieval key = SHA-256(canonical rootless URN), hex.
  const rk = retrievalKey(storeId, resourceKey);
  const { ciphertext, proof, chunkLens } = await fetchVerified(storeId, rk, root);

  // Verify inclusion proof (non-throwing; decoys return false).
  let verified = false;
  try {
    verified = !!verifyInclusion(ciphertext, proof, root);
  } catch {
    verified = false;
  }

  // Derive the per-resource AES-256 key.
  const keyHex = deriveKey(storeId, resourceKey, salt || null);

  const lens = chunkLens && chunkLens.length ? chunkLens : [ciphertext.length];
  const lensSum = lens.reduce((a, n) => a + n, 0);
  if (lensSum !== ciphertext.length) {
    // Sanity-check: chunk lengths must sum to the full ciphertext length (defense in depth;
    // a mismatch would otherwise only surface as a GCM tag failure).
    return { response: new Response("Not found", { status: 404 }) };
  }

  // Decrypt chunk 0 eagerly — the fail-closed gate (see buildDecryptStream doc comment). A tag
  // failure (decoy / wrong key) returns 404, exactly as the pre-streaming code did.
  let firstChunk;
  try {
    firstChunk = decryptChunk(keyHex, ciphertext.subarray(0, lens[0]));
  } catch {
    return { response: new Response("Not found", { status: 404 }) };
  }

  const { stream, whenDone } = buildDecryptStream(keyHex, ciphertext, lens, firstChunk);

  whenDone.then((bytes) => rememberInMemory(cacheKey, bytes)).catch(() => {});

  let persistPromise = null;
  if (pinned) {
    const headers = resourceHeaders(resourceKey, { "x-dig-verified": String(verified) });
    persistPromise = whenDone
      .then((bytes) => putContentCache(storeId, root, resourceKey, bytes, headers))
      .catch(() => {});
  }

  const response = new Response(stream, {
    status: 200,
    headers: resourceHeaders(resourceKey, { "x-dig-verified": String(verified), "x-dig-cache": "miss" }),
  });

  return { response, persistPromise };
}

// ---- Fetch interception ------------------------------------------------------
self.addEventListener("fetch", (event) => {
  const req = event.request;
  // Only intercept same-origin GET requests.
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Pass through /__dig* paths — the Lambda serves config + WASM assets there.
  if (url.pathname.startsWith("/__dig")) return;

  // Check whether the URL (or its decoded form) contains a chia:// or urn:dig:
  // reference — the browser extension model for explicit URN navigation.
  const raw = decodeURIComponent(url.pathname + url.search);
  const digMatch = raw.match(/(?:chia:\/\/|urn:dig:chia:)[^\s"'<>]*/);

  event.respondWith(
    (async () => {
      const { response, persistPromise } = digMatch
        ? await serveUrn(null, digMatch[0])
        : await serveUrn(url.pathname, null);
      // #205e — persist AFTER responding; never delays the bytes already handed to the page.
      if (persistPromise) event.waitUntil(persistPromise);
      return response;
    })()
  );
});

// ---- Test-only exports --------------------------------------------------------
// Additive named exports of the pure/testable helpers (harmless for the SW runtime — a module
// service worker executes for its side effects; nothing consumes these exports in the browser).
// Used by test/sw.test.mjs so the range-planner, parallel fan-out, cache-key builders, and
// decrypt-stream assembly get real unit coverage without needing a browser (see that file for the
// stubbing strategy for the wasm-bindgen import and the `self`/`caches` globals).
export {
  planWindows,
  runParallel,
  concatParts,
  buildDecryptStream,
  wasmCacheKey,
  contentCacheKey,
  rootIsPinned,
  parseChunkLensHeader,
  parseDigUrn,
  contentType,
};

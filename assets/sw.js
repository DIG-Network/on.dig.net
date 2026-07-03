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

// Store-sandbox CSP for the DECRYPTED DOCUMENTS this SW synthesizes (#202, #175 root cause).
//
// WHY the SW must set this itself: an SW-synthesized Response never receives the edge CSP. The store
// document a visitor sees is built here by serveUrn(); without this header the decrypted document
// would run with NO CSP at all — the per-subdomain sandbox would be ABSENT. This constant IS that
// sandbox.
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
      const res = await fetch("/__dig/dig_client_bg.wasm");
      if (!res.ok) throw new Error(`dig-client wasm fetch failed (${res.status})`);
      const bytes = await res.arrayBuffer();
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
      const hex = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
      if (hex !== DIG_CLIENT_WASM_SHA256) {
        throw new Error("dig-client wasm integrity check failed — refusing to run unverified crypto");
      }
      await initDigClient({ module_or_path: bytes });
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
 * Fetch the full ciphertext for a PINNED resource over the CACHEABLE GET content path (#205a),
 * reassembling aligned 1-MiB windows the CloudFront edge caches for a year. Reads the verification
 * metadata from response HEADERS (inclusion proof / chunk lens / program hash / total length) —
 * parity with the JSON-RPC envelope. Returns the same shape as `fetchVerified`. Throws on any
 * non-200 window so the caller can fall back to the POST JSON-RPC path.
 *
 * The GET URL: `<rpcOrigin>/stores/<storeId>/content/<rk>?root=<root>&range=<start>-<end>`. Windows
 * are 1-MiB, aligned to the window size so every PoP request is a shared cache key (the Lambda snaps
 * ranges to 64-KiB blocks; 1 MiB is a multiple, so no fragmentation).
 */
async function fetchVerifiedGet(storeId, rk, root) {
  // The content edge is the SAME origin as the JSON-RPC endpoint (rpc.dig.net) — reuse CFG.rpc.
  const base = (CFG.rpc || "https://rpc.dig.net/").replace(/\/+$/, "");
  const contentUrl = (start, end) =>
    `${base}/stores/${storeId}/content/${rk}?root=${root}&range=${start}-${end}`;

  let total = null;
  let buf = null;
  let proof = "";
  let chunkLens = null;
  let offset = 0;

  for (;;) {
    const end = offset + GET_WINDOW - 1;
    // `cache: "force-cache"` leans on the browser HTTP cache + the CloudFront edge cache (the
    // response is 1-year immutable), so a repeat/same-session read is local and a warm PoP is fast.
    const res = await fetch(contentUrl(offset, end), { cache: "force-cache" });
    if (!res.ok) throw new Error("dig content GET failed (" + res.status + ")");
    if (total === null) {
      const t = parseInt(res.headers.get(HDR_TOTAL_LENGTH) || "", 10);
      if (!Number.isFinite(t)) throw new Error("content GET missing total length");
      total = t >>> 0;
      buf = new Uint8Array(total);
      const p = res.headers.get(HDR_INCLUSION_PROOF);
      if (p) proof = p;
      chunkLens = parseChunkLensHeader(res.headers.get(HDR_CHUNK_LENS));
    }
    const chunk = new Uint8Array(await res.arrayBuffer());
    buf.set(chunk.subarray(0, Math.max(0, Math.min(chunk.length, total - offset))), offset);
    offset += chunk.length;
    // A short (or empty) window that reaches the total completes the resource. Guard against a
    // zero-length window (would loop forever) by breaking when we've covered `total` or got nothing.
    if (offset >= total || chunk.length === 0) break;
  }
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

/** The POST JSON-RPC ciphertext fetch: 3-MiB windows looped until `complete`. The always-available
 *  fallback + the path for rootless / "latest" (mutable, uncacheable) reads. */
async function fetchVerifiedPost(storeId, rk, root) {
  let offset = 0;
  let total = null;
  let buf = null;
  let proof = "";
  let chunkLens = null;

  for (;;) {
    const r = await rpcCall("dig.getContent", {
      store_id: storeId,
      root,
      retrieval_key: rk,
      offset,
      length: RPC_CHUNK,
    });
    if (!r) throw new Error("dig RPC returned no data");
    if (total === null) {
      total = r.total_length >>> 0;
      buf = new Uint8Array(total);
    }
    if (chunkLens === null && Array.isArray(r.chunk_lens)) {
      chunkLens = r.chunk_lens.map((n) => n >>> 0);
    }
    const chunk = b64ToBytes(r.ciphertext || "");
    const at = r.offset >>> 0;
    buf.set(chunk.subarray(0, Math.max(0, Math.min(chunk.length, total - at))), at);
    if (r.inclusion_proof) proof = r.inclusion_proof;
    if (r.complete || r.next_offset == null) break;
    offset = r.next_offset >>> 0;
  }
  return { ciphertext: buf, proof, chunkLens };
}

/**
 * Decrypt multi-chunk ciphertext.  Mirrors decryptResourceChunks() in
 * apps/web/lib/dig-client.js.  `chunkLens` are the per-chunk CIPHERTEXT byte
 * lengths (may be null/empty for a single-chunk resource).
 */
function decryptChunks(keyHex, ciphertext, chunkLens) {
  const lens = chunkLens && chunkLens.length ? chunkLens : [ciphertext.length];
  if (lens.length === 1) return decryptChunk(keyHex, ciphertext); // fast path
  // Sanity-check: chunk lengths must sum to the full ciphertext length (defense in depth;
  // a mismatch would otherwise only surface as a GCM tag failure).
  const lensSum = lens.reduce((a, n) => a + n, 0);
  if (lensSum !== ciphertext.length) {
    throw new Error("served ciphertext length does not match chunk lengths");
  }
  const parts = [];
  let p = 0;
  for (const len of lens) {
    parts.push(decryptChunk(keyHex, ciphertext.subarray(p, p + len)));
    p += len;
  }
  const total = parts.reduce((a, x) => a + x.length, 0);
  const out = new Uint8Array(total);
  let q = 0;
  for (const part of parts) {
    out.set(part, q);
    q += part.length;
  }
  return out;
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
const CACHE = new Map();
const CACHE_MAX = 100;

/**
 * Serve a resource: fetch from RPC, verify, decrypt, return Response.
 * `path` is the URL path (for pinned-domain requests).
 * `digUrl` is the raw chia:// or urn: string (overrides path when present).
 */
async function serveUrn(path, digUrl) {
  await ensureDig();

  let storeId, root, resourceKey, salt;
  if (digUrl) {
    const p = parseDigUrn(digUrl);
    if (!p) return new Response("Invalid DIG URN", { status: 400 });
    ({ storeId, root, resourceKey, salt } = p);
    root = root || CFG.root || "latest";
    salt = salt || CFG.salt || null;
  } else {
    ({ storeId, root, resourceKey, salt } = urnForPath(path));
  }

  const cacheKey = storeId + ":" + root + "/" + resourceKey;
  if (CACHE.has(cacheKey)) {
    return new Response(CACHE.get(cacheKey), {
      status: 200,
      headers: resourceHeaders(resourceKey, { "x-dig-cache": "hit" }),
    });
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

  // Decrypt.  A tag failure (decoy / wrong key) returns 404.
  let bytes;
  try {
    bytes = decryptChunks(keyHex, ciphertext, chunkLens);
  } catch {
    // Decoy or wrong key — treat as not found (blind model).
    return new Response("Not found", { status: 404 });
  }

  if (CACHE.size >= CACHE_MAX) CACHE.delete(CACHE.keys().next().value); // evict oldest
  CACHE.set(cacheKey, bytes);

  return new Response(bytes, {
    status: 200,
    headers: resourceHeaders(resourceKey, {
      "x-dig-verified": String(verified),
      "x-dig-cache": "miss",
    }),
  });
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
  if (digMatch) {
    event.respondWith(serveUrn(null, digMatch[0]));
    return;
  }

  // Ordinary same-origin path → serve from the pinned store.
  event.respondWith(serveUrn(url.pathname, null));
});

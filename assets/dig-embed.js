/*!
 * dig-embed.js — the DIG Network embeddable loader.
 * Stable URL: https://hub.dig.net/embed/dig-embed.js
 *
 * Drop this one <script> on ANY page and set:
 *     window.digurn = "urn:dig:chia:<storeId>[:<root>]/<entry.html>[?salt=<hex>]";
 * (before OR after the tag — the snippet polls briefly for a late-set value.) It then:
 *   1. shows a branded DIG Network loading overlay,
 *   2. fetches + decrypts the URN's content CLIENT-SIDE from rpc.dig.net (the dig-client WASM does
 *      all crypto; the host network is blind), and
 *   3. replaces the document with the content, intercepting every subsequent relative/chia:// request
 *      so the loaded app keeps reading from the SAME store + root.
 *
 * TWO-TIER REQUEST INTERCEPTION (a hard browser constraint forces this):
 *   navigator.serviceWorker.register(scriptURL) requires scriptURL to be SAME-ORIGIN with the page.
 *   A snippet loaded cross-origin therefore cannot register a dig.net SW onto a third-party page.
 *     • TIER 1 (same-origin host, e.g. the *.on.dig.net resolver doc, or a site self-hosting the SW):
 *       register a module service worker that intercepts ALL subresource + navigation fetches and
 *       decrypts each RPC response before it reaches the view/download. Full power.
 *     • TIER 2 (embed-anywhere, cross-origin): an IN-PAGE interceptor — monkey-patch fetch + XHR,
 *       rewrite DOM href/src at injection + on mutation, and decrypt in-page. This CANNOT intercept
 *       browser-native top-level navigations, nested-worker imports, or cross-origin iframe loads, but
 *       it DOES cover relative fetch/XHR + <img>/<script>/<link>/<a> rewriting for a typical app.
 *   The snippet auto-detects the best available tier and degrades gracefully.
 *
 * Dependency-free vanilla JS. The pure logic below is kept byte-compatible with
 * apps/web/lib/embed-core.js (the unit-tested single source of truth).
 */
(function () {
  "use strict";

  // Idempotency guard: never run twice on one page (e.g. snippet included twice).
  if (window.__digEmbedStarted) return;
  window.__digEmbedStarted = true;

  // ---------------------------------------------------------------------------------------------
  // Configuration. The snippet derives its OWN origin from the executing <script> so it can fetch
  // the dig-client WASM same-origin (with SRI) when possible. RPC defaults to the public node.
  // ---------------------------------------------------------------------------------------------
  var RPC_ENDPOINT = "https://rpc.dig.net";
  var RPC_CHUNK_BYTES = 3 * 1024 * 1024; // node caps each dig.getContent window at ~3 MiB
  // SRI for the read-crypto WASM — MUST equal apps/web/lib/dig-client.js DIG_CLIENT_WASM_SHA256.
  // A mismatch fails closed (refuses to run unverified crypto). Regenerate on a wasm rebuild.
  var DIG_CLIENT_WASM_SHA256 =
    "ff486be806f908a2a90780e499a04dbd34e10e3b97be0470cb9ee841a1e49e77";

  function selfScript() {
    if (document.currentScript) return document.currentScript;
    var s = document.querySelectorAll('script[src*="dig-embed.js"]');
    return s.length ? s[s.length - 1] : null;
  }
  var SELF = selfScript();
  var SELF_ORIGIN = (function () {
    try {
      return SELF && SELF.src ? new URL(SELF.src).origin : location.origin;
    } catch (_) {
      return location.origin;
    }
  })();
  // The same-origin assets path on the snippet's host (hub.dig.net) for the dig-client WASM.
  var ASSET_BASE = SELF_ORIGIN + "/dig-client";

  // ===============================================================================================
  // PURE LOGIC (mirror of apps/web/lib/embed-core.js — keep in sync; that module is the test surface)
  // ===============================================================================================
  function stripQueryHash(p) {
    return String(p == null ? "" : p).split("#")[0].split("?")[0];
  }
  function parseDigRef(raw) {
    var s = String(raw == null ? "" : raw).trim();
    if (!s) return null;
    if (s.indexOf("urn:dig:chia:") === 0) s = s.slice("urn:dig:chia:".length);
    else if (s.indexOf("chia://") === 0) s = s.slice("chia://".length);
    else return null;
    var salt = null;
    var qi = s.indexOf("?");
    if (qi !== -1) {
      var qs = new URLSearchParams(s.slice(qi + 1));
      var v = qs.get("salt");
      salt = v && /^[0-9a-fA-F]+$/.test(v) ? v.toLowerCase() : null;
      s = s.slice(0, qi);
    }
    var slash = s.indexOf("/");
    var head = slash === -1 ? s : s.slice(0, slash);
    var resourceKey = slash === -1 ? "" : s.slice(slash + 1);
    resourceKey = stripQueryHash(resourceKey).replace(/^\/+/, "") || "index.html";
    var colon = head.indexOf(":");
    var storeId = (colon === -1 ? head : head.slice(0, colon)).toLowerCase();
    var root = colon === -1 ? null : head.slice(colon + 1).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(storeId)) return null;
    if (root && !/^[0-9a-f]{64}$/.test(root)) return null;
    return { storeId: storeId, root: root || null, resourceKey: resourceKey, salt: salt };
  }
  function normalizePath(path) {
    var parts = String(path == null ? "" : path).split("/");
    var out = [];
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      if (part === "" || part === ".") continue;
      if (part === "..") {
        if (out.length) out.pop();
        continue;
      }
      out.push(part);
    }
    return "/" + out.join("/");
  }
  function resolveRelativeResourceKey(base, ref) {
    var cleaned = stripQueryHash(ref);
    if (cleaned === "") return base.replace(/^\/+/, "");
    if (cleaned.charAt(0) === "/") return normalizePath(cleaned).replace(/^\/+/, "");
    var baseDir = base.indexOf("/") !== -1 ? base.slice(0, base.lastIndexOf("/")) : "";
    var joined = (baseDir ? baseDir + "/" : "") + cleaned;
    return normalizePath(joined).replace(/^\/+/, "");
  }
  function relativeResult(path, cfg, entryKey) {
    if (!cfg || !cfg.storeId) return { kind: "external" };
    return {
      kind: "relative",
      ref: {
        storeId: cfg.storeId,
        root: cfg.root || "latest",
        resourceKey: resolveRelativeResourceKey(entryKey || "index.html", path),
        salt: cfg.salt || null,
      },
    };
  }
  function classifyReference(rawRef, ctx) {
    var cfg = ctx.cfg,
      entryKey = ctx.entryKey,
      pageOrigin = ctx.pageOrigin;
    var ref = String(rawRef == null ? "" : rawRef).trim();
    if (!ref) return { kind: "external" };
    if (ref.indexOf("chia://") === 0 || ref.indexOf("urn:dig:chia:") === 0) {
      var parsed = parseDigRef(ref);
      if (!parsed) return { kind: "external" };
      return {
        kind: "urn",
        ref: {
          storeId: parsed.storeId,
          root: parsed.root || (cfg && cfg.root) || "latest",
          resourceKey: parsed.resourceKey,
          salt: parsed.salt || (cfg && cfg.salt) || null,
        },
      };
    }
    if (/^(?:[a-z][a-z0-9+.-]*:)/i.test(ref)) {
      if (pageOrigin && (ref.indexOf(pageOrigin + "/") === 0 || ref === pageOrigin)) {
        return relativeResult(ref.slice(pageOrigin.length) || "/", cfg, entryKey);
      }
      return { kind: "external" };
    }
    if (ref.indexOf("//") === 0) return { kind: "external" };
    if (ref.charAt(0) === "#") return { kind: "external" };
    return relativeResult(ref, cfg, entryKey);
  }
  function readDigUrnGlobal(value) {
    var parsed = parseDigRef(value);
    if (!parsed) return null;
    return {
      storeId: parsed.storeId,
      root: parsed.root,
      salt: parsed.salt,
      entryKey: parsed.resourceKey || "index.html",
    };
  }
  function detectTier(env) {
    env = env || {};
    var sameOrigin = !!env.scriptOrigin && env.scriptOrigin === env.pageOrigin;
    if (env.isSecureContext && env.hasServiceWorker && env.hasModuleWorker && sameOrigin) {
      return { tier: 1, mode: "sw" };
    }
    return {
      tier: 2,
      mode: "inpage",
      reason: !env.hasServiceWorker
        ? "no-serviceworker-support"
        : !env.hasModuleWorker
          ? "no-module-worker-support"
          : !sameOrigin
            ? "cross-origin-embed"
            : !env.isSecureContext
              ? "insecure-context"
              : "unknown",
    };
  }

  // Feature-detect module-worker support (best-effort; SW module support tracks roughly the same set).
  function moduleWorkerSupported() {
    // We can't synchronously probe SW module support, but module Worker support is a strong proxy
    // (both shipped together in Chrome/Edge/Safari 16.4; Firefox has neither for SW). The `get type()`
    // getter fires synchronously as the browser reads the option BAG (before the worker URL is even
    // fetched), so we learn support without running a worker.
    //
    // CSP (#206b): the URL must use a scheme the resolver LOADER_CSP allows for `worker-src`
    // ('self' blob:). A `data:` worker URL trips a securitypolicyviolation on that tight policy even
    // though the getter still fires — so probe with a BLOB url (allowed) and revoke it immediately.
    var url = null;
    try {
      var supported = false;
      url = URL.createObjectURL(new Blob([""], { type: "text/javascript" }));
      new Worker(url, {
        get type() {
          supported = true;
          return "module";
        },
      });
      return supported;
    } catch (_) {
      return false;
    } finally {
      if (url) {
        try { URL.revokeObjectURL(url); } catch (_) {}
      }
    }
  }

  // ===============================================================================================
  // BRANDED OVERLAY (matches loader.html / app design tokens: purple→magenta gradient + DIG wordmark)
  // ===============================================================================================
  var OVERLAY_ID = "__dig_embed_overlay";

  // "NEVER BLANK" (#206): when the HOST document already painted its own branded DIG loading card
  // (the *.on.dig.net resolver loader.html sets window.__digLoaderShellPresent = true and renders a
  // <main class="dig-card"> shell in <body>), REUSE that shell instead of stacking a second
  // full-screen overlay on top of it. A duplicate overlay whose wordmark uses background-clip:text
  // could render blank and cover the good card → white screen. By adopting the already-painted shell
  // we (a) never blank it, and (b) still let overlayMessage()/overlayError()/removeOverlay() target
  // it (we tag it with OVERLAY_ID and wire a message element). Returns true if a shell was adopted.
  function adoptShellOverlay() {
    if (!window.__digLoaderShellPresent) return false;
    if (document.getElementById(OVERLAY_ID)) return true; // already adopted
    var shell = document.querySelector(".dig-card");
    if (!shell) return false;
    shell.id = OVERLAY_ID;
    // Mark it ADOPTED so the full-viewport backdrop rule below does NOT apply to it (#206b): the
    // shell's OWN card CSS already centers + sizes it (via the loader body's flex). Applying the
    // embed's `#id{position:fixed;inset:0}` backdrop to the card itself broke its layout (the error
    // card rendered stretched + left-anchored). The `.dig-adopted` guard keeps the backdrop for an
    // embed-CREATED overlay only, while the descendant `.dig-mark/.dig-err/...` rules still style the
    // error content rendered inside the adopted card.
    shell.classList.add("dig-adopted");
    // Point the message helpers at the shell's existing status line so status/error updates land on
    // the visible card. loader.html uses <p class="dig-msg"> for the status text.
    var msg = shell.querySelector(".dig-msg");
    if (msg && !msg.id) msg.id = OVERLAY_ID + "_msg";
    return true;
  }

  // Inject the overlay's stylesheet once (idempotent). Extracted so overlayError() can also ensure
  // it is present when rendering on an ADOPTED host shell (the loader shell doesn't ship this CSS).
  function ensureOverlayStyle() {
    if (document.getElementById(OVERLAY_ID + "_style")) return;
    var css =
      // Clean dark backdrop + a CONTAINED radial glow that fades to transparent well before the
      // viewport edges (so the brand color never bleeds to the page edge — it frames the card).
      // Full-viewport backdrop for an embed-CREATED overlay ONLY (:not(.dig-adopted)) — an adopted
      // host loader shell keeps its own centered card layout (see adoptShellOverlay, #206b).
      "#" + OVERLAY_ID + ":not(.dig-adopted){position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;" +
      "justify-content:center;background:#0b0a12;background-image:radial-gradient(58% 48% at 50% 42%," +
      "rgba(122,61,255,.18),rgba(122,61,255,.05) 38%,transparent 70%);color:#fff;" +
      "font-family:'Space Grotesk',system-ui,-apple-system,sans-serif;-webkit-font-smoothing:antialiased;" +
      "text-align:center;padding:24px}" +
      // The branded card: contained surface with a border, soft shadow, and a crisp purple→magenta
      // top-edge accent line. All brand color lives inside this card — no bleed.
      "#" + OVERLAY_ID + " .dig-card{position:relative;display:flex;flex-direction:column;align-items:center;" +
      "gap:18px;max-width:420px;width:100%;box-sizing:border-box;padding:36px 32px;border-radius:16px;" +
      "background:#16131f;border:1px solid #2a2440;box-shadow:0 24px 60px rgba(0,0,0,.5);overflow:hidden}" +
      "#" + OVERLAY_ID + " .dig-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;" +
      "background:linear-gradient(90deg,#7a3dff,#ff00de)}" +
      // "DIG" is painted with the brand gradient (background-clip:text over a transparent fill).
      "#" + OVERLAY_ID + " .dig-mark{font-size:30px;font-weight:700;letter-spacing:.5px;" +
      "background:linear-gradient(135deg,#7a3dff 0%,#ff00de 100%);-webkit-background-clip:text;" +
      "background-clip:text;color:transparent}" +
      // "Network" MUST NOT inherit the parent's transparent fill / clipped gradient (that made it
      // render the same color as the background — invisible). Give it its OWN explicit, legible solid
      // color via BOTH -webkit-text-fill-color (overrides the transparent fill on WebKit/Blink) and
      // color (standards fallback). #a99fc4 on the #16131f card clears WCAG AA.
      "#" + OVERLAY_ID + " .dig-mark .hub{font-weight:500;-webkit-text-fill-color:#a99fc4;color:#a99fc4}" +
      // Crisp spinner: faint purple track + one purple arc (no magenta bloom/halo).
      "#" + OVERLAY_ID + " .dig-ring{width:46px;height:46px;border-radius:50%;border:3px solid rgba(122,61,255,.22);" +
      "border-top-color:#7a3dff;animation:digspin .9s linear infinite}" +
      "@keyframes digspin{to{transform:rotate(360deg)}}" +
      "#" + OVERLAY_ID + " .dig-msg{font-size:14px;color:#a99fc4;max-width:30rem;line-height:1.55}" +
      "#" + OVERLAY_ID + " .dig-sub{font-size:12px;color:#a99fc4}" +
      "#" + OVERLAY_ID + " .dig-err{color:#ef5570;font-size:14px;max-width:30rem;line-height:1.55}" +
      "#" + OVERLAY_ID + " a{color:#9466ff}" +
      "@media (prefers-reduced-motion:reduce){#" + OVERLAY_ID + " .dig-ring{animation:none}}";
    var style = document.createElement("style");
    style.id = OVERLAY_ID + "_style";
    style.textContent = css;
    (document.head || document.documentElement).appendChild(style);
  }

  function injectOverlay() {
    // Reuse the host's already-painted branded shell when present (never stack a blank overlay).
    if (adoptShellOverlay()) return;
    if (document.getElementById(OVERLAY_ID)) return;
    ensureOverlayStyle();

    var el = document.createElement("div");
    el.id = OVERLAY_ID;
    el.setAttribute("role", "status");
    el.setAttribute("aria-live", "polite");
    el.setAttribute("aria-busy", "true");
    el.innerHTML =
      '<div class="dig-card">' +
      '<div class="dig-ring" aria-hidden="true"></div>' +
      '<div class="dig-mark">DIG<span class="hub">&nbsp;Network</span></div>' +
      '<div class="dig-msg" id="' + OVERLAY_ID + '_msg">Loading content from the DIG Network…</div>' +
      '<div class="dig-sub">Decrypting client-side · powered by Chia</div>' +
      "</div>";
    (document.body || document.documentElement).appendChild(el);
  }
  function overlayMessage(text) {
    var m = document.getElementById(OVERLAY_ID + "_msg");
    if (m) m.textContent = text;
  }
  function overlayError(text, detail) {
    var el = document.getElementById(OVERLAY_ID);
    if (!el) {
      injectOverlay();
      el = document.getElementById(OVERLAY_ID);
    }
    if (!el) return;
    // The error card needs the overlay stylesheet even when rendering on an ADOPTED host shell (the
    // loader shell ships its own card CSS but not the embed's .dig-err / .dig-mark rules).
    ensureOverlayStyle();
    el.setAttribute("aria-busy", "false");
    // When we adopted the host's branded shell, EL IS the .dig-card itself; render the error content
    // directly inside it (no nested card). Otherwise (embed-created overlay) EL is the flex backdrop
    // wrapper and needs an inner .dig-card. Detect by class.
    var errBody =
      '<div class="dig-mark">DIG<span class="hub">&nbsp;Network</span></div>' +
      '<div class="dig-err">' + escapeHtml(text) + "</div>" +
      (detail ? '<div class="dig-sub">' + escapeHtml(detail) + "</div>" : "");
    if (el.classList && el.classList.contains("dig-card")) {
      el.innerHTML = errBody;
    } else {
      el.innerHTML = '<div class="dig-card">' + errBody + "</div>";
    }
  }
  function removeOverlay() {
    var el = document.getElementById(OVERLAY_ID);
    if (el && el.parentNode) el.parentNode.removeChild(el);
    var st = document.getElementById(OVERLAY_ID + "_style");
    if (st && st.parentNode) st.parentNode.removeChild(st);
  }
  function escapeHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // ===============================================================================================
  // CONTENT MIME inference. SINGLE SOURCE OF TRUTH: apps/web/lib/embed-core.ts contentType() (tested);
  // this map is mirrored verbatim here and in services/resolver/assets/sw.js — keep all three in sync.
  // ===============================================================================================
  function contentType(resourceKey) {
    var ext = (resourceKey.split(".").pop() || "").toLowerCase();
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

  // ===============================================================================================
  // RPC + WASM read/decrypt (in-page; mirrors apps/web/lib/dig-client.js + resolver sw.js)
  // ===============================================================================================
  var _dig = null; // memoised WASM module
  function loadDigClient() {
    if (_dig) return _dig;
    _dig = (async function () {
      var glueUrl = ASSET_BASE + "/dig_client.js";
      var mod = await import(/* @vite-ignore */ glueUrl);
      var res = await fetch(ASSET_BASE + "/dig_client_bg.wasm");
      if (!res.ok) throw new Error("dig-client wasm fetch failed (" + res.status + ")");
      var bytes = await res.arrayBuffer();
      var digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
      var hex = Array.prototype.map.call(digest, function (b) {
        return b.toString(16).padStart(2, "0");
      }).join("");
      if (hex !== DIG_CLIENT_WASM_SHA256) {
        throw new Error("dig-client wasm integrity check failed — refusing to run unverified crypto");
      }
      await mod.default(bytes);
      if (typeof mod.install_global === "function") mod.install_global();
      return mod.verifyInclusion ? mod : globalThis.digClient;
    })().catch(function (e) {
      _dig = null; // allow retry on transient failure
      throw e;
    });
    return _dig;
  }

  function b64ToBytes(b64) {
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function rpcCall(method, params) {
    var res;
    try {
      res = await fetch(RPC_ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: method, params: params }),
      });
    } catch (_) {
      throw new Error("Could not reach the content network. Check your connection.");
    }
    if (!res.ok) throw new Error("dig RPC HTTP error " + res.status);
    var j = await res.json();
    if (j && j.error) throw new Error("dig RPC " + method + ": " + (j.error.message || "error"));
    return j ? j.result : null;
  }

  async function fetchVerified(storeId, rk, root) {
    var offset = 0, total = null, buf = null, proof = "", chunkLens = null;
    for (;;) {
      var r = await rpcCall("dig.getContent", {
        store_id: storeId, root: root, retrieval_key: rk, offset: offset, length: RPC_CHUNK_BYTES,
      });
      if (!r) throw new Error("dig RPC returned no data");
      if (total === null) {
        total = r.total_length >>> 0;
        buf = new Uint8Array(total);
      }
      if (chunkLens === null && Array.isArray(r.chunk_lens)) {
        chunkLens = r.chunk_lens.map(function (n) { return n >>> 0; });
      }
      var chunk = b64ToBytes(r.ciphertext || "");
      var at = r.offset >>> 0;
      buf.set(chunk.subarray(0, Math.max(0, Math.min(chunk.length, total - at))), at);
      if (r.inclusion_proof) proof = r.inclusion_proof;
      if (r.complete || r.next_offset == null) break;
      offset = r.next_offset >>> 0;
    }
    return { ciphertext: buf, proof: proof, chunkLens: chunkLens };
  }

  function decryptChunks(dig, keyHex, ciphertext, chunkLens) {
    var lens = chunkLens && chunkLens.length ? chunkLens : [ciphertext.length];
    if (lens.length === 1) return dig.decryptChunk(keyHex, ciphertext);
    var sum = lens.reduce(function (a, n) { return a + n; }, 0);
    if (sum !== ciphertext.length) throw new Error("served ciphertext length does not match chunk lengths");
    var parts = [], p = 0;
    for (var i = 0; i < lens.length; i++) {
      parts.push(dig.decryptChunk(keyHex, ciphertext.subarray(p, p + lens[i])));
      p += lens[i];
    }
    var totalLen = parts.reduce(function (a, x) { return a + x.length; }, 0);
    var out = new Uint8Array(totalLen), q = 0;
    for (var j = 0; j < parts.length; j++) { out.set(parts[j], q); q += parts[j].length; }
    return out;
  }

  // Decrypted-bytes cache, bounded (parity with sw.js).
  var CACHE = new Map();
  var CACHE_MAX = 100;

  // Fetch + decrypt one resolved resource. Returns { bytes, verified, decrypted, resourceKey }.
  async function readResource(refObj) {
    var storeId = refObj.storeId, root = refObj.root || "latest",
      resourceKey = refObj.resourceKey, salt = refObj.salt || null;
    var cacheKey = storeId + ":" + root + "/" + resourceKey;
    if (CACHE.has(cacheKey)) {
      return { bytes: CACHE.get(cacheKey), verified: false, decrypted: true, resourceKey: resourceKey, cache: "hit" };
    }
    var dig = await loadDigClient();
    var rk = dig.retrievalKey(storeId, resourceKey);
    var fv = await fetchVerified(storeId, rk, root);
    var verified = false;
    try { verified = !!dig.verifyInclusion(fv.ciphertext, fv.proof, root); } catch (_) { verified = false; }
    var keyHex = dig.deriveKey(storeId, resourceKey, salt || undefined);
    var bytes, decrypted = true;
    try {
      bytes = decryptChunks(dig, keyHex, fv.ciphertext, fv.chunkLens);
    } catch (_) {
      bytes = fv.ciphertext;
      decrypted = false;
    }
    if (CACHE.size >= CACHE_MAX) CACHE.delete(CACHE.keys().next().value);
    CACHE.set(cacheKey, bytes);
    return { bytes: bytes, verified: verified, decrypted: decrypted, resourceKey: resourceKey, cache: "miss" };
  }

  // ===============================================================================================
  // OBJECT-URL bookkeeping (revoke on unload; clean up)
  // ===============================================================================================
  var OBJECT_URLS = [];
  function makeObjectUrl(bytes, type) {
    var url = URL.createObjectURL(new Blob([bytes], { type: type }));
    OBJECT_URLS.push(url);
    return url;
  }
  window.addEventListener("pagehide", function () {
    for (var i = 0; i < OBJECT_URLS.length; i++) {
      try { URL.revokeObjectURL(OBJECT_URLS[i]); } catch (_) {}
    }
    OBJECT_URLS.length = 0;
  });

  // ===============================================================================================
  // TIER 2 — in-page interceptor (cross-origin embed; the embed-anywhere fallback).
  //   WHAT IT INTERCEPTS:  window.fetch, XMLHttpRequest, and DOM url attributes (src/href) on
  //                        injection + on mutation (img/script/link/source/a). chia:// links too.
  //   WHAT IT CANNOT DO:   top-level browser navigations (clicking a normal relative <a> still hits
  //                        the host origin — we rewrite those to object URLs / dig handlers where we
  //                        can, but a hard navigation escapes us), nested Worker/iframe subresource
  //                        loads, CSS url() references inside fetched stylesheets, and EventSource.
  //                        For those, Tier 1 (a same-origin SW) is required.
  // ===============================================================================================
  function installInPageInterceptor(cfg) {
    var ctx = { cfg: cfg, entryKey: cfg.entryKey, pageOrigin: location.origin };

    // --- fetch() patch -------------------------------------------------------------------------
    var origFetch = window.fetch ? window.fetch.bind(window) : null;
    window.fetch = function (input, init) {
      var url = typeof input === "string" ? input : input && input.url;
      // Pass through the snippet's OWN infrastructure unmodified (parity with sw.js passing /__dig*):
      // the dig-client WASM assets + the RPC endpoint must NOT be re-routed as store resources (that
      // would recurse — loadDigClient() itself uses fetch). Anything under ASSET_BASE or the RPC is ours.
      if (typeof url === "string" && (url.indexOf(ASSET_BASE) === 0 || url.indexOf(RPC_ENDPOINT) === 0)) {
        return origFetch ? origFetch(input, init) : Promise.reject(new Error("fetch unavailable"));
      }
      var cls = classifyReference(url, ctx);
      if (cls.kind === "external" || !cls.ref) {
        return origFetch ? origFetch(input, init) : Promise.reject(new Error("fetch unavailable"));
      }
      return readResource(cls.ref).then(function (r) {
        return new Response(r.bytes, {
          status: 200,
          headers: {
            "content-type": contentType(cls.ref.resourceKey),
            "x-dig-verified": String(r.verified),
            "x-dig-cache": r.cache || "miss",
          },
        });
      }).catch(function (e) {
        return new Response("DIG fetch failed: " + (e && e.message), { status: 502 });
      });
    };

    // --- XMLHttpRequest patch ------------------------------------------------------------------
    // Re-route a DIG-bound XHR through fetch+decrypt by resolving it to an object URL synchronously
    // is impossible (decrypt is async), so we intercept open()+send() and feed bytes on completion.
    var XHR = window.XMLHttpRequest;
    if (XHR) {
      var origOpen = XHR.prototype.open;
      var origSend = XHR.prototype.send;
      XHR.prototype.open = function (method, url) {
        this.__digCls = method && String(method).toUpperCase() === "GET" ? classifyReference(url, ctx) : { kind: "external" };
        if (this.__digCls.kind === "external") return origOpen.apply(this, arguments);
        this.__digMethod = method;
        return; // defer to send()
      };
      XHR.prototype.send = function () {
        var self = this;
        if (!self.__digCls || self.__digCls.kind === "external") return origSend.apply(self, arguments);
        readResource(self.__digCls.ref).then(function (r) {
          // Emulate a successful XHR by dispatching readystate + load with decrypted bytes.
          var blob = new Blob([r.bytes], { type: contentType(self.__digCls.ref.resourceKey) });
          var reader = new FileReader();
          reader.onload = function () {
            try {
              Object.defineProperty(self, "responseText", { value: reader.result, configurable: true });
              Object.defineProperty(self, "response", { value: reader.result, configurable: true });
              Object.defineProperty(self, "status", { value: 200, configurable: true });
              Object.defineProperty(self, "readyState", { value: 4, configurable: true });
            } catch (_) {}
            if (typeof self.onreadystatechange === "function") self.onreadystatechange();
            self.dispatchEvent(new Event("readystatechange"));
            self.dispatchEvent(new Event("load"));
            self.dispatchEvent(new Event("loadend"));
          };
          reader.readAsText(blob);
        }).catch(function () {
          self.dispatchEvent(new Event("error"));
        });
      };
    }

    // --- DOM url rewriting (injection + MutationObserver) --------------------------------------
    // Rewrite src/href that point at DIG resources to object URLs (decrypted up-front). For <a>
    // links we attach a click handler that loads the target document IN-PAGE (Tier 2 can't intercept
    // the native navigation, so we hijack the click instead).
    function rewriteEl(el) {
      if (!el || el.nodeType !== 1 || el.__digRewritten) return;
      var tag = el.tagName;
      if (tag === "IMG" || tag === "SCRIPT" || tag === "SOURCE" || tag === "VIDEO" || tag === "AUDIO") {
        var attr = "src";
        var val = el.getAttribute(attr);
        if (val) {
          var cls = classifyReference(val, ctx);
          if (cls.kind !== "external" && cls.ref) {
            el.__digRewritten = true;
            readResource(cls.ref).then(function (r) {
              el.setAttribute(attr, makeObjectUrl(r.bytes, contentType(cls.ref.resourceKey)));
            }).catch(function () {});
          }
        }
      } else if (tag === "LINK") {
        var rel = (el.getAttribute("rel") || "").toLowerCase();
        var href = el.getAttribute("href");
        if (href && (rel.indexOf("stylesheet") !== -1 || rel.indexOf("icon") !== -1 || rel.indexOf("preload") !== -1)) {
          var clsL = classifyReference(href, ctx);
          if (clsL.kind !== "external" && clsL.ref) {
            el.__digRewritten = true;
            readResource(clsL.ref).then(function (r) {
              el.setAttribute("href", makeObjectUrl(r.bytes, contentType(clsL.ref.resourceKey)));
            }).catch(function () {});
          }
        }
      } else if (tag === "A") {
        var ah = el.getAttribute("href");
        if (ah) {
          var clsA = classifyReference(ah, ctx);
          if (clsA.kind !== "external" && clsA.ref) {
            el.__digRewritten = true;
            el.addEventListener("click", function (ev) {
              ev.preventDefault();
              navigateInPage(clsA.ref);
            });
          }
        }
      }
    }
    function scan(root) {
      if (!root || !root.querySelectorAll) return;
      var nodes = root.querySelectorAll("img,script,source,video,audio,link,a");
      for (var i = 0; i < nodes.length; i++) rewriteEl(nodes[i]);
    }
    var mo = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var added = muts[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var n = added[j];
          if (n.nodeType === 1) {
            rewriteEl(n);
            scan(n);
          }
        }
      }
    });
    // Observe immediately; scan whatever is already there once the doc is swapped in.
    try { mo.observe(document.documentElement, { childList: true, subtree: true }); } catch (_) {}
    window.__digScanDom = scan; // exposed so the doc-swap step can do an initial pass
  }

  // In-page navigation to another DIG resource (Tier 2 <a> hijack). For an HTML target, re-swap the
  // document; for a non-HTML target, open it (object URL).
  function navigateInPage(refObj) {
    injectOverlay();
    overlayMessage("Loading…");
    readResource(refObj).then(function (r) {
      var ct = contentType(refObj.resourceKey);
      if (ct.indexOf("text/html") === 0) {
        swapDocument(new TextDecoder().decode(r.bytes));
      } else {
        removeOverlay();
        location.href = makeObjectUrl(r.bytes, ct);
      }
    }).catch(function (e) {
      overlayError("Could not load that DIG link.", e && e.message);
    });
  }

  // ===============================================================================================
  // DOCUMENT SWAP — replace the page with the loaded entry HTML.
  // ===============================================================================================
  function swapDocument(html) {
    // Rewrite inline DOM URLs after writing so the Tier-2 interceptor's scan catches them, then
    // remove the overlay. document.write replaces the whole document (scripts re-execute).
    document.open();
    document.write(html);
    document.close();
    // After the new doc parses, do an initial rewrite pass (the MutationObserver covers later nodes).
    setTimeout(function () {
      if (typeof window.__digScanDom === "function") {
        try { window.__digScanDom(document); } catch (_) {}
      }
      removeOverlay();
    }, 0);
  }

  // ===============================================================================================
  // TIER 1 — same-origin service worker (full power). Only reachable when the snippet is served from
  // the SAME origin as the page (e.g. the *.on.dig.net resolver, or a site self-hosting the SW). The
  // SW script + dig-client assets must be served same-origin (the resolver wires this; see
  // services/resolver). We register, wait for control, then fetch the entry through the SW (which
  // intercepts + decrypts everything thereafter, including future navigations).
  // ===============================================================================================
  async function runTier1(cfg) {
    // The SW config endpoint + script are served same-origin by the host. The resolver uses
    // /__dig_sw.js + /__dig/config.json. We post the pin to the SW via a config the host serves, OR
    // (embed-as-self-host) the host serves /__dig_sw.js and we hand it the pin through a query string.
    var swUrl = "/__dig_sw.js?store=" + encodeURIComponent(cfg.storeId) +
      "&root=" + encodeURIComponent(cfg.root || "") +
      "&salt=" + encodeURIComponent(cfg.salt || "") +
      "&entry=" + encodeURIComponent(cfg.entryKey || "index.html");
    var reg = await navigator.serviceWorker.register(swUrl, { scope: "/", type: "module" });
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      // First load: the SW isn't controlling yet. Reload once to gain control (guarded).
      if (!sessionStorage.getItem("dig_sw_reloaded")) {
        sessionStorage.setItem("dig_sw_reloaded", "1");
        location.reload();
        return;
      }
      throw new Error("service worker did not take control");
    }
    sessionStorage.removeItem("dig_sw_reloaded");
    var path = cfg.entryKey && cfg.entryKey !== "index.html" ? "/" + cfg.entryKey : "/index.html";
    var res = await fetch(path);
    if (!res.ok) throw new Error("DIG content unavailable (" + res.status + ")");
    var html = await res.text();
    swapDocumentTier1(html);
    void reg;
  }
  // Tier 1 doc swap: the SW intercepts all subsequent requests, so we DON'T install the in-page
  // interceptor — we just write the doc and let the SW serve its subresources.
  function swapDocumentTier1(html) {
    document.open();
    document.write(html);
    document.close();
    removeOverlay();
  }

  // ===============================================================================================
  // BOOT
  // ===============================================================================================
  function start(urnValue) {
    var cfg = readDigUrnGlobal(urnValue);
    if (!cfg) {
      overlayError(
        "No DIG content to load.",
        'Set window.digurn = "urn:dig:chia:<storeId>[:<root>]/<path>" before this snippet runs.'
      );
      return;
    }
    cfg.entryKey = cfg.entryKey || "index.html";

    var tier = detectTier({
      isSecureContext: !!window.isSecureContext,
      hasServiceWorker: "serviceWorker" in navigator,
      hasModuleWorker: moduleWorkerSupported(),
      scriptOrigin: SELF_ORIGIN,
      pageOrigin: location.origin,
    });

    if (tier.tier === 1) {
      runTier1(cfg).catch(function (e) {
        // SW path failed (e.g. Firefox slipped through, or scope/MIME issue) — fall back to in-page.
        console.warn("[dig-embed] Tier 1 SW failed, falling back to in-page:", e && e.message);
        runTier2(cfg);
      });
    } else {
      runTier2(cfg);
    }
  }

  function runTier2(cfg) {
    overlayMessage("Loading content from the DIG Network…");
    installInPageInterceptor(cfg);
    readResource({ storeId: cfg.storeId, root: cfg.root || "latest", resourceKey: cfg.entryKey, salt: cfg.salt })
      .then(function (r) {
        var ct = contentType(cfg.entryKey);
        if (ct.indexOf("text/html") === 0) {
          swapDocument(new TextDecoder().decode(r.bytes));
        } else {
          // Single non-HTML resource: render it directly via an object URL.
          removeOverlay();
          var url = makeObjectUrl(r.bytes, ct);
          if (ct.indexOf("image/") === 0) {
            document.open();
            document.write('<!doctype html><meta charset="utf-8"><title>DIG resource</title>' +
              '<body style="margin:0;background:#0b0a12;display:flex;align-items:center;justify-content:center;min-height:100vh">' +
              '<img src="' + url + '" style="max-width:100%;max-height:100vh" alt=""></body>');
            document.close();
          } else {
            location.href = url;
          }
        }
      })
      .catch(function (e) {
        overlayError("Couldn't load this DIG content.", e && e.message);
      });
  }

  // Boot: show the overlay ASAP, then detect window.digurn (poll briefly for a late-set value).
  function boot() {
    // #206b — when the host is a resolver loader shell that resolved a NON-ACTIVE status, it sets
    // window.__digShellInert and renders the status message on its OWN branded card. In that case
    // this embed must do NOTHING: never adopt/remove the shell (removeOverlay would blank the card
    // → white screen) and never stack an overlay. The branded status card is the final state.
    if (window.__digShellInert) return;
    injectOverlay();
    var tries = 0;
    (function poll() {
      if (window.__digShellInert) return; // status resolved to non-active while polling — stand down
      if (window.digurn) {
        start(window.digurn);
        return;
      }
      if (tries++ < 80) {
        setTimeout(poll, 25); // up to ~2s for the shell's async config.json to set window.digurn
        return;
      }
      // No URN ever set and no non-active status → be inert. When we ADOPTED a host loader shell,
      // LEAVE it painted (removing it would blank the branded card); only remove an overlay WE
      // created. Honest, not a hard error.
      if (!window.__digLoaderShellPresent) removeOverlay();
    })();
  }

  if (document.body) boot();
  else document.addEventListener("DOMContentLoaded", boot);
})();

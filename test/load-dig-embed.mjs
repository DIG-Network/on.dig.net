// test/load-dig-embed.mjs
//
// Loads assets/dig-embed.js's `readResource` (the Tier-2 in-page fallback content path) under plain
// Node for unit testing, WITHOUT executing the whole browser IIFE.
//
// dig-embed.js is authored as a single dependency-free browser IIFE: it registers DOM listeners and
// calls boot() at load, none of which resolve under Node. Rather than fork readResource into a
// second, drift-prone copy, this loader slices the GENUINE function bodies out of the real source
// text (brace-matched) and re-hydrates just `readResource` + its two collaborators (`decryptChunks`,
// `rootIsPinned`) inside a Function scope wired to injected fakes (a deterministic dig-client stub,
// stubbed loadDigClient/fetchVerified, an in-memory CACHE). readResource itself runs UNMODIFIED, so
// the security behaviour under test (fail-closed decrypt + pinned-root merkle gate) is the real code.
//
// Real AEAD/merkle correctness is NOT re-tested here — it is covered byte-for-byte by digstore's
// dig-client-wasm Rust suite; test/stub-dig-client.mjs stands in for the wasm crypto.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const embedPath = path.join(here, "..", "assets", "dig-embed.js");

/**
 * Extract a top-level `function NAME(...) { ... }` definition from `src` by matching balanced braces
 * starting at the function's opening `{`. Returns the full source slice, or `null` if not found.
 */
function extractFunction(src, name) {
  const sig = new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\(`);
  const start = src.search(sig);
  if (start === -1) return null;
  const open = src.indexOf("{", start);
  if (open === -1) return null;
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return src.slice(start, i + 1);
    }
  }
  return null;
}

/**
 * Build a testable `readResource` from the REAL assets/dig-embed.js source, wired to injected deps.
 * `deps` supplies { loadDigClient, fetchVerified } and optional { CACHE, CACHE_MAX }.
 *
 * `rootIsPinned` is extracted when present; before the #2261 fix it does not exist yet, so a
 * fail-open default is injected — harmless, since pre-fix readResource never references it. This lets
 * the same test file confirm the RED (pre-fix: no throw) and the GREEN (post-fix: throws).
 */
export function loadReadResource(deps) {
  const src = readFileSync(embedPath, "utf8");
  const readResourceSrc = extractFunction(src, "readResource");
  const decryptChunksSrc = extractFunction(src, "decryptChunks");
  if (!readResourceSrc || !decryptChunksSrc) {
    throw new Error(
      "dig-embed.js structure changed — readResource/decryptChunks not found; update load-dig-embed.mjs"
    );
  }
  const rootIsPinnedSrc =
    extractFunction(src, "rootIsPinned") ||
    "function rootIsPinned() { return false; }";
  // #2313: readResource canonicalizes its root at entry — inject the real helper (identity fallback
  // for a pre-fix source that has no such helper yet).
  const canonicalizeRootSrc =
    extractFunction(src, "canonicalizeRoot") ||
    "function canonicalizeRoot(root) { return root; }";

  const factory = new Function(
    "deps",
    `"use strict";
     const { loadDigClient, fetchVerified } = deps;
     const CACHE = deps.CACHE || new Map();
     const CACHE_MAX = deps.CACHE_MAX || 100;
     ${canonicalizeRootSrc}
     ${rootIsPinnedSrc}
     ${decryptChunksSrc}
     ${readResourceSrc}
     return readResource;`
  );
  return factory(deps);
}

/**
 * Extract the REAL `rootIsPinned` predicate from assets/dig-embed.js and return it as a callable, so
 * the #2313 fail-closed sentinel semantics (a non-canonical pinned root — uppercase/`0x`/whitespace —
 * still reads as PINNED and thus gated) can be pinned directly. `rootIsPinned` is authored
 * self-contained (it does its own trim/lowercase/strip-0x), so no collaborators need injecting.
 */
export function loadRootIsPinned() {
  const src = readFileSync(embedPath, "utf8");
  const rootIsPinnedSrc = extractFunction(src, "rootIsPinned");
  if (!rootIsPinnedSrc) {
    throw new Error(
      "dig-embed.js structure changed — rootIsPinned not found; update load-dig-embed.mjs"
    );
  }
  const factory = new Function(`"use strict"; ${rootIsPinnedSrc} return rootIsPinned;`);
  return factory();
}

/**
 * Extract assets/dig-embed.js's DIG URN parsing surface and return it as callables, so the parser
 * can be run against the shared cross-repo conformance table (test/urn-conformance.test.mjs).
 *
 * Like the loaders above this re-hydrates the GENUINE source text — the parser under test is the
 * shipped one, not a copy. A copy would be free to pass the table while the served asset does not.
 */
const URN_CONSTANTS = ["SALT_PARAM", "SALT_AFTER_AMP", "SALT_VALUE_RE", "BARE_URN_RE"];
const URN_FUNCTIONS = ["splitSaltQuery", "withDefaultView", "canonicalizeRoot", "parseDigRef", "readDigUrnGlobal"];

export function loadUrnParser() {
  const src = readFileSync(embedPath, "utf8");
  const parts = URN_CONSTANTS.map((name) => {
    const m = new RegExp(`^[ \t]*var ${name} = .*;$`, "m").exec(src);
    if (!m) throw new Error(`dig-embed.js structure changed — the '${name}' declaration is not a single-line 'var'; update load-dig-embed.mjs`);
    return m[0];
  }).concat(
    URN_FUNCTIONS.map((name) => {
      const fn = extractFunction(src, name);
      if (!fn) throw new Error(`dig-embed.js structure changed — ${name} not found; update load-dig-embed.mjs`);
      return fn;
    })
  );
  const factory = new Function(
    `"use strict"; ${parts.join("\n")} return { ${URN_FUNCTIONS.join(", ")} };`
  );
  return factory();
}

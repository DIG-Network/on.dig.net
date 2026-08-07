// test/vendor-map.test.mjs
//
// Guards the ONE piece of logic that lives, byte-mirrored, in BOTH vendored/authored loader files:
// the MIME `contentType()` map. assets/dig-embed.js (vendored from hub) and assets/sw.js (on.dig.net's
// own extracted resolver Service Worker) each carry a copy of the extension→MIME table, because a
// standalone module worker cannot import hub's canonical apps/web/lib/embed-core.ts. When the two
// copies silently diverge, resources serve under the wrong Content-Type on one path but not the other
// (the exact class of drift that made #2261 a live vuln, and that already bit this map once — see the
// "missing avif/ttf/otf/mp3" note in sw.js). This test pins them equal, offline, in-repo.
//
// Both contentType() functions are pure + self-contained (they close over nothing), so they are
// sliced out of the real source text (brace-matched) and evaluated directly — the genuine tables run,
// no browser/wasm needed. We assert they map every known extension identically AND agree on the
// octet-stream default for an unknown one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const assetsDir = path.join(here, "..", "assets");

/** Slice a top-level `function NAME(...) { ... }` out of `src` by matching balanced braces. */
function extractFunction(src, name) {
  const start = src.search(new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\(`));
  if (start === -1) return null;
  const open = src.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}" && --depth === 0) return src.slice(start, i + 1);
  }
  return null;
}

/** Re-hydrate the REAL `contentType` from a loader asset as a callable pure function. */
function loadContentType(file) {
  const src = readFileSync(path.join(assetsDir, file), "utf8");
  const fnSrc = extractFunction(src, "contentType");
  assert.ok(fnSrc, `contentType() not found in ${file} — the map moved; update this test`);
  return new Function(`"use strict"; ${fnSrc} return contentType;`)();
}

// The full key set the map must cover (the union that appears in the mirrored table), plus an unknown
// extension to pin the shared octet-stream default.
const EXTENSIONS = [
  "html", "htm", "js", "mjs", "css", "json",
  "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "avif",
  "woff", "woff2", "ttf", "otf",
  "txt", "pdf", "mp4", "webm", "mp3", "wasm", "xml", "md",
  "unknown-ext-that-should-default",
];

test("assets/sw.js and assets/dig-embed.js share a byte-identical contentType MIME map", () => {
  const swType = loadContentType("sw.js");
  const embedType = loadContentType("dig-embed.js");

  const swMap = Object.fromEntries(EXTENSIONS.map((e) => [e, swType(`file.${e}`)]));
  const embedMap = Object.fromEntries(EXTENSIONS.map((e) => [e, embedType(`file.${e}`)]));

  assert.deepEqual(
    embedMap,
    swMap,
    "the mirrored MIME map in dig-embed.js and sw.js has drifted — re-sync both to hub's embed-core.ts"
  );
  // Guard the shared default explicitly (deepEqual above already covers it, but make the intent loud).
  assert.equal(swMap["unknown-ext-that-should-default"], "application/octet-stream");
});

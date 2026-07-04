// test/load-sw.mjs
//
// Loads assets/sw.js under plain Node for unit testing.
//
// sw.js is authored to run as a browser module Service Worker: it has ONE absolute-path ES import
// (the wasm-bindgen glue at "/__dig/dig_client.js", meaningless outside a browser origin) and
// registers top-level `self.addEventListener(...)` listeners on import — neither resolves under
// plain Node. Rather than fork sw.js's pure orchestration logic into a second, drift-prone copy
// just to make it importable, this loader:
//
//   1. Rewrites the one wasm-bindgen import to a file:// import of stub-dig-client.mjs
//      (deterministic fake crypto — see that file's doc comment for why real AEAD/merkle
//      correctness is intentionally NOT re-tested here; it's covered by digstore's Rust suite).
//   2. Installs a minimal `self` (addEventListener/location/clients/skipWaiting) and an in-memory
//      `caches` (CacheStorage) polyfill on `globalThis`, since neither exists in Node. `fetch`,
//      `Response`, `Request`, `ReadableStream`, `crypto.subtle`, and `atob` are real Node globals
//      (Node 18+) and are used as-is — no polyfill needed for those.
//   3. Imports the transformed source via a `data:` URL (a stable Node dynamic-import target since
//      Node 17.5), so nothing is written to disk.
//
// Returns the sw.js module namespace — its named exports (see the "Test-only exports" block at the
// bottom of sw.js).
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const swPath = path.join(here, "..", "assets", "sw.js");
const stubUrl = pathToFileURL(path.join(here, "stub-dig-client.mjs")).href;

const IMPORT_RE = /import initDigClient,\s*\{[\s\S]*?\}\s*from\s*["']\/__dig\/dig_client\.js["'];/;

export async function loadSw({ locationHref = "https://teststore.on.dig.net/" } = {}) {
  const src = readFileSync(swPath, "utf8");
  if (!IMPORT_RE.test(src)) {
    throw new Error(
      "sw.js's wasm-bindgen import statement shape changed — update load-sw.mjs's IMPORT_RE to match"
    );
  }
  const transformed = src.replace(
    IMPORT_RE,
    `import initDigClient, { retrievalKey, deriveKey, verifyInclusion, decryptChunk, install_global } from ${JSON.stringify(stubUrl)};`
  );

  installSwGlobals(locationHref);

  const dataUrl = "data:text/javascript;base64," + Buffer.from(transformed, "utf8").toString("base64");
  return import(dataUrl);
}

/** Minimal `self` + `caches` polyfill so sw.js's top-level side effects (addEventListener calls)
 *  and any Cache Storage use don't throw on import under Node. */
function installSwGlobals(locationHref) {
  globalThis.self = {
    addEventListener() {}, // sw.js registers install/activate/fetch listeners; tests call the
                            // exported functions directly rather than dispatching fake events.
    location: new URL(locationHref),
    clients: { claim: async () => {} },
    skipWaiting: async () => {},
  };
  globalThis.caches = makeFakeCacheStorage();
}

/** A tiny in-memory CacheStorage stand-in: `open(name)` returns a Map-backed cache exposing the
 *  same `match`/`put`/`keys`/`delete` surface sw.js uses. */
function makeFakeCacheStorage() {
  const stores = new Map();
  return {
    async open(name) {
      if (!stores.has(name)) stores.set(name, new Map());
      const store = stores.get(name);
      return {
        async match(req) {
          return store.get(keyFor(req));
        },
        async put(req, res) {
          store.set(keyFor(req), res);
        },
        async keys() {
          return [...store.keys()].map((k) => new Request(k));
        },
        async delete(req) {
          return store.delete(keyFor(req));
        },
      };
    },
  };
}

function keyFor(req) {
  return typeof req === "string" ? req : req.url;
}

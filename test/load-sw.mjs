// test/load-sw.mjs
//
// Loads the REAL assets/sw.js under plain Node for unit testing, WITH V8 test-coverage attribution.
//
// sw.js is authored to run as a browser module Service Worker: it has ONE absolute-path ES import
// (the wasm-bindgen glue at "/__dig/dig_client.js", meaningless outside a browser origin) and
// registers top-level `self.addEventListener(...)` listeners on import — neither resolves under
// plain Node. Rather than fork sw.js's logic into a second, drift-prone copy (or rewrite its source
// into an anonymous `data:` URL, which hides the file from the coverage report — see #sw-coverage),
// this loader imports the genuine file and makes it runnable under Node by:
//
//   1. Registering a module-resolve hook (test/sw-import-hooks.mjs) that remaps the one
//      wasm-bindgen import to test/stub-dig-client.mjs (deterministic fake crypto — see that file's
//      doc comment for why real AEAD/merkle correctness is intentionally NOT re-tested here; it's
//      covered by digstore's Rust suite). The file itself is imported UNMODIFIED, so V8 attributes
//      coverage to `assets/sw.js`.
//   2. Installing a minimal `self` (addEventListener/location/clients/skipWaiting) and an in-memory
//      `caches` (CacheStorage) polyfill on `globalThis`, since neither exists in Node. `fetch`,
//      `Response`, `Request`, `ReadableStream`, `crypto.subtle`, and `atob` are real Node globals
//      (Node 18+) and are used as-is — no polyfill needed for those.
//
// Returns the sw.js module namespace — its named exports (see the "Test-only exports" block at the
// bottom of sw.js). The module is import-cached (one instance), so `self.location` is (re)set on
// each `loadSw` call and read at call-time by the exported helpers.
import { register } from "node:module";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const swPath = path.join(here, "..", "assets", "sw.js");
const swUrl = pathToFileURL(swPath).href;

// The wasm-bindgen import statement shape sw.js MUST keep for the resolve hook to find it. Asserted
// once (below) so a future edit to that import fails loudly here instead of silently breaking the
// remap and every sw.js test with it.
const IMPORT_RE = /import initDigClient,\s*\{[\s\S]*?\}\s*from\s*["']\/__dig\/dig_client\.js["'];/;

let hooksRegistered = false;

export async function loadSw({ locationHref = "https://teststore.on.dig.net/" } = {}) {
  if (!hooksRegistered) {
    const src = readFileSync(swPath, "utf8");
    if (!IMPORT_RE.test(src)) {
      throw new Error(
        "sw.js's wasm-bindgen import statement shape changed — update test/sw-import-hooks.mjs's WASM_GLUE_SPECIFIER and this IMPORT_RE to match"
      );
    }
    register("./sw-import-hooks.mjs", import.meta.url);
    hooksRegistered = true;
  }

  installSwGlobals(locationHref);
  return import(swUrl);
}

/** Minimal `self` + `caches` polyfill so sw.js's top-level side effects (addEventListener calls)
 *  and any Cache Storage use don't throw under Node. */
// sw.js registers its install/activate/fetch listeners exactly ONCE, at module import — but each
// `installSwGlobals` call swaps in a fresh `self`. Share one listener registry across every `self`
// so a listener captured at import is still reachable via a later `self.dispatch(...)`.
const swListeners = new Map();

export function installSwGlobals(locationHref) {
  const listeners = swListeners;
  globalThis.self = {
    // sw.js registers install/activate/fetch listeners at import; capture them so tests that want
    // to exercise the lifecycle/fetch handlers can dispatch a fake event (see sw-runtime.test.mjs).
    addEventListener(type, handler) {
      listeners.set(type, handler);
    },
    dispatch(type, event) {
      const handler = listeners.get(type);
      if (!handler) throw new Error(`no '${type}' listener registered`);
      return handler(event);
    },
    location: new URL(locationHref),
    origin: new URL(locationHref).origin,
    clients: { claim: async () => {} },
    skipWaiting: async () => {},
  };
  globalThis.caches = makeFakeCacheStorage();
  return globalThis.self;
}

/** A tiny in-memory CacheStorage stand-in: `open(name)` returns a Map-backed cache exposing the
 *  same `match`/`put`/`keys`/`delete` surface sw.js uses. */
export function makeFakeCacheStorage({ failOpen = false } = {}) {
  const stores = new Map();
  return {
    async open(name) {
      if (failOpen) throw new Error("cache storage unavailable");
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

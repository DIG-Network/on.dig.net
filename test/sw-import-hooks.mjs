// test/sw-import-hooks.mjs
//
// A module-customization resolve hook (registered by load-sw.mjs via `node:module`'s `register`)
// that remaps assets/sw.js's ONE browser-only import — the wasm-bindgen glue at
// "/__dig/dig_client.js" — to the deterministic in-repo crypto stub (test/stub-dig-client.mjs).
//
// WHY a resolve hook instead of the old source-rewrite-into-a-data:-URL trick: importing the REAL
// assets/sw.js file (unmodified, from its own file:// URL) is what lets V8's test-coverage tool
// attribute coverage to `assets/sw.js`. A `data:` URL import is anonymous, so the service worker's
// lines showed up NOWHERE in the coverage report — the file read as 0% covered / invisible. Loading
// the genuine file fixes the measurement without forking sw.js into a drift-prone second copy.
import { pathToFileURL, fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const STUB_URL = pathToFileURL(path.join(here, "stub-dig-client.mjs")).href;

// sw.js imports the wasm-bindgen glue by this exact absolute-path specifier (a browser same-origin
// path that is meaningless — and unresolvable — under Node). Intercept it and hand back the stub.
const WASM_GLUE_SPECIFIER = "/__dig/dig_client.js";

export async function resolve(specifier, context, nextResolve) {
  if (specifier === WASM_GLUE_SPECIFIER) {
    return { url: STUB_URL, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

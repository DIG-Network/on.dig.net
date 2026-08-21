// tests/conformance/urn-conformance.test.mjs
//
// Holds BOTH of on.dig.net's DIG URN parsers to the ratified cross-repo parse contract:
//
//   * assets/dig-embed.js  parseDigRef  — the embeddable loader (vendored from hub.dig.net)
//   * assets/sw.js         parseDigUrn  — the resolver Service Worker
//
// WHY this test carries real weight. `resourceKey` and `salt` are the inputs to the retrieval key
// and the decryption key, so a parser that is one character off asks the network for the wrong
// bytes — or, worse, derives a plausible-looking WRONG key and fails in a way a reader cannot
// distinguish from missing content. Neither file can `import` the canonical parser: dig-embed.js is
// served standalone to third-party pages, and sw.js is a module Service Worker that must boot with
// no bundler. Each therefore carries a PORT, and a port kept in sync by a comment is exactly how
// on.dig.net ended up shipping the parser hub.dig.net had already replaced (issue #17).
//
// So the mirror is pinned MECHANICALLY: the functions are sliced out of the REAL shipped source
// files (brace-matched, the established pattern in test/vendor-map.test.mjs) and evaluated
// standalone, then run against @dignetwork/dig-sdk/conformance/urn-parse.json — the same table
// dig-sdk and hub.dig.net are held to.
//
// The table is read from the INSTALLED PACKAGE, never copied into this repo. A copied fixture
// drifts silently, which is the whole failure class being closed here.
//
// Run:  cd tests/conformance && npm ci && npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const assetsDir = path.join(here, "..", "..", "assets");

const require = createRequire(import.meta.url);
const table = require("@dignetwork/dig-sdk/conformance/urn-parse.json");

/** Slice a top-level `function NAME(...) { ... }` out of `src` by matching balanced braces. */
function extractFunction(src, name) {
  const start = src.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `function ${name} not found — it moved; update this test`);
  const open = src.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}" && --depth === 0) return src.slice(start, i + 1);
  }
  assert.fail(`unbalanced braces extracting ${name}`);
}

// The declarations the parser closes over. Listed explicitly and asserted PRESENT in the source, so
// a renamed/removed declaration fails loudly here instead of silently resolving to this test's own
// copy — which would test a stale mirror while reporting green.
const SHARED_DECLS = [
  'const SALT_PARAM_NAME = "salt=";',
  'const SALT_AFTER_AMP = "&" + SALT_PARAM_NAME;',
  "const SALT_QUERY_VALUE_RE = /(?:^|[&?])salt=([0-9a-fA-F]+)/;",
];

/**
 * Re-hydrate a parser from a shipped asset as a callable pure function. `varKeyword` is the file's
 * own declaration style (dig-embed.js is an ES5 IIFE and uses `var`; sw.js is a module and uses
 * `const`), which is the ONLY permitted difference between the two copies of the algorithm.
 */
function loadParser(file, name, varKeyword) {
  const src = readFileSync(path.join(assetsDir, file), "utf8");
  const decls = SHARED_DECLS.map((d) => d.replace(/^const /, `${varKeyword} `));
  for (const decl of decls) {
    assert.ok(
      src.includes(decl),
      `${file} no longer declares \`${decl}\` — the extraction below would test a stale copy`,
    );
  }
  return new Function(
    `"use strict";
     ${decls.join("\n")}
     ${extractFunction(src, "splitQuery")}
     ${extractFunction(src, "canonicalizeRoot")}
     ${extractFunction(src, name)}
     return ${name};`,
  )();
}

const PARSERS = [
  { label: "assets/dig-embed.js parseDigRef", fn: loadParser("dig-embed.js", "parseDigRef", "var") },
  { label: "assets/sw.js parseDigUrn", fn: loadParser("sw.js", "parseDigUrn", "const") },
];

// Both parsers are the TOLERANT edge form: a reference naming a store but no resource resolves to
// the default view rather than being rejected. That widening is their job (a bare store URN is a
// legitimate request for the site's entry point) and it can never yield a DIFFERENT key — only the
// default one — so the table's `invalid` expectation is mapped onto it rather than asserted raw.
const DEFAULT_VIEW = "index.html";

test("the extracted parsers are the real ones, not empty stubs", () => {
  for (const { label, fn } of PARSERS) assert.equal(typeof fn, "function", label);
  assert.ok(table.cases.length >= 28, "conformance table is truncated");
});

for (const { label, fn } of PARSERS) {
  for (const c of table.cases) {
    test(`${label}: ${c.name}`, () => {
      const got = fn(c.urn);
      if (c.expect.invalid) {
        if (got !== null) {
          // The widening is permitted ONLY for the empty-resource-key case: a well-formed store id
          // and the default view. Anything else — notably a store id that is not 64 hex — is a
          // parser accepting a URN it cannot have derived a correct key for.
          assert.match(got.storeId, /^[0-9a-f]{64}$/, `accepted a malformed store id: ${c.urn}`);
          assert.equal(
            got.resourceKey,
            DEFAULT_VIEW,
            `accepted an invalid URN as something other than the default view: ${c.urn}`,
          );
        }
        return;
      }
      assert.notEqual(got, null, `rejected a valid URN: ${c.urn}`);
      assert.equal(got.storeId, c.expect.storeId);
      assert.equal(got.root, c.expect.root);
      assert.equal(got.resourceKey, c.expect.resourceKey);
      assert.equal(got.salt, c.expect.salt);
    });
  }

  // The two defects issue #17 measured, named individually so a regression reads as itself rather
  // than as an anonymous table row.
  test(`${label}: a non-salt query stays part of the resource key (a published key is not truncated)`, () => {
    const id = "ab".repeat(32);
    assert.equal(fn(`urn:dig:chia:${id}/report?year=2024.csv`).resourceKey, "report?year=2024.csv");
  });

  test(`${label}: the salt value is NOT percent-decoded`, () => {
    const id = "ab".repeat(32);
    // %66%66 is "ff" percent-encoded. URLSearchParams decodes it and then accepts it as hex, which
    // yields a plausible-looking but WRONG decryption key — the silent failure direction. The
    // contract reads the leading HEX RUN of the LITERAL value instead, which is empty here.
    assert.equal(fn(`urn:dig:chia:${id}/a.txt?salt=%66%66`).salt, null);
  });
}

// The two ports must be ONE algorithm, not two that happen to agree on the table today: a table is
// finite and a parser is not. Pinned by comparing the extracted source TEXT with only the four
// incidental differences normalised away — the declaration keyword, the function's own name, the
// line ending, and the indentation dig-embed.js carries from being nested inside an IIFE. Anything
// else, including a single changed operator, fails here.
test("both parsers carry the same port of the algorithm, token for token", () => {
  const normalise = (file, name) => {
    const src = readFileSync(path.join(assetsDir, file), "utf8");
    return [extractFunction(src, "splitQuery"), extractFunction(src, name)]
      .join("\n")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .join("\n")
      .replace(/\bvar\b/g, "let")
      .replace(/\bconst\b/g, "let")
      .replace(/\bparseDigUrn\b|\bparseDigRef\b/g, "parse");
  };
  assert.equal(
    normalise("sw.js", "parseDigUrn"),
    normalise("dig-embed.js", "parseDigRef"),
    "assets/sw.js and assets/dig-embed.js carry DIFFERENT URN parse logic — they must be one algorithm",
  );
});

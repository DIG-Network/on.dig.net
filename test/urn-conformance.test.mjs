// test/urn-conformance.test.mjs
//
// Runs this repo's TWO DIG URN parsers against the SHARED conformance table.
//
// Why this exists: both parsers turn a URN into a resource key and a salt, and those two values are
// the inputs to retrieval-key and decryption-key derivation. Two implementations that parse one URN
// differently derive different keys, so a reader gets bytes that do not resolve or do not decrypt.
// Agreement therefore has to be VERIFIED, not asserted in a comment — the previous comment claiming
// byte-identity with the sibling parsers was true of neither.
//
// The rule is normative in the superproject: SYSTEM.md § "DIG URN grammar (normative, cross-repo)".
// The table is read from the @dignetwork/dig-sdk package (a devDependency) and is deliberately NOT
// copied into this repo: a copied table drifts, which is the defect class this test closes.
import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { loadUrnParser } from "./load-dig-embed.mjs";
import { loadSw } from "./load-sw.mjs";

const require = createRequire(import.meta.url);
const TABLE = require("@dignetwork/dig-sdk/conformance/urn-parse.json");

const CASES = TABLE.cases;
assert.ok(Array.isArray(CASES) && CASES.length >= 20, "the shared conformance table looks empty or reshaped");

const valid = (c) => !c.expect.invalid;

test("dig-embed.js parseDigRef matches the shared conformance table (every row)", () => {
  const { parseDigRef } = loadUrnParser();
  for (const c of CASES) {
    const actual = parseDigRef(c.urn);
    if (c.expect.invalid) {
      assert.equal(actual, null, `${c.name}\n  urn: ${c.urn}`);
    } else {
      assert.deepEqual(actual, c.expect, `${c.name}\n  urn: ${c.urn}`);
    }
  }
});

test("dig-embed.js parseDigRef treats the chia:// form identically to the urn: form", () => {
  const { parseDigRef } = loadUrnParser();
  for (const c of CASES.filter((c) => c.urn.startsWith("urn:dig:chia:"))) {
    const asChia = "chia://" + c.urn.slice("urn:dig:chia:".length);
    assert.deepEqual(parseDigRef(asChia), parseDigRef(c.urn), `${c.name}\n  urn: ${c.urn}`);
  }
});

test("sw.js parseDigUrn agrees with the shared table on every parseable row", async () => {
  const { parseDigUrn } = await loadSw();
  // The `invalid` rows are excluded here on purpose: sw.js's parser is deliberately lenient about
  // the HEAD (it accepts a non-64-hex store id, which cannot resolve anyway and is not a key
  // divergence), so those rows say nothing about key agreement. Every row that a conforming parser
  // ACCEPTS must produce identical parts, because those parts are the key inputs.
  for (const c of CASES.filter(valid)) {
    assert.deepEqual(parseDigUrn(c.urn), c.expect, `${c.name}\n  urn: ${c.urn}`);
  }
  assert.equal(parseDigUrn("https://example.com/index.html"), null);
});

test("the two parsers in this repo agree with EACH OTHER on every row", async () => {
  const { parseDigRef } = loadUrnParser();
  const { parseDigUrn } = await loadSw();
  for (const c of CASES.filter(valid)) {
    assert.deepEqual(parseDigUrn(c.urn), parseDigRef(c.urn), `${c.name}\n  urn: ${c.urn}`);
  }
});

// The default view is a DERIVATION-time decision, not a parse-time one (the table's "an empty
// resource key is not a URN" row): a parser that substitutes "index.html" for an empty key reports
// a key the URN does not contain. These assert the default still reaches the two callers that need
// it, so removing it from the parser changed no served behaviour.
test("the index.html default is applied by the callers, not by the parser", async () => {
  const { parseDigRef, readDigUrnGlobal } = loadUrnParser();
  const { parseDigUrn } = await loadSw();
  const bare = "urn:dig:chia:" + "ab".repeat(32);

  // Both parsers stay honest about a URN that names no resource...
  assert.equal(parseDigRef(bare), null);
  assert.equal(parseDigUrn(bare).resourceKey, "");

  // ...and both callers still reach the default view, so no served behaviour changed. The sw.js
  // side is pinned end-to-end by "serveUrn: a URN naming NO resource serves the store's default
  // view" in test/sw-runtime.test.mjs, which reads bytes decryptable only under the index.html key.
  assert.equal(readDigUrnGlobal(bare).entryKey, "index.html");
  assert.equal(readDigUrnGlobal(bare + "/?salt=ff00").entryKey, "index.html");
  assert.equal(readDigUrnGlobal(bare + "/?salt=ff00").salt, "ff00");
});

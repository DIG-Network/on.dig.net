// test/dig-embed.test.mjs
//
// Regression tests for assets/dig-embed.js's `readResource` — the Tier-2 IN-PAGE fallback content
// path (used when the same-origin Service Worker cannot be registered). These pin the #2261
// fail-closed security contract, mirroring the Tier-1 SW fixes (#2259 decrypt gate, #2260/#2264
// merkle-inclusion gate in assets/sw.js):
//
//   * a decrypt/AEAD-tag failure MUST throw (never surface raw ciphertext as content), and
//   * a PINNED-root (concrete 64-hex) read whose merkle inclusion proof does not verify MUST throw
//     (the proof is the only thing binding served bytes to the pinned root — a clean decrypt does
//     NOT prove authenticity, since the decrypt key is derivable from public URN fields), while
//   * an unpinned "latest" read has no pinned root to bind to (blind model) → verification is
//     advisory and MUST NOT gate; the bytes still serve.
//
// readResource runs UNMODIFIED here (see test/load-dig-embed.mjs); the wasm crypto is faked
// deterministically (test/stub-dig-client.mjs) — real AEAD/merkle correctness lives in digstore.
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadReadResource } from "./load-dig-embed.mjs";
import {
  retrievalKey,
  deriveKey,
  verifyInclusion,
  decryptChunk,
  encryptChunkForTest,
} from "./stub-dig-client.mjs";

const STORE = "a".repeat(64);
const PINNED_ROOT = "b".repeat(64); // a concrete 64-hex generation root
const RESOURCE = "index.html";

/** A dig-client stub whose inclusion verdict + decrypt success are controlled per test. */
function digStub() {
  return { retrievalKey, deriveKey, verifyInclusion, decryptChunk };
}

/**
 * Wire a `readResource` over a controlled fetchVerified. `proof` selects the inclusion verdict via
 * the stub ("valid-proof" → true, anything else → false); `plaintext` (when set) yields a ciphertext
 * that decrypts cleanly for the resource key, otherwise ciphertext that fails the AEAD tag check.
 */
function makeReadResource({ proof, plaintext, salt }) {
  const keyHex = deriveKey(STORE, RESOURCE, salt);
  const ciphertext =
    plaintext != null
      ? encryptChunkForTest(keyHex, plaintext)
      : new TextEncoder().encode("undecryptable-decoy-bytes");
  return loadReadResource({
    loadDigClient: async () => digStub(),
    fetchVerified: async () => ({ ciphertext, proof, chunkLens: null }),
  });
}

const ref = (root, salt) => ({ storeId: STORE, root, resourceKey: RESOURCE, salt });

test("pinned root + failed inclusion proof → throws (fail closed)", async () => {
  const readResource = makeReadResource({ proof: "bad-proof", plaintext: "hello" });
  await assert.rejects(
    () => readResource(ref(PINNED_ROOT)),
    /merkle inclusion/i,
    "a pinned read with an unverifiable proof must NOT surface bytes"
  );
});

test("pinned root + decrypt failure → throws (never returns ciphertext)", async () => {
  const readResource = makeReadResource({ proof: "valid-proof", plaintext: null });
  await assert.rejects(
    () => readResource(ref(PINNED_ROOT)),
    /could not be decrypted/i,
    "a decrypt failure must throw, never hand back raw ciphertext"
  );
});

test("pinned root + valid proof + clean decrypt → returns bytes, verified true", async () => {
  const readResource = makeReadResource({ proof: "valid-proof", plaintext: "hello world" });
  const r = await readResource(ref(PINNED_ROOT));
  assert.equal(new TextDecoder().decode(r.bytes), "hello world");
  assert.equal(r.verified, true);
  assert.equal(r.decrypted, true);
});

test("latest (unpinned) + failed inclusion + clean decrypt → still serves (blind model)", async () => {
  const readResource = makeReadResource({ proof: "bad-proof", plaintext: "latest-content" });
  const r = await readResource(ref("latest"));
  assert.equal(new TextDecoder().decode(r.bytes), "latest-content");
  assert.equal(r.verified, false, "advisory verification does not gate an unpinned read");
});

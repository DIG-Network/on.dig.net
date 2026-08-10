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
import { loadReadResource, loadRootIsPinned } from "./load-dig-embed.mjs";
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

// ---------------------------------------------------------------------------------------------------
// #2313 — rootIsPinned MUST fail CLOSED: a pinned root rendered non-canonically (uppercase, `0x`-
// prefixed, whitespace-padded) previously read as UNPINNED, silently SKIPPING the merkle-inclusion
// gate so attacker-substituted bytes rendered. The predicate is a sentinel allowlist over the
// canonical form: UNPINNED iff (after trim + lowercase + strip-0x) it is "" or "latest"; every other
// value — including a malformed one — is PINNED (gated). Mirrors dig-sdk ac38aa95 / dig-node
// resolve_capsule_root, and MUST match assets/sw.js at the same strength.
// ---------------------------------------------------------------------------------------------------
const CANONICAL_ROOT = "b".repeat(64);

// Every non-canonical rendering of the SAME pinned root — the gate MUST still fire for each.
const NON_CANONICAL_PINNED = {
  uppercase: "B".repeat(64),
  "mixed-case": "aB".repeat(32),
  "0x-prefixed": "0x" + "b".repeat(64),
  "0X-prefixed": "0X" + "b".repeat(64),
  "leading whitespace": " " + CANONICAL_ROOT,
  "trailing whitespace": CANONICAL_ROOT + " ",
  "surrounding whitespace": " " + CANONICAL_ROOT + " ",
  "trailing newline": CANONICAL_ROOT + "\n",
  "trailing crlf": CANONICAL_ROOT + "\r\n",
  "tab-padded": "\t" + CANONICAL_ROOT + "\t",
  "0x + uppercase + whitespace": "  0X" + "B".repeat(64) + "\r\n",
};

// The sentinel (UNPINNED / not-gated) set is EXACTLY {"", "latest"} modulo canonicalization.
const UNPINNED_SENTINELS = {
  "empty string": "",
  latest: "latest",
  "latest uppercase": "LATEST",
  "latest mixed-case": "LaTeSt",
  "latest surrounded by whitespace": "  latest  ",
  "latest trailing newline": "latest\n",
  "latest with tabs": "\tlatest\t",
};

test("dig-embed rootIsPinned: non-canonical pinned roots STILL gate (fail closed)", () => {
  const rootIsPinned = loadRootIsPinned();
  assert.equal(rootIsPinned(CANONICAL_ROOT), true, "the canonical pinned root gates");
  for (const [name, root] of Object.entries(NON_CANONICAL_PINNED)) {
    assert.equal(
      rootIsPinned(root),
      true,
      `non-canonical pinned root (${name}) must read as PINNED → the merkle gate MUST fire`
    );
  }
});

test("dig-embed rootIsPinned: sentinel set is EXACTLY {'', 'latest'} (widening breaks this)", () => {
  const rootIsPinned = loadRootIsPinned();
  for (const [name, root] of Object.entries(UNPINNED_SENTINELS)) {
    assert.equal(rootIsPinned(root), false, `sentinel '${name}' must be UNPINNED (not gated)`);
  }
  // null/undefined = the mutable "latest" read = unpinned.
  assert.equal(rootIsPinned(null), false, "null root is unpinned");
  assert.equal(rootIsPinned(undefined), false, "undefined root is unpinned");
  // A malformed / non-canonical non-sentinel value must be PINNED (gated), never silently ungated.
  assert.equal(rootIsPinned("abc"), true, "a malformed non-'latest' root must be gated");
  assert.equal(rootIsPinned(CANONICAL_ROOT), true, "a normal hex root is pinned");
});

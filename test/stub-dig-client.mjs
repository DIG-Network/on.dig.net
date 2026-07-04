// test/stub-dig-client.mjs
//
// Deterministic FAKE crypto standing in for the real dig-client wasm-bindgen module in tests.
// assets/sw.js's real cryptography (AES-256-GCM-SIV decrypt, the merkle inclusion proof) is
// validated byte-for-byte by the Rust suite in digstore's `dig-client-wasm` crate — this stub
// exists ONLY so sw.js's non-crypto ORCHESTRATION logic (byte-range planning, parallel fan-out,
// cache-key building, decrypt-stream assembly, serveUrn control flow) can run and be asserted on
// under plain Node, without a browser or a real wasm build. See test/load-sw.mjs for how this is
// substituted for the real `/__dig/dig_client.js` import.

const encoder = new TextEncoder();

/** Stands in for the wasm-bindgen default init export — a no-op async init. */
export default async function initDigClient() {
  return {};
}

export function retrievalKey(storeId, resourceKey) {
  return `rk:${storeId}:${resourceKey}`;
}

export function deriveKey(storeId, resourceKey, salt) {
  return `key:${storeId}:${resourceKey}:${salt || ""}`;
}

/** Fake inclusion check: "verified" iff the proof string is the fixed sentinel below. */
export function verifyInclusion(_ciphertext, proof, _root) {
  return proof === "valid-proof";
}

/**
 * Fake AEAD chunk decrypt. `encryptChunkForTest()` below prefixes a per-key marker
 * (`ENC:<keyHex>:`) onto the plaintext; this strips it, THROWING (simulating a real AEAD tag
 * failure) whenever the marker doesn't match the given key — the same fail-closed shape as a real
 * GCM tag mismatch on a wrong key or tampered ciphertext.
 */
export function decryptChunk(keyHex, ciphertext) {
  const marker = encoder.encode(`ENC:${keyHex}:`);
  if (ciphertext.length < marker.length) throw new Error("tag mismatch");
  for (let i = 0; i < marker.length; i++) {
    if (ciphertext[i] !== marker[i]) throw new Error("tag mismatch");
  }
  return ciphertext.subarray(marker.length);
}

export function install_global() {}

/** Test-only helper (NOT part of the real wasm-bindgen surface): build a fake ciphertext chunk
 *  that decryptChunk() above will successfully "decrypt" back to `plaintext` given `keyHex`. */
export function encryptChunkForTest(keyHex, plaintext) {
  const marker = encoder.encode(`ENC:${keyHex}:`);
  const body = typeof plaintext === "string" ? encoder.encode(plaintext) : plaintext;
  const out = new Uint8Array(marker.length + body.length);
  out.set(marker, 0);
  out.set(body, marker.length);
  return out;
}

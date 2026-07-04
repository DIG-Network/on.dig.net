// test/sw.test.mjs
//
// Unit tests for the #205d/#205e orchestration logic in assets/sw.js: the byte-range planner, the
// bounded parallel fan-out, the persisted-cache key builders, and the streaming-decrypt assembly —
// plus the pre-existing pure URN/header helpers, now that a runner exists to cover them. Real
// AEAD/merkle correctness lives in digstore's `dig-client-wasm` Rust suite; see
// test/stub-dig-client.mjs for why this file uses a deterministic fake instead.
//
// Run: `node --test test/`
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadSw } from "./load-sw.mjs";
import { encryptChunkForTest } from "./stub-dig-client.mjs";

test("planWindows", async (t) => {
  const { planWindows } = await loadSw();

  await t.test("total <= windowSize yields exactly one window", () => {
    assert.deepEqual(planWindows(500, 1024), [{ index: 0, start: 0, end: 499 }]);
  });

  await t.test("aligned windows with a short final window", () => {
    assert.deepEqual(planWindows(2500, 1024), [
      { index: 0, start: 0, end: 1023 },
      { index: 1, start: 1024, end: 2047 },
      { index: 2, start: 2048, end: 2499 },
    ]);
  });

  await t.test("exact multiple of windowSize has no trailing short window", () => {
    const windows = planWindows(2048, 1024);
    assert.equal(windows.length, 2);
    assert.equal(windows[0].end, 1023);
    assert.equal(windows[1].end, 2047);
  });

  await t.test("zero total yields no windows", () => {
    assert.deepEqual(planWindows(0, 1024), []);
  });
});

test("runParallel", async (t) => {
  const { runParallel } = await loadSw();

  await t.test("visits every item exactly once", async () => {
    const seen = [];
    await runParallel([10, 20, 30, 40, 50], async (item) => {
      seen.push(item);
    }, 2);
    assert.deepEqual(seen.slice().sort((a, b) => a - b), [10, 20, 30, 40, 50]);
  });

  await t.test("never exceeds the concurrency bound", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const items = Array.from({ length: 12 }, (_, i) => i);
    await runParallel(
      items,
      async () => {
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((r) => setTimeout(r, 1));
        inFlight--;
      },
      3
    );
    assert.ok(maxInFlight <= 3, `expected at most 3 concurrent workers, saw ${maxInFlight}`);
  });

  await t.test("a worker error propagates to the caller", async () => {
    await assert.rejects(() =>
      runParallel([1, 2, 3], async (i) => {
        if (i === 2) throw new Error("boom");
      }, 2)
    );
  });

  await t.test("empty items resolves without invoking the worker", async () => {
    await runParallel([], async () => {
      throw new Error("worker must not run for an empty item list");
    }, 4);
  });
});

test("concatParts", async () => {
  const { concatParts } = await loadSw();
  const a = new Uint8Array([1, 2]);
  const b = new Uint8Array([3, 4, 5]);
  assert.deepEqual(Array.from(concatParts([a, b])), [1, 2, 3, 4, 5]);
  // Single-part fast path returns the SAME array (no wasted copy for the common case).
  assert.equal(concatParts([a]), a);
});

test("wasmCacheKey / contentCacheKey", async () => {
  const { wasmCacheKey, contentCacheKey } = await loadSw();

  const k1 = wasmCacheKey("aaaa");
  const k2 = wasmCacheKey("bbbb");
  assert.notEqual(k1.url, k2.url, "a wasm hash change must miss the old persisted entry");

  const c1 = contentCacheKey("store1", "root1", "index.html");
  const c2 = contentCacheKey("store1", "root2", "index.html");
  const c3 = contentCacheKey("store1", "root1", "other.html");
  assert.notEqual(c1.url, c2.url, "a different pinned root must be a different cache key");
  assert.notEqual(c1.url, c3.url, "a different resource key must be a different cache key");
  assert.ok(c1.url.includes("store1"));
});

test("buildDecryptStream", async (t) => {
  const { buildDecryptStream, concatParts } = await loadSw();
  const enc = new TextEncoder();

  await t.test("single chunk: enqueues the eagerly-decrypted firstChunk and closes", async () => {
    const keyHex = "k1";
    const plain = enc.encode("hello world");
    const cipher = encryptChunkForTest(keyHex, plain);
    const { stream, whenDone } = buildDecryptStream(keyHex, cipher, [cipher.length], plain);

    const reader = stream.getReader();
    const first = await reader.read();
    assert.equal(first.done, false);
    assert.deepEqual(Array.from(first.value), Array.from(plain));
    const second = await reader.read();
    assert.equal(second.done, true);
    assert.deepEqual(Array.from(await whenDone), Array.from(plain));
  });

  await t.test("multi-chunk: lazily decrypts remaining chunks in order", async () => {
    const keyHex = "k2";
    const p0 = enc.encode("AAA");
    const p1 = enc.encode("BBBB");
    const p2 = enc.encode("CC");
    const c0 = encryptChunkForTest(keyHex, p0);
    const c1 = encryptChunkForTest(keyHex, p1);
    const c2 = encryptChunkForTest(keyHex, p2);
    const cipher = concatParts([c0, c1, c2]);
    const lens = [c0.length, c1.length, c2.length];

    const { stream, whenDone } = buildDecryptStream(keyHex, cipher, lens, p0);
    const reader = stream.getReader();
    const parts = [];
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    assert.deepEqual(
      parts.map((p) => Array.from(p)),
      [Array.from(p0), Array.from(p1), Array.from(p2)]
    );
    assert.deepEqual(Array.from(await whenDone), Array.from(concatParts([p0, p1, p2])));
  });

  await t.test("a later chunk's AEAD failure errors the stream (fails closed, not silently)", async () => {
    const keyHex = "k3";
    const p0 = enc.encode("ok");
    const c0 = encryptChunkForTest(keyHex, p0);
    const badChunk = enc.encode("not encrypted with the expected marker");
    const cipher = concatParts([c0, badChunk]);
    const lens = [c0.length, badChunk.length];

    const { stream, whenDone } = buildDecryptStream(keyHex, cipher, lens, p0);
    const reader = stream.getReader();
    await reader.read(); // chunk 0 — fine, already decrypted eagerly by the caller in practice.
    await assert.rejects(() => reader.read());
    await assert.rejects(() => whenDone);
  });
});

test("rootIsPinned", async () => {
  const { rootIsPinned } = await loadSw();
  assert.equal(rootIsPinned("a".repeat(64)), true);
  assert.equal(rootIsPinned("A".repeat(64)), true); // hex is case-insensitive
  assert.equal(rootIsPinned("latest"), false);
  assert.equal(rootIsPinned(null), false);
  assert.equal(rootIsPinned("a".repeat(63)), false); // too short
  assert.equal(rootIsPinned("g".repeat(64)), false); // not hex
});

test("parseChunkLensHeader", async () => {
  const { parseChunkLensHeader } = await loadSw();
  assert.equal(parseChunkLensHeader(null), null);
  assert.equal(parseChunkLensHeader(""), null);
  assert.deepEqual(parseChunkLensHeader("10,20,30"), [10, 20, 30]);
  assert.deepEqual(parseChunkLensHeader(" 10 , 20 "), [10, 20]);
  assert.equal(parseChunkLensHeader("not,a,number"), null);
});

test("parseDigUrn", async () => {
  const { parseDigUrn } = await loadSw();

  assert.deepEqual(parseDigUrn("chia://abc123/foo/bar.html"), {
    storeId: "abc123",
    root: null,
    resourceKey: "foo/bar.html",
    salt: null,
  });

  assert.deepEqual(parseDigUrn("chia://abc123"), {
    storeId: "abc123",
    root: null,
    resourceKey: "index.html",
    salt: null,
  });

  assert.deepEqual(parseDigUrn("urn:dig:chia:abc123:" + "d".repeat(64) + "/index.html?salt=ff"), {
    storeId: "abc123",
    root: "d".repeat(64),
    resourceKey: "index.html",
    salt: "ff",
  });

  assert.equal(parseDigUrn("https://example.com"), null);
});

test("contentType", async () => {
  const { contentType } = await loadSw();
  assert.equal(contentType("index.html"), "text/html; charset=utf-8");
  assert.equal(contentType("app.js"), "text/javascript; charset=utf-8");
  assert.equal(contentType("style.CSS"), "text/css; charset=utf-8"); // case-insensitive extension
  assert.equal(contentType("photo.avif"), "image/avif");
  assert.equal(contentType("font.woff2"), "font/woff2");
  assert.equal(contentType("clip.mp3"), "audio/mpeg");
  assert.equal(contentType("unknown.xyz"), "application/octet-stream");
  assert.equal(contentType("noext"), "application/octet-stream");
});

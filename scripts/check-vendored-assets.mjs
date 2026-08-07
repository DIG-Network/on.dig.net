#!/usr/bin/env node
// scripts/check-vendored-assets.mjs
//
// The OFFLINE, deterministic integrity gate for the files in assets/ that on.dig.net does NOT author
// but VENDORS from elsewhere (assets/vendor-manifest.json is the provenance record):
//
//   * assets/dig-embed.js         — vendored from hub.dig.net (apps/web/public/embed/dig-embed.js),
//   * assets/dig_client.js        — dig-client-wasm release artifact (wasm-bindgen JS glue),
//   * assets/dig_client_bg.wasm   — dig-client-wasm release artifact (compiled read-crypto wasm).
//
// For each entry it recomputes the SHA-256 of the on-disk bytes and asserts it equals the sha256
// recorded in the manifest. A mismatch means the local copy was edited/tampered/replaced WITHOUT
// updating its provenance record — exactly the silent-drift condition that turned #2261 into a live
// vuln. On any mismatch it prints the offending asset(s) and exits non-zero, failing CI.
//
// This gate is intentionally SELF-CONTAINED: it needs no network and no other repo checked out, so it
// runs inside on.dig.net's offline ci.yml `js` job. Catching upstream CODE drift (hub changing its
// canonical dig-embed.js) is the separate, network-dependent job of .github/workflows/vendor-drift.yml.
//
// Modes:
//   node scripts/check-vendored-assets.mjs            verify (default) — fail on mismatch
//   node scripts/check-vendored-assets.mjs --update   re-vendor: rewrite every sha256 from current bytes
//   node scripts/check-vendored-assets.mjs --update --hub-ref <sha>   also stamp dig-embed.js's hub_ref
//
// The --update mode is the documented re-vendor step (runbooks/deploy.md): after deliberately copying
// fresh upstream bytes into assets/, run it to bless the new hashes into the manifest.
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, "..");
const manifestPath = path.join(repoRoot, "assets", "vendor-manifest.json");

/** SHA-256 (lowercase hex) of a file's raw bytes. */
function sha256OfFile(absPath) {
  return createHash("sha256").update(readFileSync(absPath)).digest("hex");
}

/** Parse `--flag value` / `--flag` from argv into a small options object. */
function parseArgs(argv) {
  const opts = { update: false, hubRef: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--update") opts.update = true;
    else if (argv[i] === "--hub-ref") opts.hubRef = argv[++i] ?? null;
  }
  return opts;
}

function loadManifest() {
  return JSON.parse(readFileSync(manifestPath, "utf8"));
}

/** Re-vendor: overwrite each asset's sha256 (and dig-embed.js's hub_ref if given) from current bytes. */
function update(opts) {
  const manifest = loadManifest();
  for (const asset of manifest.assets) {
    const abs = path.join(repoRoot, asset.path);
    asset.sha256 = sha256OfFile(abs);
    if (opts.hubRef && asset.kind === "hub-vendored") asset.hub_ref = opts.hubRef;
    console.log(`updated ${asset.path} -> ${asset.sha256}`);
  }
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`wrote ${path.relative(repoRoot, manifestPath)}`);
}

/** Verify: return the list of assets whose on-disk hash disagrees with the manifest. */
function findMismatches() {
  const manifest = loadManifest();
  const mismatches = [];
  for (const asset of manifest.assets) {
    const abs = path.join(repoRoot, asset.path);
    const actual = sha256OfFile(abs);
    if (actual !== asset.sha256) mismatches.push({ asset, actual });
  }
  return mismatches;
}

function verify() {
  const mismatches = findMismatches();
  if (mismatches.length === 0) {
    console.log("vendored-assets check: OK — every vendored asset matches its recorded sha256.");
    return;
  }
  console.error("vendored-assets check: FAILED — vendored asset(s) drifted from vendor-manifest.json:");
  for (const { asset, actual } of mismatches) {
    console.error(`  ${asset.path}`);
    console.error(`    expected sha256: ${asset.sha256}`);
    console.error(`    actual   sha256: ${actual}`);
  }
  console.error(
    "\nA vendored file changed without a matching provenance update. If this was a deliberate re-vendor,\n" +
      "run `node scripts/check-vendored-assets.mjs --update` (see runbooks/deploy.md). Otherwise revert the edit."
  );
  process.exit(1);
}

const opts = parseArgs(process.argv.slice(2));
if (opts.update) update(opts);
else verify();

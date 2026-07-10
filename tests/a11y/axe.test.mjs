// axe.test.mjs — WCAG 2.2 AA accessibility gate for the resolver's served documents.
//
// CLAUDE.md §6.6 mandates a CONCRETE automated accessibility tier — not a linter alone. This loads
// the REAL served assets in a headless Chromium and asserts axe-core reports ZERO WCAG 2.0/2.1/2.2
// A + AA violations.
//
// Scope: only the TWO documents src/bin/bootstrap.rs actually serves to a browser —
//   - assets/loader.html   (the branded loader shell, served for every *.on.dig.net document route)
//   - assets/pages/error.html (served verbatim for an unknown/malformed host, PAGE_ERROR)
// The four legacy per-status pages (available/pending/expired/revoked.html) are NOT served by the
// Lambda anymore (their copy now lives client-side on the loader shell, #206b) — out of scope here.
//
// loader.html's inline bootstrap fetches /__dig/config.json; under file:// that request fails
// (no such resource), which the shell's own `.catch()` maps to `{status:"error"}` and renders via
// `applyStatus("error")` — still a fully-rendered, non-blank state, so axe measures the REAL
// "temporarily unavailable" card content a viewer would see if config resolution fails.
//
// Run:  npm ci && npx playwright install --with-deps chromium && npm test
// Exit: 0 = no violations; 1 = one or more violations (details printed).

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, resolve } from "node:path";
import { chromium } from "playwright";
import { AxeBuilder } from "@axe-core/playwright";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");

const PAGES = [
  { name: "loader.html (branded loader shell)", path: resolve(ROOT, "assets", "loader.html"), settleMs: 500 },
  { name: "error.html (static error page)", path: resolve(ROOT, "assets", "pages", "error.html"), settleMs: 0 },
];

// WCAG 2.2 AA = the 2.0/2.1/2.2 A + AA success-criterion tags axe maps rules to.
const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

let failures = 0;
function fail(msg) {
  console.error(`FAIL - ${msg}`);
  failures += 1;
}

const browser = await chromium.launch();
try {
  for (const page of PAGES) {
    const url = pathToFileURL(page.path).href;
    const context = await browser.newContext();
    const tab = await context.newPage();
    const resp = await tab.goto(url, { waitUntil: "load" });
    if (resp && resp.status() >= 400) {
      fail(`could not load ${url} (status ${resp.status()})`);
    }
    if (page.settleMs > 0) {
      // Let the async /__dig/config.json fetch settle (it fails under file://, which the shell's
      // own catch() handles by rendering the "unavailable" status copy on the same branded card).
      await tab.waitForTimeout(page.settleMs);
    }

    const results = await new AxeBuilder({ page: tab }).withTags(WCAG_TAGS).analyze();
    if (results.violations.length === 0) {
      console.log(`ok   - axe: 0 WCAG 2.2 AA violations on ${page.name} (${results.passes.length} checks passed)`);
    } else {
      fail(`axe: ${results.violations.length} WCAG 2.2 AA violation(s) on ${page.name}`);
      for (const v of results.violations) {
        console.error(`\n  [${v.impact ?? "n/a"}] ${v.id}: ${v.help}`);
        console.error(`    ${v.helpUrl}`);
        for (const node of v.nodes) {
          console.error(`      target: ${JSON.stringify(node.target)}`);
          if (node.failureSummary) {
            console.error("        " + node.failureSummary.replace(/\n/g, "\n        "));
          }
        }
      }
    }
    await context.close();
  }
} finally {
  await browser.close();
}

if (failures > 0) {
  console.error(`\n${failures} page(s) failed the accessibility audit`);
  process.exit(1);
}
console.log("\nall accessibility assertions passed");

# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.5.11] - 2026-08-21

### Bug Fixes
- **urn:** Hold both on.dig.net URN parsers to the ratified conformance table (#18)

## [0.5.10] - 2026-08-10

### Bug Fixes
- **on.dig.net:** Fail-closed rootIsPinned — canonicalize root + sentinel allowlist (#2313)

## [0.5.9] - 2026-08-07

### CI
- **assets:** Vendored-asset drift-guard vs hub canonical (#2263)

## [0.5.8] - 2026-08-07

### Bug Fixes
- **embed:** Port #2259+#2260 fail-closed gates into the in-page dig-embed loader (#2261)

## [0.5.7] - 2026-08-07

### Bug Fixes
- **sw:** Fail closed on merkle inclusion failure for pinned reads (#2264)

## [0.5.5] - 2026-08-06

### Chores
- Add .gitattributes to pin LF line endings (#2198)

## [0.5.4] - 2026-07-30

### Chores
- **on.dig.net:** Drop 4 unserved legacy status pages (#268)

## [0.5.3] - 2026-07-27

### Testing
- **ci:** Add a cargo llvm-cov ≥80% gate for the Rust lib (#1680)

## [0.5.2] - 2026-07-22

### Testing
- **on.dig.net:** Cover sw.js decrypt/serve paths + gate the JS CI at ≥80% (§2.3) (#8)

## [0.5.1] - 2026-07-12

### CI
- Add flaky-test management (#489) (#7)

## [0.5.0] - 2026-07-11

### Features
- HEAD / resolves the mapped canonical URN (#308 Part A) (#6)

## [0.4.0] - 2026-07-10

### Features
- **frontend-baseline:** Expose build version + axe WCAG 2.2 AA gate (#5)

## [0.3.1] - 2026-07-06

### Bug Fixes
- 404 asset-looking paths instead of the text/html loader shell (#4)

## [0.3.0] - 2026-07-04

### Features
- **watcher:** Chain-change watcher invalidates the resolver's dynamic CloudFront paths (#2)

## [0.2.0] - 2026-07-04

### Features
- **sw:** Parallel byte-range fan-out, streaming decrypt, Cache API persistence (#1)

## [0.1.0] - 2026-07-04

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Release automation — git-cliff changelog + tag on merge, deploy on tag (#230 Unit 2)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog

### Loader
- Restore full DIG NETWORK wordmark (two-line lockup, solid-white NETWORK — fixes invisible/missing Network)



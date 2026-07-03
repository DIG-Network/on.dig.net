# on.dig.net

The `*.on.dig.net` subdomain resolver — a standalone AWS service that maps a DIG subdomain (e.g.
`chia-offer.on.dig.net`) to a pinned DIG URN and serves a first-party, **client-side-decrypting**
loader. Every subdomain gets its own isolated origin; the page fetches the pinned store's ciphertext
from `rpc.dig.net`, verifies each chunk's merkle inclusion proof, decrypts it with the dig-client
WASM, and renders it — all in the browser.

This service was split out of `hub.dig.net` so its static loader assets live in a **dedicated** S3
bucket, never a shared one. (Sharing the hub's web bucket meant the hub's `s3 sync --delete` wiped
the resolver's assets — the outage this split eliminates.)

## What's here

- `src/lib.rs` — pure resolver logic (host parsing, render/status decisions, the two CSP contexts). Unit-tested, no AWS.
- `src/domain.rs` — the read-only DynamoDB record contract (a wire-faithful subset of hub's `dighub-data::domain`).
- `src/bin/bootstrap.rs` — the AWS Lambda entrypoint (`--features aws`).
- `assets/` — the served artifacts, committed: `loader.html`, `sw.js`, `dig-embed.js`, the dig-client WASM (`dig_client.js` + `dig_client_bg.wasm`), and the status pages (`pages/*.html`).
- `infra/` — the standalone terraform stack (Lambda + API Gateway + CloudFront + the dedicated S3 asset bucket + Route53 + the CI OIDC role).
- `publish-assets.sh` — uploads the static loader assets to the dedicated S3 bucket.
- `SPEC.md` — the normative contract. `runbooks/` — deploy + local-run procedures. `llms.txt` — machine map.

## Architecture

```
viewer ─HTTPS─▶ CloudFront (*.on.dig.net, no WAF, IPv6) ─┬─ /  + /__dig/config.json ─▶ API Gateway ─▶ resolver Lambda
                                                          └─ /__dig/*, /__dig_sw.js, /dig-client/* ─▶ S3 asset bucket (OAC)
resolver Lambda ── read-only GetItem ──▶ shared `dighub` DynamoDB table (domain pins, written by hub.dig.net)
```

The document `/` is a STATIC branded loader shell served instantly (no per-request table lookup); it
resolves status + pin async from `/__dig/config.json`. See `SPEC.md` for the full contract.

## Develop

```bash
cargo test --all-targets                              # pure lib + asset-regression tests (no AWS)
cargo clippy --all-targets -- -D warnings
cargo clippy --bin bootstrap --features aws -- -D warnings
cargo lambda build --release --arm64 --features aws --bin bootstrap --output-format zip
```

The read-crypto WASM in `assets/` is a vendored copy of the shipped `dig-client-wasm` artifact.
Updating it is a deliberate, documented step (see `runbooks/deploy.md`) — the bytes are a fixed read
contract.

## Deploy

CI-driven via GitHub OIDC on merge to `main` (`.github/workflows/deploy.yml`): build the Lambda,
publish assets to the dedicated bucket, `terraform apply`. See `runbooks/deploy.md` for credentials,
the zero-downtime `*.on.dig.net` cutover procedure, and how to verify.

## License

GPL-2.0-only.

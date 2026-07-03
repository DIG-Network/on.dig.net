# Runbook — running on.dig.net locally

## Prereqs

- Rust stable (`rustup`), with `rustfmt` + `clippy` (see `rust-toolchain.toml`).
- `cargo-lambda` + `zig` (only for building the deployable zip): `pip install cargo-lambda ziglang`.
- Terraform ≥ 1.9 and the AWS CLI (only for infra / a real deploy).

## Test + lint (no AWS needed)

```bash
cargo test --all-targets                                   # pure lib + asset-regression tests
cargo clippy --all-targets -- -D warnings                  # lib + tests
cargo clippy --bin bootstrap --features aws -- -D warnings  # the Lambda binary
cargo fmt --all --check
terraform -chdir=infra fmt -check -recursive
terraform -chdir=infra init -backend=false && terraform -chdir=infra validate
```

## Run the Lambda handler locally

`cargo-lambda` runs the handler on a local emulator. It needs AWS credentials + the table name only
if you want real DynamoDB reads; without a reachable table the resolver still serves the loader shell
and returns `status:"available"` from `/__dig/config.json`.

```bash
DIGHUB_TABLE=dighub AWS_REGION=us-east-1 cargo lambda watch --features aws
# then, in another shell — the emulator maps the API-Gateway proxy event for you:
curl -H 'host: chia-offer.on.dig.net' http://127.0.0.1:9000/
curl -H 'host: chia-offer.on.dig.net' http://127.0.0.1:9000/__dig/config.json
```

The handler reads the viewer host from `x-dig-host`, falling back to `Host` (used here). Assets are
baked into the binary, so `/__dig/dig_client.js`, `/__dig_sw.js`, etc. are served directly by the
local handler too.

## Notes

- The read-crypto WASM + `dig-embed.js` + `sw.js` in `assets/` are committed, shipped artifacts — no
  build step fetches them. See `runbooks/deploy.md` for how to update them.
- There is no web front end in this repo; the "UI" is the served `loader.html` + the decrypted store
  content rendered client-side.

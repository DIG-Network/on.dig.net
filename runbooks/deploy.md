# Runbook — deploying on.dig.net

## What deploys where

| Thing | Target |
|---|---|
| resolver Lambda | `on-dig-net-resolver` (arm64, `provided.al2023`), fronted by API Gateway HTTP API `on-dig-net-resolver` |
| chain-change watcher Lambda (#33) | `on-dig-net-watcher` (arm64, `provided.al2023`), triggered by EventBridge Scheduler `on-dig-net-watcher` (`rate(1 minute)`) — see `SPEC.md` §10 |
| watcher's OWN state table | DynamoDB `on-dig-net-watcher-state` (last-known chain tip per store; NEVER the shared `dighub` table) |
| static loader assets | S3 bucket `on-dig-net-assets` (dedicated — NEVER the hub web bucket), served via CloudFront OAC |
| edge | CloudFront distribution `E34LO4V5L4RTHE` (`d1a7itvbih8xco.cloudfront.net`), alias `*.on.dig.net`, no WAF, IPv6 |
| DNS | Route53 zone `Z09143862Q3QQA5P9F8QY` (dig.net): wildcard `*.on.dig.net` A + AAAA alias → the distribution |
| TLS | ACM cert `arn:…:certificate/3966954e-faab-4c81-86cf-adf91dccb93f` (`*.on.dig.net`, us-east-1; shared — a cert may back multiple dists) |
| data | READ-ONLY `GetItem`/`Scan` on the shared `dighub` DynamoDB table (domain pins written by hub.dig.net; the watcher's `Scan` is also strictly read-only) |
| terraform state | `s3://dighub-tfstate/on.dig.net/prod/terraform.tfstate`, lock table `dighub-tflock` |

## Credentials / secrets

- CI assumes the OIDC role `on-dig-net-ci-deploy` (terraform output `ci_deploy_role_arn`). It trusts
  only this repo's `production` environment and `main` branch. No long-lived keys.
- Required repo variables (Settings → Secrets and variables → Actions → Variables):
  `CI_DEPLOY_ROLE_ARN`, `TF_STATE_BUCKET=dighub-tfstate`, `TF_LOCK_TABLE=dighub-tflock`; and a
  `production` environment.

## Normal deploy (CI)

Merge to `main` (or run the `deploy` workflow manually). `deploy.yml`:
1. builds the resolver + watcher arm64 Lambda zips (`cargo lambda build … --features aws --bin bootstrap` / `--bin watcher`),
2. publishes the static assets to `on-dig-net-assets` (`publish-assets.sh`),
3. `terraform apply` (S3 backend) — creates/updates BOTH Lambdas + the watcher's state table + its EventBridge schedule,
4. invalidates `/__dig/*` `/__dig_sw.js` `/dig-client/*`.

The chain-change watcher (#33) needs no manual verification step beyond the deploy going green —
its own EventBridge schedule starts ticking immediately once the Lambda + IAM role exist.

Watch it to green: `gh run watch <id>`.

## Manual deploy / first apply (local, ambient creds)

```bash
cargo lambda build --release --arm64 --features aws --bin bootstrap --output-format zip
cargo lambda build --release --arm64 --features aws --bin watcher --output-format zip
cd infra
terraform init -backend-config="bucket=dighub-tfstate" -backend-config="dynamodb_table=dighub-tflock" -backend-config="region=us-east-1"
ZIP="$(cygpath -w ../target/lambda/bootstrap/bootstrap.zip)"   # plain path on Linux/macOS
HASH="$(openssl dgst -sha256 -binary ../target/lambda/bootstrap/bootstrap.zip | openssl base64 -A)"
WATCHER_ZIP="$(cygpath -w ../target/lambda/watcher/bootstrap.zip)"
WATCHER_HASH="$(openssl dgst -sha256 -binary ../target/lambda/watcher/bootstrap.zip | openssl base64 -A)"
terraform apply \
  -var "lambda_package_path=$ZIP" -var "lambda_source_code_hash=$HASH" \
  -var "watcher_lambda_package_path=$WATCHER_ZIP" -var "watcher_lambda_source_code_hash=$WATCHER_HASH"
cd .. && BUCKET=on-dig-net-assets bash publish-assets.sh
```

`attach_wildcard_alias` defaults to **true** (post-cutover). NEVER apply with it `false` on the live
stack — that DETACHES the production `*.on.dig.net` alias and causes an outage.

## Verify it went live

```bash
for p in / /__dig/config.json /__dig/dig_client.js /__dig_sw.js /dig-client/dig_client.js /dig-client/dig_client_bg.wasm; do
  curl -sS -o /dev/null -w "$p -> %{http_code} %{content_type}\n" "https://chia-offer.on.dig.net$p"
done
curl -sS "https://chia-offer.on.dig.net/__dig/config.json"          # {"status":"active", … pin …}
curl -sS -D - -o /dev/null "https://chia-offer.on.dig.net/__dig_sw.js" | grep -i service-worker-allowed
```

Test the distribution BEFORE it owns the alias (e.g. a new dist) via its CloudFront domain + a Host
header (CloudFront routes by the `Host` header): `curl -H "Host: chia-offer.on.dig.net"
https://<dXXXX>.cloudfront.net/`.

## Verify the chain-change watcher (#33) is ticking

```bash
aws lambda get-function --function-name on-dig-net-watcher --query 'Configuration.State'
aws scheduler get-schedule --name on-dig-net-watcher --query 'State'
aws logs tail /aws/lambda/on-dig-net-watcher --since 5m   # look for "chain-change watcher tick complete"
aws dynamodb scan --table-name on-dig-net-watcher-state --max-items 5   # last-known tips it has recorded
```

The watcher never writes the shared `dighub` table and never invalidates per-subdomain (see
`SPEC.md` §10.2–10.3) — a healthy tick log line with `invalidated:false` most of the time is
expected; `invalidated:true` should correlate with an actual on-chain commit to a tracked store.

## Updating the read-crypto WASM (deliberate)

The dig-client WASM in `assets/` (`dig_client.js` + `dig_client_bg.wasm`) and `dig-embed.js` / `sw.js`
are the shipped, byte-fixed read artifacts. To update: copy the new artifact bytes into `assets/`,
run `cargo test` (the SRI/asset-regression tests must pass), commit, and deploy (which republishes to
S3). The bytes MUST stay byte-identical to the canonical `dig-client-wasm` release.

## Zero-downtime cutover of `*.on.dig.net` (moving the wildcard between distributions)

CloudFront routes a request by its **`Host` header**, independent of which distribution's
`*.cloudfront.net` name DNS resolved to. So the moment a distribution claims `*.on.dig.net`, all
requests for that host route to it — regardless of DNS. The move is therefore seamless when done with
the same-account atomic tool (no window where neither distribution owns the alias):

1. Stand up the target distribution fully (aliases EMPTY so there is no `CNAMEAlreadyExists`), deploy
   its assets, and TEST it via its `*.cloudfront.net` domain with a `Host: <sub>.on.dig.net` header.
2. Atomically move the alias (same AWS account — no TXT record, no source-disable needed):
   ```bash
   ETAG=$(aws cloudfront get-distribution --id <TARGET_DIST_ID> --query ETag --output text)
   aws cloudfront update-domain-association \
     --domain "*.on.dig.net" --target-resource DistributionId=<TARGET_DIST_ID> --if-match "$ETAG"
   ```
   This removes `*.on.dig.net` from the source distribution and adds it to the target in one call.
   (`associate-alias` also works but demands a DNS TXT validation record; `update-domain-association`
   is the same-account move and needs none.)
3. Verify live immediately: `curl https://<sub>.on.dig.net/` serves through the target.
4. Reconcile terraform + point DNS at the target: `terraform apply -var attach_wildcard_alias=true`
   (adds the alias to the target's TF config — already present, so no dist change — and overwrites the
   Route53 wildcard A/AAAA to alias the target distribution).

Rollback: `update-domain-association --domain "*.on.dig.net" --target-resource
DistributionId=<OLD_DIST_ID>` and re-point Route53.

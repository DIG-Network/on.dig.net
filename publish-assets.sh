#!/usr/bin/env bash
# publish-assets.sh — upload the STATIC loader assets to this service's OWN S3 asset bucket, so the
# CloudFront distribution serves them straight from the nearest PoP (ZERO Lambda on the asset paths).
#
# The distribution routes:
#   • /__dig/*        → the asset bucket (this script's uploads under `__dig/`),
#   • /__dig_sw.js    → the asset bucket (this script's upload at `__dig_sw.js`),
#   • /dig-client/*   → the asset bucket (this script's uploads under `dig-client/`),
#   • /  +  /__dig/config.json → the resolver Lambda (dynamic per-subdomain shell/pin/status).
#
# The bytes uploaded here are the SAME artifacts the resolver crate bakes in (assets/, committed in
# this repo), so the S3-served and Lambda-baked copies always match. Two path families exist because
# two code paths import the read-crypto WASM at different bases:
#   • sw.js          imports  /__dig/dig_client.js  + fetches /__dig/dig_client_bg.wasm
#   • dig-embed.js   imports  /dig-client/dig_client.js + /dig-client/dig_client_bg.wasm (ASSET_BASE)
#
# USAGE:
#   BUCKET=on-dig-net-assets bash publish-assets.sh
#   # then invalidate the asset paths (only needed if bytes changed for a stable path):
#   aws cloudfront create-invalidation --distribution-id <DIST_ID> --paths '/__dig/*' '/__dig_sw.js' '/dig-client/*'

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
assets="$here/assets"
bucket="${BUCKET:-on-dig-net-assets}"
IMMUTABLE="public, max-age=31536000, immutable"

for f in dig_client.js dig_client_bg.wasm dig-embed.js sw.js; do
  if [[ ! -f "$assets/$f" ]]; then
    echo "ERROR: $assets/$f missing" >&2
    exit 1
  fi
done

put() { # $1=local  $2=s3key  $3=content-type
  aws s3 cp "$assets/$1" "s3://$bucket/$2" \
    --content-type "$3" \
    --cache-control "$IMMUTABLE" \
    --only-show-errors
  echo "  published s3://$bucket/$2  ($3)"
}

echo "Publishing static loader assets to s3://$bucket ..."
# The /__dig/* family (served to sw.js + the loader shell).
put dig-embed.js       "__dig/dig-embed.js"       "text/javascript; charset=utf-8"
put dig_client.js      "__dig/dig_client.js"      "text/javascript; charset=utf-8"
put dig_client_bg.wasm "__dig/dig_client_bg.wasm" "application/wasm"
# The module service worker lives at the ORIGIN ROOT so it can register at scope `/`.
put sw.js              "__dig_sw.js"              "text/javascript; charset=utf-8"
# The /dig-client/* family (dig-embed.js's ASSET_BASE).
put dig_client.js      "dig-client/dig_client.js"      "text/javascript; charset=utf-8"
put dig_client_bg.wasm "dig-client/dig_client_bg.wasm" "application/wasm"

echo "Done. If a stable path's bytes changed, invalidate '/__dig/*' '/__dig_sw.js' '/dig-client/*'."

//! Chain-change watcher Lambda entrypoint (#33, cargo-lambda `bootstrap`, built with
//! `--features "aws net"`). EventBridge fires this on a 1-minute schedule
//! (`rate(1 minute)`, `infra/watcher.tf`, matching hub.dig.net's anchor-watcher cadence). One
//! tick:
//!
//!   1. `Scan`s the shared `dighub` table (READ-ONLY — same least-privilege posture as the
//!      resolver's `GetItem`, extended to `Scan`; see `infra/watcher.tf`) for every `DOMAIN#*`
//!      `META` row, deserializing each via [`on_dig_net_resolver::domain::Domain`] (the same
//!      wire-faithful struct the resolver itself reads).
//!   2. Reduces those to the distinct store ids backing a currently-servable domain
//!      ([`on_dig_net_resolver::watcher::active_store_ids`]).
//!   3. Runs [`on_dig_net_resolver::watcher::run_tick`] — the pure, fully-unit-tested
//!      orchestration — against three thin AWS adapters defined here: a coinset.org coin-lineage
//!      tip reader, a DynamoDB ledger table THIS SERVICE OWNS, and a CloudFront invalidator.
//!
//! See `src/watcher.rs` module docs for the full design rationale (why a coin-lineage tip
//! instead of a decoded root, why `pinned_root` is never written, why invalidation can't be
//! scoped to a single subdomain) and `SPEC.md` §10.

use aws_sdk_dynamodb::types::AttributeValue;
use chia_protocol::{Bytes32, Coin};
use lambda_runtime::{service_fn, Error, LambdaEvent};
use on_dig_net_resolver::domain::Domain;
use on_dig_net_resolver::watcher::{
    active_store_ids, run_tick, ChainReadResult, ChainTipReader, Invalidator, TipLedger,
};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

/// Bound on lineage-walk hops per tick per store — a safety valve, not an expected path (a store
/// checked every minute would need >20 confirmed commits in that single minute to hit it). If hit,
/// the read is treated as [`ChainReadResult::Unavailable`] (fail-safe: hold, retry next tick).
const MAX_LINEAGE_HOPS: u32 = 20;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── coinset.org coin-lineage tip reader ─────────────────────────────────────────────────────

/// Minimal coinset.org HTTP adapter: walks a singleton lineage forward via plain Chia coin-record
/// reads (no CHIP-0035 decode). Standard TLS (webpki roots via `reqwest`'s `rustls-tls`) is
/// proportionate here: the worst case of a spoofed/MITM'd response is an unnecessary-but-harmless
/// invalidation, not a fund-loss or content-integrity issue (contrast hub.dig.net's
/// anchor-watcher, which pins coinset's TLS SPKI because ITS chain reads gate real-money
/// confirmations).
struct CoinsetTipReader {
    client: reqwest::Client,
    base: String,
}

impl CoinsetTipReader {
    fn new(base: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base: base.into(),
        }
    }

    /// `Some(true)` = unspent, `Some(false)` = spent, `None` = transport/parse error or the coin
    /// is not visible on-chain at all (both fail-safe to [`ChainReadResult::Unavailable`] in the
    /// caller — a genuinely-registered store's launcher is always already on-chain, so "not
    /// found" here is itself a signal something is wrong, not a normal state).
    async fn spent(&self, coin_id_hex: &str) -> Option<bool> {
        let resp = self
            .client
            .post(format!("{}/get_coin_record_by_name", self.base))
            .json(&serde_json::json!({ "name": format!("0x{coin_id_hex}") }))
            .send()
            .await
            .ok()?;
        let v: Value = resp.json().await.ok()?;
        let rec = &v["coin_record"];
        if rec.is_null() {
            return None;
        }
        Some(
            rec["spent"].as_bool().unwrap_or(false)
                || rec["spent_block_index"].as_u64().unwrap_or(0) > 0,
        )
    }

    /// The unspent child of a spent coin, or `Ok(None)` if there is none (a melt: the lineage
    /// terminated). `Err(())` on a transport/parse error (distinct from "genuinely no child" —
    /// the caller must not mistake a flaky read for a melt).
    async fn unspent_child(&self, coin_id_hex: &str) -> Result<Option<String>, ()> {
        let resp = self
            .client
            .post(format!("{}/get_coin_records_by_parent_ids", self.base))
            .json(&serde_json::json!({
                "parent_ids": [format!("0x{coin_id_hex}")],
                "include_spent_coins": false,
            }))
            .send()
            .await
            .map_err(|_| ())?;
        let v: Value = resp.json().await.map_err(|_| ())?;
        let records = v["coin_records"].as_array().cloned().unwrap_or_default();
        if records.is_empty() {
            return Ok(None);
        }
        // The singleton successor carries an ODD amount (the CHIP-0035/singleton top-layer
        // invariant) — prefer it over an unrelated even-amount sibling output (e.g. change) from
        // the same spend. Falls back to the first record if none match (best-effort: this only
        // affects which id we remember for the NEXT tick's walk, never whether THIS tick's
        // already-detected change gets invalidated).
        let pick = records
            .iter()
            .find(|r| r["coin"]["amount"].as_u64().is_some_and(|a| a % 2 == 1))
            .or_else(|| records.first())
            .ok_or(())?;
        let parent =
            hex_to_bytes32(pick["coin"]["parent_coin_info"].as_str().unwrap_or("")).ok_or(())?;
        let puzzle_hash =
            hex_to_bytes32(pick["coin"]["puzzle_hash"].as_str().unwrap_or("")).ok_or(())?;
        let amount = pick["coin"]["amount"].as_u64().ok_or(())?;
        let child_id = Coin::new(parent, puzzle_hash, amount).coin_id();
        Ok(Some(hex::encode(child_id)))
    }
}

fn hex_to_bytes32(s: &str) -> Option<Bytes32> {
    let s = s.trim_start_matches("0x");
    let raw = hex::decode(s).ok()?;
    let arr: [u8; 32] = raw.try_into().ok()?;
    Some(Bytes32::new(arr))
}

impl ChainTipReader for CoinsetTipReader {
    async fn current_tip(&self, store_id: &str, last_known: Option<&str>) -> ChainReadResult {
        let mut cursor = last_known.unwrap_or(store_id).to_string();
        for _ in 0..MAX_LINEAGE_HOPS {
            match self.spent(&cursor).await {
                None => return ChainReadResult::Unavailable,
                Some(false) => return ChainReadResult::Tip(cursor),
                Some(true) => match self.unspent_child(&cursor).await {
                    Err(()) => return ChainReadResult::Unavailable,
                    Ok(None) => return ChainReadResult::Melted,
                    Ok(Some(child)) => cursor = child,
                },
            }
        }
        // Safety valve: an implausible number of hops in one tick. Fail-safe, retry next tick.
        ChainReadResult::Unavailable
    }
}

// ── this service's OWN watcher-state ledger (never the shared dighub table) ────────────────

struct DdbTipLedger {
    ddb: aws_sdk_dynamodb::Client,
    table: String,
}

impl TipLedger for DdbTipLedger {
    async fn get(&self, store_id: &str) -> Option<String> {
        let got = self
            .ddb
            .get_item()
            .table_name(&self.table)
            .key("store_id", AttributeValue::S(store_id.to_string()))
            .send()
            .await
            .ok()?;
        match got.item().and_then(|it| it.get("tip")) {
            Some(AttributeValue::S(tip)) => Some(tip.clone()),
            _ => None,
        }
    }

    async fn put(&self, store_id: &str, tip: &str) {
        let _ = self
            .ddb
            .put_item()
            .table_name(&self.table)
            .item("store_id", AttributeValue::S(store_id.to_string()))
            .item("tip", AttributeValue::S(tip.to_string()))
            .item("updated_at", AttributeValue::N(now().to_string()))
            .send()
            .await;
    }
}

// ── CloudFront invalidation of the resolver's two dynamic paths ────────────────────────────

struct CloudFrontInvalidator {
    cf: aws_sdk_cloudfront::Client,
    distribution_id: String,
}

impl Invalidator for CloudFrontInvalidator {
    async fn invalidate(&self) {
        let caller_reference = format!("on-dig-net-watcher-{}", now());
        let paths = aws_sdk_cloudfront::types::Paths::builder()
            .quantity(2)
            .items("/")
            .items("/__dig/config.json")
            .build()
            .expect("paths");
        let batch = aws_sdk_cloudfront::types::InvalidationBatch::builder()
            .paths(paths)
            .caller_reference(caller_reference)
            .build()
            .expect("invalidation batch");
        if let Err(e) = self
            .cf
            .create_invalidation()
            .distribution_id(&self.distribution_id)
            .invalidation_batch(batch)
            .send()
            .await
        {
            tracing::warn!("cloudfront invalidation failed: {e}");
        }
    }
}

// ── domain enumeration (read-only Scan of the shared table) ────────────────────────────────

/// Scans the shared `dighub` table for every `DOMAIN#*` `META` row, paginating on
/// `LastEvaluatedKey`. Read-only — this Lambda's IAM role grants `Scan` (+ `kms:Decrypt` on the
/// table's CMK) and nothing else on this table (`infra/watcher.tf`).
async fn scan_domains(ddb: &aws_sdk_dynamodb::Client, table: &str) -> Vec<Domain> {
    let mut domains = Vec::new();
    let mut exclusive_start_key = None;
    loop {
        let mut req = ddb
            .scan()
            .table_name(table)
            .filter_expression("sk = :meta AND begins_with(pk, :prefix)")
            .expression_attribute_values(":meta", AttributeValue::S("META".into()))
            .expression_attribute_values(":prefix", AttributeValue::S("DOMAIN#".into()))
            .projection_expression("doc");
        if let Some(key) = exclusive_start_key.take() {
            req = req.set_exclusive_start_key(Some(key));
        }
        let Ok(resp) = req.send().await else {
            tracing::warn!("dighub domain scan page failed; stopping with a partial result");
            break;
        };
        for item in resp.items() {
            if let Some(AttributeValue::S(doc)) = item.get("doc") {
                if let Ok(d) = serde_json::from_str::<Domain>(doc) {
                    domains.push(d);
                }
            }
        }
        match resp.last_evaluated_key() {
            Some(key) if !key.is_empty() => exclusive_start_key = Some(key.clone()),
            _ => break,
        }
    }
    domains
}

async fn handler(_event: LambdaEvent<Value>) -> Result<(), Error> {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb = aws_sdk_dynamodb::Client::new(&config);
    let cf = aws_sdk_cloudfront::Client::new(&config);

    let dighub_table = std::env::var("DIGHUB_TABLE").unwrap_or_default();
    let state_table = std::env::var("WATCHER_STATE_TABLE").unwrap_or_default();
    let distribution_id = std::env::var("DISTRIBUTION_ID").unwrap_or_default();
    let coinset_base =
        std::env::var("COINSET_BASE_URL").unwrap_or_else(|_| "https://api.coinset.org".into());

    if dighub_table.is_empty() || state_table.is_empty() || distribution_id.is_empty() {
        tracing::warn!("watcher misconfigured (missing DIGHUB_TABLE/WATCHER_STATE_TABLE/DISTRIBUTION_ID); skipping tick");
        return Ok(());
    }

    let domains = scan_domains(&ddb, &dighub_table).await;
    let store_ids = active_store_ids(&domains, now());

    let reader = CoinsetTipReader::new(coinset_base);
    let ledger = DdbTipLedger {
        ddb: ddb.clone(),
        table: state_table,
    };
    let invalidator = CloudFrontInvalidator {
        cf,
        distribution_id,
    };

    let report = run_tick(&store_ids, &reader, &ledger, &invalidator).await;
    tracing::info!(
        tracked = store_ids.len(),
        baseline = report.baseline,
        unchanged = report.unchanged,
        changed = report.changed,
        melted = report.melted,
        already_melted = report.already_melted,
        held = report.held,
        invalidated = report.invalidated,
        "chain-change watcher tick complete"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();
    lambda_runtime::run(service_fn(handler)).await
}

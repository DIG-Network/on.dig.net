//! Chain-change watcher — pure decision core (#33).
//!
//! When a served store's on-chain state changes (a new commit advances its singleton lineage),
//! the affected `*.on.dig.net` subdomain's cached `/` + `/__dig/config.json` responses should be
//! invalidated as soon as the change is detected, rather than waiting out their passive
//! `max-age` (300s / 30s — see `infra/cloudfront.tf`). This module is the AWS-free, fully
//! unit-tested orchestration: given a set of tracked store ids, a chain-tip PORT, a ledger PORT,
//! and an invalidation PORT, decide what changed and what to do about it. The `net`+`aws`-gated
//! adapters (coinset.org HTTP tip reader, DynamoDB ledger, CloudFront invalidator) live in
//! `src/bin/watcher.rs`, mirroring the resolver's own lib/bin split (SPEC.md, README.md).
//!
//! ## Why a coin-lineage tip, not the decoded CHIP-0035 root
//!
//! A DIG store's root changes **if and only if** its singleton lineage advances (a commit spends
//! the current tip coin and creates a successor). Watching the tip COIN ID is therefore
//! equivalent to watching the root for the purpose of "did something change", and is far
//! cheaper: it needs only generic Chia coin-record reads (`get_coin_record_by_name`,
//! `get_coin_records_by_parent_ids`), never a CHIP-0035 puzzle decode. This deliberately avoids
//! both (a) `chia-query`, whose `ChiaQuery::new()` requires a live P2P peer connection (a wallet
//! TLS cert) to construct — unsuitable for a stateless scheduled Lambda cold start — and (b)
//! `digstore-chain`'s full CHIP-0035 decode (`chia-wallet-sdk` + CLVM), heavier than this watcher
//! needs since it only has to detect a *possible* root change, never read the root's value.
//!
//! ## Why the watcher never writes `pinned_root`
//!
//! `pinned_root` (`src/domain.rs`) is `None` for the default "track latest" registration and is
//! changed ONLY by the domain owner's explicit `PATCH /v1/domains/{sub}/pin` action in
//! hub.dig.net (confirmed: no hub code path — including its own anchor-watcher — ever writes it
//! automatically). For a `None` (track-latest) domain, `/__dig/config.json` already always
//! serves `root:null` regardless of chain state — the browser resolves "latest" live via
//! `rpc.dig.net` on every read (SPEC.md §9), so there is nothing to update. For a `Some(root)`
//! (owner-locked) domain, the lock is a deliberate, explicit freeze; silently advancing it would
//! overwrite the owner's choice. So this watcher only ever triggers **invalidation** — it never
//! writes to the shared `dighub` table (kept strictly read-only, matching `infra/lambda.tf`'s
//! existing least-privilege `GetItem`-only posture, here extended to a read-only `Scan`).
//!
//! ## Why invalidation cannot be scoped to a single subdomain
//!
//! `/` and `/__dig/config.json` are cached under the SAME path for every `*.on.dig.net`
//! subdomain, differentiated only by the `x-dig-host` cache-key HEADER (`infra/cloudfront.tf`).
//! CloudFront's `CreateInvalidation` API discriminates by PATH (and optional query string), never
//! by header — so there is no way to invalidate "only `foo.on.dig.net`'s cached config.json"
//! without changing the cache-key strategy to encode the subdomain in the path or query string (a
//! bigger, riskier change to an already-live distribution, out of scope here). The watcher
//! therefore invalidates the two DYNAMIC paths distribution-wide, coalesced to at most once per
//! tick regardless of how many stores changed. This is still cheap: CloudFront bills
//! invalidations per PATH, not per cached header-variant, and the two dynamic paths are never the
//! long-TTL immutable static-asset paths (`/__dig/*`, `/__dig_sw.js`, `/dig-client/*`), which this
//! watcher never touches.

use crate::domain::{Domain, DomainStatus};
use std::collections::BTreeSet;
use std::future::Future;

/// Ledger sentinel recorded for a store whose singleton lineage terminated with no successor (a
/// melt) — see [`ChainReadResult::Melted`]. A real tip is always 64 lowercase hex, so this can
/// never collide with a genuine coin id.
pub const MELTED_SENTINEL: &str = "melted";

/// One tick's chain observation for a single store's singleton lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainReadResult {
    /// The lineage's current unspent tip coin id (64-hex), whether or not it changed since the
    /// last tick — [`decide_store`] does the comparison.
    Tip(String),
    /// The lineage terminated with no unspent successor: the store was melted on-chain.
    Melted,
    /// The chain could not be read this tick (network/parse error, or nothing is visible for the
    /// launcher yet). Fail-safe: never treated as a change.
    Unavailable,
}

/// Port: read a store's current singleton-lineage tip cheaply. `last_known` (the ledger's
/// previous tip, if any) lets an adapter resume the lineage walk from there instead of
/// re-walking from the launcher every tick.
pub trait ChainTipReader {
    fn current_tip(
        &self,
        store_id: &str,
        last_known: Option<&str>,
    ) -> impl Future<Output = ChainReadResult>;
}

/// Port: the watcher's OWN last-known-tip ledger — a dedicated table this service owns and
/// writes (never the shared `dighub` table, which stays read-only — see module docs).
pub trait TipLedger {
    fn get(&self, store_id: &str) -> impl Future<Output = Option<String>>;
    fn put(&self, store_id: &str, tip: &str) -> impl Future<Output = ()>;
}

/// Port: fire the resolver's scoped-as-possible CloudFront invalidation (the two dynamic paths;
/// see module docs for why a single-subdomain scope isn't achievable).
pub trait Invalidator {
    fn invalidate(&self) -> impl Future<Output = ()>;
}

/// The pure per-store decision (mirrors hub.dig.net anchor-watcher's `decide()` shape: a pure
/// function from prior state + observation to an action, fully unit-testable without AWS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreDecision {
    /// No prior ledger entry: record the observed tip as the baseline. Never invalidates — a
    /// store this watcher has never checked before cannot have gone stale under a cache this
    /// watcher controls.
    Baseline(String),
    /// The observed tip matches the ledger: nothing changed.
    Unchanged,
    /// The lineage advanced since the last tick: invalidate + persist the new tip.
    Changed { previous: String, current: String },
    /// Newly observed melt (the ledger did not already record the sentinel): invalidate once +
    /// persist the sentinel so later ticks skip the chain read entirely.
    Melted,
    /// Already recorded as melted: nothing further to do.
    AlreadyMelted,
    /// The chain read failed/was unavailable this tick: hold — never invalidate or overwrite the
    /// ledger on an uncertain read (fail-safe, mirrors anchor-watcher's `Hold`).
    Hold,
}

/// Decide what to do for one store, given its last-known ledger tip (if any) and this tick's
/// chain observation. Pure, synchronous, exhaustively tested below.
pub fn decide_store(last_known: Option<&str>, observed: &ChainReadResult) -> StoreDecision {
    if last_known == Some(MELTED_SENTINEL) {
        return StoreDecision::AlreadyMelted;
    }
    match observed {
        ChainReadResult::Unavailable => StoreDecision::Hold,
        ChainReadResult::Melted => StoreDecision::Melted,
        ChainReadResult::Tip(t) => match last_known {
            None => StoreDecision::Baseline(t.clone()),
            Some(prev) if prev == t => StoreDecision::Unchanged,
            Some(prev) => StoreDecision::Changed {
                previous: prev.to_string(),
                current: t.clone(),
            },
        },
    }
}

/// Distinct store ids backing every currently-servable (`Active`, non-reclaimable) domain. Reuses
/// the exact status logic `render_for` (`src/lib.rs`) already applies, so the watcher tracks
/// EXACTLY the stores whose subdomain the resolver would actually serve — no more, no less.
pub fn active_store_ids(domains: &[Domain], now: u64) -> BTreeSet<String> {
    domains
        .iter()
        .filter(|d| !d.is_reclaimable(now) && d.effective_status() == DomainStatus::Active)
        .map(|d| d.pinned_store_id.clone())
        .collect()
}

/// Outcome of one full watcher tick, for logging + tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    pub baseline: usize,
    pub unchanged: usize,
    pub changed: usize,
    pub melted: usize,
    pub already_melted: usize,
    pub held: usize,
    pub invalidated: bool,
}

/// Run one watcher tick over the given set of store ids. Fires AT MOST ONE invalidation for the
/// whole tick regardless of how many stores changed (see module docs — the resolver's two
/// dynamic paths are shared across every subdomain, so there is no finer-grained target).
pub async fn run_tick<R, L, I>(
    store_ids: &BTreeSet<String>,
    reader: &R,
    ledger: &L,
    invalidator: &I,
) -> TickReport
where
    R: ChainTipReader,
    L: TipLedger,
    I: Invalidator,
{
    let mut report = TickReport::default();
    let mut needs_invalidation = false;

    for store_id in store_ids {
        let last_known = ledger.get(store_id).await;
        if last_known.as_deref() == Some(MELTED_SENTINEL) {
            // A melted singleton can never revive: skip the chain read entirely.
            report.already_melted += 1;
            continue;
        }
        let observed = reader.current_tip(store_id, last_known.as_deref()).await;
        match decide_store(last_known.as_deref(), &observed) {
            StoreDecision::Baseline(tip) => {
                ledger.put(store_id, &tip).await;
                report.baseline += 1;
            }
            StoreDecision::Unchanged => {
                report.unchanged += 1;
            }
            StoreDecision::Changed { current, .. } => {
                ledger.put(store_id, &current).await;
                report.changed += 1;
                needs_invalidation = true;
            }
            StoreDecision::Melted => {
                ledger.put(store_id, MELTED_SENTINEL).await;
                report.melted += 1;
                needs_invalidation = true;
            }
            StoreDecision::AlreadyMelted => {
                report.already_melted += 1;
            }
            StoreDecision::Hold => {
                report.held += 1;
            }
        }
    }

    if needs_invalidation {
        invalidator.invalidate().await;
        report.invalidated = true;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    // ── decide_store: the exhaustive pure-decision matrix ──────────────────────────────

    #[test]
    fn first_observation_is_a_baseline_never_an_invalidation() {
        let d = decide_store(None, &ChainReadResult::Tip("aa".repeat(32)));
        assert_eq!(d, StoreDecision::Baseline("aa".repeat(32)));
    }

    #[test]
    fn matching_tip_is_unchanged() {
        let tip = "bb".repeat(32);
        let d = decide_store(Some(&tip), &ChainReadResult::Tip(tip.clone()));
        assert_eq!(d, StoreDecision::Unchanged);
    }

    #[test]
    fn differing_tip_is_changed_and_carries_both_values() {
        let prev = "cc".repeat(32);
        let next = "dd".repeat(32);
        let d = decide_store(Some(&prev), &ChainReadResult::Tip(next.clone()));
        assert_eq!(
            d,
            StoreDecision::Changed {
                previous: prev,
                current: next
            }
        );
    }

    #[test]
    fn first_seen_melt_is_melted_not_already_melted() {
        let d = decide_store(None, &ChainReadResult::Melted);
        assert_eq!(d, StoreDecision::Melted);
    }

    #[test]
    fn melt_observed_after_a_live_tip_is_still_melted() {
        let d = decide_store(Some(&"ee".repeat(32)), &ChainReadResult::Melted);
        assert_eq!(d, StoreDecision::Melted);
    }

    #[test]
    fn a_store_already_recorded_melted_short_circuits_regardless_of_observation() {
        assert_eq!(
            decide_store(Some(MELTED_SENTINEL), &ChainReadResult::Melted),
            StoreDecision::AlreadyMelted
        );
        // Even an (impossible in practice, but must never panic) Tip observation for an
        // already-melted store still reports AlreadyMelted, not a spurious Changed/Baseline.
        assert_eq!(
            decide_store(
                Some(MELTED_SENTINEL),
                &ChainReadResult::Tip("ff".repeat(32))
            ),
            StoreDecision::AlreadyMelted
        );
    }

    #[test]
    fn unavailable_read_always_holds_never_invalidates_regardless_of_prior_state() {
        assert_eq!(
            decide_store(None, &ChainReadResult::Unavailable),
            StoreDecision::Hold
        );
        assert_eq!(
            decide_store(Some(&"11".repeat(32)), &ChainReadResult::Unavailable),
            StoreDecision::Hold
        );
    }

    // ── active_store_ids: dedupe + status filter (reuses render_for's own status logic) ──

    fn domain(status: DomainStatus, store_id: &str, exp: Option<u64>) -> Domain {
        Domain {
            subdomain: "foo".into(),
            owner_ph: "p".into(),
            pinned_store_id: store_id.into(),
            pinned_root: None,
            salt: None,
            status,
            registered_at: Some(0),
            expires_at: exp,
            renewal_due_at: None,
            reg_spend_id: None,
            reg_coin_id: None,
            created_at: 0,
            reg_price_baseunits: None,
        }
    }

    #[test]
    fn active_store_ids_dedupes_and_excludes_non_active() {
        let store_a = "aa".repeat(32);
        let store_b = "bb".repeat(32);
        let domains = vec![
            domain(DomainStatus::Active, &store_a, None),
            // Two subdomains pinning the SAME store: one chain read covers both.
            domain(DomainStatus::Active, &store_a, None),
            domain(DomainStatus::Active, &store_b, None),
            domain(DomainStatus::Pending, &"cc".repeat(32), None),
            domain(DomainStatus::Expired, &"dd".repeat(32), None),
            domain(DomainStatus::Revoked, &"ee".repeat(32), None),
        ];
        let ids = active_store_ids(&domains, 100);
        assert_eq!(ids.len(), 2, "dedupes to the 2 distinct active store ids");
        assert!(ids.contains(&store_a));
        assert!(ids.contains(&store_b));
    }

    #[test]
    fn active_store_ids_excludes_a_reclaimable_reserved_hold() {
        // A lapsed Reserved hold is reclaimable ("available" to the resolver) — never tracked.
        let d = domain(DomainStatus::Reserved, &"ff".repeat(32), Some(50));
        assert!(active_store_ids(&[d], 51).is_empty());
    }

    // ── run_tick: orchestration over mocked ports ───────────────────────────────────────

    struct MockReader(HashMap<String, ChainReadResult>);
    impl ChainTipReader for MockReader {
        async fn current_tip(&self, store_id: &str, _last_known: Option<&str>) -> ChainReadResult {
            self.0
                .get(store_id)
                .cloned()
                .unwrap_or(ChainReadResult::Unavailable)
        }
    }

    #[derive(Default)]
    struct MockLedger(RefCell<HashMap<String, String>>);
    impl TipLedger for MockLedger {
        async fn get(&self, store_id: &str) -> Option<String> {
            self.0.borrow().get(store_id).cloned()
        }
        async fn put(&self, store_id: &str, tip: &str) {
            self.0
                .borrow_mut()
                .insert(store_id.to_string(), tip.to_string());
        }
    }

    #[derive(Default)]
    struct MockInvalidator(RefCell<u32>);
    impl Invalidator for MockInvalidator {
        async fn invalidate(&self) {
            *self.0.borrow_mut() += 1;
        }
    }

    #[tokio::test]
    async fn a_tick_with_no_prior_state_only_baselines_and_never_invalidates() {
        let store = "12".repeat(32);
        let reader = MockReader(HashMap::from([(
            store.clone(),
            ChainReadResult::Tip("aa".repeat(32)),
        )]));
        let ledger = MockLedger::default();
        let invalidator = MockInvalidator::default();

        let ids = BTreeSet::from([store.clone()]);
        let report = run_tick(&ids, &reader, &ledger, &invalidator).await;

        assert_eq!(report.baseline, 1);
        assert!(!report.invalidated);
        assert_eq!(*invalidator.0.borrow(), 0);
        assert_eq!(ledger.get(&store).await, Some("aa".repeat(32)));
    }

    #[tokio::test]
    async fn an_unchanged_tip_across_two_ticks_never_invalidates() {
        let store = "34".repeat(32);
        let tip = "bb".repeat(32);
        let reader = MockReader(HashMap::from([(
            store.clone(),
            ChainReadResult::Tip(tip.clone()),
        )]));
        let ledger = MockLedger::default();
        let invalidator = MockInvalidator::default();
        let ids = BTreeSet::from([store.clone()]);

        run_tick(&ids, &reader, &ledger, &invalidator).await; // baseline
        let second = run_tick(&ids, &reader, &ledger, &invalidator).await; // same tip again

        assert_eq!(second.unchanged, 1);
        assert!(!second.invalidated);
        assert_eq!(*invalidator.0.borrow(), 0);
    }

    #[tokio::test]
    async fn a_changed_tip_invalidates_exactly_once_even_with_multiple_changed_stores() {
        let store_a = "56".repeat(32);
        let store_b = "78".repeat(32);
        let ledger = MockLedger::default();
        ledger.put(&store_a, "old-a").await;
        ledger.put(&store_b, "old-b").await;
        let reader = MockReader(HashMap::from([
            (store_a.clone(), ChainReadResult::Tip("new-a".into())),
            (store_b.clone(), ChainReadResult::Tip("new-b".into())),
        ]));
        let invalidator = MockInvalidator::default();
        let ids = BTreeSet::from([store_a.clone(), store_b.clone()]);

        let report = run_tick(&ids, &reader, &ledger, &invalidator).await;

        assert_eq!(report.changed, 2);
        assert!(report.invalidated);
        assert_eq!(
            *invalidator.0.borrow(),
            1,
            "one tick with multiple changed stores fires exactly one coalesced invalidation"
        );
        assert_eq!(ledger.get(&store_a).await, Some("new-a".to_string()));
        assert_eq!(ledger.get(&store_b).await, Some("new-b".to_string()));
    }

    #[tokio::test]
    async fn a_held_store_never_invalidates_and_never_overwrites_the_ledger() {
        let store = "9a".repeat(32);
        let ledger = MockLedger::default();
        ledger.put(&store, "stable-tip").await;
        let reader = MockReader(HashMap::new()); // no entry -> Unavailable
        let invalidator = MockInvalidator::default();
        let ids = BTreeSet::from([store.clone()]);

        let report = run_tick(&ids, &reader, &ledger, &invalidator).await;

        assert_eq!(report.held, 1);
        assert!(!report.invalidated);
        assert_eq!(
            ledger.get(&store).await,
            Some("stable-tip".to_string()),
            "an uncertain chain read must never clobber the ledger"
        );
    }

    #[tokio::test]
    async fn a_newly_melted_store_invalidates_once_then_never_reads_the_chain_again() {
        let store = "bc".repeat(32);
        let ledger = MockLedger::default();
        ledger.put(&store, "last-live-tip").await;
        let reader = MockReader(HashMap::from([(store.clone(), ChainReadResult::Melted)]));
        let invalidator = MockInvalidator::default();
        let ids = BTreeSet::from([store.clone()]);

        let first = run_tick(&ids, &reader, &ledger, &invalidator).await;
        assert_eq!(first.melted, 1);
        assert!(first.invalidated);
        assert_eq!(ledger.get(&store).await, Some(MELTED_SENTINEL.to_string()));

        // Second tick: the ledger now says "melted" -> skip the chain read (an empty reader
        // would return Unavailable for anything it's asked, proving the read never happens).
        let second = run_tick(&ids, &reader, &ledger, &invalidator).await;
        assert_eq!(second.already_melted, 1);
        assert!(
            !second.invalidated,
            "a re-observed melt must not invalidate again"
        );
        assert_eq!(
            *invalidator.0.borrow(),
            1,
            "only the FIRST melt observation ever invalidates"
        );
    }
}

//! `*.on.dig.net` pinned-URN domain records — the ON-THE-WIRE contract this resolver reads.
//!
//! A domain pins a DIG URN (a store, optionally root-locked). The registration lifecycle is owned
//! by the hub.dig.net control plane (which WRITES these rows to the shared DynamoDB `dighub` table);
//! this resolver only READS them (`GetItem` on `DOMAIN#{subdomain}` / `CUSTOMDOM#{host}`) to decide
//! what to serve. The struct + enum below therefore MUST deserialize the exact JSON the hub persists
//! in the row's `doc` attribute — the field names, the `snake_case` status encoding, and the
//! optional/`#[serde(default)]` fields are a byte-level cross-repo contract (see SPEC.md → "Domain
//! record" and SYSTEM.md). Changing any of them here silently breaks resolution of live domains.
//!
//! This is a faithful, read-only subset of the hub's `dighub-data::domain` module: it carries only
//! what the resolver needs (the record shape + the label validator + the reserved-word list + the
//! two status helpers `render_for` consumes). The write-side types (registration-payment tx, pricing)
//! deliberately do NOT live here — this service never writes.

use serde::{Deserialize, Serialize};

/// Subdomain labels nobody may register (operational / confusing / abuse-prone). Shared verbatim
/// with the hub registration path — a label the hub refuses to register must also never resolve.
pub const RESERVED_WORDS: &[&str] = &[
    "www", "api", "rpc", "hub", "admin", "dig", "on", "mail", "ftp", "ns", "ns1", "ns2", "cdn",
    "static", "assets", "app", "root", "support", "help", "about", "status", "mx", "smtp", "imap",
    "pop", "webmail", "test", "dev", "staging",
];

/// Validate a subdomain label: lowercase RFC-1123 single label, 1..=63 chars, not reserved.
///
/// Defense-in-depth on the read side: the resolver only serves a `<label>.on.dig.net` whose label
/// passes the SAME rules the hub enforced at registration, so a malformed or reserved `Host` header
/// can never drive a DynamoDB lookup. (Handle-reservation + profanity are enforced in the hub API
/// layer where the account + handle index is available; they are not re-checked here.)
pub fn validate_label(label: &str) -> Result<(), &'static str> {
    if label.is_empty() || label.len() > 63 {
        return Err("subdomain must be 1–63 characters");
    }
    let bytes = label.as_bytes();
    let ok_char = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
    if !bytes.iter().all(|&b| ok_char(b)) {
        return Err("subdomain may contain only lowercase letters, digits, and hyphens");
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return Err("subdomain may not start or end with a hyphen");
    }
    if RESERVED_WORDS.contains(&label) {
        return Err("that subdomain is reserved");
    }
    Ok(())
}

/// Lifecycle status of a domain registration. The `snake_case` serde encoding is the on-the-wire
/// contract: it MUST match the strings the hub writes (`reserved`/`pending`/`active`/`expired`/
/// `revoked`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStatus {
    /// A short-lived hold while the user pays (pre-broadcast).
    Reserved,
    /// Payment broadcast + registered; awaiting confirmation depth.
    Pending,
    /// Confirmed; the resolver serves the pinned URN.
    Active,
    /// Past `expires_at`; the resolver serves an "expired" page until reclaimed.
    Expired,
    /// Taken down for abuse; serves a takedown page. No refund.
    Revoked,
}

/// A `*.on.dig.net` domain registration row, as persisted by the hub control plane in the shared
/// DynamoDB table's `doc` attribute. Field names + optionality are a cross-repo wire contract — see
/// the module docs. Only the fields the resolver actually reads carry behaviour; the rest are kept
/// so the row round-trips (an unknown-field-tolerant deser is not relied upon).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Domain {
    pub subdomain: String,
    pub owner_ph: String,
    /// 64-hex store id the subdomain pins.
    pub pinned_store_id: String,
    /// `None` = track latest root (live); `Some` = frozen snapshot.
    pub pinned_root: Option<String>,
    /// Optional private-store decrypt salt (hex). `None` for public stores.
    pub salt: Option<String>,
    pub status: DomainStatus,
    pub registered_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub renewal_due_at: Option<u64>,
    pub reg_spend_id: Option<String>,
    pub reg_coin_id: Option<String>,
    pub created_at: u64,
    /// The registration price agreed at reserve time, in DIG base units. `#[serde(default)]` so
    /// pre-discount-feature rows (which omit it) still deserialize.
    #[serde(default)]
    pub reg_price_baseunits: Option<u64>,
}

impl Domain {
    /// Returns the stored status unchanged. Domains are permanent — Active domains never expire
    /// (expiry arrives with CHIP-54). `expires_at` is still used for the 15-minute Reserved
    /// pre-payment hold; it is `None` on every Active domain.
    pub fn effective_status(&self) -> DomainStatus {
        self.status
    }

    /// Permanent reservations never lapse. The ONLY reclaimable state is a Reserved hold whose
    /// 15-minute pre-payment window expired without a registration (so the name frees up and the
    /// resolver serves "available" again).
    pub fn is_reclaimable(&self, now: u64) -> bool {
        self.status == DomainStatus::Reserved && self.expires_at.is_some_and(|e| now > e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_labels() {
        assert!(validate_label("alice").is_ok());
        assert!(validate_label("a-b-3").is_ok());
        assert!(validate_label("-bad").is_err()); // leading hyphen
        assert!(validate_label("bad-").is_err()); // trailing hyphen
        assert!(validate_label("UP").is_err()); // not lowercased
        assert!(validate_label("").is_err());
        assert!(validate_label(&"x".repeat(64)).is_err()); // > 63
        assert!(validate_label("www").is_err()); // reserved word
        assert!(validate_label("api").is_err());
    }

    fn active_domain() -> Domain {
        Domain {
            subdomain: "alice".into(),
            owner_ph: "ph".into(),
            pinned_store_id: "00".repeat(32),
            pinned_root: None,
            salt: None,
            status: DomainStatus::Active,
            registered_at: Some(1000),
            expires_at: None,     // permanent: no expiry
            renewal_due_at: None, // renewal arrives with CHIP-54
            reg_spend_id: Some("sp".into()),
            reg_coin_id: Some("co".into()),
            created_at: 1000,
            reg_price_baseunits: None,
        }
    }

    /// Active domains are permanent: effective_status is always Active and is_reclaimable is false.
    #[test]
    fn active_domain_is_permanent() {
        let d = active_domain();
        assert_eq!(d.effective_status(), DomainStatus::Active);
        assert!(!d.is_reclaimable(0));
        assert!(!d.is_reclaimable(u64::MAX));
    }

    /// The row round-trips through serde with the `snake_case` status + optional expiry fields — the
    /// exact shape the hub writes.
    #[test]
    fn active_domain_serde_roundtrip() {
        let d = active_domain();
        let j = serde_json::to_string(&d).unwrap();
        assert!(
            j.contains("\"status\":\"active\""),
            "status is snake_case: {j}"
        );
        let back: Domain = serde_json::from_str(&j).unwrap();
        assert_eq!(back.subdomain, "alice");
        assert_eq!(back.effective_status(), DomainStatus::Active);
        assert!(back.expires_at.is_none());
        assert!(back.renewal_due_at.is_none());
    }

    /// A pre-discount-feature row (no `reg_price_baseunits`) still deserializes (serde default).
    #[test]
    fn legacy_row_without_reg_price_deserializes() {
        let json = r#"{
            "subdomain":"legacy","owner_ph":"ph","pinned_store_id":"aa",
            "pinned_root":null,"salt":null,"status":"active","registered_at":1,
            "expires_at":null,"renewal_due_at":null,"reg_spend_id":null,
            "reg_coin_id":null,"created_at":1
        }"#;
        let d: Domain = serde_json::from_str(json).unwrap();
        assert_eq!(d.status, DomainStatus::Active);
        assert!(d.reg_price_baseunits.is_none());
    }

    /// A Reserved hold is reclaimable after its 15-minute expires_at, but NOT at or before it.
    #[test]
    fn reserved_hold_reclaimable_boundary() {
        let t: u64 = 1_000_000;
        let hold = Domain {
            subdomain: "bob".into(),
            owner_ph: "ph".into(),
            pinned_store_id: String::new(),
            pinned_root: None,
            salt: None,
            status: DomainStatus::Reserved,
            registered_at: None,
            expires_at: Some(t),
            renewal_due_at: None,
            reg_spend_id: None,
            reg_coin_id: None,
            created_at: t - 900,
            reg_price_baseunits: None,
        };
        assert!(!hold.is_reclaimable(t)); // at exactly expires_at: strict `>`
        assert!(hold.is_reclaimable(t + 1)); // one second past
    }
}

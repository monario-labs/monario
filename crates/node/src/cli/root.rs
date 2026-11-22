//! Offline, deterministic root-ceremony record.
//!
//! A trusted root remains an external launch input. This module only defines a
//! reproducible public preimage and verifies a supplied record against it. It
//! creates no genesis block, allocation, database, key or network connection.
//!
//! The derivation below is a **ceremony convention**, not a consensus rule: a
//! node still accepts the root supplied in its manifest. The tool exists so all
//! participants can recompute and compare the same public fields.

use super::{Error, hash};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Domain separator for the root identifier. The trailing NUL is literal.
pub const DOMAIN: &[u8] = b"Monario/root-ceremony/v1\0";
/// Version of the record format and the derived identifier.
pub const VERSION: u8 = 1;
/// Maximum accepted record size.
pub const MAX_BYTES: usize = 1_024;

/// Placeholders shared with the manifest template. None is valid hex.
pub const PLACEHOLDER_CHAIN_ID: &str = super::manifest::PLACEHOLDER_CHAIN_ID;
pub const PLACEHOLDER_ROOT_COMMITMENT: &str = super::manifest::PLACEHOLDER_ROOT_COMMITMENT;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    chain_id: String,
    root_timestamp: u64,
    root_commitment: String,
    /// Optional in a preimage; when present it must match the derived value.
    #[serde(default)]
    root_id: Option<String>,
}

/// A validated ceremony record. `root_id` is always the derived identifier, so
/// callers cannot act on an unverified supplied value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub chain_id: [u8; 32],
    pub root_timestamp: u64,
    pub root_commitment: [u8; 32],
    pub root_id: [u8; 32],
    /// Whether the input carried an explicit `root_id`.
    pub supplied: bool,
}

/// Parse and validate a root preimage or completed record.
///
/// The record is bounded, strictly shaped and placeholder-free. A nonzero
/// timestamp, chain id and commitment are required. If `root_id` is present it
/// must equal [`derive`]; omission is accepted so a fresh preimage can be
/// published before the identifier is known.
pub fn parse(bytes: &[u8]) -> Result<Record, Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Configuration);
    }
    let doc: Document = serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?;
    if doc.version != VERSION
        || doc.root_timestamp == 0
        || doc.root_timestamp > monario_chain::header::MAX_TIMESTAMP
    {
        return Err(Error::Configuration);
    }
    let chain_id = hash(&doc.chain_id).map_err(|_| Error::Configuration)?;
    let root_commitment = hash(&doc.root_commitment).map_err(|_| Error::Configuration)?;
    if chain_id == [0; 32] || root_commitment == [0; 32] {
        return Err(Error::Configuration);
    }
    let root_id = derive(&chain_id, doc.root_timestamp, &root_commitment);
    if let Some(text) = doc.root_id.as_deref()
        && hash(text).map_err(|_| Error::Configuration)? != root_id
    {
        return Err(Error::Configuration);
    }
    Ok(Record {
        chain_id,
        root_timestamp: doc.root_timestamp,
        root_commitment,
        root_id,
        supplied: doc.root_id.is_some(),
    })
}

/// Deterministic public root identifier:
/// `SHA-256(domain || version_le || chain_id || timestamp_le || commitment)`.
pub fn derive(chain_id: &[u8; 32], timestamp: u64, commitment: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(VERSION.to_le_bytes());
    h.update(chain_id);
    h.update(timestamp.to_le_bytes());
    h.update(commitment);
    h.finalize().into()
}

/// Verify that a manifest carries exactly the record's root fields and chain id.
///
/// This does not validate the commitment's content: no allocation format is
/// defined here and no allocation is created.
pub fn matches_manifest(record: &Record, manifest: &super::manifest::Manifest) -> bool {
    record.chain_id == manifest.config.chain_id
        && record.root_timestamp == manifest.root.timestamp
        && record.root_commitment == manifest.root.commitment
        && record.root_id == manifest.root.id
}

/// Emit a placeholder preimage. Every field must be replaced from the published
/// ceremony; the tool never generates a root or a chain.
pub fn template() -> Result<String, Error> {
    let doc = serde_json::json!({
        "version": VERSION,
        "chain_id": PLACEHOLDER_CHAIN_ID,
        "root_timestamp": 0,
        "root_commitment": PLACEHOLDER_ROOT_COMMITMENT,
    });
    serde_json::to_string_pretty(&doc).map_err(|_| Error::Output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::manifest;

    fn filled(chain: [u8; 32], timestamp: u64, commitment: [u8; 32]) -> String {
        let mut doc = template().unwrap();
        doc = doc.replace(PLACEHOLDER_CHAIN_ID, &super::super::hex(&chain));
        doc = doc.replace(PLACEHOLDER_ROOT_COMMITMENT, &super::super::hex(&commitment));
        doc.replace(
            "\"root_timestamp\": 0",
            &format!("\"root_timestamp\": {timestamp}"),
        )
    }

    fn record(chain: [u8; 32], timestamp: u64, commitment: [u8; 32]) -> Record {
        parse(filled(chain, timestamp, commitment).as_bytes()).unwrap()
    }

    #[test]
    fn template_is_never_a_valid_preimage() {
        assert!(parse(template().unwrap().as_bytes()).is_err());
    }

    #[test]
    fn root_id_is_reproducible_and_field_bound() {
        let base = record([1; 32], 1_700_000_000, [2; 32]);
        assert_eq!(base.root_id, derive(&[1; 32], 1_700_000_000, &[2; 32]));
        assert!(!base.supplied);

        let mut doc = filled([1; 32], 1_700_000_000, [2; 32]);
        doc = doc.replace(
            "}",
            &format!(
                ",\n  \"root_id\": \"{}\"\n}}",
                super::super::hex(&base.root_id)
            ),
        );
        let supplied = parse(doc.as_bytes()).unwrap();
        assert!(supplied.supplied);
        assert_eq!(supplied.root_id, base.root_id);
        assert_eq!(supplied.chain_id, base.chain_id);
        assert_eq!(supplied.root_timestamp, base.root_timestamp);
        assert_eq!(supplied.root_commitment, base.root_commitment);

        assert_ne!(
            base.root_id,
            record([3; 32], 1_700_000_000, [2; 32]).root_id
        );
        assert_ne!(
            base.root_id,
            record([1; 32], 1_700_000_001, [2; 32]).root_id
        );
        assert_ne!(
            base.root_id,
            record([1; 32], 1_700_000_000, [4; 32]).root_id
        );
    }

    #[test]
    fn malformed_and_wrong_records_fail_closed() {
        let base = record([1; 32], 1_700_000_000, [2; 32]);
        let mut doc = filled([1; 32], 1_700_000_000, [2; 32]);
        doc = doc.replace(
            "}",
            &format!(",\n  \"root_id\": \"{}\"\n}}", "00".repeat(32)),
        );
        assert!(parse(doc.as_bytes()).is_err());

        assert!(parse(filled([0; 32], 1_700_000_000, [2; 32]).as_bytes()).is_err());
        assert!(parse(filled([1; 32], 0, [2; 32]).as_bytes()).is_err());
        assert!(parse(filled([1; 32], u64::from(u32::MAX) + 1, [2; 32]).as_bytes()).is_ok());
        assert!(parse(filled([1; 32], u64::MAX, [2; 32]).as_bytes()).is_err());
        assert!(parse(filled([1; 32], 1_700_000_000, [0; 32]).as_bytes()).is_err());
        assert!(
            parse(format!("{{\"version\":2,\"chain_id\":\"{}\",\"root_timestamp\":1,\"root_commitment\":\"{}\"}}", "11".repeat(32), "22".repeat(32)).as_bytes())
                .is_err()
        );
        // Unknown fields, trailing data and oversized input are rejected.
        let mut extra = filled([1; 32], 1_700_000_000, [2; 32]);
        extra = extra.replace("}", ",\"extra\":1}");
        assert!(parse(extra.as_bytes()).is_err());
        assert!(parse(vec![b' '; MAX_BYTES + 1].as_slice()).is_err());
        assert_eq!(base.root_id.len(), 32);
    }

    #[test]
    fn manifest_must_match_the_record_exactly() {
        let chain = [0x11; 32];
        let commitment = [0x22; 32];
        let timestamp = 1_700_000_000;
        let record = record(chain, timestamp, commitment);

        let mut manifest_text = manifest::template().unwrap();
        manifest_text = manifest_text
            .replace(manifest::PLACEHOLDER_CHAIN_ID, &super::super::hex(&chain))
            .replace(
                manifest::PLACEHOLDER_ROOT_ID,
                &super::super::hex(&record.root_id),
            )
            .replace(
                manifest::PLACEHOLDER_ROOT_COMMITMENT,
                &super::super::hex(&commitment),
            )
            .replace(
                "\"root_timestamp\": 0",
                &format!("\"root_timestamp\": {timestamp}"),
            );
        let (_, parsed) = manifest::profile(manifest_text.as_bytes()).unwrap();
        assert!(matches_manifest(&record, &parsed));

        let mut wrong = manifest_text.clone();
        wrong = wrong.replace(
            &super::super::hex(&record.root_id),
            &super::super::hex(&[0x33; 32]),
        );
        let (_, parsed) = manifest::profile(wrong.as_bytes()).unwrap();
        assert!(!matches_manifest(&record, &parsed));
    }
}

use super::*;
use monario_chain::{Chain, Config, Root, consensus};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    chain_file: String,
    chain_id: String,
    root_id: String,
    root_timestamp: u64,
    root_commitment: String,
    initial_bits: u32,
    pow_limit_bits: u32,
    half_life_seconds: u64,
    #[serde(default)]
    asert_from_first_block: bool,
    seed_interval: u64,
    seed_lag: u64,
    max_future_seconds: u32,
    retained_blocks: usize,
    /// Optional explicit in-memory header window. Absent means retain everything.
    #[serde(default)]
    history_blocks: Option<u64>,
    transaction_bytes: usize,
    transactions: usize,
    inputs_per_transaction: usize,
    outputs_per_transaction: usize,
    script_bytes: usize,
}
pub struct Manifest {
    pub file: String,
    pub config: Config,
    pub root: Root,
    /// Operator-selected bounded-history window, if any.
    pub history_blocks: Option<u64>,
}
/// Placeholders in [`template`]. None is valid hex, so an unedited template can
/// never be parsed as a live manifest.
pub const PLACEHOLDER_CHAIN_ID: &str = "REPLACE_CHAIN_ID_WITH_32_BYTE_LOWERCASE_HEX";
pub const PLACEHOLDER_ROOT_ID: &str = "REPLACE_ROOT_ID_WITH_32_BYTE_LOWERCASE_HEX";
pub const PLACEHOLDER_ROOT_COMMITMENT: &str = "REPLACE_ROOT_COMMITMENT_WITH_32_BYTE_LOWERCASE_HEX";

/// Parse and fully validate a manifest, returning its computed validation profile
/// alongside the parsed values. This opens no database, reads no password and
/// starts no node.
pub fn profile(bytes: &[u8]) -> Result<([u8; 32], Manifest), Error> {
    build(bytes)
}

pub fn parse(bytes: &[u8], expected: [u8; 32]) -> Result<Manifest, Error> {
    let (profile, manifest) = build(bytes)?;
    if profile != expected {
        return Err(Error::Configuration);
    }
    Ok(manifest)
}

/// Names of manifest parameters that differ from the published recommended launch
/// values. Root, chain id and difficulty bits are explicit launch inputs and are
/// deliberately excluded. An empty result means the manifest uses the recommended
/// ASERT, RandomX, future-time, retention and payload limits.
pub fn recommended_mismatches(manifest: &Manifest) -> Vec<&'static str> {
    let c = &manifest.config;
    let mut out = Vec::new();
    if c.half_life_seconds != consensus::ASERT_HALF_LIFE_SECONDS {
        out.push("half_life_seconds");
    }
    if c.seed_interval != consensus::RANDOMX_SEED_INTERVAL {
        out.push("seed_interval");
    }
    if c.seed_lag != consensus::RANDOMX_SEED_LAG {
        out.push("seed_lag");
    }
    if c.max_future_seconds != consensus::MAX_FUTURE_SECONDS {
        out.push("max_future_seconds");
    }
    if c.retained_blocks != consensus::RETAINED_BLOCKS {
        out.push("retained_blocks");
    }
    if c.limits.transaction_bytes != consensus::TRANSACTION_BYTES {
        out.push("transaction_bytes");
    }
    if c.limits.transactions != consensus::TRANSACTIONS_PER_BLOCK {
        out.push("transactions");
    }
    if c.limits.inputs_per_transaction != consensus::INPUTS_PER_TRANSACTION {
        out.push("inputs_per_transaction");
    }
    if c.limits.outputs_per_transaction != consensus::OUTPUTS_PER_TRANSACTION {
        out.push("outputs_per_transaction");
    }
    if c.limits.script_bytes != consensus::SCRIPT_BYTES {
        out.push("script_bytes");
    }
    out
}

fn build(bytes: &[u8]) -> Result<([u8; 32], Manifest), Error> {
    if bytes.len() > 16_384 {
        return Err(Error::Configuration);
    }
    let doc: Document = serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?;
    if doc.version != 1
        || !(2..=10_000_000).contains(&doc.retained_blocks)
        // The consensus-required minimum is enforced against the opened chain;
        // here we only reject an impossible magnitude before any I/O.
        || doc
            .history_blocks
            .is_some_and(|n| !(1..=100_000_000).contains(&n))
    {
        return Err(Error::Configuration);
    }
    let root = Root {
        id: hash(&doc.root_id)?,
        timestamp: doc.root_timestamp,
        commitment: hash(&doc.root_commitment)?,
    };
    let config = Config {
        chain_id: hash(&doc.chain_id)?,
        initial_bits: doc.initial_bits,
        pow_limit_bits: doc.pow_limit_bits,
        half_life_seconds: doc.half_life_seconds,
        asert_from_first_block: doc.asert_from_first_block,
        seed_interval: doc.seed_interval,
        seed_lag: doc.seed_lag,
        coinbase_maturity: consensus::COINBASE_MATURITY,
        max_future_seconds: doc.max_future_seconds,
        retained_blocks: doc.retained_blocks,
        limits: monario_chain::Limits {
            block_bytes: monario_chain::archive::MAX_BLOCK_BYTES,
            transaction_bytes: doc.transaction_bytes,
            transactions: doc.transactions,
            inputs_per_transaction: doc.inputs_per_transaction,
            outputs_per_transaction: doc.outputs_per_transaction,
            script_bytes: doc.script_bytes,
        },
    };
    let chain = Chain::new(config.clone(), root, V6Verifier).map_err(|_| Error::Configuration)?;
    let profile = chain.validation_profile();
    Ok((
        profile,
        Manifest {
            file: name(&doc.chain_file)?,
            config,
            root,
            history_blocks: doc.history_blocks,
        },
    ))
}

/// Emit a manifest template populated with the recommended consensus values.
/// The chain id, root fields and timestamp must be replaced from the launch
/// ceremony; this function never creates a root or genesis.
pub fn template() -> Result<String, Error> {
    let doc = serde_json::json!({
        "version": 1,
        "chain_file": "chain.sqlite",
        "chain_id": PLACEHOLDER_CHAIN_ID,
        "root_id": PLACEHOLDER_ROOT_ID,
        "root_timestamp": 0,
        "root_commitment": PLACEHOLDER_ROOT_COMMITMENT,
        "initial_bits": consensus::CANDIDATE_INITIAL_BITS,
        "pow_limit_bits": consensus::CANDIDATE_POW_LIMIT_BITS,
        "half_life_seconds": consensus::ASERT_HALF_LIFE_SECONDS,
        "seed_interval": consensus::RANDOMX_SEED_INTERVAL,
        "seed_lag": consensus::RANDOMX_SEED_LAG,
        "max_future_seconds": consensus::MAX_FUTURE_SECONDS,
        "retained_blocks": consensus::RETAINED_BLOCKS,
        "transaction_bytes": consensus::TRANSACTION_BYTES,
        "transactions": consensus::TRANSACTIONS_PER_BLOCK,
        "inputs_per_transaction": consensus::INPUTS_PER_TRANSACTION,
        "outputs_per_transaction": consensus::OUTPUTS_PER_TRANSACTION,
        "script_bytes": consensus::SCRIPT_BYTES,
    });
    serde_json::to_string_pretty(&doc).map_err(|_| Error::Output)
}

#[cfg(test)]
mod launch_tests {
    use super::*;
    #[test]
    fn template_substitutes_into_a_valid_profile() {
        let template = template().unwrap();
        assert!(template.contains(PLACEHOLDER_CHAIN_ID));
        // Unedited placeholders must never parse.
        assert!(profile(template.as_bytes()).is_err());
        let filled = template
            .replace(PLACEHOLDER_CHAIN_ID, &"11".repeat(32))
            .replace(PLACEHOLDER_ROOT_ID, &"22".repeat(32))
            .replace(PLACEHOLDER_ROOT_COMMITMENT, &"33".repeat(32));
        let (profile_id, manifest) = profile(filled.as_bytes()).unwrap();
        assert_ne!(profile_id, [0; 32]);
        assert_eq!(manifest.config.chain_id, [0x11; 32]);
        assert_eq!(manifest.root.id, [0x22; 32]);
        assert!(recommended_mismatches(&manifest).is_empty());
        assert_eq!(
            manifest.config.half_life_seconds,
            consensus::ASERT_HALF_LIFE_SECONDS
        );
        assert_eq!(manifest.config.limits.block_bytes, 5_000_000);
        assert_eq!(
            manifest.config.coinbase_maturity,
            consensus::COINBASE_MATURITY
        );

        let altered = filled.replace(
            &format!(
                "\"half_life_seconds\": {}",
                consensus::ASERT_HALF_LIFE_SECONDS
            ),
            &format!(
                "\"half_life_seconds\": {}",
                consensus::ASERT_HALF_LIFE_SECONDS + 1
            ),
        );
        let (_, altered) = profile(altered.as_bytes()).unwrap();
        assert_eq!(recommended_mismatches(&altered), ["half_life_seconds"]);
    }
}

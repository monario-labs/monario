use super::*;
use monario_chain::{Chain, Config, Root};
use monario_v6::V6Verifier;
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
    transaction_bytes: usize,
    transactions: usize,
    inputs_per_transaction: usize,
    outputs_per_transaction: usize,
    script_bytes: usize,
}
pub(crate) struct Manifest {
    pub file: String,
    pub config: Config,
    pub root: Root,
}
pub(crate) fn parse(bytes: &[u8], expected: [u8; 32]) -> Result<Manifest, Error> {
    if bytes.len() > 16_384 {
        return Err(Error::Configuration);
    }
    let doc: Document = serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?;
    if doc.version != 1 || !(2..=10_000_000).contains(&doc.retained_blocks) {
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
        coinbase_maturity: monario_chain::consensus::COINBASE_MATURITY,
        max_future_seconds: doc.max_future_seconds,
        retained_blocks: doc.retained_blocks,
        limits: monario_chain::Limits {
            block_bytes: 5_000_000,
            transaction_bytes: doc.transaction_bytes,
            transactions: doc.transactions,
            inputs_per_transaction: doc.inputs_per_transaction,
            outputs_per_transaction: doc.outputs_per_transaction,
            script_bytes: doc.script_bytes,
        },
    };
    let chain = Chain::new(config.clone(), root, V6Verifier).map_err(|_| Error::Configuration)?;
    if chain.validation_profile() != expected {
        return Err(Error::Configuration);
    }
    Ok(Manifest {
        file: filename(&doc.chain_file)?,
        config,
        root,
    })
}

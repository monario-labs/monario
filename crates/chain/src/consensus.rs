//! Versioned consensus rules and candidate launch parameters.
//!
//! The values here are **binary-enforced**: a node either follows them or refuses
//! to interoperate. [`VERSION`] and [`rules_hash`] are mixed into the validation
//! profile, which the database, state checkpoints, wallet scanner and P2P handshake
//! all bind to. Changing any rule therefore changes the network identity and mixed
//! binaries fail closed instead of silently diverging.
//!
//! Per-network values that are supplied in the operator manifest (chain id, root,
//! difficulty bits, ASERT half-life, seed schedule, timestamp bound and payload
//! limits) are already bound by the profile through [`Config`]. This module also
//! publishes the recommended launch values and a [`candidate_config`] builder so a
//! launch manifest has one authoritative reference.
//!
//! Nothing in this module creates a genesis block, searches a nonce or starts a
//! network. The trusted root remains an external launch input.

use crate::{Config, Hash, Limits, archive, header, service, shielded};
use monario_monetary::{
    ATOMS_PER_COIN, EMISSION_CURVE_BONUS_ATOMS, EMISSION_CURVE_SEGMENTS, EMISSION_ROUNDING_BLOCKS,
    INITIAL_SUBSIDY_ATOMS, MAIN_EMISSION_ATOMS, MAIN_EMISSION_BLOCKS, MAX_TRANSACTION_VALUE_ATOMS,
    TAIL_EMISSION_ATOMS,
};

/// Semantic consensus version. Bump this for any rule change that is not already
/// covered by [`rules_hash`]; it is independent of the storage schema version.
pub const VERSION: u32 = 5;

/// Transaction signing branch, included in the network consensus identity.
pub const TRANSACTION_BRANCH_ID: u32 = 0x374e_4f4d;

/// Highest block height representable in durable chain indexes.
pub const MAX_BLOCK_HEIGHT: u64 = i64::MAX as u64;

/// Median-time-past window in blocks (Bitcoin/Zcash style).
pub const MEDIAN_TIME_BLOCKS: usize = 11;

/// Recommended ASERT half-life: 6 hours. At 90-second spacing this is about 240
/// blocks, faster than BCH's 2-day/600-second half-life in block terms and slower
/// (more damped) than Zcash's short averaging window.
pub const ASERT_HALF_LIFE_SECONDS: u64 = 21_600;
/// Recommended RandomX seed epoch, mirroring Monero's 2,048-block scheme.
pub const RANDOMX_SEED_INTERVAL: u64 = 2_048;
/// Recommended RandomX seed lag, mirroring Monero's 64-block advance notice.
pub const RANDOMX_SEED_LAG: u64 = 64;
/// Recommended future timestamp bound: 10 minutes (Monero's tighter bound, rather
/// than Bitcoin's 2 hours). At 90-second blocks this is about 6.7 blocks.
pub const MAX_FUTURE_SECONDS: u32 = 600;
/// Recommended miner and collateral-node coinbase maturity in blocks (6 hours at 90 seconds).
pub const COINBASE_MATURITY: u64 = 240;
/// Recommended maximum serialized transaction size: 2,000,000 bytes (the Zcash
/// `MAX_TX_SIZE` bound), below the 5,000,000-byte block cap.
pub const TRANSACTION_BYTES: usize = 2_000_000;
/// Recommended maximum transactions per block.
pub const TRANSACTIONS_PER_BLOCK: usize = 10_000;
/// Recommended transparent input cap per transaction (matches the v6 verifier).
pub const INPUTS_PER_TRANSACTION: usize = 10_000;
/// Recommended transparent output cap per transaction (matches the v6 verifier).
pub const OUTPUTS_PER_TRANSACTION: usize = 10_000;
/// Recommended maximum single script size (Bitcoin's default 10,000-byte bound).
pub const SCRIPT_BYTES: usize = 10_000;
/// Recommended undo/reorg window. Operational, not consensus finality.
pub const RETAINED_BLOCKS: usize = 10_000;

/// Candidate proof-of-work limit. This is deliberately the easiest target the
/// engine accepts so a new chain cannot become unmineable; ASERT raises difficulty
/// from here. It is a **launch candidate**, not an audited mainnet value.
pub const CANDIDATE_POW_LIMIT_BITS: u32 = 0x2100_ffff;
/// Candidate initial target: equal to the pow limit, so height 1 is mineable and
/// difficulty only moves harder. Confirm from launch hashrate before release.
pub const CANDIDATE_INITIAL_BITS: u32 = CANDIDATE_POW_LIMIT_BITS;

/// Hash over every binary-enforced consensus constant listed in this module plus
/// the monetary, block-size, shielded, service and header rules they depend on.
/// This is a freeze guard: any accidental rule edit changes the profile identity.
pub fn rules_hash() -> Hash {
    rules_hash_with_transaction_limit(MAX_TRANSACTION_VALUE_ATOMS)
}

fn rules_hash_with_transaction_limit(transaction_value_limit: u64) -> Hash {
    let mut b = Vec::new();
    for n in [
        u64::from(VERSION),
        u64::from(TRANSACTION_BRANCH_ID),
        monario_pow::BLOCK_SECONDS,
        ATOMS_PER_COIN,
        transaction_value_limit,
        INITIAL_SUBSIDY_ATOMS,
        MAIN_EMISSION_BLOCKS,
        TAIL_EMISSION_ATOMS,
        MAIN_EMISSION_ATOMS as u64,
        EMISSION_CURVE_SEGMENTS,
        EMISSION_CURVE_BONUS_ATOMS,
        EMISSION_ROUNDING_BLOCKS,
        archive::MAX_BLOCK_BYTES as u64,
        u64::from(header::HEADER_VERSION),
        header::HEADER_LEN as u64,
        header::MAX_TIMESTAMP,
        MAX_BLOCK_HEIGHT,
        128, // Aggregate supply and shielded pool encoding width.
        MEDIAN_TIME_BLOCKS as u64,
        shielded::MAX_ACTIONS_PER_TRANSACTION,
        shielded::MAX_ACTIONS_PER_BLOCK,
        shielded::PROOF_COST,
        shielded::ACTION_COST,
        shielded::MAX_COST_PER_TRANSACTION,
        shielded::MAX_COST_PER_BLOCK,
        service::COLLATERAL_ATOMS,
        u64::from(service::RECORD_FORMAT_VERSION),
        COINBASE_MATURITY,
        service::REGISTRATION_CONFIRMATIONS,
        service::QUALIFY_SECONDS,
        service::PERIOD_BLOCKS,
        service::RESPONSE_BLOCKS,
        service::MAX_REGISTRATIONS as u64,
        u64::from(service::SLOT_CAPACITY),
        service::SAMPLES as u64,
        service::MAX_RECORD_BYTES as u64,
    ] {
        b.extend(n.to_le_bytes());
    }
    header::hash_domain(b"Monario/consensus-rules/v1\0", &[&b])
}

/// Build a [`Config`] from the recommended launch values. `chain_id` and the
/// difficulty bits are explicit parameters because they remain launch inputs (the
/// root and chain id are never generated here). The result passes `Chain::new`
/// validation and binds the complete profile through [`Config`].
pub fn candidate_config(chain_id: Hash, initial_bits: u32, pow_limit_bits: u32) -> Config {
    Config {
        chain_id,
        initial_bits,
        pow_limit_bits,
        half_life_seconds: ASERT_HALF_LIFE_SECONDS,
        seed_interval: RANDOMX_SEED_INTERVAL,
        seed_lag: RANDOMX_SEED_LAG,
        coinbase_maturity: COINBASE_MATURITY,
        max_future_seconds: MAX_FUTURE_SECONDS,
        retained_blocks: RETAINED_BLOCKS,
        limits: Limits {
            block_bytes: archive::MAX_BLOCK_BYTES,
            transaction_bytes: TRANSACTION_BYTES,
            transactions: TRANSACTIONS_PER_BLOCK,
            inputs_per_transaction: INPUTS_PER_TRANSACTION,
            outputs_per_transaction: OUTPUTS_PER_TRANSACTION,
            script_bytes: SCRIPT_BYTES,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Chain;
    use crate::tests::{FixtureVerifier, config, root};

    #[test]
    fn candidate_launch_config_is_valid() {
        let c = candidate_config([5; 32], CANDIDATE_INITIAL_BITS, CANDIDATE_POW_LIMIT_BITS);
        Chain::new(c, root(), FixtureVerifier::default()).unwrap();
    }

    #[test]
    fn consensus_rules_and_profile_are_frozen() {
        // Freeze guard: this is still pre-genesis. An intentional pre-launch rule
        // change updates these pins; once a network exists, any rule change must
        // bump `VERSION`. Any accidental edit flips the identity and fails here.
        const RULES: [u8; 32] = [
            0x6a, 0x59, 0xa1, 0xae, 0xbe, 0xed, 0xc1, 0xf6, 0x07, 0xca, 0x24, 0x5b, 0x68, 0x8d,
            0x9f, 0x85, 0xac, 0x64, 0x36, 0xac, 0xc3, 0x32, 0x6b, 0xe2, 0x2a, 0xc1, 0xd9, 0xdf,
            0xb6, 0xdc, 0xff, 0x05,
        ];
        const PROFILE: [u8; 32] = [
            0xfa, 0xa9, 0x0e, 0xd7, 0x8b, 0x0e, 0x1c, 0x18, 0x7c, 0x9b, 0xd7, 0x81, 0xc3, 0xcd,
            0x3e, 0xe0, 0x5f, 0x56, 0x16, 0xc6, 0xb3, 0x62, 0x8f, 0xaf, 0x8b, 0x0f, 0x44, 0x74,
            0xee, 0x92, 0x9b, 0xcb,
        ];
        assert_eq!(rules_hash(), RULES);
        assert_eq!(crate::storage::identity(&config(), root()), PROFILE);
    }

    #[test]
    fn transaction_value_bound_changes_network_rules_identity() {
        assert_ne!(
            rules_hash(),
            rules_hash_with_transaction_limit(MAX_TRANSACTION_VALUE_ATOMS + 1)
        );
    }

    #[test]
    fn recommended_values_are_internally_consistent() {
        assert_eq!(TRANSACTION_BRANCH_ID.to_le_bytes(), *b"MON7");
        let c = candidate_config([5; 32], CANDIDATE_INITIAL_BITS, CANDIDATE_POW_LIMIT_BITS);
        assert!(c.initial_bits <= c.pow_limit_bits);
        assert!(c.seed_lag < c.seed_interval);
        assert!(c.limits.transaction_bytes <= c.limits.block_bytes);
        assert!(c.limits.inputs_per_transaction <= c.limits.transaction_bytes);
        assert!(c.limits.outputs_per_transaction <= c.limits.transaction_bytes);
        assert!(c.limits.script_bytes <= c.limits.transaction_bytes);
        assert!(c.half_life_seconds >= c.seed_interval);
    }
}

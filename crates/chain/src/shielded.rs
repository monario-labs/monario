//! Consensus-enforced shielded verification limits.
//!
//! Block size alone does not bound zero-knowledge verification work: a small block
//! can carry many Ironwood actions and many independent bundle proofs. These limits
//! are deterministic functions of the canonical transaction contents (shielded
//! action counts), never of wall-clock time, hardware, or a peer's claim. They are
//! applied identically during mempool admission, template assembly and block
//! validation.
//!
//! # Cost model
//!
//! Each shielded bundle pays a fixed proof/binding cost plus a per-action cost.
//! A transaction with `a > 0` actions costs `PROOF_COST + ACTION_COST * a` units;
//! a transaction with no shielded data costs nothing. Units are milliseconds on
//! the benchmark machine, rounded up for headroom. The numbers come from
//! `monario-v6`'s `shielded_verification_cost_benchmark` (release, process pinned
//! to one CPU with affinity mask 1, Intel i9-14900K):
//!
//! | actions | total verification |
//! |---|---|
//! | 1 | ~82 ms |
//! | 2 | ~96 ms |
//! | 4 | ~125 ms |
//! | 8 | ~181 ms |
//! | 16 | ~295 ms |
//! | 32 | ~519 ms |
//!
//! Least squares over these points is `68.3 ms + 14.1 ms/action`; an unpinned run
//! gave `69.2 ms + 15.1 ms/action`, and the marginal cost rises from about
//! 12 ms/action (1 to 2) to 14 ms/action (16 to 32). The verifier is
//! single-threaded, so pinning changes no parallelism; it only removes scheduling
//! noise. A linear model is conservative at the cap: `PROOF_COST = 100` and
//! `ACTION_COST = 20` model 1,380 units for a maximal 64-action transaction against
//! roughly 1.0 s measured, and a maximal 70-action block stays near 1.1 s here —
//! comfortably below the 90 s interval while leaving room for a slower node.
//!
//! The numerical limits are **provisional**. This machine is a high-end desktop,
//! not the intended modest reference hardware; the limits must be re-benchmarked
//! there before a release. Changing them changes consensus acceptance for every
//! node.

/// Maximum Ironwood actions in one transaction.
pub const MAX_ACTIONS_PER_TRANSACTION: u64 = 64;
/// Maximum Ironwood actions in one block. This equals the number of actions a
/// single-bundle block can afford under [`MAX_COST_PER_BLOCK`], so the structural
/// cap and the budget cannot silently diverge.
pub const MAX_ACTIONS_PER_BLOCK: u64 = 70;
/// Fixed cost of verifying one bundle proof and its binding signature.
pub const PROOF_COST: u64 = 100;
/// Additional cost for each action: spend authorization, nullifier and note
/// commitment checks, and the per-action proof circuit.
pub const ACTION_COST: u64 = 20;
/// Maximum verification cost of one transaction.
pub const MAX_COST_PER_TRANSACTION: u64 =
    PROOF_COST.saturating_add(ACTION_COST.saturating_mul(MAX_ACTIONS_PER_TRANSACTION));
/// Maximum total verification cost of one block.
pub const MAX_COST_PER_BLOCK: u64 = 1_500;

/// Deterministic verification cost of a transaction with `actions` shielded actions.
/// Actions are already bounded by [`MAX_ACTIONS_PER_TRANSACTION`] before this is
/// used; saturation keeps the function total for diagnostics.
pub const fn cost(actions: u64) -> u64 {
    if actions == 0 {
        0
    } else {
        PROOF_COST.saturating_add(ACTION_COST.saturating_mul(actions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cost_is_zero_only_without_shielded_actions() {
        assert_eq!(cost(0), 0);
        assert_eq!(cost(1), PROOF_COST + ACTION_COST);
        assert_eq!(cost(MAX_ACTIONS_PER_TRANSACTION), MAX_COST_PER_TRANSACTION);
        let transaction_cost = MAX_COST_PER_TRANSACTION;
        let block_cost = MAX_COST_PER_BLOCK;
        let block_actions = MAX_ACTIONS_PER_BLOCK;
        assert!(transaction_cost <= block_cost);
        assert!(block_actions >= MAX_ACTIONS_PER_TRANSACTION);
        // One bundle at the block action cap consumes the whole budget exactly.
        assert_eq!(cost(block_actions), block_cost);
        assert_eq!(cost(u64::MAX), u64::MAX);
    }
}

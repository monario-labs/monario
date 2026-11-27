//! Offline header/chain validation and atomic in-memory reorganizations.
//!
//! Use monario-v6's real transaction backend. `UnavailableV6` explicitly rejects
//! every transaction; there is no production PoW bypass or accepting mock backend.
pub mod archive;
pub mod assembly;
pub mod audit;
pub mod consensus;
pub mod finality;
#[cfg(test)]
mod finality_tests;
pub mod header;
pub mod ledger;
pub mod mempool;
pub mod pose;
pub mod service;
pub mod shielded;
pub mod storage;
pub mod transactions;
pub mod transfer;
pub mod wire;
#[cfg(test)]
mod wire_tests;

use header::{HEADER_LEN, Header, hash_domain, merkle_root};
pub use ledger::LedgerView;
use ledger::{Coin, Delta, Ledger, OutPoint, Overlay};
use monario_monetary::{Amount, subsidy};
use monario_pow::{Asert, Target};
/// Explicit local execution mode; neither choice changes RandomX v2 consensus.
pub use monario_randomx::Mode as VerificationMode;
use num_bigint::BigUint;
use std::collections::{BTreeMap, BTreeSet};
use transactions::{TransactionContext, TransactionError, TransactionVerifier};

pub type Hash = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Service,
    Configuration,
    HeaderEncoding,
    BlockEncoding,
    HeaderVersion,
    UnknownParent,
    DuplicateBlock,
    HeightOverflow,
    MedianTime,
    FutureTime,
    EmptyBlock,
    ResourceLimit,
    DuplicateTransaction,
    MerkleMutation,
    MerkleRoot,
    Commitment,
    Coinbase,
    ImmatureCoinbase,
    MissingInput,
    DoubleSpend,
    OutputCollision,
    NegativeFee,
    EmptyTransaction,
    InvalidAnchor,
    DuplicateNullifier,
    InvalidCommitment,
    Amount,
    OverclaimedReward,
    UnsupportedShielded,
    StateMismatch,
    Storage,
    Transaction(TransactionError),
    Pow(monario_pow::Error),
    Finality,
    /// A reorg would need undo data outside the retained window.
    ReorgTooDeep,
    /// Requested ancestry is below the retained header floor.
    HistoryUnavailable,
    /// Shielded actions or their deterministic verification cost exceed a
    /// consensus limit (per transaction or per block).
    ShieldedLimit,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "chain validation: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Resource limits must be part of the selected consensus profile, not per-peer input.
#[derive(Clone)]
pub struct Limits {
    pub block_bytes: usize,
    pub transaction_bytes: usize,
    pub transactions: usize,
    pub inputs_per_transaction: usize,
    pub outputs_per_transaction: usize,
    pub script_bytes: usize,
}

/// No launch parameters are silently selected by this library.
#[derive(Clone)]
pub struct Config {
    pub chain_id: Hash,
    pub initial_bits: u32,
    pub pow_limit_bits: u32,
    pub half_life_seconds: u64,
    pub asert_from_first_block: bool,
    pub seed_interval: u64,
    pub seed_lag: u64,
    pub coinbase_maturity: u64,
    pub max_future_seconds: u32,
    pub limits: Limits,
    /// Operational reorg window, not consensus finality. Undo deltas older than
    /// this many blocks are evicted locally; headers, work, archive summaries and
    /// shielded roots are retained so the chain keeps growing. A reorg deeper than
    /// the window fails with `ReorgTooDeep` rather than needing missing undo data.
    pub retained_blocks: usize,
}

/// Externally provisioned zero-supply root identity, not a generated genesis.
/// The caller must authenticate these constants against the selected chain spec.
#[derive(Clone, Copy)]
pub struct Root {
    pub id: Hash,
    pub timestamp: u64,
    pub commitment: Hash,
}

/// One validated non-coinbase transaction's exact fee and canonical byte size.
/// This is public chain metadata for offline estimation, never consensus state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeSample {
    pub fee_atoms: u64,
    pub bytes: u32,
}

/// Transaction byte slices must be produced by a bounded protocol decoder.
/// The transaction backend checks each slice is exactly one canonical v6 tx.
pub struct Block {
    pub header: Header,
    pub transactions: Vec<Vec<u8>>,
}

struct StagedTransaction {
    id: Hash,
    authorization_digest: Hash,
    outputs: Amount,
    fee: Amount,
    bytes: u32,
    shielded_actions: u64,
}

struct Node {
    parent: Option<Hash>,
    height: u64,
    timestamp: u64,
    // Derived from the validated parent. Keeps the exact branch anchor after
    // the optional in-memory history floor evicts the height-one header.
    first_block_time: u64,
    commitment: Hash,
    /// Selected-branch shielded state root after this block. Retained even after
    /// undo data is evicted so historical block metadata stays correct.
    shielded_root: Hash,
    work: BigUint,
    delta: Option<Delta>,
    archive: Option<archive::Summary>,
    skip: Option<Hash>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Accepted {
    pub id: Hash,
    pub became_best: bool,
    /// Old tip toward common ancestor, excluding the common ancestor.
    pub disconnected: Vec<Hash>,
    /// Common ancestor toward new tip, excluding the common ancestor.
    pub connected: Vec<Hash>,
}

/// Metadata authenticated by full validation or an explicitly trusted checkpoint.
#[derive(Clone, Copy)]
pub struct BlockInfo {
    pub parent: Option<Hash>,
    pub height: u64,
    pub commitment: Hash,
    pub shielded_root: Hash,
}

/// Transaction-effects inclusion in the currently selected validated branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confirmation {
    /// Block containing the transaction, never a retained orphan's block.
    pub block: Hash,
    /// Inclusion height.
    pub height: u64,
    /// Tip height minus inclusion height plus one; inclusion counts as one.
    pub depth: u64,
}

/// One thread-local RandomX cache. Switching seeds drops the old allocation
/// before constructing its replacement; forks cannot accumulate hidden caches.
#[derive(Default)]
struct PowEngine {
    vm: Option<monario_randomx::Verifier>,
    mode: Option<VerificationMode>,
}
trait PowCheck {
    fn check(&mut self, seed: &Hash, preimage: &[u8], target: &Target) -> Result<(), Error>;
}
impl PowCheck for PowEngine {
    fn check(&mut self, seed: &Hash, preimage: &[u8], target: &Target) -> Result<(), Error> {
        if self.vm.as_ref().is_none_or(|vm| vm.seed() != seed) {
            self.vm = None;
            self.vm = Some(
                monario_randomx::Verifier::with_mode(
                    seed,
                    self.mode.unwrap_or(VerificationMode::Interpreter),
                )
                .map_err(|e| Error::Pow(monario_pow::Error::RandomX(e)))?,
            );
        }
        monario_pow::verify(
            self.vm.as_mut().expect("initialized above"),
            seed,
            preimage,
            target,
        )
        .map_err(Error::Pow)
    }
}

/// Exclusive mutation plus staged ledger overlays makes each submission atomic.
/// This is an in-memory engine, not durable storage or a network service.
pub struct Chain<V: TransactionVerifier> {
    config: Config,
    asert: Asert,
    root: Root,
    nodes: BTreeMap<Hash, Node>,
    /// Nodes whose undo delta is still retained, ordered by height. Entries older
    /// than the configured window are evicted after each accepted block.
    undo_index: BTreeSet<(u64, Hash)>,
    /// Lowest height whose header metadata is guaranteed to be resident. Zero
    /// until an explicit bounded-history decision is made.
    history_floor: u64,
    /// Operator-selected in-memory header window. When set, the floor follows the
    /// selected tip so memory stays bounded during long runs.
    history_window: Option<u64>,
    tip: Hash,
    ledger: Ledger,
    verifier: V,
    pow: PowEngine,
    finality: Option<finality::Policy>,
    finality_warning: bool,
}

impl<V: TransactionVerifier> Chain<V> {
    pub fn new(config: Config, root: Root, verifier: V) -> Result<Self, Error> {
        let l = &config.limits;
        if config.chain_id == [0; 32]
            || root.id == [0; 32]
            || root.timestamp > header::MAX_TIMESTAMP
            || config.coinbase_maturity == 0
            || config.retained_blocks < 2
            || l.block_bytes < HEADER_LEN
            || l.block_bytes > archive::MAX_BLOCK_BYTES
            || l.transaction_bytes == 0
            || l.transaction_bytes > l.block_bytes
            || l.transactions == 0
            || l.transactions > l.block_bytes
            || l.inputs_per_transaction == 0
            || l.inputs_per_transaction > l.transaction_bytes
            || l.outputs_per_transaction == 0
            || l.outputs_per_transaction > l.transaction_bytes
            || l.script_bytes == 0
            || l.script_bytes > l.transaction_bytes
        {
            return Err(Error::Configuration);
        }
        monario_pow::seed_height(1, config.seed_interval, config.seed_lag).map_err(Error::Pow)?;
        let asert = Asert::new(
            config.half_life_seconds,
            1,
            root.timestamp,
            Target::from_compact(config.initial_bits).map_err(Error::Pow)?,
            Target::from_compact(config.pow_limit_bits).map_err(Error::Pow)?,
        )
        .map_err(Error::Pow)?;
        let mut nodes = BTreeMap::new();
        nodes.insert(
            root.id,
            Node {
                parent: None,
                height: 0,
                timestamp: root.timestamp,
                first_block_time: 0,
                commitment: root.commitment,
                shielded_root: ledger::ShieldedTree::default().root(),
                work: BigUint::ZERO,
                delta: None,
                archive: None,
                skip: None,
            },
        );
        Ok(Self {
            config,
            asert,
            root,
            nodes,
            undo_index: BTreeSet::new(),
            history_floor: 0,
            history_window: None,
            tip: root.id,
            ledger: Ledger::default(),
            verifier,
            pow: PowEngine::default(),
            finality: None,
            finality_warning: false,
        })
    }
    pub fn validation_profile(&self) -> Hash {
        storage::identity(&self.config, self.root)
    }

    fn next_block_bits(&self, parent: &Node) -> Result<u32, Error> {
        if parent.height == 0 {
            return Ok(self.config.initial_bits);
        }
        if self.config.asert_from_first_block {
            self.asert.next_bits_from_first_block(
                parent.height,
                parent.timestamp,
                parent.first_block_time,
            )
        } else {
            self.asert.next_bits(parent.height, parent.timestamp)
        }
        .map_err(Error::Pow)
    }
    pub fn tip(&self) -> Hash {
        self.tip
    }
    pub fn height(&self) -> u64 {
        self.nodes[&self.tip].height
    }
    /// Install an explicit local finality policy. Disabled by default; when a
    /// policy is absent the existing chainwork and reorg rules are unchanged. An
    /// operator pin must already be on the validated tip and at least the
    /// configured depth below it, or this fails closed.
    pub fn set_finality(&mut self, policy: finality::Policy) -> Result<(), Error> {
        if let Some(pin) = policy.pin {
            let tip = self.height();
            let depth = self.config.coinbase_maturity.saturating_add(100).max(1_000);
            if pin.height > tip || pin.height < self.history_floor || tip - pin.height < depth {
                return Err(Error::Finality);
            }
            if self.ancestor(self.tip, pin.height)? != pin.hash {
                return Err(Error::Finality);
            }
        }
        self.finality = Some(policy);
        self.finality_warning = false;
        Ok(())
    }
    /// Remove any local finality policy and warning.
    pub fn clear_finality(&mut self) {
        self.finality = None;
        self.finality_warning = false;
    }
    /// True if a warn-mode pin conflict was observed since installation.
    pub fn finality_warning(&self) -> bool {
        self.finality_warning
    }
    /// Shallowest configured finality pin/anchor height. Pruning must not remove
    /// the body at or above this height, so pinned identities stay available.
    pub fn finality_floor(&self) -> Option<u64> {
        let policy = self.finality?;
        [policy.anchor, policy.pin]
            .into_iter()
            .flatten()
            .map(|pin| pin.height)
            .min()
    }
    pub fn chainwork(&self) -> &BigUint {
        &self.nodes[&self.tip].work
    }
    pub fn ledger(&self) -> &dyn LedgerView {
        &self.ledger
    }
    /// Resolve a derived inclusion height through the validated ancestor index.
    /// Locators are hints: when the block's undo delta is still retained, the
    /// selected block must contain the exact transaction transition. Once undo
    /// data is outside the reorg window only the engine-derived height and the
    /// authenticated header remain; callers that need byte-level proof must read
    /// the block body (which fails clearly if it was pruned).
    pub fn transaction_confirmation(
        &self,
        transaction: &Hash,
    ) -> Result<Option<Confirmation>, Error> {
        let Some(&height) = self.ledger.transactions.get(transaction) else {
            return Ok(None);
        };
        let tip_height = self
            .nodes
            .get(&self.tip)
            .ok_or(Error::StateMismatch)?
            .height;
        if height == 0 || height > tip_height {
            return Err(Error::StateMismatch);
        }
        let id = self.confirmation_ancestor(height)?;
        let node = self.nodes.get(&id).ok_or(Error::StateMismatch)?;
        if let Some(delta) = node.delta.as_ref()
            && delta.transactions.get(transaction) != Some(&(false, true))
        {
            return Err(Error::StateMismatch);
        }
        let depth = tip_height
            .checked_sub(height)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::StateMismatch)?;
        Ok(Some(Confirmation {
            block: id,
            height,
            depth,
        }))
    }
    // Skip links are engine-derived (also used for consensus seed resolution),
    // never deserialized from a peer/checkpoint. Check bounds and monotonicity
    // before following them so malformed private state cannot loop or panic.
    fn confirmation_ancestor(&self, height: u64) -> Result<Hash, Error> {
        if height < self.history_floor {
            return Err(Error::HistoryUnavailable);
        }
        let mut id = self.tip;
        for _ in 0..self.nodes.len() {
            #[cfg(test)]
            tests::CONFIRMATION_STEPS.with(|n| n.set(n.get() + 1));
            let node = self.nodes.get(&id).ok_or(Error::StateMismatch)?;
            // The target may be the retained floor, whose parent is intentionally
            // absent. Check the target before requiring a resident parent.
            if node.height == height {
                return Ok(id);
            }
            let parent_id = node.parent.ok_or(Error::StateMismatch)?;
            let parent = self.nodes.get(&parent_id).ok_or(Error::StateMismatch)?;
            if parent.height.checked_add(1) != Some(node.height) || node.height < height {
                return Err(Error::StateMismatch);
            }
            let target = (node.height & (node.height - 1)).max(self.history_floor);
            match node.skip {
                Some(skip_id) => {
                    let skip = self.nodes.get(&skip_id).ok_or(Error::StateMismatch)?;
                    if skip.height != target
                        || skip.height >= node.height
                        || (skip.height == parent.height && skip_id != parent_id)
                    {
                        return Err(Error::StateMismatch);
                    }
                    id = if skip.height >= height {
                        skip_id
                    } else {
                        parent_id
                    };
                }
                None => {
                    // Only a node at the retained floor has no skip target.
                    if target < node.height {
                        return Err(Error::StateMismatch);
                    }
                    id = parent_id;
                }
            }
        }
        Err(Error::StateMismatch)
    }
    // Snapshots carry engine-derived inclusion heights; rebuild only validates
    // them. Undo deltas that are still retained must agree; nodes whose undo data
    // was evicted are covered by the authenticated snapshot itself.
    fn rebuild_confirmation_heights(
        ledger: &Ledger,
        nodes: &BTreeMap<Hash, Node>,
        tip: Hash,
    ) -> Result<(), Error> {
        let tip_height = nodes.get(&tip).ok_or(Error::StateMismatch)?.height;
        let mut id = tip;
        let mut visited = 0usize;
        loop {
            visited += 1;
            if visited > nodes.len() {
                return Err(Error::StateMismatch);
            }
            let node = nodes.get(&id).ok_or(Error::StateMismatch)?;
            if let Some(delta) = &node.delta {
                for (tx, transition) in &delta.transactions {
                    if *transition != (false, true)
                        || ledger.transactions.get(tx) != Some(&node.height)
                    {
                        return Err(Error::StateMismatch);
                    }
                }
            }
            let Some(parent_id) = node.parent else {
                if node.height != 0 || node.delta.is_some() {
                    return Err(Error::StateMismatch);
                }
                break;
            };
            let parent = nodes.get(&parent_id).ok_or(Error::StateMismatch)?;
            if parent.height.checked_add(1) != Some(node.height) {
                return Err(Error::StateMismatch);
            }
            id = parent_id;
        }
        if ledger
            .transactions
            .values()
            .any(|height| *height == 0 || *height > tip_height)
        {
            return Err(Error::StateMismatch);
        }
        Ok(())
    }
    /// Selected consensus limits, borrowed without permitting mutation.
    pub fn limits(&self) -> &Limits {
        &self.config.limits
    }
    /// Median of the active tip's timestamp window, for next-block validation.
    pub fn median_time_past(&self) -> u64 {
        self.median_time(self.tip)
    }
    pub fn contains(&self, id: &Hash) -> bool {
        self.nodes.contains_key(id)
    }
    /// Provisioned root identity; this does not create a genesis block.
    pub fn root_id(&self) -> Hash {
        self.root.id
    }
    pub fn chain_id(&self) -> Hash {
        self.config.chain_id
    }
    /// Nodes below this height no longer retain undo deltas.
    fn undo_floor(&self) -> u64 {
        self.height()
            .saturating_sub(u64::try_from(self.config.retained_blocks).unwrap_or(u64::MAX))
    }
    /// Drop undo deltas outside the reorg window. Headers, archive summaries,
    /// work and shielded roots are retained; consensus rules are unchanged.
    fn evict_expired_undo(&mut self) {
        let floor = self.undo_floor();
        while let Some(&(height, id)) = self.undo_index.first() {
            if height >= floor {
                break;
            }
            self.undo_index.remove(&(height, id));
            if let Some(node) = self.nodes.get_mut(&id) {
                node.delta = None;
            }
        }
    }
    /// Lowest height whose header metadata is guaranteed resident.
    pub fn history_floor(&self) -> u64 {
        self.history_floor
    }
    /// Header depth required by every consensus lookback: the RandomX seed
    /// schedule, the median-time window, the smartnode sampling window and the
    /// undo/reorg window. A bounded-history node must retain at least this much.
    pub fn required_history_window(&self) -> u64 {
        let seed = self
            .config
            .seed_interval
            .saturating_add(self.config.seed_lag)
            .saturating_add(1);
        let service = crate::service::PERIOD_BLOCKS
            .saturating_add(crate::service::RESPONSE_BLOCKS)
            .saturating_add(2);
        let undo = u64::try_from(self.config.retained_blocks).unwrap_or(u64::MAX);
        seed.max(service).max(undo).max(12)
    }
    /// Advance the retained-header floor, dropping older header metadata and
    /// rewriting skip links so every retained node jumps only to retained nodes.
    /// This is an explicit bounded-history decision: callers must first migrate
    /// snapshots, deep `block_info`/confirmation reads and wallet scanning to the
    /// durable index. `DurableChain` does not call this.
    pub fn advance_history_floor(&mut self, floor: u64) -> Result<u64, Error> {
        if floor > self.height() || floor < self.history_floor {
            return Err(Error::Configuration);
        }
        // A configured pin below the floor could no longer be resolved, which would
        // reject every subsequent best-chain transition. Fail closed instead.
        if let Some(pinned) = self.finality_floor()
            && floor > pinned
        {
            return Err(Error::Finality);
        }
        if floor == self.history_floor {
            return Ok(0);
        }
        self.history_floor = floor;
        let removed: Vec<Hash> = self
            .nodes
            .iter()
            .filter(|(_, node)| node.height < floor)
            .map(|(id, _)| *id)
            .collect();
        for id in &removed {
            self.nodes.remove(id);
        }
        self.undo_index.retain(|(height, _)| *height >= floor);
        self.normalize_skip_links();
        Ok(u64::try_from(removed.len()).unwrap_or(u64::MAX))
    }
    /// Shrink retained headers to the consensus-required history window.
    pub fn shrink_history(&mut self) -> Result<u64, Error> {
        let floor = self.height().saturating_sub(self.required_history_window());
        self.advance_history_floor(floor)
    }
    /// Keep the in-memory header window at `window` as the selected tip advances.
    /// `window` must be at least [`required_history_window`](Self::required_history_window).
    /// Passing `None` stops maintenance without restoring evicted headers.
    pub(crate) fn set_history_window(&mut self, window: Option<u64>) -> Result<(), Error> {
        if window.is_some_and(|window| window < self.required_history_window()) {
            return Err(Error::Configuration);
        }
        self.history_window = window;
        Ok(())
    }
    /// Follow the selected tip with the configured window. Eviction stops at a
    /// configured pin/anchor so it stays resolvable. This runs after a committed
    /// block, so it never fails the submission: retaining more headers is safe.
    fn maintain_history_floor(&mut self) {
        let Some(window) = self.history_window else {
            return;
        };
        let target = self.height().saturating_sub(window);
        let target = match self.finality_floor() {
            Some(pinned) => target.min(pinned),
            None => target,
        };
        if target <= self.history_floor {
            return;
        }
        // `target` is clamped to any pin and cannot exceed the tip, so the only
        // possible error is an inconsistent policy; retaining headers is the safe
        // outcome and the block is already committed either way.
        let _ = self.advance_history_floor(target);
    }
    fn normalize_skip_links(&mut self) {
        if self.history_floor == 0 {
            return;
        }
        let floor = self.history_floor;
        let ids: Vec<Hash> = self
            .nodes
            .iter()
            .filter(|(_, node)| node.height >= floor && node.parent.is_some())
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            let height = self.nodes[&id].height;
            let target = (height & (height - 1)).max(floor);
            let skip = if target >= height {
                None
            } else {
                self.branch_ancestor(id, target)
            };
            if let Some(node) = self.nodes.get_mut(&id) {
                node.skip = skip;
            }
        }
    }
    /// Walk parent links only (never stale skip links) to `target`.
    fn branch_ancestor(&self, mut id: Hash, target: u64) -> Option<Hash> {
        let mut steps = 0usize;
        loop {
            let node = self.nodes.get(&id)?;
            if node.height == target {
                return Some(id);
            }
            if node.height < target {
                return None;
            }
            steps += 1;
            if steps > self.nodes.len() + 1 {
                return None;
            }
            id = node.parent?;
        }
    }
    /// Exact canonical-byte commitment derived during full validation.
    pub fn block_summary(&self, id: Hash) -> Option<archive::Summary> {
        self.nodes.get(&id)?.archive
    }
    /// Bounded locator on a fully validated branch, ending at the retained floor.
    pub fn synchronization_locator(&self, from: Hash) -> Result<Vec<Hash>, Error> {
        let mut height = self.nodes.get(&from).ok_or(Error::UnknownParent)?.height;
        let mut out = Vec::new();
        let mut step = 1u64;
        while height > self.history_floor && out.len() < 31 {
            out.push(self.ancestor(from, height)?);
            if out.len() >= 10 {
                step = step.saturating_mul(2);
            }
            height = height.saturating_sub(step);
        }
        out.push(self.ancestor(from, self.history_floor)?);
        Ok(out)
    }
    /// Find the first locator on our best chain; peer heights/work are not trusted.
    pub fn synchronization_inventory(&self, locator: &[Hash]) -> Result<(Hash, Vec<Hash>), Error> {
        let floor = self.history_floor;
        let floor_id = self.ancestor(self.tip, floor)?;
        if locator.is_empty() || locator.len() > 32 || locator.last() != Some(&floor_id) {
            return Err(Error::BlockEncoding);
        }
        for id in locator {
            if let Some(node) = self.nodes.get(id)
                && node.height >= floor
                && node.height <= self.height()
                && self.ancestor(self.tip, node.height)? == *id
            {
                let end = node.height.saturating_add(128).min(self.height());
                let mut ids = Vec::new();
                for offset in 1..=end - node.height {
                    ids.push(self.ancestor(self.tip, node.height + offset)?);
                }
                return Ok((*id, ids));
            }
        }
        Err(Error::UnknownParent)
    }
    /// Metadata for an accepted block, including retained side branches.
    pub fn block_info(&self, id: &Hash) -> Option<BlockInfo> {
        self.nodes.get(id).map(|n| BlockInfo {
            parent: n.parent,
            height: n.height,
            commitment: n.commitment,
            shielded_root: n.shielded_root,
        })
    }
    /// Route from a known cursor to the current best tip. No blocks are submitted.
    pub fn route_to_tip(&self, from: Hash) -> Result<Accepted, Error> {
        if !self.nodes.contains_key(&from) {
            return Err(Error::UnknownParent);
        }
        let (disconnected, connected) = self.route(from, self.tip)?;
        Ok(Accepted {
            id: self.tip,
            became_best: from != self.tip,
            disconnected,
            connected,
        })
    }

    /// Change the local undo-data retention window. This does not change
    /// consensus or history availability; it only bounds how deep a reorg may go.
    pub fn set_retained_block_limit(&mut self, limit: usize) -> Result<(), Error> {
        if limit < 2 {
            return Err(Error::Configuration);
        }
        self.config.retained_blocks = limit;
        self.evict_expired_undo();
        Ok(())
    }

    /// `now` comes from the node's clock, never the peer. FutureTime is transient;
    /// no rejected header or body poisons the accepted-block index.
    pub fn submit(&mut self, block: Block, now: u64) -> Result<Accepted, Error> {
        // Move out the cache so the exclusive chain borrow can stage state.
        let mut pow = std::mem::take(&mut self.pow);
        let result = self.submit_checked(block, now, &mut pow);
        self.pow = pow;
        result
    }

    /// Decode a bounded canonical payload, then use the same full validation path
    /// as typed submission. A decoded block is never accepted on parsing alone.
    pub fn submit_encoded(&mut self, bytes: &[u8], now: u64) -> Result<Accepted, Error> {
        let block = wire::decode(bytes, &self.config.limits, &self.verifier)?;
        self.submit(block, now)
    }

    /// Deliberately private: test substitutes cannot be passed to public submit.
    fn submit_checked<P: PowCheck>(
        &mut self,
        block: Block,
        now: u64,
        pow: &mut P,
    ) -> Result<Accepted, Error> {
        self.submit_recorded(block, now, pow, |_, _, _, _, _| Ok(()))
    }

    /// `record` receives the accepted block, the new selected tip, the node
    /// metadata and the exact active-transaction changes this submission makes.
    /// It runs before any in-memory mutation, so a storage failure is recoverable.
    fn submit_recorded<P: PowCheck>(
        &mut self,
        block: Block,
        now: u64,
        pow: &mut P,
        mut record: impl FnMut(
            &Block,
            Hash,
            Hash,
            &Node,
            &BTreeMap<Hash, Option<(u64, Hash)>>,
        ) -> Result<(), Error>,
    ) -> Result<Accepted, Error> {
        block.header.check_encoding()?;
        self.check_body_limits(&block)?;
        let id = block.header.id(&self.config.chain_id);
        if self.nodes.contains_key(&id) {
            return Err(Error::DuplicateBlock);
        }
        let parent = self
            .nodes
            .get(&block.header.parent)
            .ok_or(Error::UnknownParent)?;
        if parent.height < self.history_floor {
            return Err(Error::HistoryUnavailable);
        }
        let height = parent.height.checked_add(1).ok_or(Error::HeightOverflow)?;
        if height > crate::consensus::MAX_BLOCK_HEIGHT {
            return Err(Error::HeightOverflow);
        }
        let median = self.median_time(block.header.parent);
        if block.header.timestamp <= median {
            return Err(Error::MedianTime);
        }
        if block.header.timestamp > now.saturating_add(u64::from(self.config.max_future_seconds)) {
            return Err(Error::FutureTime);
        }
        let target = if height > 1 && !self.config.asert_from_first_block {
            self.asert
                .validate_bits(block.header.bits, parent.height, parent.timestamp)
                .map_err(Error::Pow)?
        } else {
            let expected = self.next_block_bits(parent)?;
            if block.header.bits != expected {
                return Err(Error::Pow(monario_pow::Error::InvalidParameters));
            }
            Target::from_compact(expected).map_err(Error::Pow)?
        };
        let seed = self.seed_for(block.header.parent, height)?;
        pow.check(
            &seed,
            &block.header.pow_preimage(&self.config.chain_id),
            &target,
        )?;
        let work = &parent.work + target.work();
        let parent_commitment = parent.commitment;
        let first_block_time = if height == 1 {
            block.header.timestamp
        } else {
            parent.first_block_time
        };
        let became_best = work > self.nodes[&self.tip].work;
        if became_best {
            self.check_finality(id, block.header.parent, height)?;
        }
        let (disconnect, connect) = self.route(self.tip, block.header.parent)?;
        let mut staged = Overlay::new(&self.ledger);
        for old in &disconnect {
            staged.apply(
                self.nodes
                    .get(old)
                    .and_then(|n| n.delta.as_ref())
                    .ok_or(Error::ReorgTooDeep)?,
                true,
            )?;
        }
        for new in &connect {
            staged.apply(
                self.nodes
                    .get(new)
                    .and_then(|n| n.delta.as_ref())
                    .ok_or(Error::ReorgTooDeep)?,
                false,
            )?;
        }
        let delta = self.validate_body(&block, height, median, parent_commitment, &staged)?;
        let committed = if became_best {
            staged.apply(&delta, false)?;
            Some(staged.finish())
        } else {
            None
        };
        let shielded_root = delta.shielded.1.root();
        let block_txs: Vec<Hash> = delta.transactions.keys().copied().collect();
        // Skip links stay inside the retained window: clamp the exact power-of-two
        // jump to the header floor and omit it for the floor block itself.
        let skip = {
            let target = (height & (height - 1)).max(self.history_floor);
            if target >= height {
                None
            } else {
                Some(self.ancestor(block.header.parent, target)?)
            }
        };
        let node = Node {
            parent: Some(block.header.parent),
            height,
            timestamp: block.header.timestamp,
            first_block_time,
            commitment: block.header.commitment,
            shielded_root,
            work,
            delta: Some(delta),
            archive: Some(
                archive::summarize(&wire::encode(&block, &self.config.limits, &self.verifier)?)
                    .ok_or(Error::ResourceLimit)?,
            ),
            skip,
        };
        // Active-transaction changes for the durable index. Upsert every tx on the
        // newly connected branch (a reorg can move its height) and delete those the
        // reorg removed.
        let mut tx_changes: BTreeMap<Hash, Option<(u64, Hash)>> = BTreeMap::new();
        if became_best {
            for block_id in &connect {
                let included = &self.nodes[block_id];
                for tx in included
                    .delta
                    .as_ref()
                    .ok_or(Error::ReorgTooDeep)?
                    .transactions
                    .keys()
                {
                    tx_changes.insert(*tx, Some((included.height, *block_id)));
                }
            }
            for tx in &block_txs {
                tx_changes.insert(*tx, Some((height, id)));
            }
            if let Some(net) = &committed {
                for (tx, (_, after)) in &net.transactions {
                    if !*after {
                        tx_changes.insert(*tx, None);
                    }
                }
            }
        }
        // Persist the complete validated event, selected tip and active-tx changes
        // before mutating memory. A crash after this point is recovered by replay.
        record(
            &block,
            id,
            if became_best { id } else { self.tip },
            &node,
            &tx_changes,
        )?;
        // No fallible validation or user callback occurs after this commit point.
        self.nodes.insert(id, node);
        self.undo_index.insert((height, id));
        if let Some(delta) = committed {
            self.ledger.commit(delta);
            // Also update ids whose net membership stayed true across a reorg:
            // reinclusion may move them to another height. All source deltas
            // were validated before record(); no callback/check follows commit.
            for block_id in connect.iter().chain(std::iter::once(&id)) {
                let included = &self.nodes[block_id];
                for tx in included
                    .delta
                    .as_ref()
                    .expect("validated non-root")
                    .transactions
                    .keys()
                {
                    // Locator maintenance cannot create consensus membership.
                    *self
                        .ledger
                        .transactions
                        .get_mut(tx)
                        .expect("committed active transaction") = included.height;
                }
            }
            self.tip = id;
        }
        self.evict_expired_undo();
        self.maintain_history_floor();
        let (disconnected, connected) = if became_best {
            let mut connected = connect;
            connected.push(id);
            (disconnect, connected)
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(Accepted {
            id,
            became_best,
            disconnected,
            connected,
        })
    }

    fn check_body_limits(&self, block: &Block) -> Result<(), Error> {
        wire::block_size(block, &self.config.limits).map(|_| ())
    }

    /// Reject a best-chain transition that would drop a shipped anchor or an
    /// operator pin. Warn-mode pin conflicts are recorded without blocking.
    fn check_finality(&mut self, id: Hash, parent: Hash, height: u64) -> Result<(), Error> {
        let Some(policy) = self.finality else {
            return Ok(());
        };
        if let Some(anchor) = policy.anchor
            && !policy.anchor_bypass
            && height >= anchor.height
            && !self.branch_contains(anchor, id, parent, height)?
        {
            return Err(Error::Finality);
        }
        if let Some(pin) = policy.pin
            && !self.branch_contains(pin, id, parent, height)?
        {
            match policy.mode {
                finality::Mode::Warn => self.finality_warning = true,
                finality::Mode::Refuse => return Err(Error::Finality),
            }
        }
        Ok(())
    }

    fn branch_contains(
        &self,
        pin: finality::Pin,
        id: Hash,
        parent: Hash,
        height: u64,
    ) -> Result<bool, Error> {
        Ok(if pin.height == height {
            id == pin.hash
        } else if pin.height < height {
            self.ancestor(parent, pin.height)? == pin.hash
        } else {
            false
        })
    }
    fn stage_transaction(
        &self,
        raw: &[u8],
        context: TransactionContext<'_>,
        expected_coinbase: bool,
        staged: &mut Overlay<'_>,
        service_records: &mut Vec<(Hash, Vec<u8>)>,
    ) -> Result<StagedTransaction, Error> {
        let TransactionContext {
            height,
            median_time_past: median,
            state: base,
        } = context;
        if raw.is_empty() || raw.len() > self.config.limits.transaction_bytes {
            return Err(Error::ResourceLimit);
        }
        let tx = self
            .verifier
            .verify(
                raw,
                TransactionContext {
                    height,
                    median_time_past: median,
                    state: staged,
                },
            )
            .map_err(Error::Transaction)?;
        if tx.has_shielded_bundle {
            return Err(Error::UnsupportedShielded);
        }
        let coinbase = tx.coinbase_height.is_some();
        if coinbase != expected_coinbase
            || (coinbase && (tx.coinbase_height != Some(height) || !tx.inputs.is_empty()))
        {
            return Err(Error::Coinbase);
        }
        if (tx.outputs.is_empty() || (!coinbase && tx.inputs.is_empty())) && tx.ironwood.is_none() {
            return Err(Error::EmptyTransaction);
        }
        let l = &self.config.limits;
        let shielded_actions = if let Some(shielded) = &tx.ironwood {
            if coinbase {
                return Err(Error::Coinbase);
            }
            let actions =
                u64::try_from(shielded.commitments.len()).map_err(|_| Error::ResourceLimit)?;
            if shielded.nullifiers.len() != shielded.commitments.len()
                || shielded.commitments.is_empty()
                || shielded.commitments.len() > l.outputs_per_transaction
            {
                return Err(Error::ResourceLimit);
            }
            if actions > shielded::MAX_ACTIONS_PER_TRANSACTION
                || shielded::cost(actions) > shielded::MAX_COST_PER_TRANSACTION
            {
                return Err(Error::ShieldedLimit);
            }
            staged.shield(shielded, base)?;
            actions
        } else {
            0
        };
        if tx.inputs.len() > l.inputs_per_transaction
            || tx.outputs.len() > l.outputs_per_transaction
            || tx.outputs.len() > u32::MAX as usize
            || tx.outputs.iter().any(|o| o.script.len() > l.script_bytes)
        {
            return Err(Error::ResourceLimit);
        }
        staged.add_transaction(tx.id)?;
        let mut inputs = Amount::ZERO;
        let mut unique_inputs = BTreeSet::new();
        for input in tx.inputs {
            if !unique_inputs.insert(input) {
                return Err(Error::DoubleSpend);
            }
            let coin = staged.spend(input)?;
            if coin.coinbase
                && height.saturating_sub(coin.created_height) < self.config.coinbase_maturity
            {
                return Err(Error::ImmatureCoinbase);
            }
            inputs = inputs.checked_add(coin.value).map_err(|_| Error::Amount)?;
        }
        let mut outputs = Amount::ZERO;
        for (index, output) in tx.outputs.into_iter().enumerate() {
            let mut service_output = false;
            if let Some(payload) = service::payload(&output.script)? {
                if coinbase
                    || output.value != Amount::ZERO
                    || service_records.len() >= service::MAX_RECORDS
                {
                    return Err(Error::Service);
                }
                service_records.push((tx.id, payload));
                service_output = true;
            }
            outputs = outputs
                .checked_add(output.value)
                .map_err(|_| Error::Amount)?;
            // Zero-valued unspendable service records must not grow the UTXO set.
            if service_output {
                continue;
            }
            staged.create(
                OutPoint {
                    transaction: tx.id,
                    index: index as u32,
                },
                Coin {
                    value: output.value,
                    script: output.script,
                    created_height: height,
                    coinbase,
                },
            )?;
        }
        let fee = if coinbase {
            Amount::ZERO
        } else {
            let vb = tx.ironwood.as_ref().map_or(0, |s| s.value_balance);
            let fee = i128::from(inputs.atoms()) - i128::from(outputs.atoms()) + i128::from(vb);
            Amount::from_atoms(u64::try_from(fee).map_err(|_| Error::NegativeFee)?)
                .map_err(|_| Error::Amount)?
        };
        Ok(StagedTransaction {
            id: tx.id,
            authorization_digest: tx.authorization_digest,
            outputs,
            fee,
            bytes: u32::try_from(raw.len()).map_err(|_| Error::ResourceLimit)?,
            shielded_actions,
        })
    }

    fn validate_body(
        &self,
        block: &Block,
        height: u64,
        median: u64,
        parent_commitment: Hash,
        base: &dyn LedgerView,
    ) -> Result<Delta, Error> {
        let mut staged = Overlay::new(base);
        let mut ids = Vec::with_capacity(block.transactions.len());
        let mut authorizations = Vec::with_capacity(block.transactions.len());
        let mut fees = Amount::ZERO;
        let mut fee_samples = Vec::new();
        let mut coinbase_value = Amount::ZERO;
        let mut service_records = Vec::new();
        let mut shield_actions = 0_u64;
        let mut shield_cost = 0_u64;
        for (position, raw) in block.transactions.iter().enumerate() {
            let tx = self.stage_transaction(
                raw,
                TransactionContext {
                    height,
                    median_time_past: median,
                    state: base,
                },
                position == 0,
                &mut staged,
                &mut service_records,
            )?;
            // Deterministic block-wide shielded work, independent of timing.
            shield_actions = shield_actions
                .checked_add(tx.shielded_actions)
                .ok_or(Error::ShieldedLimit)?;
            shield_cost = shield_cost
                .checked_add(shielded::cost(tx.shielded_actions))
                .ok_or(Error::ShieldedLimit)?;
            if shield_actions > shielded::MAX_ACTIONS_PER_BLOCK
                || shield_cost > shielded::MAX_COST_PER_BLOCK
            {
                return Err(Error::ShieldedLimit);
            }
            if position == 0 {
                coinbase_value = tx.outputs;
            } else {
                fees = fees.checked_add(tx.fee).map_err(|_| Error::Amount)?;
                fee_samples.push(FeeSample {
                    fee_atoms: tx.fee.atoms(),
                    bytes: tx.bytes,
                });
            }
            ids.push(tx.id);
            authorizations.push((tx.id, tx.authorization_digest));
        }
        if merkle_root(&ids)? != block.header.merkle_root {
            return Err(Error::MerkleRoot);
        }
        self.apply_services(
            block.header.parent,
            height,
            base,
            &mut staged,
            &service_records,
        )?;
        let commitment = self
            .verifier
            .block_commitment_with_state(
                parent_commitment,
                height,
                &authorizations,
                staged.shielded().root(),
            )
            .map_err(Error::Transaction)?;
        if commitment != block.header.commitment {
            return Err(Error::Commitment);
        }
        let permitted = subsidy(height)
            .checked_add(fees)
            .map_err(|_| Error::Amount)?;
        if coinbase_value > permitted {
            return Err(Error::OverclaimedReward);
        }
        let supply = if coinbase_value >= fees {
            base.supply().checked_add(
                coinbase_value
                    .checked_sub(fees)
                    .map_err(|_| Error::Amount)?,
            )
        } else {
            base.supply().checked_sub(
                fees.checked_sub(coinbase_value)
                    .map_err(|_| Error::Amount)?,
            )
        }
        .map_err(|_| Error::Amount)?;
        staged.set_supply(supply);
        if staged.shielded().balance > supply {
            return Err(Error::Amount);
        }
        staged.finish_anchor();
        let mut delta = staged.finish();
        delta.fees = fee_samples;
        Ok(delta)
    }

    /// Recent validated fee samples from the active branch only, newest block
    /// first and bounded by both arguments. Never follows an orphan branch.
    pub fn recent_fee_samples(&self, blocks: usize, max_samples: usize) -> Vec<FeeSample> {
        let mut out = Vec::new();
        if blocks == 0 || max_samples == 0 {
            return out;
        }
        let mut cursor = self.tip;
        let mut seen = 0usize;
        while seen < blocks && out.len() < max_samples {
            let Some(node) = self.nodes.get(&cursor) else {
                break;
            };
            if let Some(delta) = &node.delta {
                for sample in delta.fees.iter().rev() {
                    if out.len() >= max_samples {
                        break;
                    }
                    out.push(*sample);
                }
            }
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
            seen += 1;
        }
        out
    }

    fn median_time(&self, mut id: Hash) -> u64 {
        let mut times = Vec::with_capacity(11);
        for _ in 0..consensus::MEDIAN_TIME_BLOCKS {
            let Some(node) = self.nodes.get(&id) else {
                break;
            };
            times.push(node.timestamp);
            if node.height <= self.history_floor {
                break;
            }
            match node.parent {
                Some(parent) => id = parent,
                None => break,
            }
        }
        if times.is_empty() {
            return self.root.timestamp;
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// Canonical ancestor at `height` on the path from `id`. Fails with
    /// `HistoryUnavailable` below the retained floor. Read-only; submits nothing.
    pub fn ancestor(&self, id: Hash, height: u64) -> Result<Hash, Error> {
        if height < self.history_floor {
            return Err(Error::HistoryUnavailable);
        }
        let mut current = id;
        let mut node = self.nodes.get(&current).ok_or(Error::HistoryUnavailable)?;
        if node.height < height {
            return Err(Error::StateMismatch);
        }
        let mut steps = 0usize;
        while node.height > height {
            steps += 1;
            if steps > self.nodes.len() + 1 {
                return Err(Error::StateMismatch);
            }
            let skip = node.skip.and_then(|skip_id| {
                self.nodes
                    .get(&skip_id)
                    .filter(|skip| skip.height >= height && skip.height < node.height)
                    .map(|_| skip_id)
            });
            let next_id = match skip {
                Some(skip_id) => skip_id,
                None => node.parent.ok_or(Error::StateMismatch)?,
            };
            let next = self.nodes.get(&next_id).ok_or(Error::HistoryUnavailable)?;
            if next.height >= node.height {
                return Err(Error::StateMismatch);
            }
            current = next_id;
            node = next;
        }
        Ok(current)
    }
    fn seed_for(&self, parent: Hash, height: u64) -> Result<Hash, Error> {
        let seed_height =
            monario_pow::seed_height(height, self.config.seed_interval, self.config.seed_lag)
                .map_err(Error::Pow)?;
        let ancestor = self.ancestor(parent, seed_height)?;
        Ok(hash_domain(
            b"Monario/randomx-seed/v1\0",
            &[&self.config.chain_id, &self.root.id, &ancestor],
        ))
    }
    fn route(&self, mut old: Hash, mut new: Hash) -> Result<(Vec<Hash>, Vec<Hash>), Error> {
        let mut detach = Vec::new();
        let mut attach = Vec::new();
        let mut steps = 0usize;
        while old != new {
            steps += 1;
            if steps > self.nodes.len() + 1 {
                return Err(Error::StateMismatch);
            }
            let old_node = self.nodes.get(&old).ok_or(Error::HistoryUnavailable)?;
            let new_node = self.nodes.get(&new).ok_or(Error::HistoryUnavailable)?;
            if old_node.height >= new_node.height {
                detach.push(old);
                old = old_node.parent.ok_or(Error::StateMismatch)?;
            } else {
                attach.push(new);
                new = new_node.parent.ok_or(Error::StateMismatch)?;
            }
        }
        attach.reverse();
        Ok((detach, attach))
    }
}

#[cfg(test)]
mod tests;

//! Offline wallet scanning and signed/private construction for a validated chain.
//! Scanner retains no signing keys; construction explicitly borrows an unlocked wallet.
//! Authenticated caches resume scans and retained reorgs; deeper reorgs replay history.
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use monario_chain::{
    Block, BlockInfo, Hash,
    header::merkle_root,
    ledger::{Coin, OutPoint},
    storage::DurableChain,
    transactions::TransactionVerifier,
};
use monario_monetary::Amount;
use monario_v6::V6Verifier;
use monario_wallet::{Network, Scope, Seed, storage::AccountProgress};
use orchard::{
    keys::FullViewingKey,
    tree::{MerkleHashOrchard, MerklePath},
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;
use zeroize::Zeroizing;

pub mod build;
mod cache;
pub mod page;
pub mod pending;
mod private_cache;
mod rollback;
#[cfg(test)]
mod restore_metrics {
    use std::cell::RefCell;
    #[derive(Default, Clone, Copy, Debug)]
    pub(super) struct Counts {
        pub encodes: usize,
        pub hashes: usize,
        pub states: usize,
        pub witnesses: usize,
        pub private_identities: usize,
        pub private_roots: usize,
        pub identity_reuses: usize,
        pub witness_reuses: usize,
        pub private_frontiers: usize,
        pub frontier_reuses: usize,
        pub stop_after_state: Option<usize>,
        pub stop_after_private_reuse: bool,
    }
    thread_local! { pub(super) static COUNTERS:RefCell<Counts>=RefCell::new(Counts::default()); }
}

#[cfg(test)]
mod tests;

/// Operational failures never change consensus or silently drop wallet entries.
#[derive(Debug)]
pub enum Error {
    Configuration,
    Capacity,
    Chain(monario_chain::storage::StorageError),
    InvalidBody,
    WrongChain,
    NotSynced,
    /// The source node no longer retains the header history needed to resume or
    /// rescan this wallet. Rescan against a source that retains it.
    SourceHistory,
    /// A page transport failed, was malformed or exceeded its bound. No partial
    /// page is accepted.
    Transport,
    UnknownNote,
    Amount,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wallet scan: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<monario_chain::storage::StorageError> for Error {
    fn from(e: monario_chain::storage::StorageError) -> Self {
        Self::Chain(e)
    }
}

/// A source opened with a bounded header window can only resume a cursor that is
/// still retained. Anything older needs a fresh scan against a full source.
fn require_retained(cursor: u64, floor: u64) -> Result<(), Error> {
    if cursor < floor {
        Err(Error::SourceHistory)
    } else {
        Ok(())
    }
}

/// Finite transparent discovery window and private full viewing key. No signing key.
/// Treat this object as sensitive: full viewing keys reveal private wallet activity.
pub struct WatchAccount {
    id: u32,
    network: Network,
    viewing: FullViewingKey,
    scripts: BTreeMap<Vec<u8>, (Scope, u32)>,
}
impl WatchAccount {
    /// Watch [0, count) in each transparent scope and ALL private diversifiers.
    /// Counts are explicit recovery inputs, not evidence that no other account or
    /// unused issued address exists. At most 10,000 transparent addresses per scope.
    pub fn from_seed(
        seed: &Seed,
        network: Network,
        id: u32,
        external: u32,
        internal: u32,
    ) -> Result<Self, Error> {
        if external > 10_000 || internal > 10_000 {
            return Err(Error::Capacity);
        }
        let account = seed
            .private_account(network, id)
            .map_err(|_| Error::Configuration)?;
        let viewing = FullViewingKey::from(account.expose_spending_key());
        let mut scripts = BTreeMap::new();
        for (scope, count) in [(Scope::External, external), (Scope::Internal, internal)] {
            for index in 0..count {
                let key = seed
                    .transparent_key(network, id, scope, index)
                    .map_err(|_| Error::Configuration)?;
                let script = key.address().script_pubkey().ok_or(Error::Configuration)?;
                if scripts.insert(script, (scope, index)).is_some() {
                    return Err(Error::Configuration);
                }
            }
        }
        Ok(Self {
            id,
            network,
            viewing,
            scripts,
        })
    }
}
impl std::fmt::Debug for WatchAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WatchAccount([REDACTED])")
    }
}

/// Local capacity limits; exhaustion returns an error with no partial scan commit.
#[derive(Clone, Copy)]
pub struct Limits {
    pub accounts: usize,
    pub transparent_addresses: usize,
    pub unspent_coins: usize,
    pub unspent_notes: usize,
}

/// Snapshot amounts, denominated in exact atoms through `Amount`.
#[derive(Debug, PartialEq, Eq)]
pub struct Balance {
    /// Transparent outputs spendable in the next block; excludes immature coinbase.
    pub transparent: Amount,
    pub immature_coinbase: Amount,
    pub private: Amount,
}

/// An owned private note and its current authentication witness. Debug is redacted.
#[derive(Clone)]
pub struct ReceivedNote {
    account: u32,
    scope: Scope,
    index: u128,
    note: orchard::Note,
    memo: Zeroizing<[u8; 512]>,
    witness: IncrementalWitness<MerkleHashOrchard, 32>,
}
impl ReceivedNote {
    pub fn account(&self) -> u32 {
        self.account
    }
    pub fn scope(&self) -> Scope {
        self.scope
    }
    pub fn address_index(&self) -> u128 {
        self.index
    }
    /// Explicit sensitive note export for transaction construction.
    pub fn expose_note(&self) -> &orchard::Note {
        &self.note
    }
    /// Memo bytes are untrusted data. Render as text only after application validation.
    pub fn expose_memo(&self) -> &[u8; 512] {
        &self.memo
    }
}
impl std::fmt::Debug for ReceivedNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceivedNote([REDACTED])")
    }
}

#[derive(Clone)]
struct State {
    tip: Hash,
    height: u64,
    tree: CommitmentTree<MerkleHashOrchard, 32>,
    coins: BTreeMap<OutPoint, (u32, Coin)>,
    notes: BTreeMap<Hash, ReceivedNote>,
    observed: BTreeMap<u32, AccountProgress>,
}
impl State {
    fn empty(root: Hash) -> Self {
        Self {
            tip: root,
            height: 0,
            tree: CommitmentTree::empty(),
            coins: BTreeMap::new(),
            notes: BTreeMap::new(),
            observed: BTreeMap::new(),
        }
    }
}

/// Batch completion is explicit: partial scans never authorize balances or witnesses.
#[derive(Debug, PartialEq, Eq)]
pub struct Progress {
    pub tip: Hash,
    pub height: u64,
    pub complete: bool,
    /// A reorg triggered replay from the root, including when deeper than any cache.
    pub restarted: bool,
    /// Number of orphaned blocks reversed using retained authenticated state.
    pub rolled_back: usize,
}

/// Bounded derived state, optionally restored from a wallet-authenticated cache.
/// Existing scanners cannot add accounts/windows: recreate and rescan instead.
pub struct Scanner {
    profile: Hash,
    root: Hash,
    accounts: Vec<WatchAccount>,
    scripts: BTreeMap<Vec<u8>, (u32, Scope, u32)>,
    limits: Limits,
    state: State,
    history: VecDeque<(Hash, Zeroizing<Vec<u8>>)>,
    cache_migrated: bool,
}
impl Scanner {
    /// Bind to a real v6 chain instance; no accepting mock backend is supported.
    pub fn new(
        source: &DurableChain<V6Verifier>,
        network: Network,
        accounts: Vec<WatchAccount>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.accounts == 0
            || limits.accounts > 128
            || limits.transparent_addresses == 0
            || limits.unspent_coins == 0
            || limits.unspent_notes == 0
            || accounts.is_empty()
            || accounts.len() > limits.accounts
        {
            return Err(Error::Configuration);
        }
        let mut ids = BTreeSet::new();
        let mut scripts = BTreeMap::new();
        for (position, a) in accounts.iter().enumerate() {
            if a.network != network || !ids.insert(a.id) {
                return Err(Error::Configuration);
            }
            // Serialized viewing keys are sensitive temporary buffers, not loggable IDs.
            let bytes = Zeroizing::new(a.viewing.to_bytes());
            for other in &accounts[..position] {
                let other = Zeroizing::new(other.viewing.to_bytes());
                if *other == *bytes {
                    return Err(Error::Configuration);
                }
            }
            for (script, (scope, index)) in &a.scripts {
                if scripts.len() >= limits.transparent_addresses {
                    return Err(Error::Capacity);
                }
                if scripts
                    .insert(script.clone(), (a.id, *scope, *index))
                    .is_some()
                {
                    return Err(Error::Configuration);
                }
            }
        }
        let root = source.chain()?.root_id();
        Ok(Self {
            profile: source.profile_id()?,
            root,
            accounts,
            scripts,
            limits,
            state: State::empty(root),
            history: VecDeque::new(),
            cache_migrated: false,
        })
    }
    fn check_source(&self, source: &DurableChain<V6Verifier>) -> Result<(), Error> {
        if source.profile_id()? != self.profile {
            return Err(Error::WrongChain);
        }
        Ok(())
    }
    fn current(&self, source: &DurableChain<V6Verifier>) -> Result<(), Error> {
        self.check_source(source)?;
        if self.state.tip != source.chain()?.tip() {
            return Err(Error::NotSynced);
        }
        Ok(())
    }
    /// At most `blocks` bodies per call. The complete batch commits atomically.
    /// Reorgs restore a retained ancestor and scan only the replacement branch.
    /// Outside retained history, replay from the root. No undo-depth finality.
    pub fn sync(
        &mut self,
        source: &DurableChain<V6Verifier>,
        blocks: usize,
    ) -> Result<Progress, Error> {
        self.check_source(source)?;
        if blocks == 0 {
            return Err(Error::Configuration);
        }
        let chain = source.chain()?;
        // A bounded-history source cannot resync a wallet whose cursor fell below
        // its retained window: the effects before that point are unavailable. Fail
        // closed instead of reporting a stale projection as current.
        require_retained(self.state.height, source.history_floor()?)?;
        let route = chain.route_to_tip(self.state.tip).map_err(|e| match e {
            monario_chain::Error::HistoryUnavailable => Error::SourceHistory,
            _ => Error::WrongChain,
        })?;
        let mut history = self.history.clone();
        let mut staged = self.state.clone();
        let mut restarted = false;
        let mut rolled_back = 0;
        if let Some(last) = route.disconnected.last() {
            let ancestor = source
                .block_info(last)
                .map_err(Error::Chain)?
                .and_then(|b| b.parent)
                .ok_or(Error::WrongChain)?;
            if let Some(index) = history.iter().position(|(id, _)| *id == ancestor) {
                let mut child = self.capture_rollback(&staged)?.ok_or(Error::Capacity)?;
                let mut checks = private_cache::PrivateChecks::default();
                for (_, encoded) in history.iter().skip(index).rev() {
                    let (parent, prepared) =
                        self.apply_prepared_delta_checked(source, &child, encoded, &mut checks)?;
                    staged = parent;
                    child = prepared;
                }
                history.truncate(index);
                rolled_back = route.disconnected.len();
            } else {
                staged = State::empty(self.root);
                history.clear();
                restarted = true;
            }
        }
        require_retained(staged.height, source.history_floor()?)?;
        let route = chain.route_to_tip(staged.tip).map_err(|e| match e {
            monario_chain::Error::HistoryUnavailable => Error::SourceHistory,
            _ => Error::WrongChain,
        })?;
        for id in route.connected.into_iter().take(blocks) {
            let info = source
                .block_info(&id)
                .map_err(Error::Chain)?
                .ok_or(Error::InvalidBody)?;
            let parent = source
                .block_info(&info.parent.ok_or(Error::InvalidBody)?)
                .map_err(Error::Chain)?
                .ok_or(Error::InvalidBody)?;
            let block = source.stored_block(id)?;
            let before = self.capture_rollback(&staged)?;
            self.scan_block(&mut staged, &block, id, info, parent.commitment)?;
            self.remember_prepared(&mut history, before, &staged)?;
        }
        self.trim_history(&mut history, &staged)?;
        let progress = Progress {
            tip: staged.tip,
            height: staged.height,
            complete: staged.tip == chain.tip(),
            restarted,
            rolled_back,
        };
        self.state = staged;
        self.history = history;
        Ok(progress)
    }
    /// Reject a stale/partial projection rather than return a misleading current balance.
    pub fn balance(
        &self,
        source: &DurableChain<V6Verifier>,
        account: u32,
    ) -> Result<Balance, Error> {
        self.current(source)?;
        if !self.accounts.iter().any(|a| a.id == account) {
            return Err(Error::Configuration);
        }
        let mut b = Balance {
            transparent: Amount::ZERO,
            immature_coinbase: Amount::ZERO,
            private: Amount::ZERO,
        };
        let next = self.state.height.checked_add(1).ok_or(Error::Amount)?;
        let maturity = source.coinbase_maturity()?;
        for (_, coin) in self.state.coins.values().filter(|(id, _)| *id == account) {
            let target = if coin.coinbase
                && next.checked_sub(coin.created_height).ok_or(Error::Amount)? < maturity
            {
                &mut b.immature_coinbase
            } else {
                &mut b.transparent
            };
            *target = target.checked_add(coin.value).map_err(|_| Error::Amount)?;
        }
        for n in self.state.notes.values().filter(|n| n.account == account) {
            b.private = b
                .private
                .checked_add(Amount::from_atoms(n.note.value().inner()).map_err(|_| Error::Amount)?)
                .map_err(|_| Error::Amount)?;
        }
        Ok(b)
    }
    /// Explicit note access only when the projection matches the validated best tip.
    pub fn unspent_notes(
        &self,
        source: &DurableChain<V6Verifier>,
    ) -> Result<&BTreeMap<Hash, ReceivedNote>, Error> {
        self.current(source)?;
        Ok(&self.state.notes)
    }
    /// Existing P2PKH watched outputs, including immature outputs. Check maturity before spending.
    pub fn unspent_coins(
        &self,
        source: &DurableChain<V6Verifier>,
    ) -> Result<&BTreeMap<OutPoint, (u32, Coin)>, Error> {
        self.current(source)?;
        Ok(&self.state.coins)
    }
    /// Validated-chain payment observations only. These are LOWER BOUNDS, never
    /// a complete recovery/issuance plan: unused issued addresses leave no chain trace.
    pub fn observed_progress(
        &self,
        source: &DurableChain<V6Verifier>,
    ) -> Result<&BTreeMap<u32, AccountProgress>, Error> {
        self.current(source)?;
        Ok(&self.state.observed)
    }
    /// Export a current, root-checked path for an unspent note; stale paths fail closed.
    pub fn witness(
        &self,
        source: &DurableChain<V6Verifier>,
        nullifier: Hash,
    ) -> Result<MerklePath, Error> {
        self.current(source)?;
        let received = self.state.notes.get(&nullifier).ok_or(Error::UnknownNote)?;
        let path = received.witness.path().ok_or(Error::InvalidBody)?;
        let position = u32::try_from(u64::from(path.position())).map_err(|_| Error::InvalidBody)?;
        let auth = path
            .path_elems()
            .try_into()
            .map_err(|_| Error::InvalidBody)?;
        let path = MerklePath::from_parts(position, auth);
        if path.root(received.note.commitment().into()).to_bytes()
            != source.chain()?.ledger().shielded().root()
        {
            return Err(Error::InvalidBody);
        }
        Ok(path)
    }

    fn scan_block(
        &self,
        state: &mut State,
        block: &Block,
        id: Hash,
        info: BlockInfo,
        parent_commitment: Hash,
    ) -> Result<(), Error> {
        if info.parent != Some(state.tip)
            || info.height != state.height.checked_add(1).ok_or(Error::InvalidBody)?
            || block.header.parent != state.tip
            || block.header.commitment != info.commitment
        {
            return Err(Error::InvalidBody);
        }
        let mut ids = Vec::with_capacity(block.transactions.len());
        for raw in &block.transactions {
            if V6Verifier
                .transaction_length(raw)
                .map_err(|_| Error::InvalidBody)?
                != raw.len()
            {
                return Err(Error::InvalidBody);
            }
            let mut bytes = raw.as_slice();
            let tx =
                Transaction::read(&mut bytes, BranchId::Nu6_3).map_err(|_| Error::InvalidBody)?;
            if !bytes.is_empty()
                || tx.version() != TxVersion::V6
                || u32::from(tx.consensus_branch_id()) != monario_v6::BRANCH_ID
                || tx.sapling_bundle().is_some()
                || tx.orchard_bundle().is_some()
            {
                return Err(Error::InvalidBody);
            }
            let mut canonical = Vec::new();
            tx.write(&mut canonical).map_err(|_| Error::InvalidBody)?;
            if canonical != *raw {
                return Err(Error::InvalidBody);
            }
            let txid = *tx.txid().as_ref();
            ids.push((
                txid,
                tx.auth_commitment()
                    .as_bytes()
                    .try_into()
                    .map_err(|_| Error::InvalidBody)?,
            ));
            if let Some(bundle) = tx.transparent_bundle() {
                for input in &bundle.vin {
                    state.coins.remove(&OutPoint {
                        transaction: *input.prevout().hash(),
                        index: input.prevout().n(),
                    });
                }
                for (index, output) in bundle.vout.iter().enumerate() {
                    let script = &output.script_pubkey().0.0;
                    if let Some((account, scope, address_index)) = self.scripts.get(script) {
                        if state.coins.len() >= self.limits.unspent_coins {
                            return Err(Error::Capacity);
                        }
                        let coinbase = bundle.vin.len() == 1
                            && *bundle.vin[0].prevout().hash() == [0; 32]
                            && bundle.vin[0].prevout().n() == u32::MAX;
                        let coin = Coin {
                            value: Amount::from_atoms(output.value().into_u64())
                                .map_err(|_| Error::Amount)?,
                            script: script.clone(),
                            created_height: info.height,
                            coinbase,
                        };
                        let outpoint = OutPoint {
                            transaction: txid,
                            index: u32::try_from(index).map_err(|_| Error::InvalidBody)?,
                        };
                        if state.coins.insert(outpoint, (*account, coin)).is_some() {
                            return Err(Error::InvalidBody);
                        }
                        observe(state, *account, *scope, u128::from(*address_index), false)?;
                    }
                }
            }
            if let Some(bundle) = tx.ironwood_bundle() {
                // Remove spent notes before updating witnesses; their witnesses are no longer useful.
                for action in bundle.actions() {
                    state.notes.remove(&action.nullifier().to_bytes());
                }
                for (action_index, action) in bundle.actions().iter().enumerate() {
                    let leaf = MerkleHashOrchard::from_cmx(action.cmx());
                    for note in state.notes.values_mut() {
                        note.witness.append(leaf).map_err(|_| Error::InvalidBody)?;
                    }
                    state.tree.append(leaf).map_err(|_| Error::InvalidBody)?;
                    let mut found = false;
                    for account in &self.accounts {
                        for (scope, upstream) in [
                            (Scope::External, orchard::keys::Scope::External),
                            (Scope::Internal, orchard::keys::Scope::Internal),
                        ] {
                            let ivk = account.viewing.to_ivk(upstream);
                            if let Some((note, _, memo)) =
                                bundle.decrypt_output_with_key(action_index, &ivk)
                            {
                                if found {
                                    return Err(Error::Configuration);
                                }
                                found = true;
                                // Zero-valued padding outputs are not spendable wallet funds.
                                if note.value().inner() == 0 {
                                    continue;
                                }
                                if state.notes.len() >= self.limits.unspent_notes {
                                    return Err(Error::Capacity);
                                }
                                let index = ivk
                                    .diversifier_index(&note.recipient())
                                    .ok_or(Error::InvalidBody)?;
                                let index = u128::from(index);
                                let nf = note.nullifier(&account.viewing).to_bytes();
                                let witness = IncrementalWitness::from_tree(state.tree.clone())
                                    .ok_or(Error::InvalidBody)?;
                                if state
                                    .notes
                                    .insert(
                                        nf,
                                        ReceivedNote {
                                            account: account.id,
                                            scope,
                                            index,
                                            note,
                                            memo: Zeroizing::new(memo),
                                            witness,
                                        },
                                    )
                                    .is_some()
                                {
                                    return Err(Error::InvalidBody);
                                }
                                observe(state, account.id, scope, index, true)?;
                            }
                        }
                    }
                }
            }
        }
        let root = state.tree.root().to_bytes();
        let commitment = V6Verifier
            .block_commitment_with_state(parent_commitment, info.height, &ids, root)
            .map_err(|_| Error::InvalidBody)?;
        let txids = ids.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        if root != info.shielded_root
            || commitment != info.commitment
            || merkle_root(&txids).map_err(|_| Error::InvalidBody)? != block.header.merkle_root
        {
            return Err(Error::InvalidBody);
        }
        state.tip = id;
        state.height = info.height;
        Ok(())
    }
}
fn observe(
    state: &mut State,
    account: u32,
    scope: Scope,
    index: u128,
    private: bool,
) -> Result<(), Error> {
    let p = state.observed.entry(account).or_default();
    let count = index.checked_add(1).ok_or(Error::Amount)?;
    match (private, scope) {
        (true, Scope::External) => p.private_external = p.private_external.max(count),
        (true, Scope::Internal) => p.private_internal = p.private_internal.max(count),
        (false, Scope::External) => {
            p.transparent_external = p
                .transparent_external
                .max(u64::try_from(count).map_err(|_| Error::Amount)?)
        }
        (false, Scope::Internal) => {
            p.transparent_internal = p
                .transparent_internal
                .max(u64::try_from(count).map_err(|_| Error::Amount)?)
        }
    }
    Ok(())
}

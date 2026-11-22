//! Transactional UTXO overlay and reversible deltas. No full-ledger clones.
use crate::{Error, Hash};
use incrementalmerkletree::frontier::Frontier;
use monario_monetary::{Amount, Supply};
use orchard::tree::MerkleHashOrchard;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct ShieldedTree {
    pub frontier: Frontier<MerkleHashOrchard, 32>,
    pub balance: Supply,
}
impl Default for ShieldedTree {
    fn default() -> Self {
        Self {
            frontier: Frontier::empty(),
            balance: Supply::ZERO,
        }
    }
}
impl ShieldedTree {
    pub fn root(&self) -> Hash {
        self.frontier.root().to_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutPoint {
    pub transaction: Hash,
    pub index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub value: Amount,
    pub script: Vec<u8>,
    pub created_height: u64,
    pub coinbase: bool,
}

/// Read-only branch state exposed to the required signature/script verifier.
pub trait LedgerView {
    fn service_entry(&self, _id: &Hash) -> Option<&crate::service::Entry> {
        None
    }
    fn service_collateral(&self, _p: &OutPoint) -> Option<Hash> {
        None
    }
    fn service_operator(&self, _p: &[u8; 33]) -> Option<Hash> {
        None
    }
    fn service_count(&self) -> usize {
        0
    }
    fn service_due(&self, _height: u64) -> Vec<Hash> {
        Vec::new()
    }
    fn service_slots(&self) -> Vec<u32> {
        vec![0; crate::service::PERIOD_BLOCKS as usize]
    }
    fn shielded(&self) -> &ShieldedTree;
    fn has_nullifier(&self, nf: &Hash) -> bool;
    fn has_anchor(&self, anchor: &Hash) -> bool;
    fn coin(&self, outpoint: &OutPoint) -> Option<&Coin>;
    fn contains_transaction(&self, id: &Hash) -> bool;
    fn supply(&self) -> Supply;
}

#[derive(Default)]
pub(crate) struct Ledger {
    pub(super) services: BTreeMap<Hash, crate::service::Entry>,
    service_collaterals: BTreeMap<OutPoint, Hash>,
    service_operators: BTreeMap<[u8; 33], Hash>,
    service_deadlines: BTreeSet<(u64, Hash)>,
    service_slot_counts: BTreeMap<u16, u32>,
    pub(super) shielded: ShieldedTree,
    pub(super) nullifiers: BTreeSet<Hash>,
    pub(super) anchors: BTreeSet<Hash>,
    pub(super) coins: BTreeMap<OutPoint, Coin>,
    // Membership remains authoritative; the value is an engine-derived inclusion
    // height. Zero is private staging/restore state, never a published locator.
    pub(super) transactions: BTreeMap<Hash, u64>,
    pub(super) supply: Supply,
}
impl LedgerView for Ledger {
    fn service_entry(&self, id: &Hash) -> Option<&crate::service::Entry> {
        self.services.get(id)
    }
    fn service_collateral(&self, p: &OutPoint) -> Option<Hash> {
        self.service_collaterals.get(p).copied()
    }
    fn service_operator(&self, p: &[u8; 33]) -> Option<Hash> {
        self.service_operators.get(p).copied()
    }
    fn service_count(&self) -> usize {
        self.services.len()
    }
    fn service_due(&self, height: u64) -> Vec<Hash> {
        self.service_deadlines
            .range(..(height, [0; 32]))
            .map(|(_, id)| *id)
            .collect()
    }
    fn service_slots(&self) -> Vec<u32> {
        (0..crate::service::PERIOD_BLOCKS)
            .map(|s| {
                self.service_slot_counts
                    .get(&(s as u16))
                    .copied()
                    .unwrap_or(0)
            })
            .collect()
    }
    fn shielded(&self) -> &ShieldedTree {
        &self.shielded
    }
    fn has_nullifier(&self, nf: &Hash) -> bool {
        self.nullifiers.contains(nf)
    }
    fn has_anchor(&self, anchor: &Hash) -> bool {
        self.anchors.contains(anchor) || *anchor == ShieldedTree::default().root()
    }
    fn coin(&self, outpoint: &OutPoint) -> Option<&Coin> {
        self.coins.get(outpoint)
    }
    fn contains_transaction(&self, id: &Hash) -> bool {
        self.transactions.contains_key(id)
    }
    fn supply(&self) -> Supply {
        self.supply
    }
}

/// Net changes for one block; a created-and-spent output leaves no UTXO change.
#[derive(Clone, Debug)]
pub(crate) struct Delta {
    pub(super) services:
        BTreeMap<Hash, (Option<crate::service::Entry>, Option<crate::service::Entry>)>,
    pub(super) shielded: (ShieldedTree, ShieldedTree),
    pub(super) nullifiers: BTreeMap<Hash, (bool, bool)>,
    pub(super) anchors: BTreeMap<Hash, (bool, bool)>,
    pub(super) coins: BTreeMap<OutPoint, (Option<Coin>, Option<Coin>)>,
    pub(super) transactions: BTreeMap<Hash, (bool, bool)>,
    pub(super) supply: (Supply, Supply),
    /// Public fee metadata for estimation; it does not affect ledger application.
    pub(super) fees: Vec<crate::FeeSample>,
}
impl Ledger {
    pub(crate) fn service_slot_load(&self, slot: u16) -> u32 {
        self.service_slot_counts.get(&slot).copied().unwrap_or(0)
    }
    pub(crate) fn set_service(&mut self, id: Hash, value: Option<crate::service::Entry>) {
        if let Some(old) = self.services.remove(&id) {
            self.service_collaterals.remove(&old.collateral);
            self.service_operators.remove(&old.operator);
            if let Some(d) = old.deadline() {
                self.service_deadlines.remove(&(d, id));
            }
            *self.service_slot_counts.entry(old.slot).or_default() -= 1;
        }
        if let Some(e) = value {
            self.service_collaterals.insert(e.collateral, id);
            self.service_operators.insert(e.operator, id);
            if let Some(d) = e.deadline() {
                self.service_deadlines.insert((d, id));
            }
            *self.service_slot_counts.entry(e.slot).or_default() += 1;
            self.services.insert(id, e);
        }
    }
    /// Called only after every check succeeds, under exclusive chain access.
    pub(crate) fn commit(&mut self, delta: Delta) {
        // Remove all old indexes first: a block may replace an operator/collateral
        // identity, and hash-sorted delta iteration is not transaction ordering.
        for id in delta.services.keys() {
            self.set_service(*id, None);
        }
        for (id, (_, after)) in delta.services {
            self.set_service(id, after);
        }
        self.shielded = delta.shielded.1;
        for (k, (_, value)) in delta.nullifiers {
            if value {
                self.nullifiers.insert(k);
            } else {
                self.nullifiers.remove(&k);
            }
        }
        for (k, (_, value)) in delta.anchors {
            if value {
                self.anchors.insert(k);
            } else {
                self.anchors.remove(&k);
            }
        }
        for (key, (_, after)) in delta.coins {
            match after {
                Some(coin) => {
                    self.coins.insert(key, coin);
                }
                None => {
                    self.coins.remove(&key);
                }
            }
        }
        for (id, (_, after)) in delta.transactions {
            if after {
                self.transactions.insert(id, 0);
            } else {
                self.transactions.remove(&id);
            }
        }
        self.supply = delta.supply.1;
    }
}

#[derive(Default)]
pub(crate) struct OverlayState {
    services: BTreeMap<Hash, Option<crate::service::Entry>>,
    shielded: ShieldedTree,
    nullifiers: BTreeMap<Hash, bool>,
    anchors: BTreeMap<Hash, bool>,
    coins: BTreeMap<OutPoint, Option<Coin>>,
    transactions: BTreeMap<Hash, bool>,
    supply: Supply,
}

pub(crate) struct Overlay<'a> {
    services: BTreeMap<Hash, Option<crate::service::Entry>>,
    shielded: ShieldedTree,
    nullifiers: BTreeMap<Hash, bool>,
    anchors: BTreeMap<Hash, bool>,
    base: &'a dyn LedgerView,
    coins: BTreeMap<OutPoint, Option<Coin>>,
    transactions: BTreeMap<Hash, bool>,
    supply: Supply,
}
impl LedgerView for Overlay<'_> {
    fn service_entry(&self, id: &Hash) -> Option<&crate::service::Entry> {
        match self.services.get(id) {
            Some(v) => v.as_ref(),
            None => self.base.service_entry(id),
        }
    }
    fn service_collateral(&self, p: &OutPoint) -> Option<Hash> {
        self.services
            .iter()
            .find_map(|(id, e)| e.as_ref().filter(|e| e.collateral == *p).map(|_| *id))
            .or_else(|| {
                self.base
                    .service_collateral(p)
                    .filter(|id| self.service_entry(id).is_some_and(|e| e.collateral == *p))
            })
    }
    fn service_operator(&self, p: &[u8; 33]) -> Option<Hash> {
        self.services
            .iter()
            .find_map(|(id, e)| e.as_ref().filter(|e| e.operator == *p).map(|_| *id))
            .or_else(|| {
                self.base
                    .service_operator(p)
                    .filter(|id| self.service_entry(id).is_some_and(|e| e.operator == *p))
            })
    }
    fn service_count(&self) -> usize {
        let mut n = self.base.service_count();
        for (id, e) in &self.services {
            match (self.base.service_entry(id).is_some(), e.is_some()) {
                (true, false) => n -= 1,
                (false, true) => n += 1,
                _ => {}
            }
        }
        n
    }
    fn service_due(&self, height: u64) -> Vec<Hash> {
        let mut due: BTreeSet<_> = self
            .base
            .service_due(height)
            .into_iter()
            .filter(|id| {
                self.service_entry(id)
                    .and_then(|e| e.deadline())
                    .is_some_and(|d| d < height)
            })
            .collect();
        for (id, e) in &self.services {
            if e.as_ref()
                .and_then(|e| e.deadline())
                .is_some_and(|d| d < height)
            {
                due.insert(*id);
            }
        }
        due.into_iter().collect()
    }
    fn service_slots(&self) -> Vec<u32> {
        let mut slots = self.base.service_slots();
        for (id, after) in &self.services {
            if let Some(before) = self.base.service_entry(id) {
                slots[before.slot as usize] -= 1;
            }
            if let Some(after) = after {
                slots[after.slot as usize] += 1;
            }
        }
        slots
    }
    fn shielded(&self) -> &ShieldedTree {
        &self.shielded
    }
    fn has_nullifier(&self, nf: &Hash) -> bool {
        self.nullifiers
            .get(nf)
            .copied()
            .unwrap_or_else(|| self.base.has_nullifier(nf))
    }
    fn has_anchor(&self, anchor: &Hash) -> bool {
        self.anchors
            .get(anchor)
            .copied()
            .unwrap_or_else(|| self.base.has_anchor(anchor))
    }
    fn coin(&self, outpoint: &OutPoint) -> Option<&Coin> {
        match self.coins.get(outpoint) {
            Some(coin) => coin.as_ref(),
            None => self.base.coin(outpoint),
        }
    }
    fn contains_transaction(&self, id: &Hash) -> bool {
        self.transactions
            .get(id)
            .copied()
            .unwrap_or_else(|| self.base.contains_transaction(id))
    }
    fn supply(&self) -> Supply {
        self.supply
    }
}
impl<'a> Overlay<'a> {
    pub(crate) fn from_state(base: &'a dyn LedgerView, state: OverlayState) -> Self {
        let OverlayState {
            services,
            shielded,
            nullifiers,
            anchors,
            coins,
            transactions,
            supply,
        } = state;
        Self {
            base,
            services,
            shielded,
            nullifiers,
            anchors,
            coins,
            transactions,
            supply,
        }
    }
    pub(crate) fn into_state(self) -> OverlayState {
        OverlayState {
            services: self.services,
            shielded: self.shielded,
            nullifiers: self.nullifiers,
            anchors: self.anchors,
            coins: self.coins,
            transactions: self.transactions,
            supply: self.supply,
        }
    }
    pub(crate) fn service_changes(&self) -> Vec<Hash> {
        self.services.keys().copied().collect()
    }
    pub(crate) fn new(base: &'a dyn LedgerView) -> Self {
        Self {
            services: BTreeMap::new(),
            shielded: base.shielded().clone(),
            nullifiers: BTreeMap::new(),
            anchors: BTreeMap::new(),
            base,
            coins: BTreeMap::new(),
            transactions: BTreeMap::new(),
            supply: base.supply(),
        }
    }
    pub(crate) fn spend(&mut self, key: OutPoint) -> Result<Coin, Error> {
        let coin = self.coin(&key).cloned().ok_or(Error::MissingInput)?;
        self.coins.insert(key, None);
        if let Some(id) = self.service_collateral(&key) {
            self.set_service(id, None);
        }
        Ok(coin)
    }
    pub(crate) fn set_service(&mut self, id: Hash, value: Option<crate::service::Entry>) {
        self.services.insert(id, value);
    }
    pub(crate) fn create(&mut self, key: OutPoint, coin: Coin) -> Result<(), Error> {
        if self.coin(&key).is_some() {
            return Err(Error::OutputCollision);
        }
        self.coins.insert(key, Some(coin));
        Ok(())
    }
    pub(crate) fn add_transaction(&mut self, id: Hash) -> Result<(), Error> {
        if self.contains_transaction(&id) {
            return Err(Error::DuplicateTransaction);
        }
        self.transactions.insert(id, true);
        Ok(())
    }
    pub(crate) fn set_supply(&mut self, supply: Supply) {
        self.supply = supply;
    }
    pub(crate) fn shield(
        &mut self,
        tx: &crate::transactions::VerifiedIronwood,
        parent: &dyn LedgerView,
    ) -> Result<(), Error> {
        if !parent.has_anchor(&tx.anchor) {
            return Err(Error::InvalidAnchor);
        }
        let balance = self.shielded.balance.atoms();
        let balance = if tx.value_balance >= 0 {
            balance.checked_sub(tx.value_balance as u128)
        } else {
            balance.checked_add(u128::from(tx.value_balance.unsigned_abs()))
        }
        .ok_or(Error::Amount)?;
        self.shielded.balance = Supply::from_atoms(balance).map_err(|_| Error::Amount)?;
        for nf in &tx.nullifiers {
            if self.has_nullifier(nf) {
                return Err(Error::DuplicateNullifier);
            }
            self.nullifiers.insert(*nf, true);
        }
        for cm in &tx.commitments {
            let leaf = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(cm))
                .ok_or(Error::InvalidCommitment)?;
            if !self.shielded.frontier.append(leaf) {
                return Err(Error::ResourceLimit);
            }
        }
        Ok(())
    }
    pub(crate) fn finish_anchor(&mut self) {
        self.anchors.insert(self.shielded.root(), true);
    }
    pub(crate) fn apply(&mut self, delta: &Delta, reverse: bool) -> Result<(), Error> {
        for (id, (a, b)) in &delta.services {
            let (before, after) = if reverse { (b, a) } else { (a, b) };
            if self.service_entry(id) != before.as_ref() {
                return Err(Error::StateMismatch);
            }
            self.services.insert(*id, after.clone());
        }
        let (old, new) = if reverse {
            (&delta.shielded.1, &delta.shielded.0)
        } else {
            (&delta.shielded.0, &delta.shielded.1)
        };
        if self.shielded.root() != old.root() || self.shielded.balance != old.balance {
            return Err(Error::StateMismatch);
        }
        if self.shielded.frontier.tree_size() != old.frontier.tree_size() {
            return Err(Error::StateMismatch);
        }
        for (key, (old, new)) in &delta.nullifiers {
            let (before, after) = if reverse { (*new, *old) } else { (*old, *new) };
            if self.has_nullifier(key) != before {
                return Err(Error::StateMismatch);
            }
            self.nullifiers.insert(*key, after);
        }
        for (key, (old, new)) in &delta.anchors {
            let (before, after) = if reverse { (*new, *old) } else { (*old, *new) };
            if self.has_anchor(key) != before {
                return Err(Error::StateMismatch);
            }
            self.anchors.insert(*key, after);
        }
        self.shielded = new.clone();
        let (before, after) = if reverse {
            (delta.supply.1, delta.supply.0)
        } else {
            delta.supply
        };
        if self.supply != before {
            return Err(Error::StateMismatch);
        }
        for (key, (old, new)) in &delta.coins {
            let (before, after) = if reverse { (new, old) } else { (old, new) };
            if self.coin(key) != before.as_ref() {
                return Err(Error::StateMismatch);
            }
            self.coins.insert(*key, after.clone());
        }
        for (id, (old, new)) in &delta.transactions {
            let (before, after) = if reverse { (*new, *old) } else { (*old, *new) };
            if self.contains_transaction(id) != before {
                return Err(Error::StateMismatch);
            }
            self.transactions.insert(*id, after);
        }
        self.supply = after;
        Ok(())
    }
    pub(crate) fn finish(self) -> Delta {
        let coins = self
            .coins
            .into_iter()
            .filter_map(|(k, after)| {
                let before = self.base.coin(&k).cloned();
                (before != after).then_some((k, (before, after)))
            })
            .collect();
        let transactions = self
            .transactions
            .into_iter()
            .filter_map(|(k, after)| {
                let before = self.base.contains_transaction(&k);
                (before != after).then_some((k, (before, after)))
            })
            .collect();
        Delta {
            services: self
                .services
                .into_iter()
                .filter_map(|(id, after)| {
                    let before = self.base.service_entry(&id).cloned();
                    (before != after).then_some((id, (before, after)))
                })
                .collect(),
            shielded: (self.base.shielded().clone(), self.shielded),
            nullifiers: self
                .nullifiers
                .into_iter()
                .filter_map(|(k, v)| {
                    let old = self.base.has_nullifier(&k);
                    (old != v).then_some((k, (old, v)))
                })
                .collect(),
            anchors: self
                .anchors
                .into_iter()
                .filter_map(|(k, v)| {
                    let old = self.base.has_anchor(&k);
                    (old != v).then_some((k, (old, v)))
                })
                .collect(),
            coins,
            transactions,
            supply: (self.base.supply(), self.supply),
            fees: Vec::new(),
        }
    }
}

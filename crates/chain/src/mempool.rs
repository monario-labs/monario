//! Bounded, first-seen ordered packages. New payloads are always fully verified.
use crate::{
    Chain, Error as ChainError, Hash, LedgerView, Overlay,
    ledger::{OutPoint, OverlayState},
    storage::{self, DurableChain},
    transactions::{TransactionContext, TransactionVerifier},
};
use monario_monetary::Amount;
use std::collections::{BTreeMap, BTreeSet};
mod topology;

/// Local unconfirmed family limits, including the transaction itself.
pub const MAX_ANCESTORS: usize = 64;
pub const MAX_DESCENDANTS: usize = 64;

#[derive(Clone, Copy)]
pub struct Limits {
    pub transactions: usize,
    pub bytes: usize,
    pub inputs: usize,
    /// Local policy, never a consensus validity rule.
    pub minimum_fee: Amount,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Stale,
    Capacity,
    Conflict,
    Fee,
    Invalid(ChainError),
    Storage,
}
struct Entry {
    id: Hash,
    payload: Hash,
    raw: Vec<u8>,
    fee: Amount,
    parents: BTreeSet<Hash>,
    descendants: usize,
}
/// Non-transferable diagnostic result of checking bytes against the current tip.
pub struct PendingInfo {
    pub id: Hash,
    pub fee: Amount,
}
impl<V: TransactionVerifier> Chain<V> {
    /// Fully check one non-coinbase transaction against confirmed current state.
    /// This does not reserve inputs, admit a package or guarantee later acceptance.
    pub fn check_pending_transaction(&self, raw: &[u8]) -> Result<PendingInfo, ChainError> {
        let height = self
            .height()
            .checked_add(1)
            .ok_or(ChainError::HeightOverflow)?;
        let mut staged = Overlay::new(self.ledger());
        let mut records = Vec::new();
        let tx = self.stage_transaction(
            raw,
            TransactionContext {
                height,
                median_time_past: self.median_time_past(),
                state: self.ledger(),
            },
            false,
            &mut staged,
            &mut records,
        )?;
        self.apply_services(self.tip(), height, self.ledger(), &mut staged, &records)?;
        if staged.shielded().balance > self.ledger().supply() {
            return Err(ChainError::Amount);
        }
        Ok(PendingInfo {
            id: tx.id,
            fee: tx.fee,
        })
    }
}
/// Diagnostic rejection IDs only; signed transaction bytes are never formatted.
#[derive(Debug, PartialEq, Eq)]
pub enum RejectedId {
    Transaction(Hash),
    PayloadDigest(Hash),
}
pub struct Reconciled {
    pub retained: usize,
    pub rejected: Vec<(RejectedId, Error)>,
    pub resurrection_limited: bool,
}
pub struct Mempool {
    limits: Limits,
    profile: Hash,
    tip: Hash,
    entries: Vec<Entry>,
    bytes: usize,
    effects: usize,
    inputs: BTreeSet<OutPoint>,
    nullifiers: BTreeSet<Hash>,
    collateral: BTreeSet<OutPoint>,
    state: Option<OverlayState>,
    poisoned: bool,
}
impl Mempool {
    pub fn new<V: TransactionVerifier>(chain: &Chain<V>, limits: Limits) -> Result<Self, Error> {
        if limits.transactions == 0
            || limits.transactions > 10000
            || limits.bytes == 0
            || limits.bytes > 64 * 1024 * 1024
            || limits.inputs == 0
            || limits.inputs > 131072
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            limits,
            profile: storage::identity(&chain.config, chain.root),
            tip: chain.tip(),
            entries: Vec::new(),
            bytes: 0,
            effects: 0,
            inputs: BTreeSet::new(),
            nullifiers: BTreeSet::new(),
            collateral: BTreeSet::new(),
            state: None,
            poisoned: false,
        })
    }
    fn current<V: TransactionVerifier>(&self, c: &Chain<V>) -> Result<(), Error> {
        if self.poisoned
            || self.tip != c.tip()
            || self.profile != storage::identity(&c.config, c.root)
        {
            Err(Error::Stale)
        } else {
            Ok(())
        }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Recognize exact current pool bytes, including authorization data. This is
    /// not a transferable validity receipt or permission to apply effects again.
    pub fn known_transaction<V: TransactionVerifier>(
        &self,
        c: &Chain<V>,
        raw: &[u8],
    ) -> Result<Option<Hash>, Error> {
        self.current(c)?;
        if self.entries.is_empty()
            || raw.is_empty()
            || raw.len() > c.config.limits.transaction_bytes
            || raw.len() > self.limits.bytes
        {
            return Ok(None);
        }
        Ok(self.exact_payload(payload_digest(raw), raw))
    }
    fn exact_payload(&self, payload: Hash, raw: &[u8]) -> Option<Hash> {
        self.entries
            .iter()
            .find(|e| e.payload == payload && e.raw == raw)
            .map(|e| e.id)
    }
    /// Admission is atomic. There is no replacement, orphan queue or negative cache.
    pub fn admit<V: TransactionVerifier>(
        &mut self,
        c: &Chain<V>,
        raw: Vec<u8>,
    ) -> Result<Hash, Error> {
        self.current(c)?;
        if self.entries.len() >= self.limits.transactions
            || raw.is_empty()
            || raw.len() > c.config.limits.transaction_bytes
            || self
                .bytes
                .checked_add(raw.len())
                .is_none_or(|n| n > self.limits.bytes)
        {
            return Err(Error::Capacity);
        }
        let payload = payload_digest(&raw);
        if self.exact_payload(payload, &raw).is_some() {
            return Err(Error::Conflict);
        }
        let height = c
            .height()
            .checked_add(1)
            .ok_or(Error::Invalid(ChainError::HeightOverflow))?;
        let mut baseline = match self.state.take() {
            Some(s) => Overlay::from_state(c.ledger(), s),
            None => Overlay::new(c.ledger()),
        };
        let result = (|| {
            let mut staged = Overlay::new(&baseline);
            let mut records = Vec::new();
            let tx = c
                .stage_transaction(
                    &raw,
                    TransactionContext {
                        height,
                        median_time_past: c.median_time_past(),
                        state: c.ledger(),
                    },
                    false,
                    &mut staged,
                    &mut records,
                )
                .map_err(Error::Invalid)?;
            if tx.fee < self.limits.minimum_fee {
                return Err(Error::Fee);
            }
            // Service collateral references act as read/write exclusion claims.
            // This prevents admission order from accepting a registration/proof
            // followed by a withdrawal that canonical block ordering would reject.
            let mut touched = staged.service_changes();
            c.apply_services(c.tip(), height, c.ledger(), &mut staged, &records)
                .map_err(Error::Invalid)?;
            for (id, payload) in &records {
                touched.push(if payload[crate::service::KIND] == 0 {
                    *id
                } else {
                    payload[crate::service::HEADER..crate::service::HEADER + 32]
                        .try_into()
                        .map_err(|_| Error::Invalid(ChainError::Service))?
                });
            }
            let collateral: BTreeSet<_> = touched
                .into_iter()
                .filter_map(|id| {
                    staged
                        .service_entry(&id)
                        .or_else(|| baseline.service_entry(&id))
                        .map(|e| e.collateral)
                })
                .collect();
            if staged.shielded().balance > c.ledger().supply() {
                return Err(Error::Invalid(ChainError::Amount));
            }
            let delta = staged.finish();
            let effects = delta.coins.len()
                + delta.nullifiers.len()
                + delta.transactions.len()
                + delta.services.len();
            if self.effects.checked_add(effects).is_none_or(|n| n > 131072) {
                return Err(Error::Capacity);
            }
            let inputs: Vec<_> = delta
                .coins
                .iter()
                .filter_map(|(p, (a, b))| (a.is_some() && b.is_none()).then_some(*p))
                .collect();
            let nullifiers: Vec<_> = delta.nullifiers.keys().copied().collect();
            if self
                .inputs
                .len()
                .checked_add(self.nullifiers.len())
                .and_then(|n| n.checked_add(inputs.len() + nullifiers.len()))
                .is_none_or(|n| n > self.limits.inputs)
            {
                return Err(Error::Capacity);
            }
            if inputs
                .iter()
                .any(|p| self.inputs.contains(p) || self.collateral.contains(p))
                || nullifiers.iter().any(|n| self.nullifiers.contains(n))
                || collateral
                    .iter()
                    .any(|p| self.inputs.contains(p) || self.collateral.contains(p))
            {
                return Err(Error::Conflict);
            }
            let pending_ids: BTreeMap<_, _> = self
                .entries
                .iter()
                .enumerate()
                .map(|(index, e)| (e.id, index))
                .collect();
            let parents = inputs
                .iter()
                .map(|p| p.transaction)
                .filter(|id| pending_ids.contains_key(id))
                .collect();
            let ancestors = self.check_topology(&parents, &pending_ids)?;
            Ok((
                delta, tx.id, tx.fee, inputs, nullifiers, collateral, effects, parents, ancestors,
            ))
        })();
        let result = match result {
            Ok((delta, id, fee, inputs, nullifiers, collateral, effects, parents, ancestors)) => {
                if baseline.apply(&delta, false).is_err() {
                    self.poisoned = true;
                    Err(Error::Stale)
                } else {
                    self.bytes += raw.len();
                    self.effects += effects;
                    self.inputs.extend(&inputs);
                    self.nullifiers.extend(&nullifiers);
                    self.collateral.extend(&collateral);
                    for index in ancestors {
                        self.entries[index].descendants += 1;
                    }
                    self.entries.push(Entry {
                        id,
                        payload,
                        raw,
                        fee,
                        parents,
                        descendants: 1,
                    });
                    Ok(id)
                }
            }
            Err(e) => Err(e),
        };
        self.state = Some(baseline.into_state());
        result
    }
    /// In insertion/dependency order. Selection still needs the template builder's
    /// full byte/count/service-record limits and final contextual verification.
    pub fn transactions<V: TransactionVerifier>(
        &self,
        c: &Chain<V>,
    ) -> Result<impl Iterator<Item = &[u8]>, Error> {
        self.current(c)?;
        Ok(self.entries.iter().map(|e| e.raw.as_slice()))
    }
    pub fn fee<V: TransactionVerifier>(
        &self,
        c: &Chain<V>,
        id: Hash,
    ) -> Result<Option<Amount>, Error> {
        self.current(c)?;
        Ok(self.entries.iter().find(|e| e.id == id).map(|e| e.fee))
    }
    /// Current verified effects IDs and exact bytes, in dependency order.
    /// Borrowed relay data is invalidated by any subsequent pool mutation.
    pub fn relay_transactions<V: TransactionVerifier>(
        &self,
        c: &Chain<V>,
    ) -> Result<impl Iterator<Item = (Hash, &[u8])>, Error> {
        self.current(c)?;
        Ok(self.entries.iter().map(|e| (e.id, e.raw.as_slice())))
    }
    fn rebuild<V: TransactionVerifier>(
        &mut self,
        c: &Chain<V>,
        extra: Vec<Vec<u8>>,
        remove: Option<Hash>,
    ) -> Result<Reconciled, Error> {
        if self.profile != storage::identity(&c.config, c.root) {
            return Err(Error::Stale);
        }
        let mut next = Self::new(c, self.limits)?;
        let mut rejected = Vec::new();
        let mut deferred = Vec::new();
        for e in &self.entries {
            if Some(e.id) == remove || c.ledger().contains_transaction(&e.id) {
                continue;
            }
            if let Err(error) = next.admit(c, e.raw.clone()) {
                if !extra.is_empty()
                    && matches!(
                        error,
                        Error::Invalid(
                            ChainError::MissingInput
                                | ChainError::Transaction(
                                    crate::transactions::TransactionError::MissingInput
                                )
                        )
                    )
                {
                    deferred.push(e);
                } else {
                    rejected.push((RejectedId::Transaction(e.id), error));
                }
            }
        }
        for raw in extra {
            // Every resurrected byte string passes ordinary admission. Nothing
            // from a disconnected block is treated as a transferable receipt.
            let id = crate::header::hash_domain(b"Monario/mempool-rejected/v1\0", &[&raw]);
            if let Err(error) = next.admit(c, raw) {
                rejected.push((RejectedId::PayloadDigest(id), error));
            }
        }
        // Detached blocks were traversed oldest first. Existing entries already
        // have dependency order, so one retry pass suffices for restored parents
        // and their pending descendants; failed/absent parents never cause a loop.
        for e in deferred {
            if let Err(error) = next.admit(c, e.raw.clone()) {
                rejected.push((RejectedId::Transaction(e.id), error));
            }
        }
        let retained = next.len();
        *self = next;
        Ok(Reconciled {
            retained,
            rejected,
            resurrection_limited: false,
        })
    }
    pub fn remove<V: TransactionVerifier>(
        &mut self,
        c: &Chain<V>,
        id: Hash,
    ) -> Result<Reconciled, Error> {
        self.current(c)?;
        self.rebuild(c, Vec::new(), Some(id))
    }
    /// Revalidate the new tip and resurrect disconnected transactions in oldest
    /// block order. Mempools are ephemeral and rebuilt after process restart.
    pub fn synchronize<V: TransactionVerifier>(
        &mut self,
        source: &DurableChain<V>,
    ) -> Result<Reconciled, Error> {
        let c = source.chain().map_err(|_| Error::Storage)?;
        if self.profile != storage::identity(&c.config, c.root) || !c.nodes.contains_key(&self.tip)
        {
            return Err(Error::Stale);
        }
        let (mut detached, _) = c.route(self.tip, c.tip()).map_err(|_| Error::Stale)?;
        detached.reverse();
        let mut extra = Vec::new();
        let mut bytes = 0usize;
        let mut limited = false;
        'blocks: for id in detached {
            let b = source.stored_block(id).map_err(|_| Error::Storage)?;
            for raw in b.transactions.into_iter().skip(1) {
                bytes = bytes.checked_add(raw.len()).ok_or(Error::Capacity)?;
                if extra.len() >= self.limits.transactions || bytes > self.limits.bytes {
                    limited = true;
                    break 'blocks;
                }
                extra.push(raw);
            }
        }
        let mut report = self.rebuild(c, extra, None)?;
        report.resurrection_limited = limited;
        Ok(report)
    }
}

fn payload_digest(raw: &[u8]) -> Hash {
    crate::header::hash_domain(b"Monario/mempool-payload/v1\0", &[raw])
}

mod selection;
pub use selection::Selection;

#[cfg(test)]
mod tests;

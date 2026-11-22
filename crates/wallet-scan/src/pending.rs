//! Reorg-sensitive diagnostics. Status changes never release durable input claims.
use monario_chain::{storage::DurableChain, transactions::TransactionVerifier};
use monario_wallet::storage::{StorageError, WalletStore};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Unsigned,
    Confirmed,
    Expired,
    Pending,
    Unavailable,
    NeedsBytes,
}
#[derive(Debug)]
pub enum Error {
    Wallet(StorageError),
    Chain(monario_chain::storage::StorageError),
    WrongProfile,
    UnknownReservation,
}
/// Inspect exactly one authenticated reservation against the current validated
/// branch. This performs at most one pending-transaction verification, never
/// releases input claims, and does not attest mempool membership or finality.
pub fn status<V: TransactionVerifier>(
    source: &DurableChain<V>,
    wallet: &WalletStore,
    reservation: [u8; 16],
) -> Result<Status, Error> {
    let chain = source.chain().map_err(Error::Chain)?;
    let r = wallet
        .reservations()
        .map_err(Error::Wallet)?
        .get(&reservation)
        .ok_or(Error::UnknownReservation)?;
    if r.profile != chain.validation_profile() {
        return Err(Error::WrongProfile);
    }
    Ok(classify(chain, r))
}
/// Recompute from the currently validated branch, not a saved status or wall clock.
/// Unavailable includes spent/missing/immature inputs and invalidated private anchors.
pub fn statuses<V: TransactionVerifier>(
    source: &DurableChain<V>,
    wallet: &WalletStore,
) -> Result<BTreeMap<[u8; 16], Status>, Error> {
    let chain = source.chain().map_err(Error::Chain)?;
    let mut statuses = BTreeMap::new();
    for (id, r) in wallet.reservations().map_err(Error::Wallet)? {
        if r.profile != chain.validation_profile() {
            return Err(Error::WrongProfile);
        }
        statuses.insert(*id, classify(chain, r));
    }
    Ok(statuses)
}
fn classify<V: TransactionVerifier>(
    chain: &monario_chain::Chain<V>,
    r: &monario_wallet::storage::pending::Reservation,
) -> Status {
    if let Some(txid) = r.transaction {
        if chain.ledger().contains_transaction(&txid) {
            Status::Confirmed
        } else if chain.height() >= r.expiry_height {
            Status::Expired
        } else if let Some(raw) = r.expose_transaction() {
            match chain.check_pending_transaction(raw) {
                Ok(info) if info.id == txid => Status::Pending,
                _ => Status::Unavailable,
            }
        } else {
            Status::NeedsBytes
        }
    } else {
        Status::Unsigned
    }
}

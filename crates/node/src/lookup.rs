//! Exact historical bytes from the currently selected validated branch only.
use crate::{Error, Hash, V6Verifier};
use monario_chain::{Confirmation, storage::DurableChain};

pub struct ConfirmedTransaction {
    pub bytes: Vec<u8>,
    pub confirmation: Confirmation,
    /// Branch snapshot for the returned depth; not a finality guarantee.
    pub validated_tip: Hash,
}

/// Resolve a validated inclusion, then authenticate its entire historical block
/// before reading any transaction bytes. Reads at most one bounded block. This
/// never treats a decoded transaction ID or a retained orphan as confirmation.
pub fn confirmed(
    source: &DurableChain<V6Verifier>,
    transaction: Hash,
) -> Result<Option<ConfirmedTransaction>, Error> {
    let chain = source.chain().map_err(|_| Error::Storage)?;
    let Some(confirmation) = source
        .transaction_confirmation(&transaction)
        .map_err(|_| Error::Storage)?
    else {
        return Ok(None);
    };
    let raw = source
        .authenticated_block_bytes(confirmation.block)
        .map_err(|e| match e {
            monario_chain::storage::StorageError::Pruned => Error::Pruned,
            _ => Error::Storage,
        })?;
    let block = monario_chain::wire::decode(&raw, chain.limits(), &V6Verifier)
        .map_err(|_| Error::Storage)?;
    let mut found = None;
    for bytes in block.transactions {
        let id = monario_v6::transaction_id(&bytes).map_err(|_| Error::Storage)?;
        if id == transaction {
            if found.is_some() {
                return Err(Error::Storage);
            }
            found = Some(bytes);
        }
    }
    Ok(Some(ConfirmedTransaction {
        bytes: found.ok_or(Error::Storage)?,
        confirmation,
        validated_tip: chain.tip(),
    }))
}

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod tests;

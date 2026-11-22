//! Bounded canonical archive scrubbing; a page is not a whole-chain certificate.
use crate::{
    Hash,
    storage::{DurableChain, StorageError},
    transactions::TransactionVerifier,
};

pub const MAX_BLOCKS: usize = 16;
#[derive(Debug)]
pub enum Error {
    Cursor,
    Storage(StorageError),
}
pub struct Page {
    pub profile: Hash,
    /// Exclusive starting cursor. Its body is not included in this page.
    pub after: Hash,
    pub end: Hash,
    pub validated_tip: Hash,
    pub blocks: u16,
    pub bytes: u64,
    /// The page ends at this snapshot's tip, not proof of earlier-page coverage.
    pub at_tip: bool,
}

/// Authenticate up to sixteen best-chain successors of a canonical cursor.
/// One bounded body is held at a time. No saved audit flag, trust decision or
/// cursor is written; failure returns no partially successful page receipt.
pub fn page<V: TransactionVerifier>(source: &DurableChain<V>, after: Hash) -> Result<Page, Error> {
    let chain = source.chain().map_err(Error::Storage)?;
    let locator = chain
        .synchronization_locator(after)
        .map_err(|_| Error::Cursor)?;
    let (anchor, ids) = chain
        .synchronization_inventory(&locator)
        .map_err(|_| Error::Cursor)?;
    if anchor != after {
        return Err(Error::Cursor);
    }
    let mut result = Page {
        profile: chain.validation_profile(),
        after,
        end: after,
        validated_tip: chain.tip(),
        blocks: 0,
        bytes: 0,
        at_tip: false,
    };
    for id in ids.into_iter().take(MAX_BLOCKS) {
        let raw = source
            .authenticated_block_bytes(id)
            .map_err(Error::Storage)?;
        result.bytes += raw.len() as u64;
        result.blocks += 1;
        result.end = id;
    }
    result.at_tip = result.end == result.validated_tip;
    Ok(result)
}

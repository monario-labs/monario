//! Bounded offline pages. A stream grants no consensus validity or checkpoint trust.
use crate::{
    Hash,
    header::{HEADER_LEN, Header},
    storage::{DurableChain, StorageError},
    transactions::TransactionVerifier,
};
use std::io::{self, Read, Write};

const MAGIC: &[u8; 8] = b"MONBLK01";
const PREFIX: usize = 74;
pub const MAX_BLOCKS: u16 = 128;
#[derive(Debug)]
pub enum Error {
    Input,
    Output,
    Format,
    Profile,
    Storage(StorageError),
}
pub struct Page {
    pub end: Hash,
    pub blocks: u16,
}
pub struct Imported {
    /// Last contiguous record, not necessarily the selected best tip.
    pub end: Hash,
    pub accepted: u16,
    pub known: u16,
}

/// Export up to 128 best-chain successors of a validated canonical cursor.
/// Output failure leaves a partial stream; flush is not an fsync guarantee.
pub fn export<V: TransactionVerifier>(
    source: &DurableChain<V>,
    after: Hash,
    output: &mut impl Write,
) -> Result<Page, Error> {
    let chain = source.chain().map_err(Error::Storage)?;
    let locator = chain
        .synchronization_locator(after)
        .map_err(|_| Error::Format)?;
    let (anchor, ids) = chain
        .synchronization_inventory(&locator)
        .map_err(|_| Error::Format)?;
    if anchor != after {
        return Err(Error::Format);
    }
    let count = ids.len() as u16; // synchronization_inventory is capped at 128.
    output.write_all(MAGIC).map_err(|_| Error::Output)?;
    output
        .write_all(&source.profile_id().map_err(Error::Storage)?)
        .map_err(|_| Error::Output)?;
    output.write_all(&anchor).map_err(|_| Error::Output)?;
    output
        .write_all(&count.to_le_bytes())
        .map_err(|_| Error::Output)?;
    let mut end = anchor;
    for id in ids {
        let raw = source
            .authenticated_block_bytes(id)
            .map_err(Error::Storage)?;
        output
            .write_all(&(raw.len() as u32).to_le_bytes())
            .map_err(|_| Error::Output)?;
        output.write_all(&raw).map_err(|_| Error::Output)?;
        end = id;
    }
    output.flush().map_err(|_| Error::Output)?;
    Ok(Page { end, blocks: count })
}

/// Import into an already selected durable chain, never choose a root/profile.
/// Each new block commits independently. Any error may follow a valid committed
/// prefix; retrying the same page authenticates known bytes before skipping them.
pub fn import<V: TransactionVerifier>(
    destination: &mut DurableChain<V>,
    input: &mut impl Read,
    now: u64,
) -> Result<Imported, Error> {
    let mut prefix = [0u8; PREFIX];
    input.read_exact(&mut prefix).map_err(|_| Error::Input)?;
    if &prefix[..8] != MAGIC {
        return Err(Error::Format);
    }
    if prefix[8..40] != destination.profile_id().map_err(Error::Storage)? {
        return Err(Error::Profile);
    }
    let anchor = prefix[40..72].try_into().expect("fixed anchor");
    let count = u16::from_le_bytes(prefix[72..74].try_into().expect("fixed count"));
    let chain = destination.chain().map_err(Error::Storage)?;
    if count > MAX_BLOCKS || chain.block_info(&anchor).is_none() {
        return Err(Error::Format);
    }
    let limit = chain
        .limits()
        .block_bytes
        .min(crate::archive::MAX_BLOCK_BYTES);
    let chain_id = chain.chain_id();
    let mut report = Imported {
        end: anchor,
        accepted: 0,
        known: 0,
    };
    for _ in 0..count {
        let mut length = [0u8; 4];
        input.read_exact(&mut length).map_err(|_| Error::Input)?;
        let length = u32::from_le_bytes(length) as usize;
        if !(HEADER_LEN + 1..=limit).contains(&length) {
            return Err(Error::Format);
        }
        let mut raw = vec![0u8; length];
        input.read_exact(&mut raw).map_err(|_| Error::Input)?;
        let header = Header::decode(&raw[..HEADER_LEN]).map_err(|_| Error::Format)?;
        if header.parent != report.end {
            return Err(Error::Format);
        }
        let id = header.id(&chain_id);
        if destination.chain().map_err(Error::Storage)?.contains(&id) {
            if destination
                .authenticated_block_bytes(id)
                .map_err(Error::Storage)?
                != raw
            {
                return Err(Error::Format);
            }
            report.known += 1;
        } else {
            destination
                .submit_encoded(&raw, now)
                .map_err(Error::Storage)?;
            report.accepted += 1;
        }
        report.end = id;
    }
    let mut trailing = [0u8; 1];
    match input.read_exact(&mut trailing) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(report),
        Err(_) => Err(Error::Input),
        Ok(()) => Err(Error::Format),
    }
}

//! Bounded block payloads: header || canonical CompactSize count || raw transactions.
//! Framing is not consensus acceptance. Use submit_encoded for full validation.
use crate::{
    Block, Error, Limits,
    header::{HEADER_LEN, Header},
    transactions::TransactionVerifier,
};

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
    if bytes.len() < n {
        return Err(Error::BlockEncoding);
    }
    let (value, rest) = bytes.split_at(n);
    *bytes = rest;
    Ok(value)
}
/// Read a minimal CompactSize integer. Callers must separately enforce their
/// field's resource limits before allocation or iteration; no implicit cap applies.
pub fn read_compact_size(bytes: &mut &[u8]) -> Result<u64, Error> {
    let tag = take(bytes, 1)?[0];
    let (width, minimum) = match tag {
        253 => (2, 253),
        254 => (4, 65536),
        255 => (8, 1_u64 << 32),
        _ => return Ok(u64::from(tag)),
    };
    let mut raw = [0; 8];
    raw[..width].copy_from_slice(take(bytes, width)?);
    let n = u64::from_le_bytes(raw);
    if n < minimum {
        return Err(Error::BlockEncoding);
    }
    Ok(n)
}
pub(crate) fn compact_size_len(n: usize) -> usize {
    if n < 253 {
        1
    } else if n <= u16::MAX as usize {
        3
    } else if n <= u32::MAX as usize {
        5
    } else {
        9
    }
}
fn write_count(out: &mut Vec<u8>, count: usize) {
    let raw = (count as u64).to_le_bytes();
    match compact_size_len(count) {
        1 => out.push(count as u8),
        3 => {
            out.push(253);
            out.extend(&raw[..2]);
        }
        5 => {
            out.push(254);
            out.extend(&raw[..4]);
        }
        _ => {
            out.push(255);
            out.extend(raw);
        }
    }
}
pub(crate) fn block_size(block: &Block, limits: &Limits) -> Result<usize, Error> {
    if block.transactions.is_empty() {
        return Err(Error::EmptyBlock);
    }
    if block.transactions.len() > limits.transactions {
        return Err(Error::ResourceLimit);
    }
    let mut size = HEADER_LEN + compact_size_len(block.transactions.len());
    for tx in &block.transactions {
        if tx.is_empty() || tx.len() > limits.transaction_bytes {
            return Err(Error::ResourceLimit);
        }
        size = size.checked_add(tx.len()).ok_or(Error::ResourceLimit)?;
        if size > limits.block_bytes.min(crate::archive::MAX_BLOCK_BYTES) {
            return Err(Error::ResourceLimit);
        }
    }
    Ok(size)
}
/// Decode exactly one bounded payload; trailing bytes and nonminimal counts fail.
/// The trusted backend frames each transaction without verifying its authorization.
pub fn decode(
    bytes: &[u8],
    limits: &Limits,
    backend: &impl TransactionVerifier,
) -> Result<Block, Error> {
    if bytes.len() > limits.block_bytes.min(crate::archive::MAX_BLOCK_BYTES) {
        return Err(Error::ResourceLimit);
    }
    let mut remaining = bytes;
    let header = Header::decode(take(&mut remaining, HEADER_LEN)?)?;
    let count =
        usize::try_from(read_compact_size(&mut remaining)?).map_err(|_| Error::ResourceLimit)?;
    if count == 0 {
        return Err(Error::EmptyBlock);
    }
    if count > limits.transactions || count > remaining.len() {
        return Err(Error::ResourceLimit);
    }
    // Grow only for successfully framed transactions, never a claimed count.
    let mut transactions = Vec::new();
    for _ in 0..count {
        let bounded = &remaining[..remaining.len().min(limits.transaction_bytes)];
        let n = backend
            .transaction_length(bounded)
            .map_err(Error::Transaction)?;
        if n == 0 || n > bounded.len() {
            return Err(Error::BlockEncoding);
        }
        transactions.push(take(&mut remaining, n)?.to_vec());
    }
    if !remaining.is_empty() {
        return Err(Error::BlockEncoding);
    }
    Ok(Block {
        header,
        transactions,
    })
}
/// Encode a structurally framed payload. Signatures, proofs and contextual
/// validity are checked only by consensus submission, not by this serializer.
pub fn encode(
    block: &Block,
    limits: &Limits,
    backend: &impl TransactionVerifier,
) -> Result<Vec<u8>, Error> {
    block.header.check_encoding()?;
    let size = block_size(block, limits)?;
    for tx in &block.transactions {
        if backend.transaction_length(tx).map_err(Error::Transaction)? != tx.len() {
            return Err(Error::BlockEncoding);
        }
    }
    let mut out = Vec::with_capacity(size);
    out.extend(block.header.encode());
    write_count(&mut out, block.transactions.len());
    for tx in &block.transactions {
        out.extend(tx);
    }
    Ok(out)
}

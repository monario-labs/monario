//! Versioned, bounded stream framing. Checksums provide integrity, not authentication.
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
pub const HEADER: usize = 16;
pub const CHUNK: usize = 65536;
pub const MAX_BLOCK: usize = 5_000_000;
pub const HELLO: u8 = 1;
pub const ACK: u8 = 2;
pub const GET_BLOCKS: u8 = 3;
pub const INVENTORY: u8 = 4;
pub const GET_BLOCK: u8 = 5;
pub const BLOCK: u8 = 6;
pub const TRANSACTION: u8 = 7;
pub const TIP: u8 = 8;
pub const PING: u8 = 9;
pub const PONG: u8 = 10;
pub const NOT_FOUND: u8 = 11;
pub const GET_TRANSACTION: u8 = 12;
pub const PARENT_TRANSACTION: u8 = 13;
pub const TRANSACTION_NOT_FOUND: u8 = 14;
pub const CANDIDATES: u8 = 15;
pub const VERSION: u8 = 2;
/// At most sixteen untrusted peer candidates per frame.
pub const MAX_CANDIDATES_PER_FRAME: usize = 16;
/// Longest accepted textual IP:port form, including IPv6 brackets.
pub const MAX_CANDIDATE_ADDRESS: usize = 64;
const MAX_CANDIDATE_PAYLOAD: usize =
    1 + MAX_CANDIDATES_PER_FRAME * (1 + MAX_CANDIDATE_ADDRESS + 32);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Header,
    Length,
    Checksum,
    Sequence,
}
pub struct Frame {
    pub kind: u8,
    pub payload: Vec<u8>,
}
pub fn magic(profile: [u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(b"Monario/p2p-magic/v1\0");
    h.update(profile);
    Sha256::digest(h.finalize())[..4]
        .try_into()
        .expect("fixed hash")
}
fn checksum(magic: [u8; 4], kind: u8, payload: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(b"Monario/p2p-frame/v1\0");
    h.update(magic);
    h.update([kind]);
    h.update((payload.len() as u32).to_le_bytes());
    h.update(payload);
    Sha256::digest(h.finalize())[..4]
        .try_into()
        .expect("fixed hash")
}
fn valid_length(kind: u8, len: usize, block: usize, tx: usize) -> bool {
    match kind {
        HELLO => len == 88,
        ACK => len == 0,
        GET_BLOCKS => (33..=1025).contains(&len),
        INVENTORY => (34..=4130).contains(&len),
        GET_BLOCK | TIP | NOT_FOUND => len == 32,
        BLOCK => {
            (32 + monario_chain::header::HEADER_LEN + 1..=block.min(MAX_BLOCK) + 32).contains(&len)
        }
        TRANSACTION => len > 0 && len <= tx.min(2_000_000),
        GET_TRANSACTION | TRANSACTION_NOT_FOUND => len == 48,
        PARENT_TRANSACTION => len > 48 && len <= 48 + tx.min(2_000_000),
        PING | PONG => len == 8,
        CANDIDATES => (1..=MAX_CANDIDATE_PAYLOAD).contains(&len),
        _ => false,
    }
}
pub fn encode(
    magic: [u8; 4],
    kind: u8,
    payload: &[u8],
    block: usize,
    tx: usize,
) -> Result<Vec<u8>, Error> {
    if !valid_length(kind, payload.len(), block, tx) {
        return Err(Error::Length);
    }
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.extend(magic);
    out.extend([kind, 0, VERSION, 0]);
    out.extend((payload.len() as u32).to_le_bytes());
    out.extend(checksum(magic, kind, payload));
    out.extend(payload);
    Ok(out)
}
/// Encode an untrusted candidate advertisement. The frame checksum only proves
/// integrity in transit; it is not authentication of the advertised identities.
pub fn encode_candidates(candidates: &[(SocketAddr, [u8; 32])]) -> Result<Vec<u8>, Error> {
    if candidates.is_empty() || candidates.len() > MAX_CANDIDATES_PER_FRAME {
        return Err(Error::Length);
    }
    let mut out = Vec::with_capacity(1 + candidates.len() * (1 + 49 + 32));
    out.push(candidates.len() as u8);
    for (address, key) in candidates {
        let text = address.to_string();
        if text.is_empty() || text.len() > MAX_CANDIDATE_ADDRESS {
            return Err(Error::Length);
        }
        out.push(text.len() as u8);
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(key);
    }
    if out.len() > MAX_CANDIDATE_PAYLOAD {
        return Err(Error::Length);
    }
    Ok(out)
}

/// Parse an untrusted candidate advertisement strictly. No trailing bytes, no
/// DNS text and no partial records are accepted.
pub fn parse_candidates(payload: &[u8]) -> Result<Vec<(SocketAddr, [u8; 32])>, Error> {
    let Some((&count, mut rest)) = payload.split_first() else {
        return Err(Error::Length);
    };
    let count = usize::from(count);
    if count == 0 || count > MAX_CANDIDATES_PER_FRAME {
        return Err(Error::Length);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let Some((&len, tail)) = rest.split_first() else {
            return Err(Error::Length);
        };
        let len = usize::from(len);
        if len == 0 || len > MAX_CANDIDATE_ADDRESS || tail.len() < len + 32 {
            return Err(Error::Length);
        }
        let text = std::str::from_utf8(&tail[..len]).map_err(|_| Error::Length)?;
        let address: SocketAddr = text.parse().map_err(|_| Error::Length)?;
        let key: [u8; 32] = tail[len..len + 32].try_into().map_err(|_| Error::Length)?;
        out.push((address, key));
        rest = &tail[len + 32..];
    }
    if !rest.is_empty() {
        return Err(Error::Length);
    }
    Ok(out)
}

pub(crate) struct Decoder {
    header: [u8; HEADER],
    have: usize,
    spec: Option<(u8, usize)>,
    payload: Vec<u8>,
    reserved: usize,
}
impl Decoder {
    pub fn new() -> Self {
        Self {
            header: [0; HEADER],
            have: 0,
            spec: None,
            payload: Vec::new(),
            reserved: 0,
        }
    }
    pub fn reserved(&self) -> usize {
        self.reserved
    }
    /// Returns at most one frame. Budget is reserved only after fixed header and
    /// protocol-phase validation, and before allocating the advertised payload.
    pub fn feed(
        &mut self,
        input: &[u8],
        magic: [u8; 4],
        block: usize,
        tx: usize,
        budget: usize,
        allow: impl Fn(u8) -> bool,
    ) -> Result<(usize, Option<Frame>), Error> {
        let mut consumed = 0;
        if self.spec.is_none() {
            let n = (HEADER - self.have).min(input.len());
            self.header[self.have..self.have + n].copy_from_slice(&input[..n]);
            self.have += n;
            consumed += n;
            if self.have < HEADER {
                return Ok((consumed, None));
            }
            if self.header[..4] != magic || self.header[5..8] != [0, VERSION, 0] {
                return Err(Error::Header);
            }
            let kind = self.header[4];
            let len =
                u32::from_le_bytes(self.header[8..12].try_into().expect("fixed header")) as usize;
            if !valid_length(kind, len, block, tx) {
                return Err(Error::Length);
            }
            if !allow(kind) {
                return Err(Error::Sequence);
            }
            self.spec = Some((kind, len));
        }
        let (kind, len) = self.spec.expect("parsed header");
        if !allow(kind) {
            return Err(Error::Sequence);
        }
        if self.reserved == 0 && len > 0 {
            if len > budget {
                return Ok((consumed, None));
            }
            self.payload = Vec::with_capacity(len);
            self.reserved = len;
        }
        let n = (len - self.payload.len()).min(input.len() - consumed);
        self.payload
            .extend_from_slice(&input[consumed..consumed + n]);
        consumed += n;
        if self.payload.len() != len {
            return Ok((consumed, None));
        }
        if self.header[12..] != checksum(magic, kind, &self.payload) {
            return Err(Error::Checksum);
        }
        let frame = Frame {
            kind,
            payload: std::mem::take(&mut self.payload),
        };
        self.have = 0;
        self.spec = None;
        self.reserved = 0;
        Ok((consumed, Some(frame)))
    }
    pub fn kind(&self) -> Option<u8> {
        self.spec.map(|s| s.0)
    }
}

#[cfg(test)]
mod tests;

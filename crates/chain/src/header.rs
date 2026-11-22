//! Exact header encoding; no Equihash field or implicit padding.
use crate::{Error, Hash};
use sha2::{Digest, Sha256};

/// Proposed Monario header wire length. This format has not been deployed.
pub const HEADER_LEN: usize = 144;
pub const HEADER_VERSION: u32 = 1;
/// Greatest timestamp supported by durable signed-integer indexes.
pub const MAX_TIMESTAMP: u64 = i64::MAX as u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u32,
    pub parent: Hash,
    pub merkle_root: Hash,
    pub commitment: Hash,
    pub timestamp: u64,
    pub bits: u32,
    pub nonce: [u8; 32],
}

impl Header {
    /// Require exactly 144 bytes; no trailing data, unsupported versions or targets.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let b: &[u8; HEADER_LEN] = bytes.try_into().map_err(|_| Error::HeaderEncoding)?;
        // Fixed offsets are established by the exact-length check above.
        let h = Self {
            version: u32::from_le_bytes(b[0..4].try_into().expect("fixed offset")),
            parent: b[4..36].try_into().expect("fixed offset"),
            merkle_root: b[36..68].try_into().expect("fixed offset"),
            commitment: b[68..100].try_into().expect("fixed offset"),
            timestamp: u64::from_le_bytes(b[100..108].try_into().expect("fixed offset")),
            bits: u32::from_le_bytes(b[108..112].try_into().expect("fixed offset")),
            nonce: b[112..144].try_into().expect("fixed offset"),
        };
        h.check_encoding()?;
        Ok(h)
    }
    pub fn check_encoding(&self) -> Result<(), Error> {
        if self.version != HEADER_VERSION {
            return Err(Error::HeaderVersion);
        }
        if self.timestamp > MAX_TIMESTAMP {
            return Err(Error::HeaderEncoding);
        }
        monario_pow::Target::from_compact(self.bits).map_err(Error::Pow)?;
        Ok(())
    }
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0; HEADER_LEN];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..36].copy_from_slice(&self.parent);
        b[36..68].copy_from_slice(&self.merkle_root);
        b[68..100].copy_from_slice(&self.commitment);
        b[100..108].copy_from_slice(&self.timestamp.to_le_bytes());
        b[108..112].copy_from_slice(&self.bits.to_le_bytes());
        b[112..].copy_from_slice(&self.nonce);
        b
    }
    /// Chain-separated cheap identifier, not the RandomX proof digest.
    pub fn id(&self, chain_id: &Hash) -> Hash {
        hash_domain(b"Monario/block-id/v1\0", &[chain_id, &self.encode()])
    }
    /// Canonical RandomX preimage, explicitly separated from block identification.
    pub fn pow_preimage(&self, chain_id: &Hash) -> Vec<u8> {
        [b"Monario/pow/v1\0".as_slice(), chain_id, &self.encode()].concat()
    }
}

pub(crate) fn hash_domain(domain: &[u8], parts: &[&[u8]]) -> Hash {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update(part);
    }
    Sha256::digest(hash.finalize()).into()
}

/// Bitcoin/Zcash-style pair tree over transaction identifiers supplied by the
/// transaction verifier. Reject real equal siblings before odd-leaf duplication.
pub fn merkle_root(ids: &[Hash]) -> Result<Hash, Error> {
    if ids.is_empty() {
        return Err(Error::EmptyBlock);
    }
    let mut level = ids.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 && pair[0] == pair[1] {
                return Err(Error::MerkleMutation);
            }
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(hash_domain(&[], &[&pair[0], right]));
        }
        level = next;
    }
    Ok(level[0])
}

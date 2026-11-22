use super::*;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};

const MAGIC: &[u8; 8] = b"MONPEER1";
const MEMORY: u32 = 65_536;
const PLAIN: usize = 8192;
const HEADER: usize = 120;
pub(super) const TOTAL: usize = HEADER + PLAIN + 16;
#[derive(Clone, Copy)]
pub(super) struct Header {
    pub checkpoint: Checkpoint,
    pub salt: [u8; 16],
}
pub(super) fn random<const N: usize>() -> Result<[u8; N], StoreError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| StoreError::Entropy)?;
    Ok(bytes)
}
pub(super) fn derive(
    password: &Password,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, StoreError> {
    let params = Params::new(MEMORY, 3, 1, Some(32)).map_err(|_| StoreError::Invalid)?;
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(MEMORY as usize)
        .map_err(|_| StoreError::Capacity)?;
    blocks.resize(MEMORY as usize, Block::default());
    let mut blocks = Zeroizing::new(blocks);
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(
            &password.0,
            salt,
            key.as_mut_slice(),
            blocks.as_mut_slice(),
        )
        .map_err(|_| StoreError::Invalid)?;
    Ok(key)
}
fn encode(h: Header, nonce: [u8; 24]) -> Vec<u8> {
    let mut b = Vec::with_capacity(TOTAL);
    b.extend(MAGIC);
    b.extend(h.checkpoint.profile);
    b.extend(h.checkpoint.public_key);
    b.extend(h.checkpoint.revision.to_le_bytes());
    b.extend(h.salt);
    b.extend(nonce);
    b
}
pub(super) fn header(b: &[u8], expected: Checkpoint) -> Result<Header, StoreError> {
    if b.len() != TOTAL
        || &b[..8] != MAGIC
        || b[8..40] != expected.profile
        || b[40..72] != expected.public_key
    {
        return Err(StoreError::Invalid);
    }
    let revision = u64::from_le_bytes(b[72..80].try_into().map_err(|_| StoreError::Invalid)?);
    if revision < expected.revision {
        return Err(StoreError::Invalid);
    }
    Ok(Header {
        checkpoint: Checkpoint {
            revision,
            ..expected
        },
        salt: b[80..96].try_into().map_err(|_| StoreError::Invalid)?,
    })
}
pub(super) fn seal(
    h: Header,
    key: &[u8; 32],
    identity: &Identity,
    config: &TrustedPeers,
) -> Result<Vec<u8>, StoreError> {
    let document = config.document()?;
    let mut plain = Zeroizing::new(vec![0; PLAIN]);
    plain[..32].copy_from_slice(identity.0.as_ref());
    plain[32..34].copy_from_slice(&(document.len() as u16).to_le_bytes());
    plain[34..34 + document.len()].copy_from_slice(&document);
    let nonce = random()?;
    let mut b = encode(h, nonce);
    let tag = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| StoreError::Invalid)?
        .encrypt_inout_detached(&XNonce::from(nonce), &b, plain.as_mut_slice().into())
        .map_err(|_| StoreError::Invalid)?;
    b.extend_from_slice(&plain);
    b.extend_from_slice(&tag);
    Ok(b)
}
pub(super) fn open(
    b: &[u8],
    h: Header,
    key: &[u8; 32],
) -> Result<(Identity, TrustedPeers), StoreError> {
    header(b, h.checkpoint)?;
    let end = b.len() - 16;
    let mut plain = Zeroizing::new(b[HEADER..end].to_vec());
    let nonce: [u8; 24] = b[96..HEADER].try_into().map_err(|_| StoreError::Invalid)?;
    let tag = Tag::try_from(&b[end..]).map_err(|_| StoreError::Invalid)?;
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| StoreError::Invalid)?
        .decrypt_inout_detached(
            &XNonce::from(nonce),
            &b[..HEADER],
            plain.as_mut_slice().into(),
            &tag,
        )
        .map_err(|_| StoreError::Invalid)?;
    decode(&plain, h.checkpoint)
}
fn decode(plain: &[u8], expected: Checkpoint) -> Result<(Identity, TrustedPeers), StoreError> {
    if plain.len() != PLAIN {
        return Err(StoreError::Invalid);
    }
    let len = usize::from(u16::from_le_bytes([plain[32], plain[33]]));
    if len > config::MAX_DOCUMENT || plain[34 + len..].iter().any(|b| *b != 0) {
        return Err(StoreError::Invalid);
    }
    let secret = Zeroizing::new(plain[..32].try_into().map_err(|_| StoreError::Invalid)?);
    let identity = Identity::from_secret(secret);
    if identity.public_key() != expected.public_key {
        return Err(StoreError::Invalid);
    }
    let config = TrustedPeers::parse(&plain[34..34 + len], expected.profile)?;
    config.valid_identity(identity.public_key())?;
    Ok((identity, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_invalid_lengths_and_padding_are_rejected() {
        let identity = Identity::from_secret(Zeroizing::new([7; 32]));
        let h = Header {
            checkpoint: Checkpoint {
                profile: [2; 32],
                public_key: identity.public_key(),
                revision: 0,
            },
            salt: [8; 16],
        };
        let key = [3; 32]; // Public test key, never used by a real identity store.
        let document = TrustedPeers::empty([2; 32]).document().unwrap();
        for attack in 0..4 {
            let mut plain = Zeroizing::new(vec![0; PLAIN]);
            plain[..32].copy_from_slice(identity.0.as_ref());
            plain[32..34].copy_from_slice(&(document.len() as u16).to_le_bytes());
            plain[34..34 + document.len()].copy_from_slice(&document);
            match attack {
                0 => plain[32..34].copy_from_slice(&u16::MAX.to_le_bytes()),
                1 => plain[PLAIN - 1] = 1,
                2 => plain[32..34].copy_from_slice(&0u16.to_le_bytes()),
                _ => plain[34] = b'[',
            }
            let nonce = random().unwrap();
            let mut bytes = encode(h, nonce);
            let tag = XChaCha20Poly1305::new_from_slice(&key)
                .unwrap()
                .encrypt_inout_detached(&XNonce::from(nonce), &bytes, plain.as_mut_slice().into())
                .unwrap();
            bytes.extend_from_slice(&plain);
            bytes.extend_from_slice(&tag);
            assert!(open(&bytes, h, &key).is_err());
        }
    }
}

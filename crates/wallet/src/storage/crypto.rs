use super::*;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};

pub(super) const LEGACY_PLAIN_LEN: usize = 8192;
pub(super) const PLAIN_LEN: usize = 2 * 1024 * 1024;
pub(super) const LEGACY_TOTAL: usize = HEADER_LEN + LEGACY_PLAIN_LEN + 16;
pub(super) const HEADER_LEN: usize = 94;
pub(super) const TOTAL: usize = HEADER_LEN + PLAIN_LEN + 16;
const MEMORY: u32 = 65536;
const PASSES: u32 = 3;
const LANES: u32 = 1;

#[derive(Clone, Copy)]
pub(super) struct Header {
    pub checkpoint: WalletCheckpoint,
    pub kind: u8,
    pub salt: [u8; 16],
}
pub(super) fn random<const N: usize>() -> Result<[u8; N], StorageError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| StorageError::Entropy)?;
    Ok(bytes)
}
pub(super) fn derive(
    password: &Password,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, StorageError> {
    let params = Params::new(MEMORY, PASSES, LANES, Some(32)).map_err(|_| StorageError::Invalid)?;
    // The upstream allocating helper frees its workspace without wiping it.
    // Own and zeroize the entire Argon2 workspace on success AND failure.
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(MEMORY as usize)
        .map_err(|_| StorageError::Capacity)?;
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
        .map_err(|_| StorageError::Invalid)?;
    Ok(key)
}
fn encode_header(h: Header, nonce: [u8; 24], version: u8) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_LEN);
    b.extend(b"MNRVAULT");
    b.extend([version, h.kind, 1, 1]);
    b.extend(MEMORY.to_le_bytes());
    b.extend(PASSES.to_le_bytes());
    b.extend(LANES.to_le_bytes());
    b.extend(h.checkpoint.wallet_id);
    b.push(match h.checkpoint.network {
        Network::Main => 0,
        Network::Test => 1,
        Network::Regtest => 2,
    });
    b.push(crate::DERIVATION_VERSION);
    b.extend(crate::COIN_TYPE.to_le_bytes());
    b.extend(h.checkpoint.revision.to_le_bytes());
    b.extend(h.salt);
    b.extend(nonce);
    b
}
pub(super) fn header(
    bytes: &[u8],
    expected: WalletCheckpoint,
    kind: u8,
) -> Result<Header, StorageError> {
    if !matches!(bytes.len(), TOTAL | LEGACY_TOTAL) {
        return Err(StorageError::Invalid);
    }
    let network = match bytes[40] {
        0 => Network::Main,
        1 => Network::Test,
        2 => Network::Regtest,
        _ => return Err(StorageError::Invalid),
    };
    let revision = u64::from_le_bytes(
        bytes[46..54]
            .try_into()
            .map_err(|_| StorageError::Invalid)?,
    );
    let id: [u8; 16] = bytes[24..40]
        .try_into()
        .map_err(|_| StorageError::Invalid)?;
    let h = Header {
        checkpoint: WalletCheckpoint {
            wallet_id: id,
            network,
            revision,
        },
        kind,
        salt: bytes[54..70]
            .try_into()
            .map_err(|_| StorageError::Invalid)?,
    };
    // Fixed supported parameters are checked BEFORE any password work. A hostile
    // header cannot select its own memory/time cost or downgrade encryption.
    if bytes[..HEADER_LEN]
        != encode_header(
            h,
            bytes[70..94]
                .try_into()
                .map_err(|_| StorageError::Invalid)?,
            if bytes.len() == TOTAL { 2 } else { 1 },
        )
        || kind > 1
        || id != expected.wallet_id
        || network != expected.network
        || revision < expected.revision
    {
        return Err(StorageError::Invalid);
    }
    Ok(h)
}
pub(super) fn seal(h: Header, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
    seal_nonce(h, key, plaintext, random()?)
}
fn seal_nonce(
    h: Header,
    key: &[u8; 32],
    plaintext: &[u8],
    nonce: [u8; 24],
) -> Result<Vec<u8>, StorageError> {
    if !matches!(plaintext.len(), PLAIN_LEN | LEGACY_PLAIN_LEN) {
        return Err(StorageError::Invalid);
    }
    let mut bytes = encode_header(h, nonce, if plaintext.len() == PLAIN_LEN { 2 } else { 1 });
    let mut buffer = Zeroizing::new(plaintext.to_vec());
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| StorageError::Invalid)?;
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(nonce), &bytes, buffer.as_mut_slice().into())
        .map_err(|_| StorageError::Invalid)?;
    bytes.extend_from_slice(&buffer);
    bytes.extend_from_slice(&tag);
    Ok(bytes)
}
pub(super) fn decrypt(
    bytes: &[u8],
    h: Header,
    key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    // Recheck the full authenticated envelope shape, including its expected kind.
    header(bytes, h.checkpoint, h.kind)?;
    let end = bytes.len() - 16;
    let mut buffer = Zeroizing::new(bytes[HEADER_LEN..end].to_vec());
    let nonce: [u8; 24] = bytes[70..94]
        .try_into()
        .map_err(|_| StorageError::Invalid)?;
    let tag = Tag::try_from(&bytes[end..]).map_err(|_| StorageError::Invalid)?;
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| StorageError::Invalid)?
        .decrypt_inout_detached(
            &XNonce::from(nonce),
            &bytes[..HEADER_LEN],
            buffer.as_mut_slice().into(),
            &tag,
        )
        .map_err(|_| StorageError::Invalid)?;
    Ok(buffer)
}

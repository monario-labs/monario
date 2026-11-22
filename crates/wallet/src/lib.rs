//! Version-1 deterministic wallet derivation and encrypted storage. No network services.
//! Seeds must be high-entropy bytes, not passwords. Secret exports are explicit.
mod bip32_key;
pub mod storage;
use hmac::{Hmac, KeyInit, Mac};
pub use monario_address::{Address, Network};
use monario_address::{PrivateReceiver, Receiver, TransparentReceiver};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Provisional numeric derivation coin type; not a SLIP-44 registration.
pub const COIN_TYPE: u32 = 0x004f_5645;
/// Version of the recovery/derivation contract; unrelated to transaction versions.
pub const DERIVATION_VERSION: u8 = 1;

/// External receiving addresses or internal change addresses, never arbitrary paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Addresses exposed for incoming payments.
    External,
    /// Separate internal/change destinations.
    Internal,
}
impl Scope {
    fn number(self) -> u32 {
        match self {
            Self::External => 0,
            Self::Internal => 1,
        }
    }
    fn private(self) -> orchard::keys::Scope {
        match self {
            Self::External => orchard::keys::Scope::External,
            Self::Internal => orchard::keys::Scope::Internal,
        }
    }
}

/// Imported or OS-generated seed. No implicit Clone, serialization or display.
/// The owned buffer is zeroized on drop; callers own any imported/exported copies.
pub struct Seed(Zeroizing<Vec<u8>>);
impl Seed {
    /// Import exactly 32 or 64 high-entropy bytes. Passwords/mnemonics are not parsed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if !matches!(bytes.len(), 32 | 64) {
            return Err(Error::SeedLength);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
    /// Generate 32 bytes using the operating system CSPRNG, failing closed on error.
    /// This does not persist a seed, create a wallet file or launch a service.
    pub fn generate() -> Result<Self, Error> {
        Self::generate_with(|bytes| getrandom::fill(bytes).map_err(|_| ()))
    }
    fn generate_with(fill: impl FnOnce(&mut [u8]) -> Result<(), ()>) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new(vec![0; 32]);
        fill(&mut bytes).map_err(|_| Error::Entropy)?;
        Ok(Self(bytes))
    }
    /// Explicitly borrow secret seed bytes for backup; never log or format them.
    pub fn expose_for_backup(&self) -> &[u8] {
        &self.0
    }
    fn domain_seed(&self, network: Network, pool: u8) -> Zeroizing<[u8; 64]> {
        let network = match network {
            Network::Main => 0,
            Network::Test => 1,
            Network::Regtest => 2,
        };
        prf(b"Monario/wallet-seed/v1\0", &[&[network, pool], &self.0])
    }
    /// Derive m/44'/COIN_TYPE'/account'/scope/index from the transparent domain.
    /// Account and index must be below 2^31. Invalid BIP32 children return errors;
    /// the implementation never silently changes the requested index.
    pub fn transparent_key(
        &self,
        network: Network,
        account: u32,
        scope: Scope,
        index: u32,
    ) -> Result<TransparentKey, Error> {
        if account >= 1 << 31 || index >= 1 << 31 {
            return Err(Error::Index);
        }
        let seed = self.domain_seed(network, 0);
        let mut node = bip32_key::Node::master(seed.as_slice())?;
        for (number, hardened) in [
            (44, true),
            (COIN_TYPE, true),
            (account, true),
            (scope.number(), false),
            (index, false),
        ] {
            node = node.child(number, hardened)?;
        }
        Ok(TransparentKey {
            network,
            secret: node.into_key(),
        })
    }
    /// Derive the Ironwood account through upstream ZIP32 at
    /// m/32'/COIN_TYPE'/account' from the separate private domain.
    pub fn private_account(&self, network: Network, account: u32) -> Result<PrivateAccount, Error> {
        let account = zip32::AccountId::try_from(account).map_err(|_| Error::Index)?;
        let seed = self.domain_seed(network, 1);
        let secret =
            orchard::keys::SpendingKey::from_zip32_seed(seed.as_slice(), COIN_TYPE, account)
                .map_err(|_| Error::Derivation)?;
        Ok(PrivateAccount { network, secret })
    }
}
impl ZeroizeOnDrop for Seed {}
impl core::fmt::Debug for Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Seed([REDACTED])")
    }
}

/// A derived transparent signing key with a zeroizing owned byte buffer.
pub struct TransparentKey {
    network: Network,
    secret: Zeroizing<[u8; 32]>,
}
impl TransparentKey {
    /// Explicit secret borrowing for signing; caller-created copies remain caller-owned.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.secret
    }
    /// Return the canonical compressed secp256k1 public key.
    pub fn public_key(&self) -> [u8; 33] {
        bip32_key::public_key(&self.secret)
    }
    /// Generate the network-bound P2PKH address of the compressed public key.
    pub fn address(&self) -> Address {
        let hash = ripemd::Ripemd160::digest(Sha256::digest(self.public_key()));
        Address::new(
            self.network,
            Receiver::Transparent(TransparentReceiver::PublicKeyHash(hash.into())),
        )
    }
}
impl ZeroizeOnDrop for TransparentKey {}
impl core::fmt::Debug for TransparentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TransparentKey([REDACTED])")
    }
}

/// An Ironwood account spending key. The upstream zeroize feature is mandatory.
pub struct PrivateAccount {
    network: Network,
    secret: orchard::keys::SpendingKey,
}
impl PrivateAccount {
    /// Explicitly borrow the spending key for the pinned Ironwood transaction backend.
    pub fn expose_spending_key(&self) -> &orchard::keys::SpendingKey {
        &self.secret
    }
    /// Derive an external/internal address at an exact 88-bit diversifier index.
    /// No address index is silently wrapped, advanced or reused.
    pub fn address(&self, scope: Scope, index: u128) -> Result<Address, Error> {
        let index = zip32::DiversifierIndex::try_from(index).map_err(|_| Error::Index)?;
        let viewing = orchard::keys::FullViewingKey::from(&self.secret);
        let raw = viewing
            .address_at(index, scope.private())
            .to_raw_address_bytes();
        let receiver = PrivateReceiver::from_raw(raw).map_err(|_| Error::Derivation)?;
        Ok(Address::new(self.network, Receiver::Private(receiver)))
    }
}
impl ZeroizeOnDrop for PrivateAccount {}
impl core::fmt::Debug for PrivateAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrivateAccount([REDACTED])")
    }
}

/// Fail-closed derivation errors, containing no seed/key/path material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A seed is not exactly 32 or 64 bytes.
    SeedLength,
    /// The OS randomness source failed; there is no fallback entropy source.
    Entropy,
    /// Account, address or diversifier index is outside its exact range.
    Index,
    /// A master/child scalar or upstream private derivation was invalid.
    Derivation,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Monario wallet: {self:?}")
    }
}
impl std::error::Error for Error {}

fn prf(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    for part in parts {
        mac.update(part);
    }
    let mut output = mac.finalize().into_bytes();
    let mut bytes = Zeroizing::new([0; 64]);
    bytes.copy_from_slice(&output);
    output.as_mut_slice().zeroize();
    bytes
}

#[cfg(test)]
mod tests;

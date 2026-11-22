//! Network-bound Bech32m payment addresses. This crate handles public receivers
//! only: it does not generate keys, wallets, transactions or network services.
use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};
use zcash_script::script::Evaluable;
/// Existing P2PKH/P2SH receiver semantics, without upstream address-string prefixes.
pub use zcash_transparent::address::TransparentAddress as TransparentReceiver;

/// The entire encoded address is at most 90 ASCII characters.
pub const MAX_ADDRESS_LEN: usize = 90;
/// Version byte in the decoded byte payload, not a SegWit witness version.
pub const ADDRESS_VERSION: u8 = 1;

/// Explicit address namespace; naming a namespace does not launch a network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// Monario primary-chain addresses.
    Main,
    /// Monario test-chain addresses.
    Test,
    /// Monario local regression-test addresses.
    Regtest,
}
impl Network {
    fn prefix(self, private: bool) -> &'static str {
        match (self, private) {
            (Self::Main, false) => "mont",
            (Self::Main, true) => "monz",
            (Self::Test, false) => "testmont",
            (Self::Test, true) => "testmonz",
            (Self::Regtest, false) => "rmont",
            (Self::Regtest, true) => "rmonz",
        }
    }
}
fn hrp(network: Network, private: bool) -> Hrp {
    Hrp::parse(network.prefix(private)).expect("fixed valid lowercase HRP")
}
fn namespace(prefix: Hrp) -> Result<(Network, bool), AddressError> {
    for network in [Network::Main, Network::Test, Network::Regtest] {
        for private in [false, true] {
            if prefix == hrp(network, private) {
                return Ok((network, private));
            }
        }
    }
    Err(AddressError::Encoding)
}

/// A canonical Ironwood raw receiver with a non-identity Pallas transmission key.
/// Parsing does not prove ownership or correct derivation of the receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateReceiver(orchard::Address);
impl PrivateReceiver {
    /// Validate an 11-byte diversifier and 32-byte encoded transmission key.
    pub fn from_raw(bytes: [u8; 43]) -> Result<Self, AddressError> {
        Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(&bytes))
            .map(Self)
            .ok_or(AddressError::InvalidReceiver)
    }
    /// Return the exact canonical raw receiver bytes.
    pub fn to_raw(self) -> [u8; 43] {
        self.0.to_raw_address_bytes()
    }
    /// Return the validated receiver for use with the pinned Ironwood builder.
    pub fn to_upstream(self) -> orchard::Address {
        self.0
    }
}

/// One explicit payment destination. There is no transparent fallback for private
/// receivers and no implicit conversion between receiver types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Receiver {
    /// A P2PKH or P2SH public-script destination.
    Transparent(TransparentReceiver),
    /// An Ironwood private-payment destination.
    Private(PrivateReceiver),
}

/// A validated receiver and its explicit network namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    network: Network,
    receiver: Receiver,
}
impl Address {
    /// Bind an already typed public receiver to a network.
    pub fn new(network: Network, receiver: Receiver) -> Self {
        Self { network, receiver }
    }
    /// Return this address's network.
    pub fn network(self) -> Network {
        self.network
    }
    /// Return the explicit destination type.
    pub fn receiver(self) -> Receiver {
        self.receiver
    }
    /// Encode canonical lowercase Bech32m using the receiver's exact network/type.
    pub fn encode(self) -> String {
        let mut data = [0; 45];
        data[0] = ADDRESS_VERSION;
        let (private, len) = match self.receiver {
            Receiver::Transparent(TransparentReceiver::PublicKeyHash(hash)) => {
                data[1] = 0;
                data[2..22].copy_from_slice(&hash);
                (false, 22)
            }
            Receiver::Transparent(TransparentReceiver::ScriptHash(hash)) => {
                data[1] = 1;
                data[2..22].copy_from_slice(&hash);
                (false, 22)
            }
            Receiver::Private(receiver) => {
                data[1] = 2;
                data[2..45].copy_from_slice(&receiver.to_raw());
                (true, 45)
            }
        };
        bech32::encode::<Bech32m>(hrp(self.network, private), &data[..len])
            .expect("fixed bounded address payload")
    }
    /// Validate against the caller's expected network. Accept uniform upper/lower
    /// case; reject mixed case, aliases, whitespace, bad padding and unknown types.
    /// No network is inferred and accepted on behalf of the caller.
    pub fn decode(encoded: &str, expected: Network) -> Result<Self, AddressError> {
        if encoded.is_empty() || encoded.len() > MAX_ADDRESS_LEN || !encoded.is_ascii() {
            return Err(AddressError::Encoding);
        }
        let checked =
            CheckedHrpstring::new::<Bech32m>(encoded).map_err(|_| AddressError::Encoding)?;
        // The generic byte iterator discards residual bits; explicitly validate
        // those bits before using it. No SegWit witness character is removed.
        checked
            .validate_segwit_padding()
            .map_err(|_| AddressError::Encoding)?;
        let (network, private) = namespace(checked.hrp())?;
        if network != expected {
            return Err(AddressError::WrongNetwork);
        }
        let len = if private { 45 } else { 22 };
        if checked.byte_iter().len() != len {
            return Err(AddressError::Encoding);
        }
        let mut data = [0; 45];
        for (out, byte) in data[..len].iter_mut().zip(checked.byte_iter()) {
            *out = byte;
        }
        if data[0] != ADDRESS_VERSION {
            return Err(AddressError::UnsupportedVersion);
        }
        let receiver = match (private, data[1]) {
            (false, 0) => Receiver::Transparent(TransparentReceiver::PublicKeyHash(
                data[2..22].try_into().expect("fixed receiver width"),
            )),
            (false, 1) => Receiver::Transparent(TransparentReceiver::ScriptHash(
                data[2..22].try_into().expect("fixed receiver width"),
            )),
            (true, 2) => Receiver::Private(PrivateReceiver::from_raw(
                data[2..45].try_into().expect("fixed receiver width"),
            )?),
            _ => return Err(AddressError::UnsupportedReceiver),
        };
        Ok(Self { network, receiver })
    }
    /// Produce the upstream canonical P2PKH/P2SH script, or None for a private
    /// receiver. Private addresses must be handled by the Ironwood payment path.
    pub fn script_pubkey(self) -> Option<Vec<u8>> {
        match self.receiver {
            Receiver::Transparent(receiver) => Some(receiver.script().to_bytes()),
            Receiver::Private(_) => None,
        }
    }
}

/// Address validation failures; invalid input is never repaired or reinterpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressError {
    /// Invalid syntax, checksum, namespace, length, alphabet or padding.
    Encoding,
    /// Valid namespace for a different network.
    WrongNetwork,
    /// Unimplemented address payload version.
    UnsupportedVersion,
    /// Unknown receiver type or receiver/prefix mismatch.
    UnsupportedReceiver,
    /// Noncanonical or identity Ironwood transmission key.
    InvalidReceiver,
}
impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Monario address: {self:?}")
    }
}
impl std::error::Error for AddressError {}

#[cfg(test)]
mod tests;

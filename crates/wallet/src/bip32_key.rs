//! BIP32 private state with owned zeroizing buffers. Curve operations are provided
//! by libsecp256k1; no elliptic-curve arithmetic is implemented here.
use super::{Error, Zeroizing, prf};
use secp256k1::{PublicKey, Scalar, SecretKey};

// These native types are Copy and do not erase themselves on drop. Erase the
// controlled instances as an additional best effort; upstream/compiler copies
// cannot be guaranteed to disappear (see docs/wallet.md).
struct BackendKey(SecretKey);
impl Drop for BackendKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}
struct BackendScalar(Scalar);
impl Drop for BackendScalar {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}
fn backend(raw: &[u8; 32]) -> Result<BackendKey, Error> {
    SecretKey::from_secret_bytes(*raw)
        .map(BackendKey)
        .map_err(|_| Error::Derivation)
}
pub(super) fn public_key(raw: &[u8; 32]) -> [u8; 33] {
    let key = backend(raw).expect("validated BIP32 private key");
    PublicKey::from_secret_key(&key.0).serialize()
}
pub(super) struct Node {
    pub(super) key: Zeroizing<[u8; 32]>,
    pub(super) chain: Zeroizing<[u8; 32]>,
}
impl Node {
    pub(super) fn master(seed: &[u8]) -> Result<Self, Error> {
        let output = prf(b"Bitcoin seed", &[seed]);
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&output[..32]);
        backend(&key)?;
        let mut chain = Zeroizing::new([0; 32]);
        chain.copy_from_slice(&output[32..]);
        Ok(Self { key, chain })
    }
    pub(super) fn child(&self, index: u32, hardened: bool) -> Result<Self, Error> {
        if index >= 1 << 31 {
            return Err(Error::Index);
        }
        let serialized = (index | if hardened { 1 << 31 } else { 0 }).to_be_bytes();
        let output = if hardened {
            prf(
                self.chain.as_slice(),
                &[&[0], self.key.as_slice(), &serialized],
            )
        } else {
            prf(
                self.chain.as_slice(),
                &[&public_key(&self.key), &serialized],
            )
        };
        self.child_from_output(output)
    }
    fn child_from_output(&self, output: Zeroizing<[u8; 64]>) -> Result<Self, Error> {
        let mut tweak = Zeroizing::new([0; 32]);
        tweak.copy_from_slice(&output[..32]);
        let scalar = BackendScalar(Scalar::from_be_bytes(*tweak).map_err(|_| Error::Derivation)?);
        let parent = backend(&self.key)?;
        let child = BackendKey(
            parent
                .0
                .add_tweak(&scalar.0)
                .map_err(|_| Error::Derivation)?,
        );
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(child.0.as_secret_bytes());
        let mut chain = Zeroizing::new([0; 32]);
        chain.copy_from_slice(&output[32..]);
        Ok(Self { key, chain })
    }
    pub(super) fn into_key(self) -> Zeroizing<[u8; 32]> {
        self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_tweaks_and_zero_child_fail_without_index_substitution() {
        let mut raw = [0; 32];
        raw[31] = 1;
        let node = Node {
            key: Zeroizing::new(raw),
            chain: Zeroizing::new([7; 32]),
        };
        let mut output = Zeroizing::new([0; 64]);
        output[..32].fill(255);
        assert!(matches!(
            node.child_from_output(output),
            Err(Error::Derivation)
        ));
        // n - 1 plus parent scalar 1 yields zero and must be rejected.
        let n_minus_one = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x40,
        ];
        let mut output = Zeroizing::new([0; 64]);
        output[..32].copy_from_slice(&n_minus_one);
        assert!(matches!(
            node.child_from_output(output),
            Err(Error::Derivation)
        ));
        // IL=0 is valid under BIP32; it preserves the scalar with a new chain code.
        let output = Zeroizing::new([0; 64]);
        assert_eq!(*node.child_from_output(output).unwrap().key, raw);
        assert!(matches!(node.child(1 << 31, false), Err(Error::Index)));
        assert_eq!(*node.key, raw);
    }
}

//! Opt-in finality anchors and pins.
//!
//! These are **local policy**, not consensus. When no policy is installed the
//! chain follows the existing chainwork and reorg rules unchanged. A pin is a
//! public `(height, hash)` pair: it reveals nothing about shielded notes,
//! addresses, amounts or mempool contents.
//!
//! The shipped [`ANCHORS`] list is append-only and compiled in. An anchor is
//! enforced as a hard local refusal unless the operator explicitly bypasses it.
//! An operator pin may be configured to warn or refuse. A signed pin is accepted
//! by threshold signature and is a suggestion the operator can override by
//! supplying an operator pin instead.

use secp256k1::{Message, PublicKey, ecdsa::Signature};
use sha2::{Digest, Sha256};

/// Maximum configured signers for a threshold-signed pin.
pub const MAX_SIGNERS: usize = 16;
/// Maximum signatures accepted for one pin.
pub const MAX_SIGNATURES: usize = 16;
/// Domain separator for the signature digest.
pub const SIGNING_DOMAIN: &[u8] = b"Monario/finality-pin/v1\0";

/// A public block identity pinned at a height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pin {
    /// Block height.
    pub height: u64,
    /// Block identifier at that height.
    pub hash: [u8; 32],
}

/// Conflict handling when a heavier branch would drop a pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Record the conflict and continue following chainwork.
    Warn,
    /// Reject the conflicting branch.
    Refuse,
}

/// Effective local finality policy. `anchor` is the shipped deep pin; `pin` is
/// the operator or signed pin already validated against the current branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Shipped deep anchor, if any.
    pub anchor: Option<Pin>,
    /// Operator or signed pin, if any.
    pub pin: Option<Pin>,
    /// Handling for a `pin` conflict. Anchors always refuse unless bypassed.
    pub mode: Mode,
    /// Explicit operator bypass of the shipped anchor.
    pub anchor_bypass: bool,
}

/// Append-only compiled anchors. Empty until a post-genesis release pins one.
/// Entries are never edited or removed; a release may only append.
pub const ANCHORS: &[Pin] = &[];

/// The latest shipped anchor, if any.
pub fn shipped_anchor() -> Option<Pin> {
    ANCHORS.last().copied()
}

/// Digest that must be signed for a threshold pin. Signing tooling must use this
/// exact function so the message is domain-separated and height-bound.
pub fn signing_digest(pin: Pin) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SIGNING_DOMAIN);
    h.update(pin.height.to_le_bytes());
    h.update(pin.hash);
    h.finalize().into()
}

/// Verify that at least `threshold` distinct configured signers signed `pin`.
///
/// Each signature is a 64-byte compact ECDSA signature over
/// [`signing_digest`]. Unknown, duplicate and malformed signatures do not count.
/// This never panics on malformed input; it returns `false`.
pub fn verify_threshold(
    pin: Pin,
    signers: &[[u8; 33]],
    threshold: usize,
    signatures: &[[u8; 64]],
) -> bool {
    if threshold == 0
        || threshold > signers.len()
        || signers.len() > MAX_SIGNERS
        || signatures.len() > MAX_SIGNATURES
    {
        return false;
    }
    let message = Message::from_digest(signing_digest(pin));
    let mut seen = [false; MAX_SIGNERS];
    let mut accepted = 0usize;
    for bytes in signatures {
        let Ok(signature) = Signature::from_compact(bytes) else {
            continue;
        };
        for (index, key) in signers.iter().enumerate() {
            if seen[index] {
                continue;
            }
            let Ok(key) = PublicKey::from_byte_array_compressed(*key) else {
                continue;
            };
            if secp256k1::ecdsa::verify(&signature, message, &key).is_ok() {
                seen[index] = true;
                accepted = accepted.saturating_add(1);
                break;
            }
        }
    }
    accepted >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{SecretKey, ecdsa};

    fn key(byte: u8) -> (SecretKey, [u8; 33]) {
        let secret = SecretKey::from_secret_bytes([byte; 32]).unwrap();
        let public = PublicKey::from_secret_key(&secret).serialize();
        (secret, public)
    }

    fn sign(secret: &SecretKey, pin: Pin) -> [u8; 64] {
        ecdsa::sign(Message::from_digest(signing_digest(pin)), secret).serialize_compact()
    }

    fn pin() -> Pin {
        Pin {
            height: 12_345,
            hash: [7; 32],
        }
    }

    #[test]
    fn threshold_requires_distinct_configured_signers() {
        let (a, ap) = key(1);
        let (b, bp) = key(2);
        let (c, cp) = key(3);
        let signers = [ap, bp, cp];
        let p = pin();
        let sa = sign(&a, p);
        let sb = sign(&b, p);
        let sc = sign(&c, p);
        assert!(verify_threshold(p, &signers, 2, &[sa, sb]));
        // One signature repeated is still one signer.
        assert!(!verify_threshold(p, &signers, 2, &[sa, sa]));
        // Unknown/threshold-too-high/malformed fail closed.
        assert!(!verify_threshold(p, &signers, 4, &[sa, sb, sc]));
        assert!(!verify_threshold(p, &signers, 2, &[[0; 64], sa]));
        let so = sign(&SecretKey::from_secret_bytes([9; 32]).unwrap(), p);
        assert!(!verify_threshold(p, &[ap, bp], 2, &[sa, so]));
    }

    #[test]
    fn signatures_are_height_and_hash_bound() {
        let (a, ap) = key(5);
        let p = pin();
        let signature = sign(&a, p);
        let mut other = p;
        other.height += 1;
        assert!(!verify_threshold(other, &[ap], 1, &[signature]));
        other = p;
        other.hash[0] ^= 1;
        assert!(!verify_threshold(other, &[ap], 1, &[signature]));
    }
}

use super::{super::valid_public, StoreError};
use crate::transport::PeerTarget;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub(super) const MAX_DOCUMENT: usize = 6_144;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    profile: String,
    // A string enforces presence: unlike Option, serde must reject a missing field.
    listen: String,
    peers: Vec<Peer>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    address: String,
    public_key: String,
}

/// Validated, bounded operator input. No peer discovery or trust-on-first-use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedPeers {
    pub(super) profile: [u8; 32],
    pub(super) listen: Option<SocketAddr>,
    pub(super) peers: Vec<PeerTarget>,
}
impl TrustedPeers {
    pub fn empty(profile: [u8; 32]) -> Self {
        Self {
            profile,
            listen: None,
            peers: Vec::new(),
        }
    }
    /// Strict JSON schema, at most 6 KiB. "off" disables listening; DNS is forbidden.
    pub fn parse(bytes: &[u8], expected_profile: [u8; 32]) -> Result<Self, StoreError> {
        if bytes.len() > MAX_DOCUMENT {
            return Err(StoreError::Invalid);
        }
        let doc: Document = serde_json::from_slice(bytes).map_err(|_| StoreError::Invalid)?;
        if doc.version != 1 || key(&doc.profile)? != expected_profile || doc.peers.len() > 32 {
            return Err(StoreError::Invalid);
        }
        let listen = if doc.listen == "off" {
            None
        } else {
            Some(address(&doc.listen, true)?)
        };
        let mut peers: Vec<PeerTarget> = Vec::with_capacity(doc.peers.len());
        for peer in doc.peers {
            let address = address(&peer.address, false)?;
            let public_key = key(&peer.public_key)?;
            if !valid_public(public_key)
                || peers
                    .iter()
                    .any(|p| p.address == address || p.public_key == public_key)
            {
                return Err(StoreError::Invalid);
            }
            peers.push(PeerTarget {
                address,
                public_key,
            });
        }
        Ok(Self {
            profile: expected_profile,
            listen,
            peers,
        })
    }
    /// Canonical public configuration; contains no secret identity key.
    pub fn document(&self) -> Result<Vec<u8>, StoreError> {
        let doc = Document {
            version: 1,
            profile: hex(&self.profile),
            listen: self.listen.map_or_else(|| "off".into(), |a| a.to_string()),
            peers: self
                .peers
                .iter()
                .map(|p| Peer {
                    address: p.address.to_string(),
                    public_key: hex(&p.public_key),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&doc).map_err(|_| StoreError::Invalid)?;
        if bytes.len() > MAX_DOCUMENT {
            return Err(StoreError::Invalid);
        }
        Ok(bytes)
    }
    pub fn profile(&self) -> [u8; 32] {
        self.profile
    }
    pub fn listen(&self) -> Option<SocketAddr> {
        self.listen
    }
    pub fn peers(&self) -> &[PeerTarget] {
        &self.peers
    }
    pub(super) fn valid_identity(&self, local: [u8; 32]) -> Result<(), StoreError> {
        if self.peers.iter().any(|p| p.public_key == local) {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }
}
fn address(text: &str, listen: bool) -> Result<SocketAddr, StoreError> {
    let addr: SocketAddr = text.parse().map_err(|_| StoreError::Invalid)?;
    if addr.port() == 0
        || addr.ip().is_multicast()
        || (!listen && addr.ip().is_unspecified())
        || matches!(addr, SocketAddr::V6(a) if a.scope_id() != 0 || a.flowinfo() != 0)
    {
        return Err(StoreError::Invalid);
    }
    Ok(addr)
}
pub(super) fn key(text: &str) -> Result<[u8; 32], StoreError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(StoreError::Invalid);
    }
    let mut key = [0; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
        key[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(key)
}
pub(super) fn hex(key: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    key.iter()
        .flat_map(|b| {
            [
                char::from(DIGITS[(b >> 4) as usize]),
                char::from(DIGITS[(b & 15) as usize]),
            ]
        })
        .collect()
}

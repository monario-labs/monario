//! Signed peer discovery for an explicitly activated, release-pinned profile.
use super::{Error, TrustedPeers, bounded, fixed_hex};
use crate::transport::PeerTarget;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Read, Write},
    net::IpAddr,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const DOMAIN: &[u8] = b"Monario/signed-peers/v1\0";
const MAX_LIST: u64 = 16_384;
const CACHE: &str = "bootstrap-peers.json";
const MAX_SEEDS: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    fn embedded(self) -> &'static [u8] {
        match self {
            Self::Mainnet => include_bytes!("../../../../launch/bootstrap/mainnet.json"),
            Self::Testnet => include_bytes!("../../../../launch/bootstrap/testnet.json"),
        }
    }

    fn url(self) -> &'static str {
        match self {
            Self::Mainnet => "https://node.monario.org/mainnet/peers.json",
            Self::Testnet => "https://testnet.monario.org/testnet/peers.json",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    profile: String,
    signing_key: String,
    fallback: Envelope,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    version: u8,
    network: Network,
    profile: String,
    sequence: u64,
    expires: u64,
    peers: Vec<Peer>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    address: String,
    public_key: String,
}

struct Verified {
    envelope: Envelope,
    sequence: u64,
    expires: u64,
    peers: Vec<PeerTarget>,
}

struct Trust {
    profile: [u8; 32],
    network: Network,
    signer: VerifyingKey,
}

impl Trust {
    fn verify(&self, envelope: Envelope) -> Result<Verified, Error> {
        let signature = Signature::from_bytes(&fixed_hex::<64>(&envelope.signature)?);
        let mut message = Vec::with_capacity(DOMAIN.len() + envelope.payload.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(envelope.payload.as_bytes());
        self.signer
            .verify_strict(&message, &signature)
            .map_err(|_| Error::Configuration)?;
        let list: Payload =
            serde_json::from_str(&envelope.payload).map_err(|_| Error::Configuration)?;
        if list.version != 1
            || list.network != self.network
            || fixed_hex::<32>(&list.profile)? != self.profile
            || list.sequence == 0
            || list.expires == 0
            || !(1..=MAX_SEEDS).contains(&list.peers.len())
        {
            return Err(Error::Configuration);
        }
        let peer_doc = serde_json::to_vec(&serde_json::json!({
            "version": 1, "profile": list.profile, "listen": "off", "peers": list.peers,
        }))
        .map_err(|_| Error::Configuration)?;
        let peers =
            TrustedPeers::parse(&peer_doc, self.profile).map_err(|_| Error::Configuration)?;
        if peers
            .peers()
            .iter()
            .any(|peer| !public_ip(peer.address.ip()))
        {
            return Err(Error::Configuration);
        }
        Ok(Verified {
            envelope,
            sequence: list.sequence,
            expires: list.expires,
            peers: peers.peers().to_vec(),
        })
    }

    fn decode(&self, bytes: &[u8]) -> Result<Verified, Error> {
        if bytes.len() as u64 > MAX_LIST {
            return Err(Error::Configuration);
        }
        self.verify(serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?)
    }
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            a != 0
                && a < 224
                && !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_documentation()
                && !(a == 100 && (64..=127).contains(&b))
                && !matches!((a, b, c), (192, 0, 0) | (192, 88, 99))
                && !(a == 198 && matches!(b, 18 | 19))
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            // Global unicast only, excluding special-use, transition and documentation ranges.
            a & 0xe000 == 0x2000
                && a != 0x2002
                && a != 0x3fff
                && !(a == 0x2001 && (b <= 0x01ff || b == 0x0db8))
        }
    }
}

fn bundle(
    bytes: &[u8],
    network: Network,
    profile: [u8; 32],
) -> Result<Option<(Trust, Verified)>, Error> {
    if bytes.len() as u64 > MAX_LIST * 2 {
        return Err(Error::Configuration);
    }
    let Some(bundle): Option<Bundle> =
        serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?
    else {
        return Ok(None);
    };
    if fixed_hex::<32>(&bundle.profile)? != profile {
        return Ok(None);
    }
    let trust = Trust {
        profile,
        network,
        signer: VerifyingKey::from_bytes(&fixed_hex::<32>(&bundle.signing_key)?)
            .map_err(|_| Error::Configuration)?,
    };
    // The fallback must also fit in the downloaded envelope format.
    let bytes = serde_json::to_vec(&bundle.fallback).map_err(|_| Error::Configuration)?;
    let fallback = trust.decode(&bytes)?;
    Ok(Some((trust, fallback)))
}

pub(super) fn check(
    network: &str,
    profile: [u8; 32],
    bytes: Option<&[u8]>,
    now: u64,
) -> Result<serde_json::Value, Error> {
    let kind = match network {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        _ => return Err(Error::Arguments),
    };
    let (_, fallback) = bundle(bytes.unwrap_or_else(|| kind.embedded()), kind, profile)?
        .ok_or(Error::Configuration)?;
    if fallback.expires <= now {
        return Err(Error::Configuration);
    }
    Ok(
        serde_json::json!({"operation":"bootstrap-check", "network":network,
        "profile":super::hex(&profile), "sequence":fallback.sequence, "expires":fallback.expires,
        "seeds":fallback.peers.len(), "network_started":false}),
    )
}

fn fetch(network: Network) -> Result<Vec<u8>, Error> {
    use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

    let agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(5)))
        .tls_config(
            TlsConfig::builder()
                .provider(TlsProvider::NativeTls)
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .new_agent();
    let mut response = agent
        .get(network.url())
        .call()
        .map_err(|_| Error::Configuration)?;
    if response.status() != 200 {
        return Err(Error::Configuration);
    }
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_LIST + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Configuration)?;
    if bytes.len() as u64 > MAX_LIST {
        return Err(Error::Configuration);
    }
    Ok(bytes)
}

fn cached(root: &Path, trust: &Trust) -> Result<Option<Verified>, Error> {
    match fs::symlink_metadata(root.join(CACHE)) {
        Ok(_) => trust.decode(&bounded(root, CACHE, MAX_LIST)?).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::Configuration),
    }
}

fn persist(root: &Path, bytes: &[u8]) -> Result<(), Error> {
    // Write, sync and replace in the same directory. An interrupted write keeps
    // either the previous signed floor or the complete new one.
    let mut pending = tempfile::NamedTempFile::new_in(root).map_err(|_| Error::Storage)?;
    pending.write_all(bytes).map_err(|_| Error::Storage)?;
    pending.as_file().sync_all().map_err(|_| Error::Storage)?;
    pending
        .persist(root.join(CACHE))
        .map_err(|_| Error::Storage)?;
    #[cfg(unix)]
    fs::File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Error::Storage)?;
    Ok(())
}

fn select(
    fallback: Verified,
    cached: Option<Verified>,
    refresh: Option<(Verified, Vec<u8>)>,
    now: u64,
    save: impl FnOnce(&[u8]) -> Result<(), Error>,
) -> Result<Vec<PeerTarget>, Error> {
    let baseline = match cached {
        Some(cached)
            if cached.sequence == fallback.sequence
                && cached.envelope.payload != fallback.envelope.payload =>
        {
            return Err(Error::Configuration);
        }
        Some(cached) if cached.sequence > fallback.sequence => cached,
        _ => fallback,
    };
    let selected = match refresh {
        Some((candidate, bytes))
            if candidate.sequence > baseline.sequence && candidate.expires > now =>
        {
            save(&bytes)?;
            candidate
        }
        _ => baseline,
    };
    Ok(if selected.expires > now {
        selected.peers
    } else {
        Vec::new()
    })
}

/// Called only after explicit network activation and the authenticated receipt.
/// No matching launch profile means no outbound bootstrap request.
pub(super) fn startup(root: &Path, profile: [u8; 32]) -> Result<Vec<PeerTarget>, Error> {
    let mainnet = bundle(Network::Mainnet.embedded(), Network::Mainnet, profile)?;
    let testnet = bundle(Network::Testnet.embedded(), Network::Testnet, profile)?;
    let (trust, fallback) = match (mainnet, testnet) {
        (Some(valid), None) | (None, Some(valid)) => valid,
        (None, None) => return Ok(Vec::new()),
        _ => return Err(Error::Configuration),
    };
    let cache = cached(root, &trust)?;
    let refreshed = fetch(trust.network)
        .ok()
        .and_then(|raw| trust.decode(&raw).ok().map(|list| (list, raw)));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Configuration)?
        .as_secs();
    select(fallback, cache, refreshed, now, |bytes| {
        persist(root, bytes)
    })
}

#[cfg(test)]
mod tests;

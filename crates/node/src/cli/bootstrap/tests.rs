use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

const PROFILE: [u8; 32] = [42; 32];

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[3; 32])
}

fn trust() -> Trust {
    Trust {
        network: Network::Testnet,
        profile: PROFILE,
        signer: signer().verifying_key(),
    }
}

fn payload(sequence: u64, expires: u64, address: &str) -> Value {
    json!({
        "version": 1, "network": "testnet", "profile": super::super::hex(&PROFILE),
        "sequence": sequence, "expires": expires,
        "peers": [{"address": address, "public_key": "44".repeat(32)}],
    })
}

fn signed(payload: &str, signer: &SigningKey) -> Vec<u8> {
    use std::fmt::Write as _;
    let signature = signer.sign(&[DOMAIN, payload.as_bytes()].concat());
    let mut hex = String::new();
    for byte in signature.to_bytes() {
        write!(hex, "{byte:02x}").unwrap();
    }
    serde_json::to_vec(&Envelope {
        payload: payload.into(),
        signature: hex,
    })
    .unwrap()
}

fn signed_list(sequence: u64, expires: u64, address: &str) -> Vec<u8> {
    signed(&payload(sequence, expires, address).to_string(), &signer())
}

fn descriptor(fallback: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "profile": super::super::hex(&PROFILE),
        "signing_key": super::super::hex(&signer().verifying_key().to_bytes()),
        "fallback": serde_json::from_slice::<Value>(fallback).unwrap(),
    }))
    .unwrap()
}

#[test]
fn bootstrap_signature_binds_exact_payload_network_and_profile() {
    let trust = trust();
    let valid = signed_list(1, 100, "8.8.8.8:19445");
    assert!(trust.decode(&valid).is_ok());
    assert!(trust.decode(&vec![b' '; MAX_LIST as usize + 1]).is_err());
    let mut envelope: Envelope = serde_json::from_slice(&valid).unwrap();
    envelope.payload.push(' ');
    assert!(trust.verify(envelope).is_err());
    let test = payload(1, 100, "8.8.8.8:19445");
    assert!(
        trust
            .decode(&signed(
                &test.to_string(),
                &SigningKey::from_bytes(&[4; 32])
            ))
            .is_err()
    );
    for (field, value) in [
        ("network", json!("mainnet")),
        ("profile", json!("11".repeat(32))),
        ("version", json!(2)),
        ("sequence", json!(0)),
        ("listen", json!("0.0.0.0:1")),
    ] {
        let mut invalid = test.clone();
        invalid[field] = value;
        assert!(
            trust
                .decode(&signed(&invalid.to_string(), &signer()))
                .is_err()
        );
    }
    let duplicate = test.to_string().replacen('{', "{\"version\":1,", 1);
    assert!(trust.decode(&signed(&duplicate, &signer())).is_err());
}

#[test]
fn bootstrap_prohibits_private_targets_and_reuses_peer_pin_validation() {
    let trust = trust();
    for address in [
        "localhost:1",
        "8.8.8.8:0",
        "10.0.0.1:1",
        "100.64.0.1:1",
        "127.0.0.1:1",
        "169.254.1.1:1",
        "198.18.0.1:1",
        "192.0.2.1:1",
        "224.0.0.1:1",
        "[::1]:1",
        "[::ffff:127.0.0.1]:1",
        "[fe80::1]:1",
        "[2001:db8::1]:1",
        "[2002::1]:1",
        "[fc00::1]:1",
    ] {
        assert!(
            trust.decode(&signed_list(1, 100, address)).is_err(),
            "{address}"
        );
    }
    assert!(
        trust
            .decode(&signed_list(1, 100, "[2606:4700::1]:1"))
            .is_ok()
    );
    let mut list = payload(1, 100, "8.8.8.8:19445");
    list["peers"][0]["public_key"] = json!("00".repeat(32));
    assert!(trust.decode(&signed(&list.to_string(), &signer())).is_err());
    let entry = payload(1, 100, "8.8.8.8:19445")["peers"][0].clone();
    for peers in [vec![], vec![entry.clone(); 2], vec![entry; MAX_SEEDS + 1]] {
        list["peers"] = json!(peers);
        assert!(trust.decode(&signed(&list.to_string(), &signer())).is_err());
    }
}

#[test]
fn bootstrap_replay_and_expiry_keep_the_durable_sequence_floor() {
    let trust = trust();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let fallback = || trust.decode(&signed_list(1, 1_000, "8.8.8.8:1")).unwrap();
    let remote = |seq, expires, address| {
        let raw = signed_list(seq, expires, address);
        Some((trust.decode(&raw).unwrap(), raw))
    };
    let use_list = |incoming, now| {
        select(
            fallback(),
            cached(root, &trust).unwrap(),
            incoming,
            now,
            |raw| persist(root, raw),
        )
        .unwrap()
    };
    assert_eq!(use_list(None, 30)[0].address.to_string(), "8.8.8.8:1");
    assert_eq!(
        use_list(remote(2, 100, "9.9.9.9:1"), 30)[0]
            .address
            .to_string(),
        "9.9.9.9:1"
    );
    assert_eq!(cached(root, &trust).unwrap().unwrap().sequence, 2);

    // A torn scratch write never changes the signed file that is reopened.
    let mut pending = tempfile::NamedTempFile::new_in(root).unwrap();
    pending.write_all(b"incomplete write").unwrap();
    assert_eq!(
        use_list(remote(1, 1_000, "8.8.8.8:1"), 31)[0]
            .address
            .to_string(),
        "9.9.9.9:1"
    );
    assert_eq!(
        use_list(remote(2, 1_000, "8.8.8.8:1"), 31)[0]
            .address
            .to_string(),
        "9.9.9.9:1"
    );
    assert!(use_list(remote(1, 1_000, "8.8.8.8:1"), 100).is_empty());
    assert!(use_list(remote(3, 100, "8.8.8.8:1"), 100).is_empty());
    assert_eq!(cached(root, &trust).unwrap().unwrap().sequence, 2);
    assert!(
        select(
            fallback(),
            cached(root, &trust).unwrap(),
            remote(3, 200, "8.8.8.8:1"),
            100,
            |_| Err(Error::Storage)
        )
        .is_err()
    );
    assert_eq!(cached(root, &trust).unwrap().unwrap().sequence, 2);
    assert_eq!(
        use_list(remote(3, 200, "8.8.8.8:1"), 100)[0]
            .address
            .to_string(),
        "8.8.8.8:1"
    );
    fs::write(root.join(CACHE), b"corrupt").unwrap();
    assert!(cached(root, &trust).is_err());
}

#[test]
fn bootstrap_release_check_stays_offline_and_fails_closed() {
    let bytes = descriptor(&signed_list(1, 100, "8.8.8.8:19445"));
    assert_eq!(
        check("testnet", PROFILE, &bytes, 99).unwrap()["network_started"],
        false
    );
    assert!(check("testnet", PROFILE, &bytes, 100).is_err());
    assert!(check("mainnet", PROFILE, &bytes, 99).is_err());
    assert!(check("testnet", [1; 32], &bytes, 99).is_err());
    assert!(check("testnet", PROFILE, b"null", 99).is_err());
    assert_eq!(
        Network::Mainnet.url(),
        "https://node.monario.org/mainnet/peers.json"
    );
    assert_eq!(
        Network::Testnet.url(),
        "https://testnet.monario.org/testnet/peers.json"
    );
    let dir = tempfile::tempdir().unwrap();
    assert!(startup(dir.path(), [0; 32]).unwrap().is_empty());
    assert!(!dir.path().join(CACHE).exists());
}

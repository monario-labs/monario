//! Public test secrets and temporary directories only. No socket is opened.
use super::config::{hex, key};
use super::*;
use crate::tests::private_tempdir;
use std::{
    process::{Command, Stdio},
    sync::{Mutex, atomic::AtomicBool},
};

static VAULT: Mutex<()> = Mutex::new(());
const PROFILE: [u8; 32] = [2; 32];
fn password() -> Password {
    Password::from_bytes(b"public test password only").unwrap()
}
fn next_password() -> Password {
    Password::from_bytes(b"public rotated password only").unwrap()
}
fn identity() -> Identity {
    Identity::from_secret(Zeroizing::new([7; 32]))
}
fn peer_key(n: u8) -> [u8; 32] {
    Identity::from_secret(Zeroizing::new([n; 32])).public_key()
}
fn document(n: u8) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"version":1,"profile":hex(&PROFILE),"listen":"off","peers":[{"address":"127.0.0.1:12345","public_key":hex(&peer_key(n))}]})).unwrap()
}
fn peers(n: u8) -> TrustedPeers {
    TrustedPeers::parse(&document(n), PROFILE).unwrap()
}
fn fixture() -> (tempfile::TempDir, IdentityDirectory, IdentityStore) {
    let temp = private_tempdir();
    let dir = IdentityDirectory::open(temp.path()).unwrap();
    let store =
        IdentityStore::create_inner(&dir, "peer", &password(), peers(11), identity(), |_| {})
            .unwrap();
    (temp, dir, store)
}

#[test]
fn bootstrap_seeds_are_bounded_and_do_not_replace_sealed_operator_peers() {
    let _guard = VAULT.lock().unwrap();
    let (_temp, _dir, store) = fixture();
    let manual = store.configuration().unwrap().peers()[0].clone();
    let candidate = |ip: u8, public_key| PeerTarget {
        address: format!("8.8.8.{ip}:1").parse().unwrap(),
        public_key,
    };
    let mut seeds = vec![
        PeerTarget {
            address: manual.address,
            public_key: peer_key(12),
        },
        candidate(1, manual.public_key),
        candidate(2, identity().public_key()),
    ];
    seeds.extend((30..70).map(|n| candidate(n, peer_key(n))));
    let driver = store.into_driver_with_seeds(seeds).unwrap();
    assert_eq!(
        driver.store.configuration().unwrap().peers(),
        std::slice::from_ref(&manual)
    );
    assert_eq!(driver.driver.config.connect.len(), 32);
    assert_eq!(driver.driver.config.connect[0], manual);
    assert_eq!(driver.driver.config.connect[1], candidate(30, peer_key(30)));
    assert_eq!(driver.checkpoint().unwrap().revision, 0);
}

#[test]
fn strict_configuration_schema_bounds_addresses_and_keys() {
    let base: serde_json::Value = serde_json::from_slice(&document(11)).unwrap();
    for attack in 0..14 {
        let mut doc = base.clone();
        match attack {
            0 => {
                doc["version"] = 2.into();
            }
            1 => {
                doc["profile"] = hex(&[3; 32]).into();
            }
            2 => {
                doc["extra"] = true.into();
            }
            3 => {
                doc["peers"][0]["extra"] = true.into();
            }
            4 => {
                doc["peers"][0]["address"] = "example.com:12345".into();
            }
            5 => {
                doc["peers"][0]["address"] = "0.0.0.0:12345".into();
            }
            6 => {
                doc["peers"][0]["address"] = "[ff02::1]:12345".into();
            }
            7 => {
                doc["peers"][0]["address"] = "127.0.0.1:0".into();
            }
            8 => {
                doc["peers"][0]["public_key"] = hex(&[0; 32]).into();
            }
            9 => {
                doc["peers"][0]["public_key"] = hex(&peer_key(11)).to_uppercase().into();
            }
            10 => {
                doc["listen"] = "[ff02::1]:12345".into();
            }
            11 => {
                doc.as_object_mut().unwrap().remove("listen");
            }
            12 => {
                doc["peers"]
                    .as_array_mut()
                    .unwrap()
                    .push(base["peers"][0].clone());
            }
            _ => {
                doc["peers"][0]["address"] = "[fe80::1%2]:12345".into();
            }
        }
        assert!(
            TrustedPeers::parse(&serde_json::to_vec(&doc).unwrap(), PROFILE).is_err(),
            "attack {attack}"
        );
    }
    for bytes in [
        b"null".as_slice(),
        b"[]",
        b"{",
        b"\xff",
        b"{\"version\":1,\"version\":1}",
        &[b' '; config::MAX_DOCUMENT + 1],
    ] {
        assert!(TrustedPeers::parse(bytes, PROFILE).is_err());
    }
    let mut full = TrustedPeers::empty(PROFILE);
    for n in 0..32 {
        full.peers.push(crate::transport::PeerTarget {
            address: format!("127.0.0.1:{}", 10000 + u16::from(n))
                .parse()
                .unwrap(),
            public_key: peer_key(20 + n),
        });
    }
    assert_eq!(
        TrustedPeers::parse(&full.document().unwrap(), PROFILE).unwrap(),
        full
    );
    full.peers.push(crate::transport::PeerTarget {
        address: "127.0.0.1:20000".parse().unwrap(),
        public_key: peer_key(99),
    });
    assert!(TrustedPeers::parse(&full.document().unwrap(), PROFILE).is_err());
    let mut v6 = base;
    v6["listen"] = "[::]:12345".into();
    v6["peers"][0]["address"] = "[::1]:12345".into();
    let parsed = TrustedPeers::parse(&serde_json::to_vec(&v6).unwrap(), PROFILE).unwrap();
    assert!(parsed.listen().unwrap().is_ipv6());
    assert_eq!(parsed.peers()[0].public_key, peer_key(11));
    assert_eq!(parsed.profile(), PROFILE);
}

#[test]
fn durable_identity_pins_password_rotation_and_no_plaintext() {
    let _serial = VAULT.lock().unwrap();
    let (temp, dir, mut store) = fixture();
    let initial = store.checkpoint().unwrap();
    assert_eq!(initial.public_key, identity().public_key());
    assert_eq!(store.configuration().unwrap(), &peers(11));
    let old = sqlite::read(&store.db).unwrap();
    let changed = store.replace_configuration(peers(12)).unwrap();
    assert_eq!(changed.revision, 1);
    assert_eq!(changed.public_key, initial.public_key);
    let new = sqlite::read(&store.db).unwrap();
    assert_ne!(&old[96..120], &new[96..120]);
    let rotated = store.change_password(&next_password()).unwrap();
    assert_eq!(rotated.revision, 2);
    assert_ne!(&new[80..96], &sqlite::read(&store.db).unwrap()[80..96]);
    drop(store);
    assert_eq!(
        IdentityStore::open(&dir, "peer", &password(), rotated).err(),
        Some(StoreError::Invalid)
    );
    let reopened = IdentityStore::open(&dir, "peer", &next_password(), rotated).unwrap();
    assert_eq!(reopened.checkpoint().unwrap(), rotated);
    assert_eq!(reopened.configuration().unwrap(), &peers(12));
    drop(reopened);
    for entry in fs::read_dir(temp.path()).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        for secret in [
            [7; 32].as_slice(),
            b"public test password only",
            b"public rotated password only",
            document(11).as_slice(),
            document(12).as_slice(),
        ] {
            assert!(!bytes.windows(secret.len()).any(|w| w == secret));
        }
    }
}

#[test]
fn tampered_envelopes_and_authenticated_plaintext_fail_closed() {
    let _serial = VAULT.lock().unwrap();
    let (_temp, _dir, store) = fixture();
    let cp = store.checkpoint().unwrap();
    let original = sqlite::read(&store.db).unwrap();
    for offset in [
        0,
        7,
        8,
        39,
        40,
        71,
        72,
        79,
        80,
        95,
        96,
        119,
        120,
        151,
        152,
        153,
        154,
        crypto::TOTAL - 1,
    ] {
        let mut bytes = original.clone();
        bytes[offset] ^= 128;
        if let Ok(header) = crypto::header(&bytes, cp) {
            assert!(crypto::open(&bytes, header, &store.key).is_err());
        }
    }
    for end in [0, 8, 120, crypto::TOTAL - 1] {
        assert!(crypto::header(&original[..end], cp).is_err());
    }
    assert!(crypto::header(&[original.as_slice(), &[0]].concat(), cp).is_err());
    assert!(
        crypto::header(
            &original,
            Checkpoint {
                profile: [3; 32],
                ..cp
            }
        )
        .is_err()
    );
    assert!(
        crypto::header(
            &original,
            Checkpoint {
                public_key: peer_key(99),
                ..cp
            }
        )
        .is_err()
    );
    assert!(crypto::header(&original, Checkpoint { revision: 1, ..cp }).is_err());
    // Even a valid AEAD payload must contain the bound identity and a valid pin configuration.
    let wrong_identity = crypto::seal(
        store.header,
        &store.key,
        &Identity::from_secret(Zeroizing::new([8; 32])),
        &store.config,
    )
    .unwrap();
    assert!(crypto::open(&wrong_identity, store.header, &store.key).is_err());
    let wrong_profile = crypto::seal(
        store.header,
        &store.key,
        &store.identity,
        &TrustedPeers::empty([3; 32]),
    )
    .unwrap();
    assert!(crypto::open(&wrong_profile, store.header, &store.key).is_err());
    let self_pin = peers(7);
    let bytes = crypto::seal(store.header, &store.key, &store.identity, &self_pin).unwrap();
    assert!(crypto::open(&bytes, store.header, &store.key).is_err());
}

#[test]
fn rollback_substitution_corruption_missing_files_and_single_owner() {
    let _serial = VAULT.lock().unwrap();
    let (_temp, dir, mut store) = fixture();
    let cp = store.checkpoint().unwrap();
    let path = dir.path("peer").unwrap();
    let before = sqlite::read(&store.db).unwrap();
    assert!(IdentityStore::open(&dir, "peer", &password(), cp).is_err());
    assert_eq!(
        IdentityStore::create(&dir, "peer", &password(), peers(11)).err(),
        Some(StoreError::AlreadyExists)
    );
    let latest = store.replace_configuration(peers(12)).unwrap();
    store
        .db
        .execute("UPDATE identity SET envelope=?1", rusqlite::params![before])
        .unwrap();
    drop(store);
    assert_eq!(
        IdentityStore::open(&dir, "peer", &password(), latest).err(),
        Some(StoreError::Invalid)
    );
    // An old trusted receipt cannot detect a rollback to an older valid file.
    let old = IdentityStore::open(&dir, "peer", &password(), cp).unwrap();
    assert_eq!(old.configuration().unwrap(), &peers(11));
    old.db
        .execute("UPDATE identity SET envelope=zeroblob(100000)", [])
        .unwrap();
    drop(old);
    assert_eq!(
        IdentityStore::open(&dir, "peer", &password(), cp).err(),
        Some(StoreError::Invalid)
    );
    let missing = dir.path("missing").unwrap();
    assert!(IdentityStore::open(&dir, "missing", &password(), cp).is_err());
    assert!(!missing.exists());
    let mut bytes = fs::read(&path).unwrap();
    bytes.truncate(100);
    fs::write(&path, bytes).unwrap();
    assert!(IdentityStore::open(&dir, "peer", &password(), cp).is_err());
}

#[test]
fn rejected_configurations_do_not_mutate_and_write_errors_poison() {
    let _serial = VAULT.lock().unwrap();
    let (_temp, _dir, mut store) = fixture();
    let cp = store.checkpoint().unwrap();
    for invalid in [TrustedPeers::empty([3; 32]), peers(7)] {
        assert_eq!(
            store.replace_configuration(invalid),
            Err(StoreError::Invalid)
        );
        assert_eq!(store.checkpoint().unwrap(), cp);
    }
    store.header.checkpoint.revision = u64::MAX;
    assert_eq!(
        store.replace_configuration(peers(12)),
        Err(StoreError::Capacity)
    );
    store.header.checkpoint = cp;
    store.db.execute_batch("PRAGMA query_only=ON;").unwrap();
    assert!(store.replace_configuration(peers(12)).is_err());
    assert_eq!(store.checkpoint(), Err(StoreError::Poisoned));
    assert_eq!(store.configuration().err(), Some(StoreError::Poisoned));
    assert_eq!(
        store.change_password(&next_password()),
        Err(StoreError::Poisoned)
    );
    assert_eq!(
        store.into_driver().err().map(|e| e == StoreError::Poisoned),
        Some(true)
    );
}

#[test]
fn unsafe_names_passwords_and_sidecars_are_rejected() {
    let _serial = VAULT.lock().unwrap();
    let (_temp, dir, store) = fixture();
    for name in [
        "",
        "..",
        "../escape",
        "a/b",
        "a\\b",
        "C:escape",
        "con",
        "COM1",
        "LPT9",
        "name.",
        "a b",
        "é",
    ] {
        assert_eq!(dir.path(name).err(), Some(StoreError::InvalidName));
    }
    for len in [0, 11, 1025] {
        assert_eq!(
            Password::from_bytes(&vec![7; len]).err(),
            Some(StoreError::PasswordPolicy)
        );
    }
    assert_eq!(format!("{:?}", password()), "Password([REDACTED])");
    let cp = store.checkpoint().unwrap();
    drop(store);
    fs::create_dir(dir.root.join("peer.monp-wal")).unwrap();
    assert_eq!(
        IdentityStore::open(&dir, "peer", &password(), cp).err(),
        Some(StoreError::Invalid)
    );
    fs::remove_dir(dir.root.join("peer.monp-wal")).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(dir.path("peer").unwrap(), dir.root.join("alias.monp")).unwrap();
        assert!(IdentityStore::open(&dir, "alias", &password(), cp).is_err());
        fs::hard_link(dir.path("peer").unwrap(), dir.root.join("hard.monp")).unwrap();
        assert!(IdentityStore::open(&dir, "hard", &password(), cp).is_err());
    }
}

#[test]
fn persisted_identity_interoperates_and_driver_keeps_exclusive_owner_without_network() {
    let _serial = VAULT.lock().unwrap();
    let (_temp, dir, mut store) = fixture();
    let (_nd, mut n) = crate::tests::node();
    let config = TrustedPeers::empty(n.profile);
    // Provision a distinct profile-bound store, using the public create API/CSPRNG.
    let other = IdentityStore::create(&dir, "runtime", &password(), config).unwrap();
    let cp = other.checkpoint().unwrap();
    let driver = other.into_driver().unwrap();
    assert_eq!(driver.checkpoint().unwrap(), cp);
    assert!(IdentityStore::open(&dir, "runtime", &password(), cp).is_err());
    driver.run(&mut n, &AtomicBool::new(true)).unwrap();
    assert!(n.stopped());
    drop(driver);
    let reopened = IdentityStore::open(&dir, "runtime", &password(), cp).unwrap();
    assert_eq!(reopened.checkpoint().unwrap().public_key, cp.public_key);
    drop(reopened);
    // A persisted identity completes the real encrypted protocol under its original pin.
    let cp = store.checkpoint().unwrap();
    drop(store);
    store = IdentityStore::open(&dir, "peer", &password(), cp).unwrap();
    let (a, b) = super::super::tests::memory_pair();
    let client = Identity::from_secret(Zeroizing::new([12; 32]));
    let mut a = super::super::SecureConnection::new(
        a,
        &client,
        super::super::Role::Initiator {
            remote_key: cp.public_key,
        },
        PROFILE,
        0,
    )
    .unwrap();
    let mut b = super::super::SecureConnection::new(
        b,
        &store.identity,
        super::super::Role::Responder,
        PROFILE,
        0,
    )
    .unwrap();
    for ms in 0..100 {
        a.inner.stream.advance(ms).unwrap();
        b.inner.stream.advance(ms).unwrap();
    }
    assert!(a.inner.stream.established && b.inner.stream.established);
}

#[test]
fn identity_crash_worker() {
    let Some(root) = std::env::var_os("MONAR_IDENTITY_CRASH_DIR") else {
        return;
    };
    let phase = std::env::var("MONAR_IDENTITY_CRASH_PHASE").unwrap() == "after";
    let operation = std::env::var("MONAR_IDENTITY_CRASH_OPERATION").unwrap();
    let dir = IdentityDirectory::open(Path::new(&root)).unwrap();
    let cp = Checkpoint {
        profile: PROFILE,
        public_key: identity().public_key(),
        revision: 0,
    };
    let hook = |committed| {
        if committed == phase {
            std::process::exit(if phase { 82 } else { 81 });
        }
    };
    if operation == "create" {
        IdentityStore::create_inner(&dir, "peer", &password(), peers(11), identity(), hook)
            .unwrap();
    } else {
        let mut store = IdentityStore::open(&dir, "peer", &password(), cp).unwrap();
        if operation == "config" {
            store.replace_inner(peers(12), hook).unwrap();
        } else {
            assert_eq!(operation, "password");
            store.password_inner(&next_password(), hook).unwrap();
        }
    }
    panic!("crash hook did not run");
}

#[test]
fn process_death_before_and_after_commits_preserves_identity_and_pins() {
    let _serial = VAULT.lock().unwrap();
    for operation in ["create", "config", "password"] {
        for after in [false, true] {
            let temp = private_tempdir();
            let dir = IdentityDirectory::open(temp.path()).unwrap();
            let cp = Checkpoint {
                profile: PROFILE,
                public_key: identity().public_key(),
                revision: 0,
            };
            if operation != "create" {
                drop(
                    IdentityStore::create_inner(
                        &dir,
                        "peer",
                        &password(),
                        peers(11),
                        identity(),
                        |_| {},
                    )
                    .unwrap(),
                );
            }
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "transport::encrypted::persistent::tests::identity_crash_worker",
                ])
                .env("MONAR_IDENTITY_CRASH_DIR", temp.path())
                .env(
                    "MONAR_IDENTITY_CRASH_PHASE",
                    if after { "after" } else { "before" },
                )
                .env("MONAR_IDENTITY_CRASH_OPERATION", operation)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(if after { 82 } else { 81 }));
            for entry in fs::read_dir(temp.path()).unwrap() {
                let bytes = fs::read(entry.unwrap().path()).unwrap();
                for secret in [
                    [7; 32].as_slice(),
                    b"public test password only",
                    b"public rotated password only",
                ] {
                    assert!(!bytes.windows(secret.len()).any(|w| w == secret));
                }
            }
            if operation == "create" && !after {
                assert!(IdentityStore::open(&dir, "peer", &password(), cp).is_err());
                assert!(IdentityStore::create(&dir, "peer", &password(), peers(11)).is_err());
            } else {
                let credentials = if operation == "password" && after {
                    next_password()
                } else {
                    password()
                };
                let reopened = IdentityStore::open(&dir, "peer", &credentials, cp).unwrap();
                let expected_revision = u64::from(operation != "create" && after);
                assert_eq!(
                    reopened.checkpoint().unwrap(),
                    Checkpoint {
                        revision: expected_revision,
                        ..cp
                    }
                );
                assert_eq!(
                    reopened.configuration().unwrap(),
                    &peers(if operation == "config" && after {
                        12
                    } else {
                        11
                    })
                );
                drop(reopened);
                if operation == "password" {
                    assert!(
                        IdentityStore::open(
                            &dir,
                            "peer",
                            &if after { password() } else { next_password() },
                            cp
                        )
                        .is_err()
                    );
                }
            }
        }
    }
}

#[test]
fn checkpoint_hex_roundtrips_without_secret_material() {
    assert_eq!(key(&hex(&peer_key(7))).unwrap(), peer_key(7));
    assert!(key(&"f".repeat(65)).is_err());
    assert!(key(&"é".repeat(32)).is_err());
}

#[test]
fn extra_schema_objects_cannot_hide_behind_sqlite_name_prefixes() {
    let _serial = VAULT.lock().unwrap();
    for sql in ["CREATE TABLE extra(x)", "CREATE TABLE sqliteevil(x)"] {
        let (_temp, dir, store) = fixture();
        let cp = store.checkpoint().unwrap();
        store.db.execute_batch(sql).unwrap();
        drop(store);
        assert_eq!(
            IdentityStore::open(&dir, "peer", &password(), cp).err(),
            Some(StoreError::Invalid)
        );
    }
}

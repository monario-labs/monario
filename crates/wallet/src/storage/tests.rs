//! Public passwords/seeds and temporary files only. No real wallet is created.
use super::*;
fn password() -> Password {
    Password::from_bytes(b"public test password only").unwrap()
}
fn backup_password() -> Password {
    Password::from_bytes(b"public backup password only").unwrap()
}
fn seed() -> Seed {
    Seed::from_bytes(&[7; 32]).unwrap()
}
fn fixture() -> (tempfile::TempDir, WalletDirectory, WalletStore) {
    let temp = tempfile::tempdir().unwrap();
    let dir = WalletDirectory::open(temp.path()).unwrap();
    let store = WalletStore::create(&dir, "wallet", seed(), Network::Main, &password()).unwrap();
    (temp, dir, store)
}
#[test]
fn unexpected_schema_objects_including_sqlite_prefixes_are_rejected() {
    for sql in [
        "CREATE TABLE sqliteevil(x)",
        "CREATE TABLE SqlItEeViL(x)",
        "CREATE VIEW sqliteevil AS SELECT singleton FROM vault",
        "CREATE INDEX sqliteevil ON vault(singleton)",
        "CREATE TRIGGER sqliteevil BEFORE UPDATE ON vault BEGIN SELECT RAISE(ABORT,'unexpected trigger'); END",
        "CREATE TABLE extra(x)",
        "CREATE TABLE scan_cache(x)",
        "ANALYZE",
    ] {
        let (_temp, dir, store) = fixture();
        let cp = store.checkpoint().unwrap();
        let envelope = read_record(&store.db).unwrap();
        store.db.execute_batch(sql).unwrap();
        drop(store);
        let path = dir.path("wallet").unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(
            WalletStore::open(&dir, "wallet", &password(), cp).err(),
            Some(StorageError::Invalid),
            "{sql}"
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(read_record(&db).unwrap(), envelope);
    }
}
#[test]
fn unexpected_backup_schema_rejects_before_creating_recovery_destination() {
    let (_temp, dir, store) = fixture();
    let cp = store.backup(&dir, "backup", &backup_password()).unwrap();
    let db = connect(&dir.path("backup").unwrap(), false).unwrap();
    db.execute_batch("CREATE TABLE sqliteevil(x)").unwrap();
    drop(db);
    let before = fs::read(dir.path("backup").unwrap()).unwrap();
    assert_eq!(
        WalletStore::recover(
            &dir,
            "backup",
            &backup_password(),
            cp,
            &dir,
            "recovered",
            &password()
        )
        .err(),
        Some(StorageError::Invalid)
    );
    assert!(!dir.path("recovered").unwrap().exists());
    assert_eq!(fs::read(dir.path("backup").unwrap()).unwrap(), before);
    assert_eq!(store.expose_seed().unwrap().expose_for_backup(), [7; 32]);
}
#[test]
fn encrypted_roundtrip_reserves_all_types_before_return() {
    let (_temp, dir, mut store) = fixture();
    let initial = store.checkpoint().unwrap();
    let mut expected = 0;
    let mut nonces = std::collections::BTreeSet::new();
    for kind in [AddressKind::Transparent, AddressKind::Private] {
        for scope in [Scope::External, Scope::Internal] {
            let issued = store.next_address(0, scope, kind).unwrap();
            expected += 1;
            assert_eq!(issued.index, 0);
            assert_eq!(issued.checkpoint.revision, expected);
            assert!(nonces.insert(read_record(&store.db).unwrap()[70..94].to_vec()));
            let address = match kind {
                AddressKind::Transparent => seed()
                    .transparent_key(Network::Main, 0, scope, 0)
                    .unwrap()
                    .address(),
                AddressKind::Private => seed()
                    .private_account(Network::Main, 0)
                    .unwrap()
                    .address(scope, 0)
                    .unwrap(),
            };
            assert_eq!(issued.address, address);
        }
    }
    let cp = store.checkpoint().unwrap();
    let before = store.account_progress().unwrap().clone();
    drop(store);
    let bytes = fs::read(dir.path("wallet").unwrap()).unwrap();
    assert!(!bytes.windows(32).any(|b| b == [7; 32]));
    assert!(!bytes.windows(25).any(|b| b == b"public test password only"));
    let mut store = WalletStore::open(&dir, "wallet", &password(), initial).unwrap();
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert_eq!(store.account_progress().unwrap(), &before);
    assert_eq!(store.expose_seed().unwrap().expose_for_backup(), [7; 32]);
    assert_eq!(
        store
            .next_address(0, Scope::External, AddressKind::Private)
            .unwrap()
            .index,
        1
    );
}
#[test]
fn passwords_identity_rollback_and_single_owner_fail_closed() {
    let (_temp, dir, mut store) = fixture();
    let cp = store.checkpoint().unwrap();
    assert!(WalletStore::open(&dir, "wallet", &password(), cp).is_err());
    drop(store);
    assert!(matches!(
        WalletStore::open(&dir, "wallet", &backup_password(), cp),
        Err(StorageError::Invalid)
    ));
    for expected in [
        WalletCheckpoint {
            wallet_id: [0; 16],
            ..cp
        },
        WalletCheckpoint {
            network: Network::Test,
            ..cp
        },
        WalletCheckpoint { revision: 1, ..cp },
    ] {
        assert!(matches!(
            WalletStore::open(&dir, "wallet", &password(), expected),
            Err(StorageError::Invalid)
        ));
    }
    store = WalletStore::open(&dir, "wallet", &password(), cp).unwrap();
    let old = read_record(&store.db).unwrap();
    let fresh = store
        .next_address(0, Scope::External, AddressKind::Transparent)
        .unwrap()
        .checkpoint;
    store
        .db
        .execute("UPDATE vault SET envelope=?1", params![old])
        .unwrap();
    drop(store);
    assert!(matches!(
        WalletStore::open(&dir, "wallet", &password(), fresh),
        Err(StorageError::Invalid)
    ));
}
#[test]
fn backup_restore_blocks_issuance_until_trusted_high_water_marks() {
    let (_temp, dir, mut store) = fixture();
    store
        .next_address(0, Scope::External, AddressKind::Transparent)
        .unwrap();
    let backup = store.backup(&dir, "backup", &backup_password()).unwrap();
    store
        .next_address(0, Scope::External, AddressKind::Transparent)
        .unwrap();
    store
        .next_address(1, Scope::Internal, AddressKind::Private)
        .unwrap();
    let latest = store.checkpoint().unwrap();
    let progress = store.account_progress().unwrap().clone();
    assert!(WalletStore::open(&dir, "backup", &backup_password(), backup).is_err());
    let mut restored = WalletStore::recover(
        &dir,
        "backup",
        &backup_password(),
        backup,
        &dir,
        "restored",
        &password(),
    )
    .unwrap();
    assert_eq!(restored.expose_seed().unwrap().expose_for_backup(), [7; 32]);
    assert_eq!(
        restored
            .next_address(0, Scope::External, AddressKind::Transparent)
            .err(),
        Some(StorageError::RecoveryRequired)
    );
    let cp = restored.checkpoint().unwrap();
    drop(restored);
    let mut restored = WalletStore::open(&dir, "restored", &password(), cp).unwrap();
    assert!(restored.recovery_required().unwrap());
    let missing = RecoveryPlan::from_trusted_scan(BTreeMap::new(), latest.revision).unwrap();
    assert_eq!(
        restored.finish_recovery(missing),
        Err(StorageError::Invalid)
    );
    let mut lower = BTreeMap::new();
    lower.insert(0, AccountProgress::default());
    assert_eq!(
        restored.finish_recovery(RecoveryPlan::from_trusted_scan(lower, latest.revision).unwrap()),
        Err(StorageError::Invalid)
    );
    assert_eq!(
        restored.finish_recovery(
            RecoveryPlan::from_trusted_scan(progress.clone(), u64::MAX)
                .unwrap()
                .with_trusted_reservations(BTreeMap::new())
                .unwrap()
        ),
        Err(StorageError::Capacity)
    );
    let floor = RecoveryPlan::from_trusted_scan(progress, latest.revision)
        .unwrap()
        .with_trusted_reservations(BTreeMap::new())
        .unwrap();
    let final_cp = restored.finish_recovery(floor).unwrap();
    assert!(final_cp.revision > latest.revision);
    assert_eq!(
        restored
            .next_address(0, Scope::External, AddressKind::Transparent)
            .unwrap()
            .index,
        2
    );
    assert_eq!(
        restored
            .next_address(1, Scope::Internal, AddressKind::Private)
            .unwrap()
            .index,
        1
    );
    assert_eq!(
        store.backup(&dir, "backup", &backup_password()),
        Err(StorageError::AlreadyExists)
    );
}

#[test]
fn independent_libsodium_envelope_and_64_byte_seed_roundtrip() {
    let envelope = include_bytes!("../../tests/storage-v1.bin");
    let checkpoint = WalletCheckpoint {
        wallet_id: core::array::from_fn(|i| i as u8),
        network: Network::Main,
        revision: 9,
    };
    let header = crypto::header(envelope, checkpoint, 0).unwrap();
    let key = crypto::derive(
        &Password::from_bytes(b"public storage interoperability password").unwrap(),
        &header.salt,
    )
    .unwrap();
    let plain = crypto::decrypt(envelope, header, &key).unwrap();
    let decoded = state::decode(&plain).unwrap();
    assert_eq!(decoded.seed.expose_for_backup(), [7; 32]);
    assert_eq!(
        decoded.accounts.get(&0),
        Some(&AccountProgress {
            transparent_external: 3,
            transparent_internal: 1,
            private_external: 2,
            private_internal: 4
        })
    );
    assert!(!decoded.recovery);
    let temp = tempfile::tempdir().unwrap();
    let dir = WalletDirectory::open(temp.path()).unwrap();
    let public_seed: Vec<u8> = (0..64).collect();
    let store = WalletStore::create(
        &dir,
        "long_seed",
        Seed::from_bytes(&public_seed).unwrap(),
        Network::Regtest,
        &password(),
    )
    .unwrap();
    let cp = store.checkpoint().unwrap();
    drop(store);
    let store = WalletStore::open(&dir, "long_seed", &password(), cp).unwrap();
    assert_eq!(
        store.expose_seed().unwrap().expose_for_backup(),
        public_seed
    );
}
#[test]
fn password_rotation_preserves_seed_indices_and_rejects_old_credentials() {
    let (_temp, dir, mut store) = fixture();
    let cp = store.checkpoint().unwrap();
    store
        .next_address(0, Scope::External, AddressKind::Private)
        .unwrap();
    let old = read_record(&store.db).unwrap();
    let fresh = store.change_password(&backup_password()).unwrap();
    let new = read_record(&store.db).unwrap();
    assert_ne!(&old[54..70], &new[54..70]);
    assert_ne!(&old[70..94], &new[70..94]);
    drop(store);
    assert!(WalletStore::open(&dir, "wallet", &password(), fresh).is_err());
    let mut store = WalletStore::open(&dir, "wallet", &backup_password(), cp).unwrap();
    assert_eq!(
        store
            .next_address(0, Scope::External, AddressKind::Private)
            .unwrap()
            .index,
        1
    );
    assert_eq!(store.expose_seed().unwrap().expose_for_backup(), [7; 32]);
}
#[test]
fn failed_write_poisoning_and_no_plaintext_in_journal() {
    let (_temp, dir, mut store) = fixture();
    let cp = store.checkpoint().unwrap();
    let original = read_record(&store.db).unwrap();
    store.db.execute_batch("CREATE TRIGGER fail_write BEFORE UPDATE ON vault BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert_eq!(
        store
            .next_address(0, Scope::External, AddressKind::Transparent)
            .err(),
        Some(StorageError::Storage)
    );
    assert_eq!(read_record(&store.db).unwrap(), original);
    assert_eq!(store.expose_seed().err(), Some(StorageError::Poisoned));
    assert_eq!(store.checkpoint(), Err(StorageError::Poisoned));
    assert_eq!(
        store.backup(&dir, "badbackup", &password()),
        Err(StorageError::Poisoned)
    );
    store.db.execute_batch("DROP TRIGGER fail_write").unwrap();
    drop(store);
    let mut reopened = WalletStore::open(&dir, "wallet", &password(), cp).unwrap();
    assert_eq!(
        reopened
            .next_address(0, Scope::External, AddressKind::Transparent)
            .unwrap()
            .index,
        0
    );
}
#[test]
fn malformed_envelopes_and_authenticated_state_are_bounded() {
    let (_temp, dir, store) = fixture();
    let cp = store.checkpoint().unwrap();
    let original = read_record(&store.db).unwrap();
    for end in 0..original.len() {
        assert!(crypto::header(&original[..end], cp, 0).is_err());
    }
    for offset in [
        0,
        8,
        9,
        10,
        11,
        12,
        16,
        20,
        24,
        40,
        41,
        42,
        46,
        54,
        70,
        94,
        crypto::TOTAL - 1,
    ] {
        let mut changed = original.clone();
        changed[offset] ^= 128;
        if let Ok(header) = crypto::header(&changed, cp, 0) {
            assert!(crypto::decrypt(&changed, header, &store.key).is_err());
        }
    }
    assert_eq!(
        crypto::header(&[original.as_slice(), &[0]].concat(), cp, 0).err(),
        Some(StorageError::Invalid)
    );
    let plain = state::encode(&seed(), &BTreeMap::new(), false).unwrap();
    for end in [0, 1, 32, crypto::PLAIN_LEN - 1] {
        assert!(state::decode(&plain[..end]).is_err());
    }
    let mut bad = plain.to_vec();
    bad[0] = 2;
    assert!(state::decode(&bad).is_err());
    let mut bad = plain.to_vec();
    bad[34..36].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(state::decode(&bad).is_err());
    let mut bad = plain.to_vec();
    bad[crypto::PLAIN_LEN - 1] = 1;
    assert!(state::decode(&bad).is_err());
    store
        .db
        .execute("UPDATE vault SET envelope=zeroblob(1000000)", [])
        .unwrap();
    drop(store);
    assert!(WalletStore::open(&dir, "wallet", &password(), cp).is_err());
}
#[test]
fn exhausted_indices_capacity_and_untrusted_names_never_wrap() {
    let (_temp, dir, mut store) = fixture();
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
        assert_eq!(dir.path(name).err(), Some(StorageError::InvalidName));
    }
    for len in [0, 11, 1025] {
        assert!(matches!(
            Password::from_bytes(&vec![7; len]),
            Err(StorageError::PasswordPolicy)
        ));
    }
    assert_eq!(format!("{:?}", password()), "Password([REDACTED])");
    let p = AccountProgress {
        transparent_external: state::T_END,
        private_internal: state::P_END,
        ..AccountProgress::default()
    };
    store.state.accounts.insert(0, p);
    assert_eq!(
        store
            .next_address(0, Scope::External, AddressKind::Transparent)
            .err(),
        Some(StorageError::Exhausted)
    );
    assert_eq!(
        store
            .next_address(0, Scope::Internal, AddressKind::Private)
            .err(),
        Some(StorageError::Exhausted)
    );
    assert_eq!(store.account_progress().unwrap().get(&0), Some(&p));
    let mut bad = BTreeMap::new();
    bad.insert(
        0,
        AccountProgress {
            private_external: state::P_END + 1,
            ..p
        },
    );
    assert!(RecoveryPlan::from_trusted_scan(bad, 0).is_err());
    for id in 1..state::MAX_ACCOUNTS as u32 {
        store.state.accounts.insert(id, AccountProgress::default());
    }
    assert_eq!(
        store
            .next_address(999, Scope::External, AddressKind::Transparent)
            .err(),
        Some(StorageError::Capacity)
    );
    assert_eq!(
        WalletStore::create(&dir, "wallet", seed(), Network::Main, &password()).err(),
        Some(StorageError::AlreadyExists)
    );
}
#[test]
fn crash_worker() {
    let Some(root) = std::env::var_os("MONAR_WALLET_CRASH_DIR") else {
        return;
    };
    let id = std::env::var("MONAR_WALLET_CRASH_ID").unwrap();
    let mut wallet_id = [0; 16];
    for (i, part) in id.as_bytes().chunks_exact(2).enumerate() {
        wallet_id[i] = u8::from_str_radix(core::str::from_utf8(part).unwrap(), 16).unwrap();
    }
    let dir = WalletDirectory::open(Path::new(&root)).unwrap();
    let cp = WalletCheckpoint {
        wallet_id,
        network: Network::Main,
        revision: 0,
    };
    let mut store = WalletStore::open(&dir, "wallet", &password(), cp).unwrap();
    let after = std::env::var("MONAR_WALLET_CRASH_PHASE").unwrap() == "after";
    let hook = |committed| {
        if committed == after {
            std::process::exit(if after { 82 } else { 81 });
        }
    };
    match std::env::var("MONAR_WALLET_CRASH_OPERATION")
        .unwrap()
        .as_str()
    {
        "scan-cache" => {
            store
                .save_scan_cache_inner([9; 32], b"new public derived cache", hook)
                .unwrap();
        }
        "issue" => {
            store
                .issue(0, Scope::External, AddressKind::Transparent, hook)
                .unwrap();
        }
        "password" => {
            store
                .change_password_inner(&backup_password(), hook)
                .unwrap();
        }
        "backup" => {
            store
                .backup_inner(&dir, "backup", &backup_password(), hook)
                .unwrap();
        }
        operation @ ("schema-table" | "schema-trigger") => {
            let tx = store.db.transaction().unwrap();
            tx.execute_batch(if operation == "schema-table" {
                "CREATE TABLE sqliteevil(x)"
            } else {
                "CREATE TRIGGER sqliteevil BEFORE UPDATE ON vault BEGIN SELECT RAISE(ABORT,'unexpected trigger'); END"
            }).unwrap();
            hook(false);
            tx.commit().unwrap();
            hook(true);
        }
        _ => panic!("unknown crash operation"),
    }
    panic!("crash hook did not execute");
}
#[test]
fn process_death_before_and_after_commit_recovers_wallet_password_and_backup() {
    for operation in ["issue", "password", "backup"] {
        for (phase, code, committed) in [("before", 81, false), ("after", 82, true)] {
            let (temp, dir, store) = fixture();
            let cp = store.checkpoint().unwrap();
            drop(store);
            let id: String = cp.wallet_id.iter().map(|b| format!("{b:02x}")).collect();
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "storage::tests::crash_worker", "--nocapture"])
                .env("MONAR_WALLET_CRASH_DIR", temp.path())
                .env("MONAR_WALLET_CRASH_ID", id)
                .env("MONAR_WALLET_CRASH_PHASE", phase)
                .env("MONAR_WALLET_CRASH_OPERATION", operation)
                .status()
                .unwrap();
            assert_eq!(result.code(), Some(code));
            let credentials = if operation == "password" && committed {
                backup_password()
            } else {
                password()
            };
            let mut reopened = WalletStore::open(&dir, "wallet", &credentials, cp).unwrap();
            assert_eq!(reopened.expose_seed().unwrap().expose_for_backup(), [7; 32]);
            let next = reopened
                .next_address(0, Scope::External, AddressKind::Transparent)
                .unwrap();
            assert_eq!(
                next.index,
                if operation == "issue" && committed {
                    1
                } else {
                    0
                }
            );
            if operation == "backup" {
                let result = WalletStore::recover(
                    &dir,
                    "backup",
                    &backup_password(),
                    cp,
                    &dir,
                    "recovered",
                    &password(),
                );
                assert_eq!(result.is_ok(), committed);
                if let Ok(restored) = result {
                    assert!(restored.recovery_required().unwrap());
                }
            }
            for name in [
                "wallet.monw",
                "wallet.monw-journal",
                "backup.monw",
                "backup.monw-journal",
            ] {
                if let Ok(bytes) = fs::read(temp.path().join(name)) {
                    assert!(!bytes.windows(32).any(|b| b == [7; 32]));
                }
            }
        }
    }
}

#[test]
fn schema_changes_around_process_death_recover_or_fail_closed() {
    for operation in ["schema-table", "schema-trigger"] {
        for (phase, code, committed) in [("before", 81, false), ("after", 82, true)] {
            let (temp, dir, store) = fixture();
            let cp = store.checkpoint().unwrap();
            let envelope = read_record(&store.db).unwrap();
            drop(store);
            let id: String = cp.wallet_id.iter().map(|b| format!("{b:02x}")).collect();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "storage::tests::crash_worker"])
                .env("MONAR_WALLET_CRASH_DIR", temp.path())
                .env("MONAR_WALLET_CRASH_ID", id)
                .env("MONAR_WALLET_CRASH_PHASE", phase)
                .env("MONAR_WALLET_CRASH_OPERATION", operation)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(code));
            for entry in fs::read_dir(temp.path()).unwrap() {
                let bytes = fs::read(entry.unwrap().path()).unwrap();
                for secret in [[7; 32].as_slice(), b"public test password only"] {
                    assert!(!bytes.windows(secret.len()).any(|b| b == secret));
                }
            }
            let opened = WalletStore::open(&dir, "wallet", &password(), cp);
            if committed {
                assert_eq!(opened.err(), Some(StorageError::Invalid));
                let db = Connection::open_with_flags(
                    dir.path("wallet").unwrap(),
                    OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .unwrap();
                assert_eq!(read_record(&db).unwrap(), envelope);
            } else {
                let mut reopened = opened.unwrap();
                assert_eq!(reopened.checkpoint().unwrap(), cp);
                assert_eq!(reopened.expose_seed().unwrap().expose_for_backup(), [7; 32]);
                assert_eq!(read_record(&reopened.db).unwrap(), envelope);
                let address = reopened
                    .next_address(0, Scope::External, AddressKind::Transparent)
                    .unwrap();
                assert_eq!(address.index, 0);
                assert_eq!(address.checkpoint.revision, cp.revision + 1);
            }
        }
    }
}

#[test]
fn encrypted_scan_cache_authentication_scope_rotation_and_backup() {
    let (temp, dir, mut store) = fixture();
    let cp = store.checkpoint().unwrap();
    let envelope = read_record(&store.db).unwrap();
    assert!(store.load_scan_cache([9; 32]).unwrap().is_none());
    let marker = b"public private-note test cache marker";
    store.save_scan_cache([9; 32], marker).unwrap();
    assert_eq!(
        store.load_scan_cache([9; 32]).unwrap().unwrap().as_slice(),
        marker
    );
    assert!(store.load_scan_cache([8; 32]).unwrap().is_none());
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert_eq!(read_record(&store.db).unwrap(), envelope);
    assert_eq!(
        store.save_scan_cache([9; 32], &vec![0; 4 * 1024 * 1024 + 1]),
        Err(StorageError::Capacity)
    );
    let backup = store.backup(&dir, "backup", &backup_password()).unwrap();
    let recovered = WalletStore::recover(
        &dir,
        "backup",
        &backup_password(),
        backup,
        &dir,
        "recovered",
        &password(),
    )
    .unwrap();
    assert!(recovered.load_scan_cache([9; 32]).unwrap().is_none());
    drop(recovered);
    let cp = store.change_password(&backup_password()).unwrap();
    drop(store);
    let store = WalletStore::open(&dir, "wallet", &backup_password(), cp).unwrap();
    assert_eq!(
        store.load_scan_cache([9; 32]).unwrap().unwrap().as_slice(),
        marker
    );
    for entry in fs::read_dir(temp.path()).unwrap() {
        let b = fs::read(entry.unwrap().path()).unwrap();
        assert!(!b.windows(marker.len()).any(|v| v == marker));
    }
    let original: Vec<u8> = store
        .db
        .query_row("SELECT envelope FROM scan_cache", [], |r| r.get(0))
        .unwrap();
    let other = WalletStore::create(&dir, "other", seed(), Network::Main, &password()).unwrap();
    other.save_scan_cache([9; 32], marker).unwrap();
    other
        .db
        .execute("UPDATE scan_cache SET envelope=?1", [&original])
        .unwrap();
    assert_eq!(
        other.load_scan_cache([9; 32]).err(),
        Some(StorageError::Invalid)
    );
    drop(other);
    for position in [0, 32, 56, original.len() - 1] {
        let mut bad = original.clone();
        bad[position] ^= 1;
        store
            .db
            .execute("UPDATE scan_cache SET envelope=?1", [bad])
            .unwrap();
        assert_eq!(
            store.load_scan_cache([9; 32]).err(),
            Some(StorageError::Invalid)
        );
    }
    store.save_scan_cache([9; 32], marker).unwrap();
    assert!(store.load_scan_cache([9; 32]).is_ok());
}

#[test]
fn scan_cache_process_death_preserves_old_or_new_and_wallet_claims() {
    for initialized in [false, true] {
        for (phase, code, committed) in [("before", 81, false), ("after", 82, true)] {
            let (temp, dir, mut store) = fixture();
            let token = store
                .reserve_inputs(
                    [2; 32],
                    [3; 32],
                    100,
                    vec![pending::Input::Transparent {
                        transaction: [4; 32],
                        index: 0,
                    }],
                )
                .unwrap();
            store
                .bind_reservation(token, [5; 32], b"public signed-byte fixture")
                .unwrap();
            let cp = store.checkpoint().unwrap();
            let envelope = read_record(&store.db).unwrap();
            if initialized {
                store
                    .save_scan_cache([9; 32], b"old public derived cache")
                    .unwrap();
            }
            drop(store);
            let id: String = cp.wallet_id.iter().map(|b| format!("{b:02x}")).collect();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "storage::tests::crash_worker"])
                .env("MONAR_WALLET_CRASH_DIR", temp.path())
                .env("MONAR_WALLET_CRASH_ID", id)
                .env("MONAR_WALLET_CRASH_PHASE", phase)
                .env("MONAR_WALLET_CRASH_OPERATION", "scan-cache")
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(code));
            let store = WalletStore::open(&dir, "wallet", &password(), cp).unwrap();
            let cache = store.load_scan_cache([9; 32]).unwrap();
            let expected = if committed {
                Some(b"new public derived cache".as_slice())
            } else if initialized {
                Some(b"old public derived cache".as_slice())
            } else {
                None
            };
            assert_eq!(cache.as_deref().map(|b| b.as_slice()), expected);
            assert_eq!(read_record(&store.db).unwrap(), envelope);
            assert_eq!(store.checkpoint().unwrap(), cp);
            assert_eq!(store.reservations().unwrap().len(), 1);
            assert_eq!(
                store.reservations().unwrap()[&token].expose_transaction(),
                Some(b"public signed-byte fixture".as_slice())
            );
        }
    }
}

#[test]
fn scan_cache_growth_ceiling_accounts_for_sqlite_page_size() {
    let (_temp, dir, store) = fixture();
    let cp = store.checkpoint().unwrap();
    drop(store);
    let db = Connection::open(dir.path("wallet").unwrap()).unwrap();
    db.execute_batch("PRAGMA page_size=65536; VACUUM;").unwrap();
    drop(db);
    let store = WalletStore::open(&dir, "wallet", &password(), cp).unwrap();
    store
        .save_scan_cache([9; 32], b"public page-size fixture")
        .unwrap();
    let page_size: i64 = store
        .db
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .unwrap();
    let pages: i64 = store
        .db
        .query_row("PRAGMA max_page_count", [], |r| r.get(0))
        .unwrap();
    assert_eq!(page_size, 65536);
    assert_eq!(page_size * pages, 16 * 1024 * 1024);
    assert_eq!(
        store.load_scan_cache([9; 32]).unwrap().unwrap().as_slice(),
        b"public page-size fixture"
    );
}

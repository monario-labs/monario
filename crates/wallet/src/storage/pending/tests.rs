use super::*;
fn password() -> Password {
    Password::from_bytes(b"public pending wallet test password").unwrap()
}
fn fixture() -> (tempfile::TempDir, WalletDirectory, WalletStore) {
    let temp = tempfile::tempdir().unwrap();
    let dir = WalletDirectory::open(temp.path()).unwrap();
    let store = WalletStore::create(
        &dir,
        "pending",
        Seed::from_bytes(&[7; 32]).unwrap(),
        Network::Main,
        &password(),
    )
    .unwrap();
    (temp, dir, store)
}
fn input() -> Input {
    Input::Transparent {
        transaction: [31; 32],
        index: 7,
    }
}
#[test]
fn reservations_conflict_bind_backup_recovery_and_cancellation() {
    let (_temp, dir, mut wallet) = fixture();
    let token = wallet
        .reserve_inputs(
            [1; 32],
            [2; 32],
            100,
            vec![
                input(),
                Input::Private {
                    nullifier: [32; 32],
                },
            ],
        )
        .unwrap();
    assert_eq!(
        wallet.reserve_inputs([1; 32], [2; 32], 100, vec![input()]),
        Err(StorageError::InputReserved)
    );
    wallet.cancel_unsigned_reservation(token).unwrap();
    let token = wallet
        .reserve_inputs([1; 32], [2; 32], 100, vec![input()])
        .unwrap();
    let checkpoint = wallet
        .bind_reservation(token, [3; 32], b"public signed fixture")
        .unwrap();
    assert!(wallet.cancel_unsigned_reservation(token).is_err());
    assert!(
        wallet
            .bind_reservation(token, [4; 32], b"public signed fixture")
            .is_err()
    );
    let backup = wallet.backup(&dir, "backup", &password()).unwrap();
    drop(wallet);
    let wallet = WalletStore::open(&dir, "pending", &password(), checkpoint).unwrap();
    assert_eq!(
        wallet.reservations().unwrap()[&token].transaction,
        Some([3; 32])
    );
    assert_eq!(
        wallet.reservations().unwrap()[&token].expose_transaction(),
        Some(b"public signed fixture".as_slice())
    );
    let restored = WalletStore::recover(
        &dir,
        "backup",
        &password(),
        backup,
        &dir,
        "restored",
        &password(),
    )
    .unwrap();
    assert_eq!(
        restored.reservations().unwrap()[&token].inputs,
        vec![input()]
    );
    assert!(restored.recovery_required().unwrap());
    let envelope = read_record(&wallet.db).unwrap();
    assert!(!envelope.windows(32).any(|w| w == [31; 32]));
    assert_eq!(
        format!("{:?}", wallet.reservations().unwrap()[&token]),
        "Reservation([REDACTED])"
    );
}
#[test]
fn legacy_envelope_opens_and_next_write_migrates_without_losing_counters() {
    let temp = tempfile::tempdir().unwrap();
    let dir = WalletDirectory::open(temp.path()).unwrap();
    let envelope = include_bytes!("../../../tests/storage-v1.bin");
    let checkpoint = WalletCheckpoint {
        wallet_id: core::array::from_fn(|i| i as u8),
        network: Network::Main,
        revision: 9,
    };
    let mut db = connect(&dir.path("legacy").unwrap(), true).unwrap();
    write_record(&mut db, envelope, true, |_| {}).unwrap();
    drop(db);
    let password = Password::from_bytes(b"public storage interoperability password").unwrap();
    let mut wallet = WalletStore::open(&dir, "legacy", &password, checkpoint).unwrap();
    assert!(wallet.reservations().unwrap().is_empty());
    assert_eq!(read_record(&wallet.db).unwrap()[8], 1);
    let issued = wallet
        .next_address(0, Scope::External, AddressKind::Transparent)
        .unwrap();
    assert_eq!(issued.index, 3);
    assert_eq!(read_record(&wallet.db).unwrap()[8], 2);
    drop(wallet);
    let wallet = WalletStore::open(&dir, "legacy", &password, issued.checkpoint).unwrap();
    assert_eq!(
        wallet.account_progress().unwrap()[&0].transparent_external,
        4
    );
}
#[test]
fn pending_encoding_bounds_duplicates_and_recovery_attestation_fail_closed() {
    let (_temp, _dir, mut wallet) = fixture();
    assert!(
        wallet
            .reserve_inputs([1; 32], [2; 32], 100, vec![input(), input()])
            .is_err()
    );
    assert!(
        wallet
            .reserve_inputs([1; 32], [2; 32], 100, vec![])
            .is_err()
    );
    let id = wallet
        .reserve_inputs([1; 32], [2; 32], 100, vec![input()])
        .unwrap();
    let plain = state::encode_pending(
        &wallet.state.seed,
        &wallet.state.accounts,
        false,
        &wallet.state.pending,
    )
    .unwrap();
    let mut bad = plain.to_vec();
    bad[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(state::decode(&bad).is_err());
    assert!(wallet.bind_reservation(id, [3; 32], &[]).is_err());
    wallet
        .bind_reservation(id, [3; 32], b"public signed fixture")
        .unwrap();
    wallet.compact_reservation_bytes(id).unwrap();
    assert!(
        wallet.reservations().unwrap()[&id]
            .expose_transaction()
            .is_none()
    );
    assert_eq!(
        wallet.reserve_inputs([1; 32], [2; 32], 100, vec![input()]),
        Err(StorageError::InputReserved)
    );
    wallet.state.recovery = true;
    let plan =
        RecoveryPlan::from_trusted_scan(BTreeMap::new(), wallet.checkpoint().unwrap().revision)
            .unwrap();
    assert_eq!(
        wallet.finish_recovery(plan),
        Err(StorageError::RecoveryRequired)
    );
    let plan =
        RecoveryPlan::from_trusted_scan(BTreeMap::new(), wallet.checkpoint().unwrap().revision)
            .unwrap()
            .with_trusted_reservations(BTreeMap::new())
            .unwrap();
    wallet.finish_recovery(plan).unwrap();
    assert!(wallet.reservations().unwrap().contains_key(&id));
}
#[test]
fn pending_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_PENDING_CRASH_DIR") else {
        return;
    };
    let dir = WalletDirectory::open(Path::new(&path)).unwrap();
    let id: Vec<u8> = std::env::var("MONAR_PENDING_CRASH_ID")
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let checkpoint = WalletCheckpoint {
        wallet_id: id.try_into().unwrap(),
        network: Network::Main,
        revision: 0,
    };
    let mut wallet = WalletStore::open(&dir, "pending", &password(), checkpoint).unwrap();
    let mut records = wallet.state.pending.clone();
    let token = [9; 16];
    records.insert(
        token,
        Reservation {
            id: token,
            profile: [1; 32],
            validated_tip: [2; 32],
            expiry_height: if std::env::var_os("MONAR_PENDING_CRASH_WIDE").is_some() {
                u64::from(u32::MAX) + 50
            } else {
                100
            },
            transaction: Some([3; 32]),
            inputs: vec![input()],
            bytes: Some(Zeroizing::new(b"public signed fixture".to_vec())),
            service_proof: Some(service_proof()),
        },
    );
    let after = std::env::var("MONAR_PENDING_CRASH_PHASE").unwrap() == "after";
    wallet
        .commit_pending(records, |committed| {
            if committed == after {
                std::process::exit(if after { 92 } else { 91 });
            }
        })
        .unwrap();
}
#[test]
fn pending_process_death_both_sides_of_commit() {
    for (phase, code, present, wide) in [
        ("before", 91, false, false),
        ("after", 92, true, false),
        ("before", 91, false, true),
        ("after", 92, true, true),
    ] {
        let (temp, dir, wallet) = fixture();
        let checkpoint = wallet.checkpoint().unwrap();
        drop(wallet);
        let id: String = checkpoint
            .wallet_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::pending::tests::pending_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_PENDING_CRASH_DIR", temp.path())
            .env("MONAR_PENDING_CRASH_ID", id)
            .env("MONAR_PENDING_CRASH_PHASE", phase)
            .envs(wide.then_some(("MONAR_PENDING_CRASH_WIDE", "1")))
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(code));
        let mut wallet = WalletStore::open(&dir, "pending", &password(), checkpoint).unwrap();
        assert_eq!(!wallet.reservations().unwrap().is_empty(), present);
        if present && wide {
            assert_eq!(
                wallet.reservations().unwrap()[&[9; 16]].expiry_height,
                u64::from(u32::MAX) + 50
            );
        }
        assert_eq!(
            wallet
                .reserve_inputs([1; 32], [2; 32], 100, vec![input()])
                .is_err(),
            present
        );
    }
}

fn service_proof() -> ServiceProof {
    ServiceProof {
        registration: [41; 32],
        period_start: 1920,
        challenge: [42; 32],
        operator: secp256k1::PublicKey::from_secret_key(
            &secp256k1::SecretKey::from_secret_bytes([9; 32]).unwrap(),
        )
        .serialize(),
        fee_atoms: 1,
    }
}
#[test]
fn service_attempts_survive_reopen_compaction_and_changes_without_releasing_claims() {
    let (_temp, dir, mut wallet) = fixture();
    let plain = wallet
        .reserve_inputs([1; 32], [2; 32], 100, vec![input()])
        .unwrap();
    let mut proof = service_proof();
    for n in 0..MAX_SERVICE_ATTEMPTS {
        proof.challenge = [50 + n as u8; 32];
        let token = wallet
            .reserve_service_inputs(
                [1; 32],
                [2; 32],
                100,
                vec![Input::Transparent {
                    transaction: [60 + n as u8; 32],
                    index: 0,
                }],
                proof,
                3,
            )
            .unwrap();
        assert!(wallet.cancel_unsigned_reservation(token).is_err());
        if n == 0 {
            wallet
                .bind_reservation(token, [70; 32], b"public proof fixture")
                .unwrap();
            wallet.compact_reservation_bytes(token).unwrap();
        }
    }
    let cp = wallet.checkpoint().unwrap();
    drop(wallet);
    let mut wallet = WalletStore::open(&dir, "pending", &password(), cp).unwrap();
    assert!(
        wallet.reservations().unwrap()[&plain]
            .service_proof
            .is_none()
    );
    assert_eq!(
        wallet
            .reservations()
            .unwrap()
            .values()
            .filter(|r| r.service_proof.is_some())
            .count(),
        3
    );
    assert!(
        wallet
            .reserve_service_inputs(
                [1; 32],
                [2; 32],
                100,
                vec![Input::Transparent {
                    transaction: [90; 32],
                    index: 0
                }],
                proof,
                100
            )
            .is_err()
    );
    proof.period_start += 1920;
    assert!(
        wallet
            .reserve_service_inputs(
                [1; 32],
                [2; 32],
                100,
                vec![Input::Transparent {
                    transaction: [90; 32],
                    index: 0
                }],
                proof,
                0
            )
            .is_err()
    );
    wallet
        .reserve_service_inputs(
            [1; 32],
            [2; 32],
            100,
            vec![Input::Transparent {
                transaction: [90; 32],
                index: 0,
            }],
            proof,
            1,
        )
        .unwrap();
    assert_eq!(wallet.reservations().unwrap().len(), 5);
}
#[test]
fn proof_metadata_encoding_is_bounded_and_legacy_records_remain_readable() {
    let (_temp, _dir, mut wallet) = fixture();
    wallet
        .reserve_inputs([1; 32], [2; 32], 100, vec![input()])
        .unwrap();
    let mut old = Vec::new();
    encode(wallet.reservations().unwrap(), &mut old).unwrap();
    assert_eq!(&old[..8], b"MNRPEND1");
    assert_eq!(decode(&old, &mut 0).unwrap().len(), 1);
    wallet
        .cancel_unsigned_reservation(*wallet.reservations().unwrap().keys().next().unwrap())
        .unwrap();
    wallet
        .reserve_service_inputs([1; 32], [2; 32], 100, vec![input()], service_proof(), 3)
        .unwrap();
    let mut data = Vec::new();
    encode(wallet.reservations().unwrap(), &mut data).unwrap();
    assert_eq!(&data[..8], b"MNRPEND2");
    assert_eq!(
        decode(&data, &mut 0)
            .unwrap()
            .values()
            .next()
            .unwrap()
            .service_proof,
        Some(service_proof())
    );
    for n in 0..data.len() {
        assert!(decode(&data[..n], &mut 0).is_err());
    }
    for (offset, count) in [(96, 1), (129, 8), (169, 33), (202, 8)] {
        let mut bad = data.clone();
        bad[offset..offset + count].fill(if offset == 96 { 2 } else { 0 });
        assert!(decode(&bad, &mut 0).is_err());
    }
}

#[test]
fn wide_expiry_survives_reopen_without_releasing_claim() {
    let (_temp, dir, mut wallet) = fixture();
    let expiry = u64::from(u32::MAX) + 50;
    let token = wallet
        .reserve_inputs([1; 32], [2; 32], expiry, vec![input()])
        .unwrap();
    let checkpoint = wallet
        .bind_reservation(token, [3; 32], b"public signed fixture")
        .unwrap();
    let mut encoded = Vec::new();
    encode(wallet.reservations().unwrap(), &mut encoded).unwrap();
    assert_eq!(
        decode(&encoded, &mut 0).unwrap()[&token].expiry_height,
        expiry
    );
    assert_eq!(&encoded[..8], b"MNRPEND3");
    for end in 0..encoded.len() {
        assert!(decode(&encoded[..end], &mut 0).is_err());
    }
    drop(wallet);
    let mut reopened = WalletStore::open(&dir, "pending", &password(), checkpoint).unwrap();
    assert_eq!(
        reopened.reservations().unwrap()[&token].expiry_height,
        expiry
    );
    assert_eq!(
        reopened.reservations().unwrap()[&token].expose_transaction(),
        Some(b"public signed fixture".as_slice())
    );
    assert!(matches!(
        reopened.reserve_inputs([1; 32], [2; 32], expiry, vec![input()]),
        Err(StorageError::InputReserved)
    ));
}

#[test]
fn widening_mixed_reservations_preserves_legacy_signed_claims() {
    let (_temp, dir, mut wallet) = fixture();
    let legacy = wallet
        .reserve_inputs([1; 32], [2; 32], 100, vec![input()])
        .unwrap();
    wallet
        .bind_reservation(legacy, [3; 32], b"legacy public fixture")
        .unwrap();
    let mut legacy_encoding = Vec::new();
    encode(wallet.reservations().unwrap(), &mut legacy_encoding).unwrap();
    assert_eq!(&legacy_encoding[..8], b"MNRPEND1");
    let second = Input::Private {
        nullifier: [42; 32],
    };
    let expiry = u64::from(u32::MAX) + 1;
    let wide = wallet
        .reserve_inputs([1; 32], [2; 32], expiry, vec![second])
        .unwrap();
    let checkpoint = wallet
        .bind_reservation(wide, [4; 32], b"wide public fixture")
        .unwrap();
    drop(wallet);
    let mut reopened = WalletStore::open(&dir, "pending", &password(), checkpoint).unwrap();
    assert_eq!(reopened.reservations().unwrap()[&legacy].expiry_height, 100);
    assert_eq!(
        reopened.reservations().unwrap()[&legacy].expose_transaction(),
        Some(b"legacy public fixture".as_slice())
    );
    assert_eq!(
        reopened.reservations().unwrap()[&wide].expiry_height,
        expiry
    );
    assert_eq!(
        reopened.reservations().unwrap()[&wide].expose_transaction(),
        Some(b"wide public fixture".as_slice())
    );
    assert!(matches!(
        reopened.reserve_inputs([1; 32], [2; 32], 101, vec![input()]),
        Err(StorageError::InputReserved)
    ));
    assert!(matches!(
        reopened.reserve_inputs([1; 32], [2; 32], expiry, vec![second]),
        Err(StorageError::InputReserved)
    ));
}

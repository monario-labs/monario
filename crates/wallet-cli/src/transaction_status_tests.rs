//! Validated lifecycle observations never mutate claims, even across process death.
use super::*;
use crate::transaction_status::inspect;
use monario_wallet::storage::pending::Input;

fn observe(store: &WalletStore, source: &DurableChain<V6Verifier>, token: [u8; 16], state: &str) {
    let before = store.checkpoint().unwrap();
    let inputs = store.reservations().unwrap()[&token].inputs.clone();
    let result = inspect(store, source, token).unwrap();
    assert_eq!(result["state"], state);
    assert_eq!(result["validated_tip"], hex(&source.chain().unwrap().tip()));
    assert_eq!(result["chain_confirmation_proven"], state == "confirmed");
    if state != "confirmed" {
        assert_eq!(result["confirmations"], "0");
        assert!(result["confirmation_height"].is_null());
        assert!(result["confirmation_block"].is_null());
    }
    assert_eq!(result["wallet_claims_retained"], true);
    assert_eq!(result["network_delivery_proven"], false);
    assert_eq!(result["mempool_membership_proven"], false);
    assert!(result.get("transaction_hex").is_none());
    assert!(result.get("nullifiers").is_none());
    assert_eq!(store.checkpoint().unwrap(), before);
    assert_eq!(store.reservations().unwrap()[&token].inputs, inputs);
}

#[test]
fn real_transparent_private_status_reorg_conflict_expiry_and_restart_preserve_claims() {
    for private in [false, true] {
        let dir = private_dir();
        let (mut chain, base) = source(dir.path(), private);
        let mut store = wallet(dir.path());
        let doc = intent(&store, &chain, private, false, 8);
        let signed = make(&mut store, &chain, &doc).unwrap();
        let token = id(signed["reservation"].as_str().unwrap()).unwrap();
        let raw = decode(signed["transaction_hex"].as_str().unwrap());
        let cp = store.checkpoint().unwrap();
        drop(store);
        let vault = wallet_vault(dir.path());
        let store = open_wallet(dir.path(), cp);
        let height = if private { 4 } else { 3 };
        observe(&store, &chain, token, "valid-for-next-block");
        let mut confirmed = base.clone();
        confirmed.accept(&mut chain, height, &[raw]);
        observe(&store, &chain, token, "confirmed");
        let mut empty = base.clone();
        empty.accept(&mut chain, height, &[]);
        empty.accept(&mut chain, height + 1, &[]);
        observe(&store, &chain, token, "valid-for-next-block");
        let mut conflict = base;
        conflict.accept(
            &mut chain,
            height,
            &[fixture(if private { "conflict" } else { "deposit" })],
        );
        conflict.accept(&mut chain, height + 1, &[]);
        conflict.accept(&mut chain, height + 2, &[]);
        observe(&store, &chain, token, "unavailable");
        empty.accept(&mut chain, height + 2, &[]);
        empty.accept(&mut chain, height + 3, &[]);
        observe(&store, &chain, token, "valid-for-next-block");
        let expiry = u32::try_from(store.reservations().unwrap()[&token].expiry_height).unwrap();
        for h in height + 4..=expiry {
            empty.accept(&mut chain, h, &[]);
            if h + 1 == expiry {
                observe(&store, &chain, token, "valid-for-next-block");
            }
        }
        observe(&store, &chain, token, "expired");
        drop(store);
        assert_eq!(wallet_vault(dir.path()), vault);
        drop(chain);
        let chain = DurableChain::open(
            &dir.path().join("chain.sqlite"),
            config(),
            root(),
            V6Verifier,
            u64::MAX / 2,
        )
        .unwrap();
        let store = open_wallet(dir.path(), cp);
        observe(&store, &chain, token, "expired");
        drop(store);
        assert_eq!(wallet_vault(dir.path()), vault);
    }
}

#[test]
fn single_status_handles_compaction_unsigned_wrong_profile_and_unrelated_bad_bytes() {
    let dir = private_dir();
    let (mut chain, mut model) = source(dir.path(), false);
    let mut store = wallet(dir.path());
    let doc = intent(&store, &chain, false, false, 8);
    let signed = make(&mut store, &chain, &doc).unwrap();
    let token = id(signed["reservation"].as_str().unwrap()).unwrap();
    let raw = decode(signed["transaction_hex"].as_str().unwrap());
    let profile = chain.profile_id().unwrap();
    let tip = chain.chain().unwrap().tip();
    let unsigned = store
        .reserve_inputs(
            profile,
            tip,
            20,
            vec![Input::Private {
                nullifier: [44; 32],
            }],
        )
        .unwrap();
    observe(&store, &chain, unsigned, "unsigned");
    let invalid = store
        .reserve_inputs(
            profile,
            tip,
            20,
            vec![Input::Private {
                nullifier: [45; 32],
            }],
        )
        .unwrap();
    store
        .bind_reservation(invalid, [46; 32], b"invalid v6 bytes")
        .unwrap();
    observe(&store, &chain, invalid, "unavailable");
    let foreign = store
        .reserve_inputs(
            [99; 32],
            tip,
            20,
            vec![Input::Private {
                nullifier: [47; 32],
            }],
        )
        .unwrap();
    observe(&store, &chain, token, "valid-for-next-block");
    assert!(inspect(&store, &chain, foreign).is_err());
    assert!(inspect(&store, &chain, [0; 16]).is_err());
    store.compact_reservation_bytes(token).unwrap();
    observe(&store, &chain, token, "needs-bytes");
    model.accept(&mut chain, 3, &[raw]);
    observe(&store, &chain, token, "confirmed");
    assert_eq!(
        inspect(&store, &chain, token).unwrap()["signed_bytes_available"],
        false
    );
}

fn status_args(path: &Path, cp: WalletCheckpoint, profile: Hash, token: [u8; 16]) -> Vec<OsString> {
    let mut values = cli_args(path, cp, profile);
    values[0] = "transaction-status".into();
    values.truncate(values.len() - 4); // No address windows are needed or accepted.
    values.extend(["--reservation".into(), hex(&token).into()]);
    values
}

#[test]
fn status_cli_authentication_pins_and_output_failures_leave_encrypted_state_unchanged() {
    let dir = private_dir();
    let cfg = production();
    let profile = manifest_file(dir.path(), &cfg);
    let mut chain = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        cfg,
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    Model::new().accept(&mut chain, 1, &[]);
    let pin = chain
        .create_state_checkpoint(monario_node::cli::STATE_CHECKPOINT_LIMITS)
        .unwrap()
        .commitment();
    let mut store = wallet(dir.path());
    let token = store
        .reserve_inputs(
            profile,
            chain.chain().unwrap().tip(),
            10,
            vec![Input::Private { nullifier: [8; 32] }],
        )
        .unwrap();
    let cp = store.checkpoint().unwrap();
    drop(store);
    drop(chain);
    let args = status_args(dir.path(), cp, profile, token);
    let before = wallet_vault(dir.path());
    let mut out = Vec::new();
    crate::execute(
        Command::parse(args.clone()).unwrap(),
        &mut credentials(),
        &mut out,
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["state"], "unsigned");
    assert_eq!(value["full_chain_replay"], true);
    for bad in [
        ["--external".into(), "1".into()],
        ["--node-directory".into(), "other".into()],
        ["--rescan".into(), "unused".into()],
        ["--confirmations".into(), "1000".into()],
        ["--confirmation-height".into(), "0".into()],
    ] {
        let mut invalid = args.clone();
        invalid.extend(bad);
        assert!(Command::parse(invalid).is_err());
    }
    for bad_pin in [false, true] {
        let mut pinned = args.clone();
        pinned.extend([
            "--checkpoint".into(),
            hex(&if bad_pin { [0; 32] } else { pin }).into(),
        ]);
        let mut output = Vec::new();
        let result = crate::execute(
            Command::parse(pinned).unwrap(),
            &mut credentials(),
            &mut output,
        );
        assert_eq!(result.is_ok(), !bad_pin);
        if bad_pin {
            assert!(output.is_empty());
        }
    }
    let mut wrong = credentials().into_inner();
    wrong[2] ^= 1;
    let mut output = Vec::new();
    assert!(
        crate::execute(
            Command::parse(args.clone()).unwrap(),
            &mut Cursor::new(wrong),
            &mut output
        )
        .is_err()
    );
    assert!(output.is_empty());
    for flag in ["--wallet-id", "--profile", "--reservation"] {
        let mut invalid = args.clone();
        let i = invalid.iter().position(|s| s == flag).unwrap() + 1;
        invalid[i] = if flag == "--profile" {
            hex(&[0; 32])
        } else {
            hex(&[0; 16])
        }
        .into();
        let mut output = Vec::new();
        assert!(
            crate::execute(
                Command::parse(invalid).unwrap(),
                &mut credentials(),
                &mut output
            )
            .is_err()
        );
        assert!(output.is_empty());
    }
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        crate::execute(
            Command::parse(args).unwrap(),
            &mut credentials(),
            &mut Broken
        ),
        Err(Error::Output)
    );
    assert_eq!(wallet_vault(dir.path()), before);
    assert_eq!(open_wallet(dir.path(), cp).reservations().unwrap().len(), 1);
}

#[test]
fn lifecycle_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_STATUS_TEST_DIRECTORY") else {
        return;
    };
    let path = PathBuf::from(path);
    let cp = WalletCheckpoint {
        wallet_id: id(&std::env::var("MONAR_STATUS_TEST_WALLET").unwrap()).unwrap(),
        network: Network::Main,
        revision: 0,
    };
    let token = id(&std::env::var("MONAR_STATUS_TEST_TOKEN").unwrap()).unwrap();
    let chain = DurableChain::open(
        &path.join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let store = open_wallet(&path, cp);
    let value = inspect(&store, &chain, token).unwrap();
    struct ExitOutput {
        file: fs::File,
        partial: bool,
    }
    impl Write for ExitOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.partial {
                self.file.write_all(&bytes[..bytes.len() / 2])?;
                self.file.sync_all()?;
                std::process::exit(86);
            }
            self.file.write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.file.sync_all()?;
            std::process::exit(87)
        }
    }
    report(
        &value,
        &mut ExitOutput {
            file: fs::File::create(path.join("status-output")).unwrap(),
            partial: std::env::var("MONAR_STATUS_TEST_PHASE").unwrap() == "partial",
        },
    )
    .unwrap();
}

#[test]
fn lifecycle_process_death_preserves_real_signed_claims_and_recoverable_output() {
    for private in [false, true] {
        let dir = private_dir();
        let (chain, _) = source(dir.path(), private);
        let mut store = wallet(dir.path());
        let doc = intent(&store, &chain, private, false, 8);
        let signed = make(&mut store, &chain, &doc).unwrap();
        let token = id(signed["reservation"].as_str().unwrap()).unwrap();
        let cp = store.checkpoint().unwrap();
        let claims = store.reservations().unwrap()[&token].inputs.clone();
        drop(store);
        drop(chain);
        let before = wallet_vault(dir.path());
        for phase in ["partial", "complete"] {
            let result = Process::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "balance::tests::construction::lifecycle::lifecycle_crash_worker",
                ])
                .env("MONAR_STATUS_TEST_DIRECTORY", dir.path())
                .env("MONAR_STATUS_TEST_WALLET", hex(&cp.wallet_id))
                .env("MONAR_STATUS_TEST_TOKEN", hex(&token))
                .env("MONAR_STATUS_TEST_PHASE", phase)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(
                result.code(),
                Some(if phase == "partial" { 86 } else { 87 })
            );
            let output = fs::read(dir.path().join("status-output")).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&output).is_ok(),
                phase == "complete"
            );
            assert_eq!(wallet_vault(dir.path()), before);
            let chain = DurableChain::open(
                &dir.path().join("chain.sqlite"),
                config(),
                root(),
                V6Verifier,
                u64::MAX / 2,
            )
            .unwrap();
            let store = open_wallet(dir.path(), cp);
            observe(&store, &chain, token, "valid-for-next-block");
            assert_eq!(store.reservations().unwrap()[&token].inputs, claims);
            assert_eq!(
                store.reservations().unwrap()[&token]
                    .expose_transaction()
                    .unwrap(),
                decode(signed["transaction_hex"].as_str().unwrap())
            );
        }
    }
}

#[test]
fn recovered_wallet_status_does_not_attest_history_or_unlock_spending() {
    let dir = private_dir();
    let (chain, _) = source(dir.path(), false);
    let mut store = wallet(dir.path());
    let doc = intent(&store, &chain, false, false, 8);
    let signed = make(&mut store, &chain, &doc).unwrap();
    let token = id(signed["reservation"].as_str().unwrap()).unwrap();
    let original = WalletDirectory::open(dir.path()).unwrap();
    let backup_password = password(b"public lifecycle backup password").unwrap();
    let cp = store.backup(&original, "saved", &backup_password).unwrap();
    let restored_dir = private_dir();
    let mut restored = WalletStore::recover(
        &original,
        "saved",
        &backup_password,
        cp,
        &WalletDirectory::open(restored_dir.path()).unwrap(),
        "wallet",
        &password(PASSWORD).unwrap(),
    )
    .unwrap();
    assert!(restored.recovery_required().unwrap());
    observe(&restored, &chain, token, "valid-for-next-block");
    assert!(restored.recovery_required().unwrap());
    assert!(matches!(
        restored.reserve_inputs(
            chain.profile_id().unwrap(),
            chain.chain().unwrap().tip(),
            20,
            vec![Input::Private {
                nullifier: [66; 32]
            }]
        ),
        Err(StorageError::RecoveryRequired)
    ));
    assert_eq!(
        restored.reservations().unwrap()[&token]
            .expose_transaction()
            .unwrap(),
        decode(signed["transaction_hex"].as_str().unwrap())
    );
}

#[test]
fn confirmed_depth_tracks_real_private_and_transparent_reinclusion_checkpoint_and_restart() {
    for private in [false, true] {
        let dir = private_dir();
        let (mut chain, base) = source(dir.path(), private);
        let mut store = wallet(dir.path());
        let doc = intent(&store, &chain, private, false, 8);
        let signed = make(&mut store, &chain, &doc).unwrap();
        let token = id(signed["reservation"].as_str().unwrap()).unwrap();
        let raw = decode(signed["transaction_hex"].as_str().unwrap());
        let height = if private { 4 } else { 3 };
        let mut model = base.clone();
        model.accept(&mut chain, height, std::slice::from_ref(&raw));
        let block = chain.chain().unwrap().tip();
        let first = inspect(&store, &chain, token).unwrap();
        assert_eq!(first["confirmations"], "1");
        assert_eq!(first["confirmation_height"], height.to_string());
        assert_eq!(first["confirmation_block"], hex(&block));
        model.accept(&mut chain, height + 1, &[]);
        model.accept(&mut chain, height + 2, &[]);
        let before = inspect(&store, &chain, token).unwrap();
        assert_eq!(before["confirmations"], "3");
        let pin = chain
            .create_state_checkpoint(monario_node::cli::STATE_CHECKPOINT_LIMITS)
            .unwrap();
        drop(chain);
        let chain = DurableChain::open(
            &dir.path().join("chain.sqlite"),
            config(),
            root(),
            V6Verifier,
            u64::MAX / 2,
        )
        .unwrap();
        assert_eq!(inspect(&store, &chain, token).unwrap(), before);
        drop(chain);
        let mut chain = DurableChain::open_with_checkpoint(
            &dir.path().join("chain.sqlite"),
            config(),
            root(),
            V6Verifier,
            u64::MAX / 2,
            pin,
            monario_node::cli::STATE_CHECKPOINT_LIMITS,
        )
        .unwrap();
        assert_eq!(inspect(&store, &chain, token).unwrap(), before);
        store.compact_reservation_bytes(token).unwrap();
        let mut side = base;
        for h in height..=height + 3 {
            side.accept(&mut chain, h, &[]);
        }
        observe(&store, &chain, token, "needs-bytes");
        side.accept(&mut chain, height + 4, &[raw]);
        let new_block = chain.chain().unwrap().tip();
        assert_ne!(new_block, block);
        side.accept(&mut chain, height + 5, &[]);
        let result = inspect(&store, &chain, token).unwrap();
        assert_eq!(result["state"], "confirmed");
        assert_eq!(result["confirmations"], "2");
        assert_eq!(result["confirmation_height"], (height + 4).to_string());
        assert_eq!(result["confirmation_block"], hex(&new_block));
        assert_eq!(result["signed_bytes_available"], false);
        let cp = store.checkpoint().unwrap();
        drop(store);
        drop(chain);
        let chain = DurableChain::open(
            &dir.path().join("chain.sqlite"),
            config(),
            root(),
            V6Verifier,
            u64::MAX / 2,
        )
        .unwrap();
        let store = open_wallet(dir.path(), cp);
        assert_eq!(inspect(&store, &chain, token).unwrap(), result);
    }
}

#[test]
fn confirmed_depth_output_crashes_recover_and_reorgs_invalidate_prior_counts() {
    for private in [false, true] {
        let dir = private_dir();
        let (mut chain, base) = source(dir.path(), private);
        let mut store = wallet(dir.path());
        let doc = intent(&store, &chain, private, false, 8);
        let signed = make(&mut store, &chain, &doc).unwrap();
        let token = id(signed["reservation"].as_str().unwrap()).unwrap();
        let cp = store.checkpoint().unwrap();
        let raw = decode(signed["transaction_hex"].as_str().unwrap());
        let height = if private { 4 } else { 3 };
        let mut confirmed = base.clone();
        confirmed.accept(&mut chain, height, &[raw]);
        let block = chain.chain().unwrap().tip();
        confirmed.accept(&mut chain, height + 1, &[]);
        drop(store);
        drop(chain);
        let before = wallet_vault(dir.path());
        for phase in ["partial", "complete"] {
            let result = Process::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "balance::tests::construction::lifecycle::lifecycle_crash_worker",
                ])
                .env("MONAR_STATUS_TEST_DIRECTORY", dir.path())
                .env("MONAR_STATUS_TEST_WALLET", hex(&cp.wallet_id))
                .env("MONAR_STATUS_TEST_TOKEN", hex(&token))
                .env("MONAR_STATUS_TEST_PHASE", phase)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(
                result.code(),
                Some(if phase == "partial" { 86 } else { 87 })
            );
            let bytes = fs::read(dir.path().join("status-output")).unwrap();
            let value = serde_json::from_slice::<serde_json::Value>(&bytes);
            if phase == "complete" {
                let value = value.unwrap();
                assert_eq!(value["confirmations"], "2");
                assert_eq!(value["confirmation_height"], height.to_string());
                assert_eq!(value["confirmation_block"], hex(&block));
            } else {
                assert!(value.is_err());
            }
            assert_eq!(wallet_vault(dir.path()), before);
            let chain = DurableChain::open(
                &dir.path().join("chain.sqlite"),
                config(),
                root(),
                V6Verifier,
                u64::MAX / 2,
            )
            .unwrap();
            let store = open_wallet(dir.path(), cp);
            let value = inspect(&store, &chain, token).unwrap();
            assert_eq!(value["confirmations"], "2");
            assert_eq!(value["confirmation_block"], hex(&block));
            assert_eq!(store.reservations().unwrap().len(), 1);
        }
        let mut chain = DurableChain::open(
            &dir.path().join("chain.sqlite"),
            config(),
            root(),
            V6Verifier,
            u64::MAX / 2,
        )
        .unwrap();
        let mut side = base;
        for h in height..=height + 2 {
            side.accept(&mut chain, h, &[]);
        }
        let store = open_wallet(dir.path(), cp);
        observe(&store, &chain, token, "valid-for-next-block");
        drop(store);
        drop(chain);
        assert_eq!(wallet_vault(dir.path()), before);
    }
}

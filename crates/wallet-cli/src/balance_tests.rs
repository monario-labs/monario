//! Public deterministic fixtures. Fixed nonces are checked, never searched.
use super::*;
use incrementalmerkletree::frontier::CommitmentTree;
use monario_chain::{
    Block, Config, Hash, Root,
    header::{Header, merkle_root},
    transactions::TransactionVerifier,
};
use orchard::tree::MerkleHashOrchard;
use std::{
    io::Cursor,
    process::{Command as Process, Stdio},
};
use zcash_primitives::transaction::{self, Transaction, TransactionData};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_script::script;
use zcash_transparent::{address::Script, bundle as tb};
const PASSWORD: &[u8] = b"public balance test password only";

#[test]
fn an_evicted_source_history_is_distinguishable_from_a_scan_failure() {
    assert!(matches!(
        crate::balance::scan_error(monario_wallet_scan::Error::SourceHistory),
        Error::ScanHistory
    ));
    assert!(matches!(
        crate::balance::scan_error(monario_wallet_scan::Error::NotSynced),
        Error::Scan
    ));
}
#[path = "wallet_checkpoint_tests.rs"]
mod checkpoints;
#[path = "transaction_tests.rs"]
mod construction;
fn private_dir() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir().unwrap()
    }
}
fn wallet(path: &Path) -> WalletStore {
    WalletStore::create(
        &WalletDirectory::open(path).unwrap(),
        "wallet",
        Seed::from_bytes(&[7; 32]).unwrap(),
        Network::Main,
        &password(PASSWORD).unwrap(),
    )
    .unwrap()
}
fn wallet_vault(path: &Path) -> Vec<u8> {
    let db = rusqlite::Connection::open_with_flags(
        path.join("wallet.monw"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.query_row("SELECT envelope FROM vault WHERE singleton=1", [], |r| {
        r.get(0)
    })
    .unwrap()
}
fn options(source: &DurableChain<V6Verifier>) -> Options {
    Options {
        directory: PathBuf::new(),
        manifest: "manifest.json".into(),
        profile: source.profile_id().unwrap(),
        external: 2,
        internal: 2,
        blocks: 100,
        checkpoint: None,
        rescan: false,
    }
}
fn value(store: &WalletStore, source: &DurableChain<V6Verifier>) -> serde_json::Value {
    serde_json::to_value(scan(store, 0, &options(source), source).unwrap()).unwrap()
}
fn amounts(value: &serde_json::Value, transparent: &str, immature: &str, private: &str) {
    assert_eq!(value["confirmed_transparent_atoms"], transparent);
    assert_eq!(value["immature_coinbase_atoms"], immature);
    assert_eq!(value["confirmed_private_atoms"], private);
    assert_eq!(value["units"], "atoms");
    assert_eq!(value["complete_to_local_tip"], true);
    assert_eq!(value["excludes_pending"], true);
}

#[test]
fn cli_incremental_private_scans_reuse_cache_and_rebuild_on_reorg_or_explicit_rescan() {
    let dir = private_dir();
    let store = wallet(dir.path());
    let cp = store.checkpoint().unwrap();
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let funding = model.clone();
    let mut opts = options(&source);
    opts.blocks = 1;
    assert!(prepare(&store, 0, &opts, &source).is_err());
    assert!(store.load_scan_cache([0; 32]).unwrap().is_none());
    opts.blocks = 100;
    let full = prepare(&store, 0, &opts, &source).unwrap();
    let before = store.load_scan_cache([0; 32]).unwrap().unwrap();
    opts.blocks = 1;
    let cached = prepare(&store, 0, &opts, &source).unwrap();
    assert_eq!(
        full.balance(&source, 0).unwrap(),
        cached.balance(&source, 0).unwrap()
    );
    opts.rescan = true;
    assert!(prepare(&store, 0, &opts, &source).is_err());
    assert_eq!(store.load_scan_cache([0; 32]).unwrap().unwrap(), before);
    opts.rescan = false;
    model.accept(&mut source, 4, &[fixture("transfer")]);
    assert_eq!(
        prepare(&store, 0, &opts, &source)
            .unwrap()
            .balance(&source, 0)
            .unwrap()
            .private
            .atoms(),
        0
    );
    model.accept(&mut source, 5, &[fixture("withdrawal")]);
    assert_eq!(
        prepare(&store, 0, &opts, &source)
            .unwrap()
            .balance(&source, 0)
            .unwrap()
            .transparent
            .atoms(),
        70
    );
    let old = store.load_scan_cache([0; 32]).unwrap().unwrap();
    let mut side = funding;
    side.accept(&mut source, 4, &[fixture("conflict")]);
    side.accept(&mut source, 5, &[]);
    side.accept(&mut source, 6, &[]);
    assert!(prepare(&store, 0, &opts, &source).is_err());
    assert_eq!(store.load_scan_cache([0; 32]).unwrap().unwrap(), old);
    opts.blocks = 3;
    let reorg = prepare(&store, 0, &opts, &source).unwrap();
    opts.rescan = true;
    opts.blocks = 100;
    let replay = prepare(&store, 0, &opts, &source).unwrap();
    assert_eq!(
        reorg.balance(&source, 0).unwrap(),
        replay.balance(&source, 0).unwrap()
    );
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert!(store.reservations().unwrap().is_empty());
    drop(store);
    let db = rusqlite::Connection::open(dir.path().join("wallet.monw")).unwrap();
    db.execute(
        "UPDATE scan_cache SET envelope=zeroblob(length(envelope))",
        [],
    )
    .unwrap();
    drop(db);
    let store = WalletStore::open(
        &WalletDirectory::open(dir.path()).unwrap(),
        "wallet",
        &password(PASSWORD).unwrap(),
        cp,
    )
    .unwrap();
    opts.rescan = false;
    assert!(prepare(&store, 0, &opts, &source).is_err());
    opts.rescan = true;
    assert!(prepare(&store, 0, &opts, &source).is_ok());
    opts.rescan = false;
    opts.blocks = 1;
    assert!(prepare(&store, 0, &opts, &source).is_ok());
}

#[test]
fn cli_commits_legacy_cache_upgrade_at_unchanged_tip_without_wallet_revision_changes() {
    let dir = private_dir();
    let store = wallet(dir.path());
    let cp = store.checkpoint().unwrap();
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let mut opts = options(&source);
    prepare(&store, 0, &opts, &source).unwrap();
    let plain = store.load_scan_cache([0; 32]).unwrap().unwrap();
    // This fixed public fixture contains the format marker only in its trailer.
    let footer = plain.windows(8).position(|b| b == b"MONWUD02").unwrap();
    store.save_scan_cache([0; 32], &plain[..footer]).unwrap();
    opts.blocks = 1;
    let migrated = prepare(&store, 0, &opts, &source).unwrap();
    assert!(migrated.cache_was_migrated());
    assert_eq!(migrated.balance(&source, 0).unwrap().private.atoms(), 90);
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert!(store.reservations().unwrap().is_empty());
    let upgraded = store.load_scan_cache([0; 32]).unwrap().unwrap();
    assert_eq!(&upgraded[footer..footer + 8], b"MONWUD02");
    assert!(
        !prepare(&store, 0, &opts, &source)
            .unwrap()
            .cache_was_migrated()
    );
    assert_eq!(store.load_scan_cache([0; 32]).unwrap().unwrap(), upgraded);
}

#[test]
fn verified_private_spends_maturity_reservations_reopen_and_reorg_reports() {
    // Reduced maturity is confined to this real-verifier fixture; manifest
    // Acceptance below separately enforces production maturity 240.
    let dir = private_dir();
    let path = dir.path().join("chain.sqlite");
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut store = wallet(dir.path());
    let original = store.checkpoint().unwrap();
    let mut model = Model::new();
    amounts(&value(&store, &source), "0", "0", "0");
    model.accept(&mut source, 1, &[]);
    amounts(&value(&store, &source), "0", "100", "0");
    model.accept(&mut source, 2, &[]);
    amounts(&value(&store, &source), "100", "0", "0");
    model.accept(&mut source, 3, &[fixture("deposit")]);
    amounts(&value(&store, &source), "0", "0", "90");
    let funding = model.clone();
    let mut partial = options(&source);
    partial.blocks = 2;
    partial.rescan = true;
    assert!(matches!(
        scan(&store, 0, &partial, &source),
        Err(Error::Scan)
    ));
    let mut wrong = options(&source);
    wrong.profile = [0; 32];
    assert!(matches!(scan(&store, 0, &wrong, &source), Err(Error::Scan)));
    model.accept(&mut source, 4, &[fixture("transfer")]);
    amounts(&value(&store, &source), "0", "0", "0");
    model.accept(&mut source, 5, &[fixture("withdrawal")]);
    amounts(&value(&store, &source), "70", "0", "0");
    let tx = Transaction::read(fixture("withdrawal").as_slice(), BranchId::Nu6_3).unwrap();
    store
        .reserve_inputs(
            source.profile_id().unwrap(),
            source.chain().unwrap().tip(),
            100,
            vec![monario_wallet::storage::pending::Input::Transparent {
                transaction: *tx.txid().as_ref(),
                index: 0,
            }],
        )
        .unwrap();
    let before = value(&store, &source);
    assert_eq!(before["pending_reservations"], 1);
    let cp = store.checkpoint().unwrap();
    assert_eq!(cp.revision, original.revision + 1);
    drop(source);
    drop(store);
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let store = WalletStore::open(
        &WalletDirectory::open(dir.path()).unwrap(),
        "wallet",
        &password(PASSWORD).unwrap(),
        cp,
    )
    .unwrap();
    assert_eq!(value(&store, &source), before);
    let mut side = funding;
    side.accept(&mut source, 4, &[fixture("conflict")]);
    side.accept(&mut source, 5, &[]);
    assert_eq!(value(&store, &source), before);
    side.accept(&mut source, 6, &[]);
    let after = value(&store, &source);
    amounts(&after, "0", "0", "0");
    assert_ne!(after["validated_tip"], before["validated_tip"]);
    assert_eq!(after["height"], "6");
    assert_eq!(after["pending_reservations"], 1);
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert_eq!(store.reservations().unwrap().len(), 1);
    assert!(store.account_progress().unwrap().is_empty());
}

fn manifest_file(path: &Path, cfg: &Config) -> [u8; 32] {
    let root = root();
    let doc = serde_json::json!({ "version":1, "chain_file":"chain.sqlite",
        "chain_id":hex(&cfg.chain_id), "root_id":hex(&root.id),
        "root_timestamp":root.timestamp, "root_commitment":hex(&root.commitment),
        "initial_bits":cfg.initial_bits, "pow_limit_bits":cfg.pow_limit_bits,
        "half_life_seconds":cfg.half_life_seconds, "seed_interval":cfg.seed_interval,
        "seed_lag":cfg.seed_lag, "max_future_seconds":cfg.max_future_seconds,
        "retained_blocks":cfg.retained_blocks, "transaction_bytes":cfg.limits.transaction_bytes,
        "transactions":cfg.limits.transactions, "inputs_per_transaction":cfg.limits.inputs_per_transaction,
        "outputs_per_transaction":cfg.limits.outputs_per_transaction, "script_bytes":cfg.limits.script_bytes });
    fs::write(
        path.join("manifest.json"),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
    monario_chain::Chain::new(cfg.clone(), root, V6Verifier)
        .unwrap()
        .validation_profile()
}
fn cli_args(path: &Path, cp: WalletCheckpoint, profile: [u8; 32]) -> Vec<OsString> {
    [
        "balance".to_owned(),
        "--directory".into(),
        path.to_str().unwrap().into(),
        "--name".into(),
        "wallet".into(),
        "--network".into(),
        "main".into(),
        "--password-stdin".into(),
        "--wallet-id".into(),
        hex(&cp.wallet_id),
        "--revision".into(),
        cp.revision.to_string(),
        "--chain-directory".into(),
        path.to_str().unwrap().into(),
        "--manifest".into(),
        "manifest.json".into(),
        "--profile".into(),
        hex(&profile),
        "--external".into(),
        "2".into(),
        "--internal".into(),
        "2".into(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}
fn credentials() -> Cursor<Vec<u8>> {
    let mut input = (PASSWORD.len() as u16).to_le_bytes().to_vec();
    input.extend(PASSWORD);
    Cursor::new(input)
}
fn cli(path: &Path, cp: WalletCheckpoint, profile: [u8; 32]) -> Result<serde_json::Value, Error> {
    let mut output = Vec::new();
    crate::execute(
        Command::parse(cli_args(path, cp, profile))?,
        &mut credentials(),
        &mut output,
    )?;
    Ok(serde_json::from_slice(&output).unwrap())
}
fn production() -> Config {
    let mut cfg = config();
    cfg.coinbase_maturity = monario_chain::consensus::COINBASE_MATURITY;
    cfg.limits.block_bytes = 5_000_000;
    cfg
}
#[test]
fn manifest_database_and_link_attacks_fail_without_balance_output() {
    let dir = private_dir();
    let store = wallet(dir.path());
    let cp = store.checkpoint().unwrap();
    drop(store);
    let cfg = production();
    let profile = manifest_file(dir.path(), &cfg);
    let document = fs::read(dir.path().join("manifest.json")).unwrap();
    let path = dir.path().join("chain.sqlite");
    // Application/version stamps alone do not make an initialized chain.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA application_id=1297042993; PRAGMA user_version=1;")
        .unwrap();
    drop(conn);
    assert!(cli(dir.path(), cp, profile).is_err());
    let conn = rusqlite::Connection::open(&path).unwrap();
    let tables: i64 = conn
        .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
        .unwrap();
    assert_eq!(tables, 0);
    drop(conn);
    fs::remove_file(&path).unwrap();
    let source = DurableChain::open(&path, cfg, root(), V6Verifier, u64::MAX / 2).unwrap();
    drop(source);
    for replacement in [
        b"{".to_vec(),
        vec![b' '; 16_385],
        {
            let mut doc: serde_json::Value = serde_json::from_slice(&document).unwrap();
            doc["unknown"] = true.into();
            serde_json::to_vec(&doc).unwrap()
        },
        {
            let mut doc: serde_json::Value = serde_json::from_slice(&document).unwrap();
            doc["chain_file"] = "../chain.sqlite".into();
            serde_json::to_vec(&doc).unwrap()
        },
        {
            let mut doc: serde_json::Value = serde_json::from_slice(&document).unwrap();
            doc["root_id"] = hex(&[0; 32]).into();
            serde_json::to_vec(&doc).unwrap()
        },
    ] {
        fs::write(dir.path().join("manifest.json"), replacement).unwrap();
        let mut output = Vec::new();
        assert!(
            crate::execute(
                Command::parse(cli_args(dir.path(), cp, profile)).unwrap(),
                &mut credentials(),
                &mut output
            )
            .is_err()
        );
        assert!(output.is_empty());
    }
    fs::write(dir.path().join("manifest.json"), document).unwrap();
    // A held chain owner excludes a concurrent scan, avoiding inconsistent views.
    let source = DurableChain::open(&path, production(), root(), V6Verifier, u64::MAX / 2).unwrap();
    assert!(cli(dir.path(), cp, profile).is_err());
    drop(source);
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let manifest = dir.path().join("manifest.json");
        fs::rename(&manifest, dir.path().join("real.json")).unwrap();
        symlink("real.json", &manifest).unwrap();
        assert!(cli(dir.path(), cp, profile).is_err());
        fs::remove_file(&manifest).unwrap();
        fs::rename(dir.path().join("real.json"), manifest).unwrap();
        fs::hard_link(&path, dir.path().join("linked.sqlite")).unwrap();
        assert!(cli(dir.path(), cp, profile).is_err());
        fs::remove_file(dir.path().join("linked.sqlite")).unwrap();
        symlink("manifest.json", dir.path().join("chain.sqlite-wal")).unwrap();
        assert!(cli(dir.path(), cp, profile).is_err());
        fs::remove_file(dir.path().join("chain.sqlite-wal")).unwrap();
    }
    amounts(&cli(dir.path(), cp, profile).unwrap(), "0", "0", "0");
}

#[test]
fn scanning_recovered_wallet_keeps_recovery_lock_and_authenticated_history() {
    let dir = private_dir();
    let source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let store = wallet(dir.path());
    let directory = WalletDirectory::open(dir.path()).unwrap();
    let cp = store
        .backup(&directory, "snapshot", &password(PASSWORD).unwrap())
        .unwrap();
    drop(store);
    let restored = WalletStore::recover(
        &directory,
        "snapshot",
        &password(PASSWORD).unwrap(),
        cp,
        &directory,
        "restored",
        &password(PASSWORD).unwrap(),
    )
    .unwrap();
    let before = restored.checkpoint().unwrap();
    let output = value(&restored, &source);
    amounts(&output, "0", "0", "0");
    assert_eq!(output["checkpoint"]["recovery_required"], true);
    assert!(restored.recovery_required().unwrap());
    assert_eq!(restored.checkpoint().unwrap(), before);
}
#[test]
fn cli_requires_existing_authenticated_chain_and_bounded_complete_scan() {
    let dir = private_dir();
    let store = wallet(dir.path());
    let cp = store.checkpoint().unwrap();
    drop(store);
    let cfg = production();
    let profile = manifest_file(dir.path(), &cfg);
    let path = dir.path().join("chain.sqlite");
    assert!(cli(dir.path(), cp, profile).is_err());
    assert!(!path.exists());
    fs::write(&path, []).unwrap();
    assert!(cli(dir.path(), cp, profile).is_err());
    assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    fs::remove_file(&path).unwrap();
    let mut source =
        DurableChain::open(&path, cfg.clone(), root(), V6Verifier, u64::MAX / 2).unwrap();
    // These fixed headers have the same difficulty on this 90-second schedule.
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    drop(source);
    let result = cli(dir.path(), cp, profile).unwrap();
    amounts(&result, "0", "100", "0");
    assert_eq!(result["height"], "2");
    let mut args = cli_args(dir.path(), cp, profile);
    args.extend([OsString::from("--max-blocks"), OsString::from("1")]);
    args.push(OsString::from("--rescan"));
    let mut output = Vec::new();
    assert_eq!(
        crate::execute(
            Command::parse(args).unwrap(),
            &mut credentials(),
            &mut output
        ),
        Err(Error::Scan)
    );
    assert!(output.is_empty());
    assert!(cli(dir.path(), cp, [0; 32]).is_err());
    for (flag, bad) in [
        ("--external", "10001"),
        ("--internal", "-1"),
        ("--manifest", "../chain"),
        ("--manifest", "NUL.json"),
        ("--profile", "bad"),
        ("--account", "2147483648"),
        ("--max-blocks", "0"),
    ] {
        let mut args = cli_args(dir.path(), cp, profile);
        if let Some(i) = args.iter().position(|v| v == flag) {
            args[i + 1] = bad.into();
        } else {
            args.extend([flag.into(), bad.into()]);
        }
        assert!(Command::parse(args).is_err());
    }
    let mut store = WalletStore::open(
        &WalletDirectory::open(dir.path()).unwrap(),
        "wallet",
        &password(PASSWORD).unwrap(),
        cp,
    )
    .unwrap();
    for _ in 0..3 {
        store
            .next_address(0, Scope::External, AddressKind::Transparent)
            .unwrap();
    }
    let latest = store.checkpoint().unwrap();
    drop(store);
    assert_eq!(cli(dir.path(), latest, profile).err(), Some(Error::Scan));
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE blocks SET data=zeroblob(length(data)) WHERE seq=1",
        [],
    )
    .unwrap();
    drop(conn);
    assert!(cli(dir.path(), cp, profile).is_err());
}

#[test]
fn balance_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_BALANCE_TEST_DIR") else {
        return;
    };
    let path = PathBuf::from(path);
    let phase = std::env::var("MONAR_BALANCE_TEST_PHASE").unwrap();
    let cp = WalletCheckpoint {
        wallet_id: id(&std::env::var("MONAR_BALANCE_TEST_ID").unwrap()).unwrap(),
        network: Network::Main,
        revision: 0,
    };
    let profile = hash(&std::env::var("MONAR_BALANCE_TEST_PROFILE").unwrap()).unwrap();
    if phase == "partial" {
        let source = DurableChain::open(
            &path.join("chain.sqlite"),
            production(),
            root(),
            V6Verifier,
            u64::MAX / 2,
        )
        .unwrap();
        let store = WalletStore::open(
            &WalletDirectory::open(&path).unwrap(),
            "wallet",
            &password(PASSWORD).unwrap(),
            cp,
        )
        .unwrap();
        let watch =
            WatchAccount::from_seed(store.expose_seed().unwrap(), Network::Main, 0, 2, 2).unwrap();
        let mut scanner = Scanner::new(
            &source,
            Network::Main,
            vec![watch],
            Limits {
                accounts: 1,
                transparent_addresses: 4,
                unspent_coins: 100,
                unspent_notes: 100,
            },
        )
        .unwrap();
        assert!(!scanner.sync(&source, 1).unwrap().complete);
        std::process::exit(83);
    }
    struct ExitOutput;
    impl Write for ExitOutput {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            std::process::exit(84)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            std::process::exit(84)
        }
    }
    crate::execute(
        Command::parse(cli_args(&path, cp, profile)).unwrap(),
        &mut credentials(),
        &mut ExitOutput,
    )
    .unwrap();
}

#[test]
fn interrupted_scans_and_output_failure_recover_without_wallet_mutation() {
    let dir = private_dir();
    let store = wallet(dir.path());
    let cp = store.checkpoint().unwrap();
    drop(store);
    let cfg = production();
    let profile = manifest_file(dir.path(), &cfg);
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        cfg,
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    drop(source);
    let expected = cli(dir.path(), cp, profile).unwrap();
    let original = fs::read(dir.path().join("wallet.monw")).unwrap();
    for (phase, exit) in [("partial", 83), ("output", 84)] {
        let status = Process::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "balance::tests::balance_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_BALANCE_TEST_DIR", dir.path())
            .env("MONAR_BALANCE_TEST_PHASE", phase)
            .env("MONAR_BALANCE_TEST_ID", hex(&cp.wallet_id))
            .env("MONAR_BALANCE_TEST_PROFILE", hex(&profile))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(exit));
        assert_eq!(cli(dir.path(), cp, profile).unwrap(), expected);
        assert_eq!(fs::read(dir.path().join("wallet.monw")).unwrap(), original);
        for entry in fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            let filename = path.file_name().unwrap().to_str().unwrap();
            assert!(
                filename == "manifest.json"
                    || filename.starts_with("chain.sqlite")
                    || filename.starts_with("wallet.monw")
            );
            let bytes = fs::read(path).unwrap();
            for secret in [PASSWORD, [7; 32].as_slice()] {
                assert!(!bytes.windows(secret.len()).any(|w| w == secret));
            }
        }
    }
}
fn config() -> Config {
    Config {
        chain_id: [2; 32],
        initial_bits: 0x2100ffff,
        pow_limit_bits: 0x2100ffff,
        half_life_seconds: 3600,
        seed_interval: 8,
        seed_lag: 2,
        coinbase_maturity: 2,
        max_future_seconds: 120,
        retained_blocks: 1000,
        limits: monario_chain::Limits {
            block_bytes: 100000,
            transaction_bytes: 20000,
            transactions: 100,
            inputs_per_transaction: 100,
            outputs_per_transaction: 100,
            script_bytes: 1000,
        },
    }
}
fn root() -> Root {
    Root {
        id: [3; 32],
        timestamp: 1000,
        commitment: [4; 32],
    }
}
fn coinbase(height: u32) -> Vec<u8> {
    assert!(height > 0);
    let mut script_sig = if height <= 16 {
        vec![0x50 + height as u8]
    } else {
        let mut n = height.to_le_bytes().to_vec();
        while n.last() == Some(&0) {
            n.pop();
        }
        if n.last().is_some_and(|b| b & 0x80 != 0) {
            n.push(0);
        }
        let mut script = vec![n.len() as u8];
        script.extend(n);
        script
    };
    script_sig.push(0);
    let key = Seed::from_bytes(&[7; 32])
        .unwrap()
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap();
    let vout = vec![tb::TxOut::new(
        Zatoshis::from_u64(if height == 1 { 100 } else { 0 }).unwrap(),
        Script(script::Code(key.address().script_pubkey().unwrap())),
    )];
    let tx: TransactionData<transaction::Authorized> = TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        height.into(),
        Some(tb::Bundle {
            vin: vec![tb::TxIn::from_parts(
                tb::OutPoint::new([0; 32], u32::MAX),
                Script(script::Code(script_sig)),
                u32::MAX,
            )],
            vout,
            authorization: tb::Authorized,
        }),
        None,
        None,
        None,
    );
    let mut raw = Vec::new();
    tx.freeze().unwrap().write(&mut raw).unwrap();
    raw
}
fn fixture(name: &str) -> Vec<u8> {
    match name {
        "deposit" => include_bytes!("../../v6/tests/fixtures/spend-deposit-v6.bin").to_vec(),
        "transfer" => include_bytes!("../../v6/tests/fixtures/spend-transfer-v6.bin").to_vec(),
        "withdrawal" => include_bytes!("../../v6/tests/fixtures/spend-withdrawal-v6.bin").to_vec(),
        "conflict" => include_bytes!("../../v6/tests/fixtures/spend-conflict-v6.bin").to_vec(),
        _ => panic!("unknown public fixture"),
    }
}
#[derive(Clone)]
struct Model {
    parent: Hash,
    commitment: Hash,
    tree: CommitmentTree<MerkleHashOrchard, 32>,
}
impl Model {
    fn new() -> Self {
        Self {
            parent: root().id,
            commitment: root().commitment,
            tree: CommitmentTree::empty(),
        }
    }
    fn candidate(&self, height: u32, extra: &[Vec<u8>]) -> (Block, Self) {
        let mut transactions = vec![coinbase(height)];
        transactions.extend_from_slice(extra);
        let mut next = self.clone();
        let mut ids = Vec::new();
        for raw in &transactions {
            let tx = Transaction::read(raw.as_slice(), BranchId::Nu6_3).unwrap();
            ids.push((
                *tx.txid().as_ref(),
                tx.auth_commitment().as_bytes().try_into().unwrap(),
            ));
            if let Some(b) = tx.ironwood_bundle() {
                for a in b.actions() {
                    next.tree
                        .append(MerkleHashOrchard::from_cmx(a.cmx()))
                        .unwrap();
                }
            }
        }
        let commitment = V6Verifier
            .block_commitment_with_state(
                self.commitment,
                height.into(),
                &ids,
                next.tree.root().to_bytes(),
            )
            .unwrap();
        let header = Header {
            version: 1,
            parent: self.parent,
            merkle_root: merkle_root(&ids.iter().map(|(id, _)| *id).collect::<Vec<_>>()).unwrap(),
            commitment,
            timestamp: 1000 + 105 * u64::from(height),
            bits: config().initial_bits,
            nonce: [0; 32],
        };
        next.parent = header.id(&config().chain_id);
        next.commitment = commitment;
        (
            Block {
                header,
                transactions,
            },
            next,
        )
    }
    fn accept(&mut self, source: &mut DurableChain<V6Verifier>, height: u32, extra: &[Vec<u8>]) {
        let (block, next) = self.candidate(height, extra);
        let encoded = monario_chain::wire::encode(&block, &config().limits, &V6Verifier).unwrap();
        source
            .submit_encoded(&encoded, block.header.timestamp + 120)
            .unwrap_or_else(|error| panic!("wallet fixture block rejected: {error:?}"));
        *self = next;
    }
}

#[test]
fn discover_grows_the_transparent_window_and_reports_lower_bounds() {
    let dir = private_dir();
    let mut store = wallet(dir.path());
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[]);
    let opts = options(&source);
    let discovery = crate::Discovery {
        gap: 2,
        start: 2,
        max: 16,
        blocks: 100,
    };
    let value = discover(&store, 0, &opts, &discovery, &source).unwrap();
    assert_eq!(value["observed"]["transparent_external"], "1");
    assert_eq!(value["window"], 4);
    assert_eq!(value["saturated"], false);
    assert_eq!(value["observation_is_lower_bound"], true);
    assert_eq!(value["confirmed_transparent_atoms"], "100");
    assert_eq!(value["immature_coinbase_atoms"], "0");
    assert_eq!(value["complete_to_local_tip"], true);

    for _ in 0..3 {
        store
            .next_address(0, Scope::External, AddressKind::Transparent)
            .unwrap();
    }
    let value = discover(&store, 0, &opts, &discovery, &source).unwrap();
    assert_eq!(value["window"], 5);
    assert_eq!(value["observed"]["transparent_external"], "1");
}

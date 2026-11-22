//! Socket-free wallet publication and real node admission, reorg and restart.
use super::*;
use monario_node::{Clock, Node, submission::Inbox, transport::Identity};
#[path = "wallet_maintenance_tests.rs"]
mod maintenance;
fn key() -> Hash {
    Identity::from_secret(Zeroizing::new([11; 32])).public_key()
}
fn node(source: DurableChain<V6Verifier>) -> Node {
    Node::new(
        source,
        monario_node::Limits {
            peers: 4,
            receive_bytes: 16 * 1024 * 1024,
            send_bytes: 8 * 1024 * 1024,
            messages_per_window: 128,
            bytes_per_window: 8 * 1024 * 1024,
            tx_checks_per_window: 16,
        },
        monario_chain::mempool::Limits {
            transactions: 1024,
            bytes: 8 * 1024 * 1024,
            inputs: 131072,
            minimum_fee: Amount::ZERO,
        },
    )
    .unwrap()
}
fn clock(ms: u64) -> Clock {
    Clock {
        monotonic_ms: ms,
        unix_seconds: 2000,
    }
}
fn advance(n: &mut Node, ms: &mut u64) {
    *ms += 10_000;
    n.tick(clock(*ms)).unwrap();
}
fn import(n: &mut Node, model: &mut Model, height: u32, extra: &[Vec<u8>], ms: &mut u64) {
    let (b, next) = model.candidate(height, extra);
    let raw = monario_chain::wire::encode(&b, &config().limits, &V6Verifier).unwrap();
    *ms += 10_000;
    n.import_block(&raw, clock(*ms)).unwrap();
    *model = next;
}
fn args(
    wallet: &Path,
    local: &Path,
    cp: WalletCheckpoint,
    pins: (Hash, Hash),
    token: [u8; 16],
    action: &str,
) -> Vec<OsString> {
    [
        action.to_owned(),
        "--directory".into(),
        wallet.to_str().unwrap().into(),
        "--name".into(),
        "wallet".into(),
        "--network".into(),
        "main".into(),
        "--password-stdin".into(),
        "--wallet-id".into(),
        hex(&cp.wallet_id),
        "--revision".into(),
        cp.revision.to_string(),
        "--profile".into(),
        hex(&pins.0),
        "--reservation".into(),
        hex(&token),
        "--node-directory".into(),
        local.to_str().unwrap().into(),
        "--submission-inbox".into(),
        "local".into(),
        "--node-public-key".into(),
        hex(&pins.1),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}
fn run(
    wallet: &Path,
    local: &Path,
    cp: WalletCheckpoint,
    pins: (Hash, Hash),
    token: [u8; 16],
    action: &str,
) -> Result<serde_json::Value, Error> {
    let mut out = Vec::new();
    crate::execute(
        Command::parse(args(wallet, local, cp, pins, token, action))?,
        &mut credentials(),
        &mut out,
    )?;
    Ok(serde_json::from_slice(&out).unwrap())
}
#[test]
fn wallet_submission_reaches_real_mempool_and_reorgs_never_release_claims() {
    for private in [false, true] {
        let wallet_dir = private_dir();
        let local = private_dir();
        let (source, model) = source(wallet_dir.path(), private);
        let mut store = wallet(wallet_dir.path());
        let doc = intent(&store, &source, private, false, 8);
        let signed = make(&mut store, &source, &doc).unwrap();
        let raw = decode(signed["transaction_hex"].as_str().unwrap());
        let cp = store.checkpoint().unwrap();
        let token = id(signed["reservation"].as_str().unwrap()).unwrap();
        let profile = source.profile_id().unwrap();
        drop(store);
        let before = fs::read(wallet_dir.path().join("wallet.monw")).unwrap();
        drop(Inbox::create(local.path(), "local", profile, key()).unwrap());
        let queued = run(
            wallet_dir.path(),
            local.path(),
            cp,
            (profile, key()),
            token,
            "submit",
        )
        .unwrap();
        assert_eq!(queued["last_observation"], "queued");
        assert_eq!(queued["published"], true);
        assert!(queued.get("transaction_hex").is_none());
        let mut n = node(source);
        n.attach_submission_inbox(Inbox::open(local.path(), "local", profile, key()).unwrap())
            .unwrap();
        let mut ms = 0;
        advance(&mut n, &mut ms);
        assert_eq!(n.mempool().len(), 1);
        assert_eq!(n.peer_count(), 0);
        let accepted = run(
            wallet_dir.path(),
            local.path(),
            cp,
            (profile, key()),
            token,
            "submit",
        )
        .unwrap();
        assert_eq!(accepted["last_observation"], "admitted-at-tip");
        assert_eq!(accepted["submission"], queued["submission"]);
        assert_eq!(accepted["network_delivery_proven"], false);
        let height = if private { 4 } else { 3 };
        let base = model.clone();
        let mut best = model;
        import(
            &mut n,
            &mut best,
            height,
            std::slice::from_ref(&raw),
            &mut ms,
        );
        advance(&mut n, &mut ms);
        assert_eq!(n.mempool().len(), 0);
        let mut side = base.clone();
        import(&mut n, &mut side, height, &[], &mut ms);
        import(&mut n, &mut side, height + 1, &[], &mut ms);
        advance(&mut n, &mut ms);
        assert_eq!(n.mempool().len(), 1);
        assert_eq!(
            run(
                wallet_dir.path(),
                local.path(),
                cp,
                (profile, key()),
                token,
                "submission-status"
            )
            .unwrap()["last_observation"],
            "admitted-at-tip"
        );
        let mut conflict = base;
        import(
            &mut n,
            &mut conflict,
            height,
            &[fixture(if private { "conflict" } else { "deposit" })],
            &mut ms,
        );
        import(&mut n, &mut conflict, height + 1, &[], &mut ms);
        import(&mut n, &mut conflict, height + 2, &[], &mut ms);
        advance(&mut n, &mut ms);
        assert_eq!(n.mempool().len(), 0);
        let status = run(
            wallet_dir.path(),
            local.path(),
            cp,
            (profile, key()),
            token,
            "submission-status",
        )
        .unwrap();
        assert_eq!(status["last_observation"], "not-admitted-at-tip");
        assert_eq!(
            status["checked_tip"],
            hex(&n.source().chain().unwrap().tip())
        );
        assert_eq!(
            fs::read(wallet_dir.path().join("wallet.monw")).unwrap(),
            before
        );
        let store = open_wallet(wallet_dir.path(), cp);
        assert_eq!(store.checkpoint().unwrap(), cp);
        assert_eq!(store.reservations().unwrap().len(), 1);
        n.shutdown().unwrap();
    }
}
#[test]
fn submission_pins_credentials_unsigned_records_and_recovery_fail_closed() {
    let dir = private_dir();
    let local = private_dir();
    let (source, _) = source(dir.path(), false);
    let profile = source.profile_id().unwrap();
    let mut store = wallet(dir.path());
    let doc = intent(&store, &source, false, false, 8);
    let signed = make(&mut store, &source, &doc).unwrap();
    let token = id(signed["reservation"].as_str().unwrap()).unwrap();
    let cp = store.checkpoint().unwrap();
    drop(store);
    assert!(
        run(
            dir.path(),
            local.path(),
            cp,
            (profile, key()),
            token,
            "submit"
        )
        .is_err()
    );
    assert!(!local.path().join("local.mons").exists());
    drop(Inbox::create(local.path(), "local", profile, key()).unwrap());
    assert!(
        run(
            dir.path(),
            local.path(),
            cp,
            ([0; 32], key()),
            token,
            "submit"
        )
        .is_err()
    );
    assert!(
        run(
            dir.path(),
            local.path(),
            cp,
            (profile, [1; 32]),
            token,
            "submit"
        )
        .is_err()
    );
    assert!(
        run(
            dir.path(),
            local.path(),
            cp,
            (profile, key()),
            [0; 16],
            "submit"
        )
        .is_err()
    );
    let mut output = Vec::new();
    assert!(
        crate::execute(
            Command::parse(args(
                dir.path(),
                local.path(),
                cp,
                (profile, key()),
                token,
                "submit"
            ))
            .unwrap(),
            &mut Cursor::new(vec![1, 0, 0]),
            &mut output
        )
        .is_err()
    );
    assert!(output.is_empty());
    assert_eq!(
        run(
            dir.path(),
            local.path(),
            cp,
            (profile, key()),
            token,
            "submission-status"
        )
        .unwrap()["last_observation"],
        "absent"
    );
    let directory = WalletDirectory::open(dir.path()).unwrap();
    let store = open_wallet(dir.path(), cp);
    let backup = store
        .backup(&directory, "snapshot", &password(PASSWORD).unwrap())
        .unwrap();
    drop(store);
    let recovered = WalletStore::recover(
        &directory,
        "snapshot",
        &password(PASSWORD).unwrap(),
        backup,
        &directory,
        "restored",
        &password(PASSWORD).unwrap(),
    )
    .unwrap();
    let recovered_cp = recovered.checkpoint().unwrap();
    drop(recovered);
    let mut values = args(
        dir.path(),
        local.path(),
        recovered_cp,
        (profile, key()),
        token,
        "submit",
    );
    let i = values.iter().position(|s| s == "--name").unwrap();
    values[i + 1] = "restored".into();
    assert_eq!(
        crate::execute(
            Command::parse(values).unwrap(),
            &mut credentials(),
            &mut Vec::new()
        ),
        Err(Error::RecoveryLocked)
    );
    let mut store = open_wallet(dir.path(), cp);
    let unfinished = store
        .reserve_inputs(
            profile,
            source.chain().unwrap().tip(),
            100,
            vec![monario_wallet::storage::pending::Input::Private { nullifier: [4; 32] }],
        )
        .unwrap();
    let cp = store.checkpoint().unwrap();
    drop(store);
    assert!(
        run(
            dir.path(),
            local.path(),
            cp,
            (profile, key()),
            unfinished,
            "submit"
        )
        .is_err()
    );
    let mut values = args(
        dir.path(),
        local.path(),
        cp,
        (profile, key()),
        token,
        "submit",
    );
    let i = values
        .iter()
        .position(|s| s == "--submission-inbox")
        .unwrap();
    values[i + 1] = "../escape".into();
    assert!(Command::parse(values).is_err());
    struct LostReceipt;
    impl Write for LostReceipt {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    assert_eq!(
        crate::execute(
            Command::parse(args(
                dir.path(),
                local.path(),
                cp,
                (profile, key()),
                token,
                "submit"
            ))
            .unwrap(),
            &mut credentials(),
            &mut LostReceipt
        ),
        Err(Error::Output)
    );
    let recovered = run(
        dir.path(),
        local.path(),
        cp,
        (profile, key()),
        token,
        "submission-status",
    )
    .unwrap();
    assert_eq!(recovered["last_observation"], "queued");
    let retry = run(
        dir.path(),
        local.path(),
        cp,
        (profile, key()),
        token,
        "submit",
    )
    .unwrap();
    assert_eq!(retry["submission"], recovered["submission"]);
    assert_eq!(open_wallet(dir.path(), cp).checkpoint().unwrap(), cp);
}
#[test]
fn mutated_private_authorization_is_not_admitted_and_polling_is_bounded() {
    let dir = private_dir();
    let local = private_dir();
    let (source, _) = source(dir.path(), true);
    let profile = source.profile_id().unwrap();
    let mut inbox = Inbox::create(local.path(), "local", profile, key()).unwrap();
    let raw = fixture("transfer");
    let mut invalid = raw.clone();
    *invalid.last_mut().unwrap() ^= 1;
    let bad = inbox.enqueue(&invalid).unwrap();
    let good = inbox.enqueue(&raw).unwrap();
    let mut n = node(source);
    n.attach_submission_inbox(Inbox::open(local.path(), "local", profile, key()).unwrap())
        .unwrap();
    n.tick(clock(0)).unwrap();
    assert!(n.mempool().is_empty());
    assert_eq!(inbox.status(bad).unwrap().unwrap().state, 2);
    n.tick(clock(999)).unwrap();
    assert!(n.mempool().is_empty());
    assert_eq!(inbox.status(good).unwrap().unwrap().state, 0);
    n.tick(clock(1000)).unwrap();
    assert_eq!(n.mempool().len(), 1);
    assert_eq!(inbox.status(good).unwrap().unwrap().state, 1);
    n.tick(clock(1001)).unwrap();
    assert_eq!(n.mempool().len(), 1);
    n.shutdown().unwrap();
}

#[test]
fn node_submission_crash_worker() {
    let Some(root) = std::env::var_os("MONAR_LOCAL_NODE_CRASH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let local = PathBuf::from(std::env::var_os("MONAR_LOCAL_NODE_CRASH_INBOX").unwrap());
    let source = DurableChain::open(
        &root.join("chain.sqlite"),
        config(),
        super::root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let profile = source.profile_id().unwrap();
    let mut n = node(source);
    if std::env::var("MONAR_LOCAL_NODE_CRASH_PHASE").unwrap() == "before-receipt" {
        n.submit_transaction(fs::read(root.join("signed-test.bin")).unwrap(), clock(0))
            .unwrap();
        std::process::exit(83);
    }
    n.attach_submission_inbox(Inbox::open(&local, "local", profile, key()).unwrap())
        .unwrap();
    n.tick(clock(0)).unwrap();
    assert_eq!(n.mempool().len(), 1);
    std::process::exit(84);
}
#[test]
fn node_crashes_replay_published_signed_bytes_even_after_old_admission_receipt() {
    for private in [false, true] {
        for phase in ["before-receipt", "after-receipt"] {
            let dir = private_dir();
            let local = private_dir();
            let (source, _) = source(dir.path(), private);
            let profile = source.profile_id().unwrap();
            let mut store = wallet(dir.path());
            let doc = intent(&store, &source, private, false, 8);
            let signed = make(&mut store, &source, &doc).unwrap();
            let cp = store.checkpoint().unwrap();
            let token = id(signed["reservation"].as_str().unwrap()).unwrap();
            fs::write(
                dir.path().join("signed-test.bin"),
                decode(signed["transaction_hex"].as_str().unwrap()),
            )
            .unwrap();
            drop(store);
            drop(source);
            drop(Inbox::create(local.path(), "local", profile, key()).unwrap());
            run(
                dir.path(),
                local.path(),
                cp,
                (profile, key()),
                token,
                "submit",
            )
            .unwrap();
            let status = Process::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "balance::tests::construction::submissions::node_submission_crash_worker",
                ])
                .env("MONAR_LOCAL_NODE_CRASH_ROOT", dir.path())
                .env("MONAR_LOCAL_NODE_CRASH_INBOX", local.path())
                .env("MONAR_LOCAL_NODE_CRASH_PHASE", phase)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(
                status.code(),
                Some(if phase == "before-receipt" { 83 } else { 84 })
            );
            let source = DurableChain::open(
                &dir.path().join("chain.sqlite"),
                config(),
                root(),
                V6Verifier,
                u64::MAX / 2,
            )
            .unwrap();
            let mut n = node(source);
            n.attach_submission_inbox(Inbox::open(local.path(), "local", profile, key()).unwrap())
                .unwrap();
            assert!(n.mempool().is_empty());
            n.tick(clock(0)).unwrap();
            assert_eq!(n.mempool().len(), 1);
            assert_eq!(
                run(
                    dir.path(),
                    local.path(),
                    cp,
                    (profile, key()),
                    token,
                    "submission-status"
                )
                .unwrap()["last_observation"],
                "admitted-at-tip"
            );
            let store = open_wallet(dir.path(), cp);
            assert_eq!(store.checkpoint().unwrap(), cp);
            assert_eq!(store.reservations().unwrap().len(), 1);
            n.shutdown().unwrap();
        }
    }
}

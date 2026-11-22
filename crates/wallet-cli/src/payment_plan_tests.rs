//! Public-key fixtures; no sockets, genesis generation or nonce search.
use super::*;
use monario_wallet_scan::build::{
    self,
    selection::{self, Pool},
};

fn document(
    store: &WalletStore,
    source: &DurableChain<V6Verifier>,
    private: bool,
) -> serde_json::Value {
    let mut doc = intent(store, source, private, private, 8);
    doc["funding"] = if private { "private" } else { "transparent" }.into();
    doc
}
fn plan(
    store: &WalletStore,
    source: &DurableChain<V6Verifier>,
    doc: &serde_json::Value,
) -> Result<serde_json::Value, Error> {
    tx::plan::prepare(
        store,
        0,
        &options(source),
        source,
        &serde_json::to_vec(doc).unwrap(),
        amount(2),
    )
}
#[test]
fn planning_both_pools_constructs_real_verified_transactions_and_reorg_keeps_claims() {
    for private in [false, true] {
        let dir = private_dir();
        let (mut source, mut model) = source(dir.path(), private);
        let mut store = wallet(dir.path());
        let doc = document(&store, &source, private);
        let cp = store.checkpoint().unwrap();
        let planned = plan(&store, &source, &doc).unwrap();
        assert_eq!(planned, plan(&store, &source, &doc).unwrap());
        assert_eq!(planned["signed"], false);
        assert_eq!(planned["claims_reserved"], false);
        assert_eq!(planned["input_count"], 1);
        assert_eq!(planned["change_atoms"], if private { "19" } else { "9" });
        assert_eq!(store.checkpoint().unwrap(), cp);
        assert!(store.reservations().unwrap().is_empty());
        let scanner = prepare(&store, 0, &options(&source), &source).unwrap();
        let before = model.clone();
        let signed = make(&mut store, &source, &planned["request"]).unwrap();
        let bytes = verify(&source, &signed);
        assert!(plan(&store, &source, &doc).is_err());
        let height = source.chain().unwrap().height() as u32 + 1;
        model.accept(&mut source, height, &[bytes]);
        assert!(
            selection::select(
                &source,
                &scanner,
                &store,
                0,
                if private {
                    Pool::Private
                } else {
                    Pool::Transparent
                },
                amount(1)
            )
            .is_err()
        );
        let mut side = before;
        side.accept(&mut source, height, &[]);
        side.accept(&mut source, height + 1, &[]);
        let mut current = doc.clone();
        current["validated_tip"] = hex(&source.chain().unwrap().tip()).into();
        if let Ok(replanned) = plan(&store, &source, &current) {
            assert!(!private);
            assert_ne!(
                replanned["request"]["funding"],
                planned["request"]["funding"]
            );
        }
        let mut fixed = planned["request"].clone();
        fixed["validated_tip"] = current["validated_tip"].clone();
        assert!(make(&mut store, &source, &fixed).is_err());
        assert!(make(&mut store, &source, &planned["request"]).is_err());
        let cp = store.checkpoint().unwrap();
        drop(store);
        let store = open_wallet(dir.path(), cp);
        assert_eq!(store.reservations().unwrap().len(), 1);
        if let Ok(replanned) = plan(&store, &source, &current) {
            assert!(!private);
            assert_ne!(
                replanned["request"]["funding"],
                planned["request"]["funding"]
            );
        }
    }
}

#[test]
fn planning_rejects_malformed_intent_fee_expiry_network_and_service_without_claims() {
    let dir = private_dir();
    let (source, _) = source(dir.path(), true);
    let store = wallet(dir.path());
    let base = document(&store, &source, true);
    let cp = store.checkpoint().unwrap();
    let wrong = Seed::from_bytes(&[8; 32])
        .unwrap()
        .private_account(Network::Test, 0)
        .unwrap()
        .address(Scope::External, 0)
        .unwrap()
        .encode();
    let cases = [
        ("version", serde_json::json!(2)),
        ("funding", serde_json::json!("mixed")),
        ("funding", serde_json::json!({"pool":"private","inputs":[]})),
        ("validated_tip", serde_json::json!(hex(&[0; 32]))),
        ("fee_atoms", serde_json::json!("3")),
        ("fee_atoms", serde_json::json!("-1")),
        ("payments", serde_json::json!([])),
        (
            "payments",
            serde_json::json!([{"address":wrong,"amount_atoms":"1"}]),
        ),
        (
            "payments",
            serde_json::json!([{"address":base["payments"][0]["address"],"amount_atoms":"0"}]),
        ),
        ("expiry_height", serde_json::json!(0)),
        ("expiry_height", serde_json::json!(u32::MAX)),
        ("change", serde_json::json!("auto")),
        ("service", serde_json::json!({"kind":"proof"})),
    ];
    for (field, value) in cases {
        let mut doc = base.clone();
        doc[field] = value;
        assert!(plan(&store, &source, &doc).is_err(), "{field}");
        assert_eq!(store.checkpoint().unwrap(), cp);
        assert!(store.reservations().unwrap().is_empty());
    }
    for bytes in [
        b"{".as_slice(),
        &vec![b' '; 65_537],
        b"{\"version\":1,\"version\":1}",
    ] {
        assert!(
            tx::plan::prepare(&store, 0, &options(&source), &source, bytes, amount(2)).is_err()
        );
    }
}

#[test]
fn selection_binds_owner_account_and_excludes_unsigned_claims_from_other_profiles() {
    for private in [false, true] {
        let dir = private_dir();
        let (source, _) = source(dir.path(), private);
        let mut store = wallet(dir.path());
        let scanner = prepare(&store, 0, &options(&source), &source).unwrap();
        let pool = if private {
            Pool::Private
        } else {
            Pool::Transparent
        };
        let selected = selection::select(&source, &scanner, &store, 0, pool, amount(70)).unwrap();
        let claims = match selected.funding {
            build::Funding::Transparent(points) => points
                .into_iter()
                .map(|p| monario_wallet::storage::pending::Input::Transparent {
                    transaction: p.transaction,
                    index: p.index,
                })
                .collect(),
            build::Funding::Private(ids) => ids
                .into_iter()
                .map(|nullifier| monario_wallet::storage::pending::Input::Private { nullifier })
                .collect(),
        };
        store.reserve_inputs([99; 32], [88; 32], 1, claims).unwrap();
        assert!(selection::select(&source, &scanner, &store, 0, pool, amount(70)).is_err());
        assert!(selection::select(&source, &scanner, &store, 1, pool, amount(1)).is_err());
        let other_dir = private_dir();
        let other = WalletStore::create(
            &WalletDirectory::open(other_dir.path()).unwrap(),
            "other",
            Seed::from_bytes(&[8; 32]).unwrap(),
            Network::Main,
            &password(PASSWORD).unwrap(),
        )
        .unwrap();
        assert!(selection::select(&source, &scanner, &other, 0, pool, amount(1)).is_err());
    }
}

#[test]
fn selection_reorg_removes_unconfirmed_private_deposit_and_restores_public_funding() {
    let dir = private_dir();
    let (mut source, mut model) = source(dir.path(), false);
    let store = wallet(dir.path());
    let mut side = model.clone();
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let doc = document(&store, &source, true);
    assert!(plan(&store, &source, &doc).is_ok());
    side.accept(&mut source, 3, &[]);
    side.accept(&mut source, 4, &[]);
    assert!(plan(&store, &source, &doc).is_err());
    let mut current = doc;
    current["validated_tip"] = hex(&source.chain().unwrap().tip()).into();
    assert!(plan(&store, &source, &current).is_err());
    current["funding"] = "transparent".into();
    assert!(plan(&store, &source, &current).is_ok());
    assert!(store.reservations().unwrap().is_empty());
}

#[test]
fn planning_recovery_lock_and_immature_coinbase_fail_closed() {
    let dir = private_dir();
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
    let store = wallet(dir.path());
    let doc = document(&store, &source, false);
    assert!(plan(&store, &source, &doc).is_err());
    model.accept(&mut source, 2, &[]);
    let doc = document(&store, &source, false);
    assert!(plan(&store, &source, &doc).is_ok());
    let directory = WalletDirectory::open(dir.path()).unwrap();
    let cp = store
        .backup(&directory, "snapshot", &password(PASSWORD).unwrap())
        .unwrap();
    drop(store);
    let recovered = WalletStore::recover(
        &directory,
        "snapshot",
        &password(PASSWORD).unwrap(),
        cp,
        &directory,
        "restored",
        &password(PASSWORD).unwrap(),
    )
    .unwrap();
    assert!(plan(&recovered, &source, &doc).is_err());
    assert!(recovered.reservations().unwrap().is_empty());
}

#[test]
fn planning_cli_guards_authentication_arguments_and_private_request_files() {
    let dir = private_dir();
    let store = wallet(dir.path());
    let cp = store.checkpoint().unwrap();
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        production(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    let doc = document(&store, &source, false);
    let profile = manifest_file(dir.path(), &production());
    drop(store);
    drop(source);
    write_request(dir.path(), &doc);
    let mut args = construct_args(dir.path(), cp, profile);
    args[0] = "plan-payment".into();
    assert!(Command::parse(args.clone()).is_ok());
    let original = wallet_vault(dir.path());
    let invoke = || {
        let mut out = Vec::new();
        assert!(
            crate::execute(
                Command::parse(args.clone()).unwrap(),
                &mut credentials(),
                &mut out
            )
            .is_err()
        );
        assert!(out.is_empty());
        assert_eq!(wallet_vault(dir.path()), original);
    };
    invoke(); // Production maturity is 240; this output is immature.
    fs::remove_file(dir.path().join("payment.json")).unwrap();
    invoke();
    fs::create_dir(dir.path().join("payment.json")).unwrap();
    invoke();
    fs::remove_dir(dir.path().join("payment.json")).unwrap();
    write_request(dir.path(), &doc);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        fs::set_permissions(
            dir.path().join("payment.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        invoke();
        fs::set_permissions(
            dir.path().join("payment.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::hard_link(
            dir.path().join("payment.json"),
            dir.path().join("alias.json"),
        )
        .unwrap();
        invoke();
        fs::remove_file(dir.path().join("alias.json")).unwrap();
        fs::rename(
            dir.path().join("payment.json"),
            dir.path().join("real.json"),
        )
        .unwrap();
        symlink("real.json", dir.path().join("payment.json")).unwrap();
        invoke();
    }
    let mut bad = args.clone();
    let i = bad.iter().position(|v| v == "--request").unwrap();
    bad[i + 1] = "../payment.json".into();
    assert!(Command::parse(bad).is_err());
    let mut bad = args.clone();
    bad.extend(["--node-directory", "unused"].map(OsString::from));
    assert!(Command::parse(bad).is_err());
    let mut wrong = Cursor::new([vec![12, 0], vec![b'x'; 12]].concat());
    let mut out = Vec::new();
    assert_eq!(
        crate::execute(Command::parse(args).unwrap(), &mut wrong, &mut out),
        Err(Error::Credentials)
    );
    assert!(out.is_empty());
    assert_eq!(wallet_vault(dir.path()), original);
}

#[test]
fn planning_crash_worker() {
    let Some(dir) = std::env::var_os("MONAR_PLAN_TEST_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let cp = WalletCheckpoint {
        wallet_id: id(&std::env::var("MONAR_PLAN_TEST_ID").unwrap()).unwrap(),
        network: Network::Main,
        revision: 0,
    };
    let source = DurableChain::open(
        &dir.join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let store = open_wallet(&dir, cp);
    let bytes = fs::read(dir.join("payment.json")).unwrap();
    let result =
        tx::plan::prepare(&store, 0, &options(&source), &source, &bytes, amount(2)).unwrap();
    struct ExitOutput {
        complete: bool,
        wrote: bool,
    }
    impl Write for ExitOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.complete {
                return Ok(bytes.len());
            }
            if self.wrote {
                std::process::exit(87);
            }
            self.wrote = true;
            Ok(1.min(bytes.len()))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            std::process::exit(87)
        }
    }
    report(
        &result,
        &mut ExitOutput {
            complete: std::env::var("MONAR_PLAN_TEST_PHASE").unwrap() == "complete",
            wrote: false,
        },
    )
    .unwrap();
}
#[test]
fn planning_process_death_during_output_leaves_no_claims_or_issuance() {
    for (private, phase) in [
        (false, "partial"),
        (false, "complete"),
        (true, "partial"),
        (true, "complete"),
    ] {
        let dir = private_dir();
        let (source, _) = source(dir.path(), private);
        let store = wallet(dir.path());
        let cp = store.checkpoint().unwrap();
        let doc = document(&store, &source, private);
        write_request(dir.path(), &doc);
        drop(store);
        drop(source);
        let original = wallet_vault(dir.path());
        let status = Process::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "balance::tests::construction::planning::planning_crash_worker",
            ])
            .env("MONAR_PLAN_TEST_DIR", dir.path())
            .env("MONAR_PLAN_TEST_PHASE", phase)
            .env("MONAR_PLAN_TEST_ID", hex(&cp.wallet_id))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(87));
        assert_eq!(wallet_vault(dir.path()), original);
        let source = DurableChain::open(
            &dir.path().join("chain.sqlite"),
            config(),
            root(),
            V6Verifier,
            u64::MAX / 2,
        )
        .unwrap();
        let store = open_wallet(dir.path(), cp);
        assert_eq!(store.checkpoint().unwrap(), cp);
        assert!(store.account_progress().unwrap().is_empty());
        assert!(store.reservations().unwrap().is_empty());
        assert!(plan(&store, &source, &doc).is_ok());
    }
}

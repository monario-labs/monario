//! Real v6 adapters with public seeds/passwords and fixed-nonce synthetic chains.
use super::*;
use crate::transactions as tx;
use monario_monetary::Amount;
#[path = "transaction_status_tests.rs"]
mod lifecycle;
#[path = "operator_tests.rs"]
mod operator;
#[path = "payment_plan_tests.rs"]
mod planning;
#[path = "rebroadcast_tests.rs"]
mod rebroadcast;
#[path = "wallet_submission_tests.rs"]
mod submissions;

fn amount(n: u64) -> Amount {
    Amount::from_atoms(n).unwrap()
}
fn inventory(store: &WalletStore, source: &DurableChain<V6Verifier>) -> serde_json::Value {
    let mut scan_options = options(source);
    scan_options.blocks = 1000;
    let scanner = prepare(store, 0, &scan_options, source).unwrap();
    tx::inputs(store, source, &scanner, 0).unwrap()
}
fn intent(
    store: &WalletStore,
    source: &DurableChain<V6Verifier>,
    private: bool,
    destination_private: bool,
    destination_seed: u8,
) -> serde_json::Value {
    let inputs = inventory(store, source);
    let funding = if private {
        serde_json::json!({"pool":"private","inputs":[inputs["private"][0]["nullifier"]]})
    } else {
        let p = inputs["transparent"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["amount_atoms"] == "100")
            .unwrap();
        serde_json::json!({"pool":"transparent","inputs":[{"transaction":p["transaction"],"index":p["index"]}]})
    };
    let seed = Seed::from_bytes(&[destination_seed; 32]).unwrap();
    let address = if destination_private {
        seed.private_account(Network::Main, 0)
            .unwrap()
            .address(Scope::External, 0)
            .unwrap()
    } else {
        seed.transparent_key(Network::Main, 0, Scope::External, 0)
            .unwrap()
            .address()
    };
    serde_json::json!({"version":1,"validated_tip":hex(&source.chain().unwrap().tip()),
        "funding":funding,"payments":[{"address":address.encode(),"amount_atoms":if private {"70"} else {"90"}}],
        "fee_atoms":"1","expiry_height":source.chain().unwrap().height()+10,
        "change":if private {"private"} else {"transparent"}})
}
fn make(
    store: &mut WalletStore,
    source: &DurableChain<V6Verifier>,
    doc: &serde_json::Value,
) -> Result<serde_json::Value, Error> {
    tx::construct(
        store,
        0,
        &options(source),
        source,
        &serde_json::to_vec(doc).unwrap(),
        amount(2),
    )
    .map(|v| serde_json::to_value(v).unwrap())
}
fn decode(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn verify(source: &DurableChain<V6Verifier>, output: &serde_json::Value) -> Vec<u8> {
    let bytes = decode(output["transaction_hex"].as_str().unwrap());
    let mut pool = monario_chain::mempool::Mempool::new(
        source.chain().unwrap(),
        monario_chain::mempool::Limits {
            transactions: 32,
            bytes: 1_000_000,
            inputs: 1024,
            minimum_fee: Amount::ZERO,
        },
    )
    .unwrap();
    let id = pool.admit(source.chain().unwrap(), bytes.clone()).unwrap();
    assert_eq!(output["transaction_id"], hex(&id));
    assert_eq!(
        pool.fee(source.chain().unwrap(), id).unwrap(),
        Some(amount(1))
    );
    assert_eq!(output["broadcast"], false);
    bytes
}
fn source(dir: &Path, private: bool) -> (DurableChain<V6Verifier>, Model) {
    let mut source = DurableChain::open(
        &dir.join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    if private {
        model.accept(&mut source, 3, &[fixture("deposit")]);
    }
    (source, model)
}
fn open_wallet(dir: &Path, cp: WalletCheckpoint) -> WalletStore {
    WalletStore::open(
        &WalletDirectory::open(dir).unwrap(),
        "wallet",
        &password(PASSWORD).unwrap(),
        cp,
    )
    .unwrap()
}

#[test]
fn payout_execute_plans_signs_and_publishes_one_reviewed_batch() {
    let dir = private_dir();
    let store = wallet(dir.path());
    let cp = store.checkpoint().unwrap();
    let mut cfg = production();
    // A longer fixture epoch reuses the real RandomX cache.
    cfg.seed_interval = 1000;
    let profile = manifest_file(dir.path(), &cfg);
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        cfg.clone(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let mut model = Model::new();
    for height in 1..=240 {
        model.accept(&mut source, height, &[]);
    }
    let address = Seed::from_bytes(&[8; 32])
        .unwrap()
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap()
        .address();
    let doc = serde_json::json!({"version":1,"validated_tip":hex(&source.chain().unwrap().tip()),
        "funding":"transparent","payments":[{"address":address.encode(),"amount_atoms":"50"}],
        "fee_atoms":"1","expiry_height":source.chain().unwrap().height()+10,"change":"transparent"});
    fs::write(
        dir.path().join("payout.json"),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            dir.path().join("payout.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    monario_node::submission::Inbox::create(dir.path(), "payout-inbox", profile, [11; 32]).unwrap();
    drop(store);
    drop(model);
    drop(source);
    let mut args = cli_args(dir.path(), cp, profile);
    args[0] = "payout-execute".into();
    args.extend(
        [
            "--request",
            "payout.json",
            "--max-fee-atoms",
            "1",
            "--node-directory",
            dir.path().to_str().unwrap(),
            "--submission-inbox",
            "payout-inbox",
            "--node-public-key",
            hex(&[11; 32]).as_str(),
        ]
        .into_iter()
        .map(OsString::from),
    );
    let mut output = Vec::new();
    crate::execute(
        Command::parse(args).unwrap(),
        &mut credentials(),
        &mut output,
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["operation"], "payout-execute");
    assert_eq!(value["signed"]["transaction_hex"], serde_json::Value::Null);
    assert_eq!(value["signed"]["broadcast"], false);
    assert_eq!(value["submission"]["published"], true);
    assert_eq!(value["submission"]["inbox_phase"], "active");
    assert_eq!(value["network_delivery_proven"], false);
    let source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        cfg,
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let store = open_wallet(dir.path(), cp);
    let token = id(value["signed"]["reservation"].as_str().unwrap()).unwrap();
    let exported = serde_json::to_value(tx::export(&store, profile, token).unwrap()).unwrap();
    assert_eq!(
        exported["transaction_id"],
        value["signed"]["transaction_id"]
    );
    let bytes = verify(&source, &exported);
    assert!(!bytes.is_empty());
    assert_eq!(store.reservations().unwrap().len(), 1);
}

#[test]
fn input_scan_reports_a_tip_and_height_even_with_no_spendable_outputs() {
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
    let inputs = inventory(&store, &source);

    assert_eq!(inputs["validated_tip"], hex(&source.chain().unwrap().tip()));
    assert_eq!(inputs["height"], "0");
    assert!(inputs["transparent"].as_array().unwrap().is_empty());
    assert!(inputs["private"].as_array().unwrap().is_empty());
}

#[test]
fn transparent_construction_verifies_and_reorg_retains_exact_signed_claims() {
    let dir = private_dir();
    let (mut source, mut model) = source(dir.path(), false);
    let mut store = wallet(dir.path());
    let doc = intent(&store, &source, false, false, 8);
    let before = model.clone();
    let output = make(&mut store, &source, &doc).unwrap();
    assert_eq!(output["change_atoms"], "9");
    let bytes = verify(&source, &output);
    let inv = inventory(&store, &source);
    let chain = source.chain().unwrap();
    assert_eq!(inv["validated_tip"], hex(&chain.tip()));
    assert_eq!(inv["height"], chain.height().to_string());
    assert!(
        inv["transparent"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["amount_atoms"] == "100" && p["reserved"] == true)
    );
    assert!(make(&mut store, &source, &doc).is_err());
    let cp = store.checkpoint().unwrap();
    let token = id(output["reservation"].as_str().unwrap()).unwrap();
    model.accept(&mut source, 3, std::slice::from_ref(&bytes));
    assert_eq!(value(&store, &source)["confirmed_transparent_atoms"], "9");
    let mut side = before;
    side.accept(&mut source, 3, &[]);
    side.accept(&mut source, 4, &[]);
    assert_eq!(value(&store, &source)["confirmed_transparent_atoms"], "100");
    assert!(make(&mut store, &source, &doc).is_err());
    let mut current = doc.clone();
    current["validated_tip"] = hex(&source.chain().unwrap().tip()).into();
    assert!(make(&mut store, &source, &current).is_err());
    assert_eq!(store.checkpoint().unwrap(), cp);
    drop(source);
    drop(store);
    let source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let store = open_wallet(dir.path(), cp);
    let exported =
        serde_json::to_value(tx::export(&store, source.profile_id().unwrap(), token).unwrap())
            .unwrap();
    assert_eq!(exported["transaction_hex"], output["transaction_hex"]);
    assert_eq!(exported["validated_tip"], output["validated_tip"]);
    assert_eq!(store.reservations().unwrap().len(), 1);
}
#[test]
fn transparent_to_private_and_private_withdrawal_adapters_use_real_proofs() {
    let dir = private_dir();
    let (mut source, mut model) = source(dir.path(), false);
    let mut store = wallet(dir.path());
    let doc = intent(&store, &source, false, true, 7);
    let shield = make(&mut store, &source, &doc).unwrap();
    let bytes = verify(&source, &shield);
    model.accept(&mut source, 3, &[bytes]);
    amounts(&value(&store, &source), "9", "0", "90");
    let doc = intent(&store, &source, true, false, 8);
    let withdrawal = make(&mut store, &source, &doc).unwrap();
    assert_eq!(withdrawal["change_atoms"], "19");
    let before = model.clone();
    let bytes = verify(&source, &withdrawal);
    model.accept(&mut source, 4, &[bytes]);
    amounts(&value(&store, &source), "9", "0", "19");
    let cp = store.checkpoint().unwrap();
    let mut side = before;
    side.accept(&mut source, 4, &[]);
    side.accept(&mut source, 5, &[]);
    amounts(&value(&store, &source), "9", "0", "90");
    assert!(make(&mut store, &source, &doc).is_err());
    let mut current = doc;
    current["validated_tip"] = hex(&source.chain().unwrap().tip()).into();
    assert!(make(&mut store, &source, &current).is_err());
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert!(
        inventory(&store, &source)["private"][0]["reserved"]
            .as_bool()
            .unwrap()
    );
}
#[test]
fn private_construction_from_pinned_checkpoint_is_self_verified_and_bound() {
    let dir = private_dir();
    let (mut full, mut model) = source(dir.path(), true);
    let pin = full
        .create_state_checkpoint(monario_node::cli::STATE_CHECKPOINT_LIMITS)
        .unwrap();
    drop(full);
    let mut source = DurableChain::open_with_checkpoint(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
        pin,
        monario_node::cli::STATE_CHECKPOINT_LIMITS,
    )
    .unwrap();
    let mut store = wallet(dir.path());
    let mut doc = intent(&store, &source, true, false, 8);
    let mut opts = options(&source);
    opts.checkpoint = Some(pin.commitment());
    // Cache the spent state, then recover its private note and witness through a reorg.
    prepare(&store, 0, &opts, &source).unwrap();
    let funding = model.clone();
    model.accept(&mut source, 4, &[fixture("transfer")]);
    model.accept(&mut source, 5, &[fixture("withdrawal")]);
    prepare(&store, 0, &opts, &source).unwrap();
    model = funding;
    model.accept(&mut source, 4, &[]);
    model.accept(&mut source, 5, &[]);
    model.accept(&mut source, 6, &[]);
    doc["validated_tip"] = hex(&source.chain().unwrap().tip()).into();
    opts.blocks = 3;
    let output = serde_json::to_value(
        tx::construct(
            &mut store,
            0,
            &opts,
            &source,
            &serde_json::to_vec(&doc).unwrap(),
            amount(2),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(output["chain_checkpoint"], hex(&pin.commitment()));
    let raw = verify(&source, &output);
    let cp = store.checkpoint().unwrap();
    model.accept(&mut source, 7, &[raw]);
    amounts(&value(&store, &source), "0", "0", "19");
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert_eq!(store.reservations().unwrap().len(), 1);
}

#[test]
fn malformed_requests_policy_ownership_and_expiry_fail_before_reservation() {
    let dir = private_dir();
    let (source, _) = source(dir.path(), false);
    let mut store = wallet(dir.path());
    let base = intent(&store, &source, false, false, 8);
    let cp = store.checkpoint().unwrap();
    let mut cases = vec![b"{".to_vec(), vec![b' '; 65_537]];
    for (field, bad) in [
        ("version", 2.into()),
        ("fee_atoms", "3".into()),
        ("expiry_height", 0.into()),
        ("expiry_height", 999.into()),
        ("validated_tip", hex(&[0; 32]).into()),
        ("payments", serde_json::json!([])),
        ("change", "auto".into()),
        ("extra", true.into()),
    ] {
        let mut doc = base.clone();
        doc[field] = bad;
        cases.push(serde_json::to_vec(&doc).unwrap());
    }
    for (field, bad) in [
        ("amount_atoms", "0"),
        ("amount_atoms", "101"),
        ("amount_atoms", "1.5"),
        ("amount_atoms", "18446744073709551616"),
        ("address", "invalid"),
    ] {
        let mut doc = base.clone();
        doc["payments"][0][field] = bad.into();
        cases.push(serde_json::to_vec(&doc).unwrap());
    }
    let mut doc = base.clone();
    doc["funding"]["inputs"][0]["transaction"] = hex(&[0; 32]).into();
    cases.push(serde_json::to_vec(&doc).unwrap());
    let mut doc = base.clone();
    let point = doc["funding"]["inputs"][0].clone();
    doc["funding"]["inputs"].as_array_mut().unwrap().push(point);
    cases.push(serde_json::to_vec(&doc).unwrap());
    let mut doc = base.clone();
    doc["payments"][0]["amount_atoms"] = serde_json::json!(90);
    cases.push(serde_json::to_vec(&doc).unwrap());
    let wrong = Seed::from_bytes(&[8; 32])
        .unwrap()
        .transparent_key(Network::Test, 0, Scope::External, 0)
        .unwrap()
        .address()
        .encode();
    let mut doc = base.clone();
    doc["payments"][0]["address"] = wrong.into();
    cases.push(serde_json::to_vec(&doc).unwrap());
    let mut duplicate = serde_json::to_string(&base).unwrap();
    duplicate.insert_str(1, "\"version\":1,");
    cases.push(duplicate.into_bytes());
    for bytes in cases {
        assert!(
            tx::construct(&mut store, 0, &options(&source), &source, &bytes, amount(2)).is_err()
        );
        assert_eq!(store.checkpoint().unwrap(), cp);
        assert!(store.reservations().unwrap().is_empty());
    }
    let directory = WalletDirectory::open(dir.path()).unwrap();
    let backup = store
        .backup(&directory, "snapshot", &password(PASSWORD).unwrap())
        .unwrap();
    drop(store);
    let mut restored = WalletStore::recover(
        &directory,
        "snapshot",
        &password(PASSWORD).unwrap(),
        backup,
        &directory,
        "restored",
        &password(PASSWORD).unwrap(),
    )
    .unwrap();
    assert!(make(&mut restored, &source, &base).is_err());
    assert!(restored.recovery_required().unwrap());
    assert!(restored.reservations().unwrap().is_empty());
}
fn write_request(root: &Path, doc: &serde_json::Value) {
    fs::write(root.join("payment.json"), serde_json::to_vec(doc).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("payment.json"), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn construct_args(root: &Path, cp: WalletCheckpoint, profile: [u8; 32]) -> Vec<OsString> {
    let mut args = cli_args(root, cp, profile);
    args[0] = "construct".into();
    args.extend(["--request", "payment.json", "--max-fee-atoms", "2"].map(OsString::from));
    args
}
#[test]
fn cli_request_file_guards_and_immature_funding_do_not_change_wallet() {
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
    let doc = intent(&store, &source, false, false, 8);
    let profile = manifest_file(dir.path(), &production());
    drop(store);
    drop(source);
    write_request(dir.path(), &doc);
    let original = wallet_vault(dir.path());
    let invoke = || {
        let mut output = Vec::new();
        let result = crate::execute(
            Command::parse(construct_args(dir.path(), cp, profile)).unwrap(),
            &mut credentials(),
            &mut output,
        );
        assert!(output.is_empty());
        assert!(result.is_err());
        assert_eq!(wallet_vault(dir.path()), original);
    };
    invoke();
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
    let mut args = construct_args(dir.path(), cp, profile);
    *args.last_mut().unwrap() = "-1".into();
    assert!(Command::parse(args).is_err());
    let mut args = construct_args(dir.path(), cp, profile);
    let i = args.iter().position(|s| s == "--request").unwrap();
    args[i + 1] = "../payment.json".into();
    assert!(Command::parse(args).is_err());
}

#[test]
fn full_cli_constructs_and_validates_after_production_coinbase_maturity() {
    let dir = private_dir();
    let store = wallet(dir.path());
    let cp = store.checkpoint().unwrap();
    let mut cfg = production();
    // A longer fixture epoch reuses the real RandomX cache; proof checking stays enabled.
    cfg.seed_interval = 1000;
    let profile = manifest_file(dir.path(), &cfg);
    let path = dir.path().join("chain.sqlite");
    let mut source =
        DurableChain::open(&path, cfg.clone(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut model = Model::new();
    for height in 1..=100 {
        model.accept(&mut source, height, &[]);
    }
    let doc = intent(&store, &source, false, true, 7);
    write_request(dir.path(), &doc);
    drop(source);
    drop(store);
    let mut output = Vec::new();
    crate::execute(
        Command::parse(construct_args(dir.path(), cp, profile)).unwrap(),
        &mut credentials(),
        &mut output,
    )
    .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let mut source =
        DurableChain::open(&path, cfg.clone(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let bytes = verify(&source, &result);
    model.accept(&mut source, 241, &[bytes]);
    let store = open_wallet(dir.path(), cp);
    let doc = intent(&store, &source, true, false, 8);
    write_request(dir.path(), &doc);
    drop(store);
    drop(source);
    let mut output = Vec::new();
    crate::execute(
        Command::parse(construct_args(dir.path(), cp, profile)).unwrap(),
        &mut credentials(),
        &mut output,
    )
    .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let mut source = DurableChain::open(&path, cfg, root(), V6Verifier, u64::MAX / 2).unwrap();
    let bytes = verify(&source, &result);
    model.accept(&mut source, 242, &[bytes]);
    drop(source);
    let mut args = cli_args(dir.path(), cp, profile);
    args[0] = "inputs".into();
    let mut output = Vec::new();
    crate::execute(
        Command::parse(args).unwrap(),
        &mut credentials(),
        &mut output,
    )
    .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["reservations"].as_array().unwrap().len(), 2);
    assert_eq!(result["private"][0]["amount_atoms"], "19");
    assert!(
        result["transparent"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["amount_atoms"] == "9")
    );
}

#[test]
fn construction_crash_worker() {
    let Some(root) = std::env::var_os("MONAR_CONSTRUCTION_TEST_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let phase = std::env::var("MONAR_CONSTRUCTION_TEST_PHASE").unwrap();
    let cp = WalletCheckpoint {
        wallet_id: id(&std::env::var("MONAR_CONSTRUCTION_TEST_ID").unwrap()).unwrap(),
        network: Network::Main,
        revision: 0,
    };
    let source = DurableChain::open(
        &root.join("chain.sqlite"),
        config(),
        super::root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    if phase == "before" {
        struct ExitInput;
        impl Read for ExitInput {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                std::process::exit(85)
            }
        }
        crate::execute(
            Command::parse(construct_args(&root, cp, source.profile_id().unwrap())).unwrap(),
            &mut ExitInput,
            &mut Vec::new(),
        )
        .unwrap();
    } else {
        let mut store = open_wallet(&root, cp);
        let bytes = fs::read(root.join("payment.json")).unwrap();
        let output =
            tx::construct(&mut store, 0, &options(&source), &source, &bytes, amount(2)).unwrap();
        struct ExitOutput;
        impl Write for ExitOutput {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                std::process::exit(86)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                std::process::exit(86)
            }
        }
        report(&output, &mut ExitOutput).unwrap();
    }
}
#[test]
fn construction_crashes_recover_exact_bytes_without_resigning_or_releasing_claims() {
    for private in [false, true] {
        for phase in ["before", "signed"] {
            let dir = private_dir();
            let (source, _) = source(dir.path(), private);
            let store = wallet(dir.path());
            let cp = store.checkpoint().unwrap();
            let profile = source.profile_id().unwrap();
            let doc = intent(&store, &source, private, false, 8);
            write_request(dir.path(), &doc);
            // The pre-credential child only needs the profile-pinned manifest arguments.
            manifest_file(dir.path(), &config());
            drop(store);
            drop(source);
            let status = Process::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "balance::tests::construction::construction_crash_worker",
                ])
                .env("MONAR_CONSTRUCTION_TEST_DIR", dir.path())
                .env("MONAR_CONSTRUCTION_TEST_PHASE", phase)
                .env("MONAR_CONSTRUCTION_TEST_ID", hex(&cp.wallet_id))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(if phase == "before" { 85 } else { 86 }));
            let source = DurableChain::open(
                &dir.path().join("chain.sqlite"),
                config(),
                root(),
                V6Verifier,
                u64::MAX / 2,
            )
            .unwrap();
            let mut store = open_wallet(dir.path(), cp);
            if phase == "before" {
                assert_eq!(store.checkpoint().unwrap(), cp);
                assert!(store.reservations().unwrap().is_empty());
                continue;
            }
            let current = store.checkpoint().unwrap();
            assert!(current.revision > cp.revision);
            let token = *store.reservations().unwrap().keys().next().unwrap();
            let exported =
                serde_json::to_value(tx::export(&store, profile, token).unwrap()).unwrap();
            verify(&source, &exported);
            assert!(make(&mut store, &source, &doc).is_err());
            assert_eq!(store.checkpoint().unwrap(), current);
            assert!(tx::export(&store, [0; 32], token).is_err());
            drop(store);
            drop(source);
            // Export through the real command dispatcher without re-opening or replaying a chain.
            let mut args = vec![
                "transaction-export".into(),
                "--directory".into(),
                dir.path().to_str().unwrap().into(),
                "--name".into(),
                "wallet".into(),
                "--network".into(),
                "main".into(),
                "--password-stdin".into(),
                "--wallet-id".into(),
                hex(&cp.wallet_id),
                "--revision".into(),
                current.revision.to_string(),
                "--profile".into(),
                hex(&profile),
                "--reservation".into(),
                hex(&token),
            ];
            let mut output = Vec::new();
            crate::execute(
                Command::parse(args.drain(..).map(OsString::from)).unwrap(),
                &mut credentials(),
                &mut output,
            )
            .unwrap();
            let actual: serde_json::Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(actual, exported);
            for name in ["wallet.monw", "wallet.monw-wal", "wallet.monw-journal"] {
                let Ok(bytes) = fs::read(dir.path().join(name)) else {
                    continue;
                };
                for secret in [PASSWORD, [7; 32].as_slice()] {
                    assert!(!bytes.windows(secret.len()).any(|w| w == secret));
                }
            }
        }
    }
}

//! Public fixtures, real v6/RandomX validation and fixed zero nonces only.
use super::*;
use monario_address::{Address, Receiver};
use monario_chain::{
    ledger::OutPoint,
    service,
    storage::{SnapshotLimits, TrustedCheckpoint},
};

fn cfg() -> Config {
    let mut c = config();
    c.coinbase_maturity = monario_chain::consensus::COINBASE_MATURITY;
    c.seed_interval = 1 << 20;
    c.retained_blocks = 10000;
    c.limits.block_bytes = 5_000_000;
    c.limits.script_bytes = service::MAX_RECORD_BYTES + 4;
    c
}
fn receiver(seed: u8) -> Address {
    Seed::from_bytes(&[seed; 32])
        .unwrap()
        .transparent_key(Network::Main, 0, Scope::External, 0)
        .unwrap()
        .address()
}
fn accept(c: &mut DurableChain<V6Verifier>, parent: Hash, txs: Vec<Vec<u8>>, tag: &[u8]) -> Hash {
    let chain = c.chain().unwrap();
    let height = chain.block_info(&parent).unwrap().height + 1;
    let Receiver::Transparent(receiver) = receiver(7).receiver() else {
        panic!("public receiver")
    };
    let t = chain
        .build_template(parent, 1000 + 105 * height, 1_000_000, txs, |p| {
            monario_v6::coinbase::encode(p, receiver, tag)
                .map_err(|_| monario_chain::Error::Coinbase)
        })
        .unwrap();
    c.submit(t.block, 1_000_000).unwrap().id
}
fn make_service(
    store: &mut WalletStore,
    source: &DurableChain<V6Verifier>,
    doc: &serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let mut opts = options(source);
    opts.blocks = 10000;
    opts.internal = 4;
    tx::construct(
        store,
        0,
        &opts,
        source,
        &serde_json::to_vec(doc).unwrap(),
        amount(2),
    )
    .map(|v| serde_json::to_value(v).unwrap())
}
fn points(store: &WalletStore, source: &DurableChain<V6Verifier>) -> Vec<serde_json::Value> {
    let mut opts = options(source);
    opts.blocks = 10000;
    opts.internal = 4;
    let scanner = prepare(store, 0, &opts, source).unwrap();
    tx::inputs(store,source,&scanner,0).unwrap()["transparent"].as_array().unwrap().iter()
        .filter(|v|v["mature_next_block"]==true && v["reserved"]==false && v["amount_atoms"]!="0")
        .map(|v|serde_json::json!({"transaction":v["transaction"],"index":v["index"],"amount_atoms":v["amount_atoms"]})).collect()
}
fn subsidy_points(all: &[serde_json::Value], store: &WalletStore) -> Vec<serde_json::Value> {
    let rewards: std::collections::HashSet<u64> = (1..=200)
        .map(|h| monario_monetary::subsidy(h).atoms())
        .collect();
    let claimed: std::collections::HashSet<String> = store
        .reservations()
        .unwrap()
        .values()
        .flat_map(|r| r.inputs.iter())
        .filter_map(|input| match input {
            monario_wallet::storage::pending::Input::Transparent { transaction, index } => {
                Some(format!("{}:{index}", hex(transaction)))
            }
            monario_wallet::storage::pending::Input::Private { .. } => None,
        })
        .collect();
    all.iter()
        .filter(|p| {
            p["amount_atoms"]
                .as_str()
                .and_then(|a| a.parse::<u64>().ok())
                .is_some_and(|a| rewards.contains(&a))
        })
        .filter(|p| {
            !claimed.contains(&format!(
                "{}:{}",
                p["transaction"].as_str().unwrap(),
                p["index"].as_u64().unwrap()
            ))
        })
        .cloned()
        .collect()
}
fn doc(
    source: &DurableChain<V6Verifier>,
    funds: Vec<serde_json::Value>,
    payments: Vec<serde_json::Value>,
    intent: serde_json::Value,
) -> serde_json::Value {
    let inputs: Vec<_> = funds
        .into_iter()
        .map(|v| serde_json::json!({"transaction":v["transaction"],"index":v["index"]}))
        .collect();
    let mut out = serde_json::json!({"version":1,"validated_tip":hex(&source.chain().unwrap().tip()),"funding":{"pool":"transparent","inputs":inputs},
        "payments":payments,"fee_atoms":"1","expiry_height":source.chain().unwrap().height()+50,"change":"transparent"});
    if !intent.is_null() {
        out["service"] = intent;
    }
    out
}
fn pay(address: Address, value: u64) -> serde_json::Value {
    serde_json::json!({"address":address.encode(),"amount_atoms":value.to_string()})
}
fn snap_limits() -> SnapshotLimits {
    monario_node::cli::STATE_CHECKPOINT_LIMITS
}
fn reopen(dir: &Path, pin: TrustedCheckpoint) -> DurableChain<V6Verifier> {
    let mut source = DurableChain::open_with_checkpoint(
        &dir.join("chain.sqlite"),
        cfg(),
        root(),
        V6Verifier,
        1_000_000,
        pin,
        snap_limits(),
    )
    .unwrap();
    source
        .set_verification_mode(monario_chain::VerificationMode::SecureJit)
        .unwrap();
    source
}
fn open_named(dir: &Path, name: &str, cp: WalletCheckpoint) -> WalletStore {
    WalletStore::open(
        &WalletDirectory::open(dir).unwrap(),
        name,
        &password(PASSWORD).unwrap(),
        cp,
    )
    .unwrap()
}
fn crash_sign(
    dir: &Path,
    mut source: DurableChain<V6Verifier>,
    mut store: WalletStore,
    name: &str,
    request: &serde_json::Value,
) -> (DurableChain<V6Verifier>, WalletStore, Vec<u8>) {
    let mut signed = Vec::new();
    for phase in ["before", "signed"] {
        let pin = source.create_state_checkpoint(snap_limits()).unwrap();
        let cp = store.checkpoint().unwrap();
        let claims = store.reservations().unwrap().len();
        manifest_file(dir, &cfg());
        write_request(dir, request);
        fs::write(dir.join("operator-control.json"),serde_json::to_vec(&serde_json::json!({"name":name,"id":hex(&cp.wallet_id),"revision":cp.revision,"pin":hex(&pin.commitment())})).unwrap()).unwrap();
        drop(store);
        drop(source);
        let status = Process::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "balance::tests::construction::operator::operator_crash_worker",
            ])
            .env("MONAR_OPERATOR_TEST_DIR", dir)
            .env("MONAR_OPERATOR_TEST_PHASE", phase)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(if phase == "before" { 81 } else { 82 }));
        source = reopen(dir, pin);
        store = open_named(dir, name, cp);
        if phase == "before" {
            assert_eq!(store.checkpoint().unwrap(), cp);
            assert_eq!(store.reservations().unwrap().len(), claims);
        } else {
            assert_eq!(store.reservations().unwrap().len(), claims + 1);
            let emitted: serde_json::Value =
                serde_json::from_slice(&fs::read(dir.join("operator-result.json")).unwrap())
                    .unwrap();
            let token = id(emitted["reservation"].as_str().unwrap()).unwrap();
            let exported = serde_json::to_value(
                tx::export(&store, source.profile_id().unwrap(), token).unwrap(),
            )
            .unwrap();
            assert_eq!(exported["transaction_hex"], emitted["transaction_hex"]);
            signed = verify(&source, &exported);
            let latest = store.checkpoint().unwrap();
            assert!(make_service(&mut store, &source, request).is_err());
            assert_eq!(store.checkpoint().unwrap(), latest);
        }
    }
    (source, store, signed)
}
#[test]
fn operator_crash_worker() {
    let Some(dir) = std::env::var_os("MONAR_OPERATOR_TEST_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let control: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("operator-control.json")).unwrap()).unwrap();
    let cp = WalletCheckpoint {
        wallet_id: id(control["id"].as_str().unwrap()).unwrap(),
        network: Network::Main,
        revision: control["revision"].as_u64().unwrap(),
    };
    let pin = balance::hash(control["pin"].as_str().unwrap()).unwrap();
    let mut args = construct_args(&dir, cp, manifest_file(&dir, &cfg()));
    let pos = args.iter().position(|s| s == "--internal").unwrap();
    args[pos + 1] = "1024".into();
    let pos = args.iter().position(|s| s == "--name").unwrap();
    args[pos + 1] = control["name"].as_str().unwrap().into();
    args.extend(["--checkpoint".into(), hex(&pin).into()]);
    // Prior scans cached a smaller internal window; rebuild the watch set so the
    // crash worker can see the next issued change address.
    args.push("--rescan".into());
    struct StopInput;
    impl Read for StopInput {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            std::process::exit(81)
        }
    }
    struct StopOutput(Vec<u8>);
    impl Write for StopOutput {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let command = Command::parse(args).unwrap();
    if std::env::var("MONAR_OPERATOR_TEST_PHASE").unwrap() == "before" {
        crate::execute(command, &mut StopInput, &mut Vec::new()).unwrap();
    } else {
        let mut emitted = StopOutput(Vec::new());
        crate::execute(command, &mut credentials(), &mut emitted).unwrap();
        fs::write(dir.join("operator-result.json"), emitted.0).unwrap();
        std::process::exit(82);
    }
    panic!("crash hook did not execute");
}
#[test]
fn malformed_service_requests_fail_before_issuance_or_input_claims() {
    let dir = private_dir();
    let (source, _) = source(dir.path(), false);
    let mut store = wallet(dir.path());
    let base = intent(&store, &source, false, false, 8);
    let cp = store.checkpoint().unwrap();
    let variants = [
        serde_json::json!({"kind":"rotation","registration":hex(&[0;32]),"owner_index":0,"operator_public_key":"00","authorization":"é"}),
        serde_json::json!({"kind":"reactivation","registration":hex(&[0;32]),"owner_index":0,"authorization":"0"}),
        serde_json::json!({"kind":"unknown"}),
        serde_json::json!({"kind":"proof","registration":hex(&[0;32]),"operator_index":0,"secret":"disallowed"}),
        serde_json::json!({"kind":"proof","registration":"00","operator_index":0}),
        serde_json::json!({"kind":"proof","registration":hex(&[0;32]),"operator_index":2147483648u32}),
        serde_json::json!({"kind":"registration","collateral_transaction":hex(&[0;32]),"collateral_index":0,"owner_index":0,"operator_public_key":"00"}),
    ];
    for service in variants {
        let mut bad = base.clone();
        bad["payments"] = serde_json::json!([]);
        bad["service"] = service;
        assert!(make_service(&mut store, &source, &bad).is_err());
        assert_eq!(store.checkpoint().unwrap(), cp);
        assert!(store.reservations().unwrap().is_empty());
    }
}
struct Archival {
    dir: tempfile::TempDir,
    source: DurableChain<V6Verifier>,
    owner: WalletStore,
    operator: WalletStore,
    registration: Hash,
    collateral_id: String,
    end: u64,
    operator_key: serde_json::Value,
    checkpoint: WalletCheckpoint,
}
/// Build the public archival fixture up to a registered-but-not-yet-due proof
/// window: real chain, real owner and operator wallets, real registration and a
/// real inbox. Mining to `end` makes the proof due.
fn archival_fixture() -> Archival {
    let dir = private_dir();
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        cfg(),
        root(),
        V6Verifier,
        1_000_000,
    )
    .unwrap();
    source
        .set_verification_mode(monario_chain::VerificationMode::SecureJit)
        .unwrap();
    let mut owner = wallet(dir.path());
    let mut operator = WalletStore::create(
        &WalletDirectory::open(dir.path()).unwrap(),
        "operator",
        Seed::from_bytes(&[8; 32]).unwrap(),
        Network::Main,
        &password(PASSWORD).unwrap(),
    )
    .unwrap();
    let operator_key = crate::service::issue_key(&mut operator, 0).unwrap();
    for _ in 0..133 {
        let tip = source.chain().unwrap().tip();
        accept(&mut source, tip, vec![], b"operator fixture");
    }
    let funding = points(&owner, &source).into_iter().take(32).collect();
    let merge = doc(
        &source,
        funding,
        vec![pay(receiver(7), 23_999_999_999)],
        serde_json::Value::Null,
    );
    let merged = make_service(&mut owner, &source, &merge).unwrap();
    let raw = verify(&source, &merged);
    let tip = source.chain().unwrap().tip();
    accept(&mut source, tip, vec![raw], b"operator fixture");
    let all = points(&owner, &source);
    let mut funding = vec![
        all.iter()
            .find(|p| p["transaction"] == merged["transaction_id"] && p["index"] == 0)
            .unwrap()
            .clone(),
    ];
    funding.extend(subsidy_points(&all, &owner).into_iter().rev().take(2));
    let collateral_request = doc(
        &source,
        funding,
        vec![
            pay(receiver(7), service::COLLATERAL_ATOMS),
            pay(receiver(8), 10),
            pay(receiver(8), 10),
        ],
        serde_json::Value::Null,
    );
    let collateral = make_service(&mut owner, &source, &collateral_request).unwrap();
    let raw = verify(&source, &collateral);
    let tip = source.chain().unwrap().tip();
    accept(&mut source, tip, vec![raw], b"operator fixture");
    let collateral_id = collateral["transaction_id"].as_str().unwrap();
    let fee = points(&owner, &source)
        .into_iter()
        .find(|p| p["transaction"] == collateral_id && p["index"] == 3)
        .unwrap();
    let registration = serde_json::json!({"kind":"registration","collateral_transaction":collateral_id,"collateral_index":0,"owner_index":0,"operator_public_key":operator_key["operator_public_key"]});
    let registration_request = doc(&source, vec![fee], vec![], registration);
    let before = owner.checkpoint().unwrap();
    let claims = owner.reservations().unwrap().len();
    for (field, bad) in [
        ("owner_index", serde_json::json!(1)),
        (
            "operator_public_key",
            serde_json::json!(hex(&Seed::from_bytes(&[7; 32])
                .unwrap()
                .transparent_key(Network::Main, 0, Scope::External, 0)
                .unwrap()
                .public_key())),
        ),
    ] {
        let mut bad_request = registration_request.clone();
        bad_request["service"][field] = bad;
        assert!(make_service(&mut owner, &source, &bad_request).is_err());
        assert_eq!(owner.checkpoint().unwrap(), before);
        assert_eq!(owner.reservations().unwrap().len(), claims);
    }
    let (mut source, owner, signed) =
        crash_sign(dir.path(), source, owner, "wallet", &registration_request);
    let tx = Transaction::read(signed.as_slice(), BranchId::Nu6_3).unwrap();
    let registration = *tx.txid().as_ref();
    let tip = source.chain().unwrap().tip();
    accept(&mut source, tip, vec![signed], b"operator fixture");
    let end = source
        .chain()
        .unwrap()
        .ledger()
        .service_entry(&registration)
        .unwrap()
        .next_start
        + service::PERIOD_BLOCKS;
    let proof_funds = points(&operator, &source);
    let early = doc(
        &source,
        vec![proof_funds[0].clone()],
        vec![],
        serde_json::json!({"kind":"proof","registration":hex(&registration),"operator_index":0}),
    );
    let cp = operator.checkpoint().unwrap();
    assert!(make_service(&mut operator, &source, &early).is_err());
    assert_eq!(operator.checkpoint().unwrap(), cp);
    monario_node::submission::Inbox::create(
        dir.path(),
        "operator-inbox",
        source.profile_id().unwrap(),
        step_key(),
    )
    .unwrap();
    let early_policy = step_policy(registration, &proof_funds);
    let (source, operator, waiting) = step_once(dir.path(), source, operator, &early_policy);
    assert_eq!(waiting["state"], "waiting");
    assert_eq!(operator.checkpoint().unwrap(), cp);
    Archival {
        dir,
        source,
        owner,
        operator,
        registration,
        collateral_id: collateral_id.to_owned(),
        end,
        operator_key,
        checkpoint: cp,
    }
}

#[test]
fn real_registration_archival_proof_reorg_and_crash_recovery() {
    let Archival {
        dir,
        mut source,
        mut owner,
        mut operator,
        registration,
        collateral_id,
        end,
        operator_key,
        checkpoint: cp,
    } = archival_fixture();
    let collateral_id = collateral_id.as_str();

    while source.chain().unwrap().height() < end {
        let tip = source.chain().unwrap().tip();
        let extra = if source.chain().unwrap().height() + 1 == end - 2 {
            // Explicit manual fee provisioning, shared by the later fork branches.
            let fee = subsidy_points(&points(&owner, &source), &owner)
                .into_iter()
                .next()
                .unwrap();
            let funding = doc(
                &source,
                vec![fee],
                vec![pay(receiver(8), 10), pay(receiver(8), 10)],
                serde_json::Value::Null,
            );
            let funding = make_service(&mut owner, &source, &funding).unwrap();
            vec![verify(&source, &funding)]
        } else {
            vec![]
        };
        accept(&mut source, tip, extra, b"operator fixture");
        let height = source.chain().unwrap().height();
        if height % 256 == 0 {
            eprintln!("archival fixture: fully validated height {height}/{end}");
        }
    }
    let fork_parent = source
        .chain()
        .unwrap()
        .block_info(&source.chain().unwrap().tip())
        .unwrap()
        .parent
        .unwrap();
    let proof_funds = points(&operator, &source);
    assert_eq!(proof_funds.len(), 4);
    let policy = step_policy(registration, &proof_funds);
    let proof_request = doc(
        &source,
        vec![proof_funds[0].clone()],
        vec![],
        serde_json::json!({"kind":"proof","registration":hex(&registration),"operator_index":0}),
    );
    let mut wrong = proof_request.clone();
    wrong["service"]["operator_index"] = 1.into();
    assert!(make_service(&mut operator, &source, &wrong).is_err());
    assert_eq!(operator.checkpoint().unwrap(), cp);
    let (mut source, operator, expired) = step_crashes(dir.path(), source, operator, &policy);
    let expiry = operator
        .reservations()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .expiry_height;
    while source.chain().unwrap().height() < expiry {
        let parent = source.chain().unwrap().tip();
        accept(&mut source, parent, vec![], b"operator fixture");
    }
    let mut expired_pool = monario_chain::mempool::Mempool::new(
        source.chain().unwrap(),
        monario_chain::mempool::Limits {
            transactions: 10,
            bytes: 100000,
            inputs: 100,
            minimum_fee: Amount::ZERO,
        },
    )
    .unwrap();
    assert!(
        expired_pool
            .admit(source.chain().unwrap(), expired)
            .is_err()
    );
    let (mut source, operator, retried) = step_once(dir.path(), source, operator, &policy);
    assert_eq!(retried["created"], true);
    assert_eq!(retried["attempts"], 2);
    let proof = step_bytes(&source, &operator, &retried);
    source = consume_scheduled_inbox(dir.path(), source, &proof);
    let tip = source.chain().unwrap().tip();
    accept(&mut source, tip, vec![proof.clone()], b"operator fixture");
    assert_eq!(
        source
            .chain()
            .unwrap()
            .ledger()
            .service_entry(&registration)
            .unwrap()
            .credited_seconds,
        86400
    );
    let old_height = source.chain().unwrap().height();
    let mut side = fork_parent;
    while source.chain().unwrap().block_info(&side).unwrap().height <= old_height {
        side = accept(&mut source, side, vec![], b"alternate fixture");
    }
    assert_eq!(
        source
            .chain()
            .unwrap()
            .ledger()
            .service_entry(&registration)
            .unwrap()
            .credited_seconds,
        0
    );
    let mut pool = monario_chain::mempool::Mempool::new(
        source.chain().unwrap(),
        monario_chain::mempool::Limits {
            transactions: 10,
            bytes: 100000,
            inputs: 100,
            minimum_fee: Amount::ZERO,
        },
    )
    .unwrap();
    assert!(pool.admit(source.chain().unwrap(), proof).is_err());
    let mut operator = operator;
    let old = operator.checkpoint().unwrap();
    assert!(make_service(&mut operator, &source, &proof_request).is_err());
    assert_eq!(operator.checkpoint().unwrap(), old);
    let (mut source, operator, fresh) = step_once(dir.path(), source, operator, &policy);
    assert_eq!(fresh["created"], true);
    assert_eq!(fresh["attempts"], 3);
    let raw = step_bytes(&source, &operator, &fresh);
    source = consume_scheduled_inbox(dir.path(), source, &raw);
    assert_eq!(operator.reservations().unwrap().len(), 3);
    let tip = source.chain().unwrap().tip();
    accept(&mut source, tip, vec![raw], b"alternate fixture");
    assert_eq!(
        source
            .chain()
            .unwrap()
            .ledger()
            .service_entry(&registration)
            .unwrap()
            .credited_seconds,
        86400
    );
    let proven_tip = source.chain().unwrap().tip();
    let proven_height = source.chain().unwrap().height();
    let mut side = fork_parent;
    while source.chain().unwrap().block_info(&side).unwrap().height <= proven_height {
        side = accept(&mut source, side, vec![], b"third fixture");
    }
    let (mut source, operator, limited) = step_once(dir.path(), source, operator, &policy);
    assert_eq!(limited["state"], "attempt_limit");
    assert_eq!(operator.reservations().unwrap().len(), 3);
    let mut restored = proven_tip;
    let target = source.chain().unwrap().height();
    while source
        .chain()
        .unwrap()
        .block_info(&restored)
        .unwrap()
        .height
        <= target
    {
        restored = accept(&mut source, restored, vec![], b"restored fixture");
    }
    let (mut source, operator, confirmed) = step_once(dir.path(), source, operator, &policy);
    assert_eq!(confirmed["state"], "waiting");
    assert_eq!(operator.reservations().unwrap().len(), 3);
    assert_eq!(
        source
            .chain()
            .unwrap()
            .ledger()
            .service_entry(&registration)
            .unwrap()
            .credited_seconds,
        86400
    );
    let pin = source.create_state_checkpoint(snap_limits()).unwrap();
    drop(source);
    let source = reopen(dir.path(), pin);
    assert_eq!(
        source
            .chain()
            .unwrap()
            .ledger()
            .service_entry(&registration)
            .unwrap()
            .credited_seconds,
        86400
    );
    assert_eq!(owner.reservations().unwrap().len(), 4);
    for name in ["wallet.monw", "operator.monw"] {
        let bytes = fs::read(dir.path().join(name)).unwrap();
        for secret in [PASSWORD, [7; 32].as_slice(), [8; 32].as_slice()] {
            assert!(!bytes.windows(secret.len()).any(|w| w == secret));
        }
    }
    let p = OutPoint {
        transaction: balance::hash(collateral_id).unwrap(),
        index: 0,
    };
    assert!(source.chain().unwrap().ledger().coin(&p).is_some());
    let cp = owner.checkpoint().unwrap();
    let profile = source.profile_id().unwrap();
    let mut args = cli_args(dir.path(), cp, profile);
    args[0] = "service-status".into();
    for flag in ["--external", "--internal"] {
        let pos = args.iter().position(|s| s == flag).unwrap();
        args.remove(pos);
        args.remove(pos);
    }
    args.extend([
        "--registration".into(),
        hex(&registration).into(),
        "--checkpoint".into(),
        hex(&pin.commitment()).into(),
    ]);
    drop(owner);
    drop(source);
    let mut bytes = Vec::new();
    crate::execute(
        Command::parse(args).unwrap(),
        &mut credentials(),
        &mut bytes,
    )
    .unwrap();
    let status: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status["registered"], true);
    assert_eq!(status["service"]["credited_seconds"], "86400");
    assert_eq!(
        status["service"]["qualified_before_next_block_transactions"],
        false
    );
    assert_eq!(
        open_named(dir.path(), "wallet", cp).checkpoint().unwrap(),
        cp
    );
    let mut source = reopen(dir.path(), pin);
    let mut owner = open_named(dir.path(), "wallet", cp);
    let before = source
        .chain()
        .unwrap()
        .ledger()
        .service_entry(&registration)
        .unwrap()
        .clone();
    let mut replacement = WalletStore::create(
        &WalletDirectory::open(dir.path()).unwrap(),
        "replacement",
        Seed::from_bytes(&[9; 32]).unwrap(),
        Network::Main,
        &password(PASSWORD).unwrap(),
    )
    .unwrap();
    let issued = crate::service::issue_key(&mut replacement, 0).unwrap();
    let replacement_cp = replacement.checkpoint().unwrap();
    let mut auth_args = cli_args(dir.path(), replacement_cp, profile);
    auth_args[0] = "service-authorize".into();
    let pos = auth_args.iter().position(|s| s == "--name").unwrap();
    auth_args[pos + 1] = "replacement".into();
    for flag in ["--external", "--internal"] {
        let pos = auth_args.iter().position(|s| s == flag).unwrap();
        auth_args.remove(pos);
        auth_args.remove(pos);
    }
    auth_args.extend([
        "--registration".into(),
        hex(&registration).into(),
        "--checkpoint".into(),
        hex(&pin.commitment()).into(),
        "--purpose".into(),
        "rotation".into(),
        "--operator-index".into(),
        "0".into(),
    ]);
    drop(replacement);
    drop(source);
    let mut authorization = Vec::new();
    crate::execute(
        Command::parse(auth_args).unwrap(),
        &mut credentials(),
        &mut authorization,
    )
    .unwrap();
    let authorization: serde_json::Value = serde_json::from_slice(&authorization).unwrap();
    assert_eq!(
        open_named(dir.path(), "replacement", replacement_cp)
            .checkpoint()
            .unwrap(),
        replacement_cp
    );
    source = reopen(dir.path(), pin);
    let fee = subsidy_points(&points(&owner, &source), &owner)
        .into_iter()
        .next_back()
        .unwrap();
    let mut request = doc(
        &source,
        vec![fee],
        vec![],
        serde_json::json!({"kind":"rotation","registration":hex(&registration),"owner_index":0,"operator_public_key":issued["operator_public_key"],"authorization":authorization["authorization"]}),
    );
    let original = owner.checkpoint().unwrap();
    request["service"]["operator_public_key"] = operator_key["operator_public_key"].clone();
    assert!(make_service(&mut owner, &source, &request).is_err());
    assert_eq!(owner.checkpoint().unwrap(), original);
    request["service"]["operator_public_key"] = issued["operator_public_key"].clone();
    let (mut source, owner, raw) = crash_sign(dir.path(), source, owner, "wallet", &request);
    let parent = source.chain().unwrap().tip();
    accept(&mut source, parent, vec![raw], b"rotation fixture");
    let after = source
        .chain()
        .unwrap()
        .ledger()
        .service_entry(&registration)
        .unwrap();
    assert_eq!(hex(&after.operator), issued["operator_public_key"]);
    assert_eq!(after.credited_seconds, before.credited_seconds);
    assert_eq!(after.next_start, before.next_start);
    let pin = source.create_state_checkpoint(snap_limits()).unwrap();
    drop(source);
    let mut source = reopen(dir.path(), pin);
    let side = accept(&mut source, parent, vec![], b"rotation reorg");
    accept(&mut source, side, vec![], b"rotation reorg");
    assert_eq!(
        source
            .chain()
            .unwrap()
            .ledger()
            .service_entry(&registration),
        Some(&before)
    );
    assert_eq!(owner.reservations().unwrap().len(), 5);
}

#[test]
fn archival_fixture_signs_and_publishes_under_the_supervisor() {
    let Archival {
        dir,
        mut source,
        owner: _,
        operator,
        registration,
        end,
        ..
    } = archival_fixture();
    while source.chain().unwrap().height() < end {
        let tip = source.chain().unwrap().tip();
        accept(&mut source, tip, vec![], b"operator fixture");
    }
    let policy = step_policy(registration, &points(&operator, &source));
    let (mut source, operator, result) = supervise_once(dir.path(), source, operator, &policy);
    assert_eq!(result["state"], "published");
    assert_eq!(result["created"], true);
    assert_eq!(result["network_delivery_proven"], false);
    assert_eq!(
        source
            .chain()
            .unwrap()
            .ledger()
            .service_entry(&registration)
            .unwrap()
            .credited_seconds,
        0
    );
    let raw = step_bytes(&source, &operator, &result);
    source = consume_scheduled_inbox(dir.path(), source, &raw);
    let tip = source.chain().unwrap().tip();
    accept(&mut source, tip, vec![raw], b"operator fixture");
    assert_eq!(
        source
            .chain()
            .unwrap()
            .ledger()
            .service_entry(&registration)
            .unwrap()
            .credited_seconds,
        86400
    );
}
fn step_key() -> Hash {
    monario_node::transport::Identity::from_secret(Zeroizing::new([11; 32])).public_key()
}
fn step_policy(registration: Hash, fee_inputs: &[serde_json::Value]) -> serde_json::Value {
    serde_json::json!({"version":1,"registration":hex(&registration),"operator_index":0,"fee_atoms":"1","period_fee_budget_atoms":"3","fee_inputs":fee_inputs.iter().map(|p|serde_json::json!({"transaction":p["transaction"],"index":p["index"]})).collect::<Vec<_>>()})
}
fn step_args(
    dir: &Path,
    cp: WalletCheckpoint,
    profile: Hash,
    pin: TrustedCheckpoint,
) -> Vec<OsString> {
    let mut args = cli_args(dir, cp, profile);
    args[0] = "service-step".into();
    let pos = args.iter().position(|s| s == "--name").unwrap();
    args[pos + 1] = "operator".into();
    let pos = args.iter().position(|s| s == "--internal").unwrap();
    args[pos + 1] = "4".into();
    args.extend([
        "--schedule".into(),
        "payment.json".into(),
        "--max-fee-atoms".into(),
        "1".into(),
        "--node-directory".into(),
        dir.as_os_str().to_owned(),
        "--submission-inbox".into(),
        "operator-inbox".into(),
        "--node-public-key".into(),
        hex(&step_key()).into(),
        "--checkpoint".into(),
        hex(&pin.commitment()).into(),
    ]);
    args
}
fn step_once(
    dir: &Path,
    mut source: DurableChain<V6Verifier>,
    store: WalletStore,
    policy: &serde_json::Value,
) -> (DurableChain<V6Verifier>, WalletStore, serde_json::Value) {
    let cp = store.checkpoint().unwrap();
    let pin = source.create_state_checkpoint(snap_limits()).unwrap();
    let profile = manifest_file(dir, &cfg());
    write_request(dir, policy);
    drop(store);
    drop(source);
    let mut output = Vec::new();
    crate::execute(
        Command::parse(step_args(dir, cp, profile, pin)).unwrap(),
        &mut credentials(),
        &mut output,
    )
    .unwrap();
    (
        reopen(dir, pin),
        open_named(dir, "operator", cp),
        serde_json::from_slice(&output).unwrap(),
    )
}
fn supervise_once(
    dir: &Path,
    mut source: DurableChain<V6Verifier>,
    store: WalletStore,
    policy: &serde_json::Value,
) -> (DurableChain<V6Verifier>, WalletStore, serde_json::Value) {
    let cp = store.checkpoint().unwrap();
    let pin = source.create_state_checkpoint(snap_limits()).unwrap();
    let profile = manifest_file(dir, &cfg());
    write_request(dir, policy);
    drop(store);
    drop(source);
    let mut args = step_args(dir, cp, profile, pin);
    args[0] = "service-supervise".into();
    args.extend([
        "--interval-seconds".into(),
        "1".into(),
        "--max-steps".into(),
        "1".into(),
    ]);
    let mut output = Vec::new();
    crate::execute(
        Command::parse(args).unwrap(),
        &mut credentials(),
        &mut output,
    )
    .unwrap();
    let lines: Vec<&str> = std::str::from_utf8(&output).unwrap().lines().collect();
    assert_eq!(lines.len(), 2, "one step line plus the stop line");
    let step: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let end: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(end["service"], "supervise");
    assert_eq!(end["steps"], "1");
    (reopen(dir, pin), open_named(dir, "operator", cp), step)
}
fn step_bytes(
    source: &DurableChain<V6Verifier>,
    store: &WalletStore,
    result: &serde_json::Value,
) -> Vec<u8> {
    let token = id(result["submission"]["reservation"].as_str().unwrap()).unwrap();
    let output =
        serde_json::to_value(tx::export(store, source.profile_id().unwrap(), token).unwrap())
            .unwrap();
    verify(source, &output)
}
fn step_crashes(
    dir: &Path,
    mut source: DurableChain<V6Verifier>,
    mut store: WalletStore,
    policy: &serde_json::Value,
) -> (DurableChain<V6Verifier>, WalletStore, Vec<u8>) {
    let mut exact = Vec::new();
    for (phase, code) in [("signed", 83), ("published", 84)] {
        let cp = store.checkpoint().unwrap();
        let pin = source.create_state_checkpoint(snap_limits()).unwrap();
        let profile = manifest_file(dir, &cfg());
        write_request(dir, policy);
        fs::write(dir.join("step-control.json"),serde_json::to_vec(&serde_json::json!({"id":hex(&cp.wallet_id),"revision":cp.revision,"profile":hex(&profile),"pin":hex(&pin.commitment())})).unwrap()).unwrap();
        drop(store);
        drop(source);
        let status = Process::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "balance::tests::construction::operator::service_step_crash_worker",
            ])
            .env("MONAR_STEP_TEST_DIR", dir)
            .env("MONAR_STEP_TEST_PHASE", phase)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(code));
        source = reopen(dir, pin);
        store = open_named(dir, "operator", cp);
        assert_eq!(store.reservations().unwrap().len(), 1);
        let r = store.reservations().unwrap().values().next().unwrap();
        let bytes = r.expose_transaction().unwrap();
        if phase == "signed" {
            exact = bytes.to_vec();
        } else {
            assert_eq!(bytes, exact);
        }
        let inbox =
            monario_node::submission::Inbox::open(dir, "operator-inbox", profile, step_key())
                .unwrap();
        assert_eq!(
            inbox
                .status(monario_node::submission::digest(bytes))
                .unwrap()
                .is_some(),
            phase == "published"
        );
    }
    let (source, store, result) = step_once(dir, source, store, policy);
    assert_eq!(result["state"], "published");
    assert_eq!(result["created"], false);
    assert_eq!(step_bytes(&source, &store, &result), exact);
    (source, store, exact)
}
#[test]
fn service_step_crash_worker() {
    let Some(dir) = std::env::var_os("MONAR_STEP_TEST_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let control: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("step-control.json")).unwrap()).unwrap();
    let cp = WalletCheckpoint {
        wallet_id: id(control["id"].as_str().unwrap()).unwrap(),
        network: Network::Main,
        revision: control["revision"].as_u64().unwrap(),
    };
    let profile = balance::hash(control["profile"].as_str().unwrap()).unwrap();
    let pin = TrustedCheckpoint::from_commitment(
        balance::hash(control["pin"].as_str().unwrap()).unwrap(),
    );
    let mut command = Command::parse(step_args(&dir, cp, profile, pin)).unwrap();
    let mut store = open_named(&dir, "operator", cp);
    let phase = std::env::var("MONAR_STEP_TEST_PHASE").unwrap();
    crate::service_step::execute_with_hook(
        &dir,
        &mut store,
        command.account,
        command.scan.take().unwrap(),
        command.step.take().unwrap(),
        |published| {
            if (phase == "published") == published {
                std::process::exit(if published { 84 } else { 83 });
            }
        },
    )
    .unwrap();
    panic!("crash hook did not run");
}

fn consume_scheduled_inbox(
    dir: &Path,
    mut source: DurableChain<V6Verifier>,
    expected: &[u8],
) -> DurableChain<V6Verifier> {
    let pin = source.create_state_checkpoint(snap_limits()).unwrap();
    let profile = source.profile_id().unwrap();
    let mut node = monario_node::Node::new(
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
    .unwrap();
    node.attach_submission_inbox(
        monario_node::submission::Inbox::open(dir, "operator-inbox", profile, step_key()).unwrap(),
    )
    .unwrap();
    for ms in [10000, 20000, 30000] {
        node.tick(monario_node::Clock {
            monotonic_ms: ms,
            unix_seconds: 1_000_000,
        })
        .unwrap();
    }
    assert_eq!(node.peer_count(), 0);
    assert!(
        node.mempool()
            .transactions(node.source().chain().unwrap())
            .unwrap()
            .any(|b| b == expected)
    );
    assert_eq!(
        monario_node::submission::Inbox::open(dir, "operator-inbox", profile, step_key())
            .unwrap()
            .status(monario_node::submission::digest(expected))
            .unwrap()
            .unwrap()
            .state,
        1
    );
    node.shutdown().unwrap();
    drop(node);
    reopen(dir, pin)
}

#[test]
fn real_wallet_schedule_and_chain_run_one_supervised_step() {
    let dir = private_dir();
    let chain_cfg = cfg();
    let mut source = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        chain_cfg.clone(),
        root(),
        V6Verifier,
        1_000_000,
    )
    .unwrap();
    source
        .set_verification_mode(monario_chain::VerificationMode::SecureJit)
        .unwrap();
    let operator = WalletStore::create(
        &WalletDirectory::open(dir.path()).unwrap(),
        "operator",
        Seed::from_bytes(&[8; 32]).unwrap(),
        Network::Main,
        &password(PASSWORD).unwrap(),
    )
    .unwrap();
    let cp = operator.checkpoint().unwrap();
    // A registration that was never posted: the real step must report
    // `unregistered` and create no transaction.
    let policy = step_policy(
        [12; 32],
        &[serde_json::json!({"transaction": hex(&[5; 32]), "index": 0})],
    );
    write_request(dir.path(), &policy);
    let profile = manifest_file(dir.path(), &chain_cfg);
    monario_node::submission::Inbox::create(dir.path(), "operator-inbox", profile, step_key())
        .unwrap();
    drop(operator);
    drop(source);

    let mut args = cli_args(dir.path(), cp, profile);
    args[0] = "service-supervise".into();
    let name = args.iter().position(|s| s == "--name").unwrap();
    args[name + 1] = "operator".into();
    args.extend([
        "--schedule".into(),
        "payment.json".into(),
        "--max-fee-atoms".into(),
        "1".into(),
        "--node-directory".into(),
        dir.path().as_os_str().to_owned(),
        "--submission-inbox".into(),
        "operator-inbox".into(),
        "--node-public-key".into(),
        hex(&step_key()).into(),
        "--interval-seconds".into(),
        "1".into(),
        "--max-steps".into(),
        "1".into(),
        "--health-file".into(),
        "supervise-health.json".into(),
    ]);
    let mut output = Vec::new();
    crate::execute(
        Command::parse(args).unwrap(),
        &mut credentials(),
        &mut output,
    )
    .unwrap();
    let lines: Vec<&str> = std::str::from_utf8(&output).unwrap().lines().collect();
    assert_eq!(lines.len(), 2, "one step line plus the stop line");
    let step: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(step["state"], "unregistered");
    assert_eq!(step["created"], false);
    let end: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(end["service"], "supervise");
    assert_eq!(end["steps"], "1");
    assert_eq!(end["reason"], "max_steps");
    let health: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("supervise-health.json")).unwrap())
            .unwrap();
    assert_eq!(health["healthy"], true);
    assert_eq!(health["steps"], "1");
    assert_eq!(health["stopped"], "max_steps");
    assert_eq!(health["last"]["state"], "unregistered");
}

//! Checkpoint trust is explicit; old bodies and a real verified tail still matter.
use super::*;
use monario_chain::storage::TrustedCheckpoint;
const LIMITS: monario_chain::storage::SnapshotLimits = monario_node::cli::STATE_CHECKPOINT_LIMITS;
fn invoke(
    root: &Path,
    cp: WalletCheckpoint,
    profile: [u8; 32],
    pin: [u8; 32],
) -> Result<serde_json::Value, Error> {
    let mut args = cli_args(root, cp, profile);
    args.extend([OsString::from("--checkpoint"), OsString::from(hex(&pin))]);
    let mut out = Vec::new();
    crate::execute(Command::parse(args)?, &mut credentials(), &mut out)?;
    Ok(serde_json::from_slice(&out).unwrap())
}
#[test]
fn wallet_cli_pins_checkpoint_and_rejects_corrupt_cache_or_skipped_bodies() {
    let dir = private_dir();
    let store = wallet(dir.path());
    let cp = store.checkpoint().unwrap();
    drop(store);
    let cfg = production();
    let profile = manifest_file(dir.path(), &cfg);
    let path = dir.path().join("chain.sqlite");
    let mut source =
        DurableChain::open(&path, cfg.clone(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    let pin = source.create_state_checkpoint(LIMITS).unwrap().commitment();
    model.accept(&mut source, 2, &[]);
    drop(source);
    let before = wallet_vault(dir.path());
    let balance = invoke(dir.path(), cp, profile, pin).unwrap();
    amounts(&balance, "0", "100", "0");
    assert_eq!(balance["height"], "2");
    assert_eq!(balance["chain_checkpoint"], hex(&pin));
    assert_eq!(balance["full_chain_replay"], false);
    assert_eq!(
        invoke(dir.path(), cp, profile, [0; 32]).err(),
        Some(Error::Scan)
    );
    assert!(cli(dir.path(), cp, profile).is_ok());
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE checkpoint_rows SET data=zeroblob(length(data)+1) WHERE ordinal=0",
        [],
    )
    .unwrap();
    drop(db);
    assert!(invoke(dir.path(), cp, profile, pin).is_err());
    let mut source = DurableChain::open(&path, cfg, root(), V6Verifier, u64::MAX / 2).unwrap();
    let repaired = source.create_state_checkpoint(LIMITS).unwrap().commitment();
    assert_ne!(repaired, pin);
    drop(source);
    // A trusted state cache skips old signature/PoW replay, never wallet body authentication.
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE blocks SET data=zeroblob(length(data)) WHERE seq=1",
        [],
    )
    .unwrap();
    drop(db);
    assert!(invoke(dir.path(), cp, profile, repaired).is_err());
    assert_eq!(wallet_vault(dir.path()), before);
    let mut info = vec![
        "info".into(),
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
        cp.revision.to_string(),
    ];
    assert!(Command::parse(info.clone().into_iter().map(OsString::from)).is_ok());
    info.extend(["--checkpoint".into(), hex(&pin)]);
    assert!(Command::parse(info.into_iter().map(OsString::from)).is_err());
}
#[test]
fn private_balances_and_reorgs_match_checkpoint_restore_and_validated_tail() {
    let dir = private_dir();
    let path = dir.path().join("chain.sqlite");
    let store = wallet(dir.path());
    let cp = store.checkpoint().unwrap();
    let mut source = DurableChain::open(&path, config(), root(), V6Verifier, u64::MAX / 2).unwrap();
    let mut model = Model::new();
    model.accept(&mut source, 1, &[]);
    model.accept(&mut source, 2, &[]);
    model.accept(&mut source, 3, &[fixture("deposit")]);
    let funding = model.clone();
    let pin = source.create_state_checkpoint(LIMITS).unwrap();
    model.accept(&mut source, 4, &[fixture("transfer")]);
    model.accept(&mut source, 5, &[fixture("withdrawal")]);
    amounts(&value(&store, &source), "70", "0", "0");
    let tip = source.chain().unwrap().tip();
    drop(source);
    let mut source = DurableChain::open_with_checkpoint(
        &path,
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
        pin,
        LIMITS,
    )
    .unwrap();
    assert_eq!(source.chain().unwrap().tip(), tip);
    let mut opts = options(&source);
    opts.checkpoint = Some(pin.commitment());
    amounts(
        &serde_json::to_value(scan(&store, 0, &opts, &source).unwrap()).unwrap(),
        "70",
        "0",
        "0",
    );
    let mut side = funding;
    side.accept(&mut source, 4, &[fixture("conflict")]);
    side.accept(&mut source, 5, &[]);
    side.accept(&mut source, 6, &[]);
    amounts(
        &serde_json::to_value(scan(&store, 0, &opts, &source).unwrap()).unwrap(),
        "0",
        "0",
        "0",
    );
    let tip = source.chain().unwrap().tip();
    drop(source);
    let source = DurableChain::open_with_checkpoint(
        &path,
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
        TrustedCheckpoint::from_commitment(pin.commitment()),
        LIMITS,
    )
    .unwrap();
    assert_eq!(source.chain().unwrap().tip(), tip);
    amounts(&value(&store, &source), "0", "0", "0");
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert!(store.reservations().unwrap().is_empty());
}

//! Explicit local publication only; no network or replacement signatures.
use super::*;
use crate::submission::{Destination, rebroadcast as api};
use monario_node::submission::Inbox;
use monario_wallet::storage::pending::Input;

fn destination(path: &Path, key: Hash) -> Destination {
    Destination::parse(&mut BTreeMap::from([
        ("--node-directory".into(), path.as_os_str().to_owned()),
        ("--submission-inbox".into(), "local".into()),
        ("--node-public-key".into(), hex(&key).into()),
    ]))
    .unwrap()
}
fn step(
    store: &WalletStore,
    chain: &DurableChain<V6Verifier>,
    path: &Path,
    after: Option<[u8; 16]>,
) -> serde_json::Value {
    api::step(store, chain, destination(path, [11; 32]), after, || {}).unwrap()
}
fn inbox(path: &Path, profile: Hash) -> Inbox {
    Inbox::open(path, "local", profile, [11; 32]).unwrap()
}

fn args(path: &Path, cp: WalletCheckpoint, profile: Hash) -> Vec<OsString> {
    let mut values = cli_args(path, cp, profile);
    values[0] = "rebroadcast-step".into();
    values.truncate(values.len() - 4);
    values.extend([
        "--node-directory".into(),
        path.as_os_str().to_owned(),
        "--submission-inbox".into(),
        "local".into(),
        "--node-public-key".into(),
        hex(&[11; 32]).into(),
    ]);
    values
}

#[test]
fn rebroadcast_parser_requires_chain_and_destination_pins_and_rejects_extra_authority() {
    let cp = WalletCheckpoint {
        wallet_id: [1; 16],
        network: Network::Main,
        revision: 1,
    };
    let values = args(Path::new("wallet"), cp, [2; 32]);
    assert!(Command::parse(values.clone()).is_ok());
    let mut resumed = values.clone();
    resumed.extend(["--after-reservation".into(), hex(&[3; 16]).into()]);
    assert!(Command::parse(resumed).is_ok());
    for flag in [
        "--manifest",
        "--profile",
        "--node-directory",
        "--submission-inbox",
        "--node-public-key",
    ] {
        let mut bad = values.clone();
        let index = bad.iter().position(|v| v == flag).unwrap();
        bad.drain(index..index + 2);
        assert!(Command::parse(bad).is_err());
    }
    for pair in [
        ["--after-reservation", "xyz"],
        ["--reservation", "00"],
        ["--external", "1"],
        ["--max-fee-atoms", "1"],
    ] {
        let mut bad = values.clone();
        bad.extend(pair.map(OsString::from));
        assert!(Command::parse(bad).is_err());
    }
}

#[test]
fn bounded_pages_visit_each_reservation_once_without_verifying_skipped_profiles_or_unsigned_bytes()
{
    let dir = private_dir();
    let (chain, _) = source(dir.path(), false);
    let profile = chain.profile_id().unwrap();
    let mut store = wallet(dir.path());
    for n in 0..19u8 {
        let token = store
            .reserve_inputs(
                if n == 0 { [99; 32] } else { profile },
                chain.chain().unwrap().tip(),
                20,
                vec![Input::Private { nullifier: [n; 32] }],
            )
            .unwrap();
        if n == 1 || n == 2 {
            store
                .bind_reservation(token, [n; 32], b"invalid signed bytes")
                .unwrap();
            if n == 2 {
                store.compact_reservation_bytes(token).unwrap();
            }
        }
    }
    drop(Inbox::create(dir.path(), "local", profile, [11; 32]).unwrap());
    let before = store.checkpoint().unwrap();
    let mut seen = std::collections::BTreeSet::new();
    let mut states = std::collections::BTreeSet::new();
    let mut after = None;
    let mut sizes = Vec::new();
    loop {
        let result = step(&store, &chain, dir.path(), after);
        let entries = result["results"].as_array().unwrap();
        assert!(entries.len() <= 8);
        sizes.push(entries.len());
        for entry in entries {
            assert!(seen.insert(id(entry["reservation"].as_str().unwrap()).unwrap()));
            assert_eq!(entry["queued_exact_bytes"], false);
            states.insert(entry["state"].as_str().unwrap().to_owned());
        }
        after = result["next_after_reservation"]
            .as_str()
            .map(|v| id(v).unwrap());
        if after.is_none() {
            break;
        }
    }
    assert_eq!(sizes, [8, 8, 3]);
    assert_eq!(
        seen,
        store.reservations().unwrap().keys().copied().collect()
    );
    assert_eq!(
        states,
        ["unsigned", "unavailable", "needs-bytes", "other-profile"]
            .map(str::to_owned)
            .into()
    );
    assert_eq!(
        step(&store, &chain, dir.path(), Some([255; 16]))["examined"],
        0
    );
    assert_eq!(store.checkpoint().unwrap(), before);
}

#[test]
fn real_signed_private_rebroadcast_revalidates_confirmation_reorg_conflict_expiry_and_cleanup() {
    for private in [false, true] {
        let dir = private_dir();
        let (mut chain, base) = source(dir.path(), private);
        let profile = chain.profile_id().unwrap();
        let mut store = wallet(dir.path());
        let doc = intent(&store, &chain, private, false, 8);
        let signed = make(&mut store, &chain, &doc).unwrap();
        let raw = decode(signed["transaction_hex"].as_str().unwrap());
        let token = id(signed["reservation"].as_str().unwrap()).unwrap();
        let digest = monario_node::submission::digest(&raw);
        let cp = store.checkpoint().unwrap();
        let claims = store.reservations().unwrap()[&token].inputs.clone();
        let mut inbox = Inbox::create(dir.path(), "local", profile, [11; 32]).unwrap();
        let queued = step(&store, &chain, dir.path(), None);
        assert_eq!(queued["results"][0]["submission"], hex(&digest));
        assert_eq!(queued["results"][0]["state"], "valid-for-next-block");
        assert_eq!(step(&store, &chain, dir.path(), None), queued);
        assert!(inbox.forget(digest).unwrap());
        let h = if private { 4 } else { 3 };
        let mut confirmed = base.clone();
        confirmed.accept(&mut chain, h, std::slice::from_ref(&raw));
        assert_eq!(
            step(&store, &chain, dir.path(), None)["results"][0]["state"],
            "confirmed"
        );
        assert!(inbox.status(digest).unwrap().is_none());
        let mut empty = base.clone();
        empty.accept(&mut chain, h, &[]);
        empty.accept(&mut chain, h + 1, &[]);
        assert_eq!(
            step(&store, &chain, dir.path(), None)["results"][0]["submission"],
            hex(&digest)
        );
        assert!(inbox.forget(digest).unwrap());
        let mut conflict = base;
        conflict.accept(
            &mut chain,
            h,
            &[fixture(if private { "conflict" } else { "deposit" })],
        );
        conflict.accept(&mut chain, h + 1, &[]);
        conflict.accept(&mut chain, h + 2, &[]);
        assert_eq!(
            step(&store, &chain, dir.path(), None)["results"][0]["state"],
            "unavailable"
        );
        assert!(inbox.status(digest).unwrap().is_none());
        empty.accept(&mut chain, h + 2, &[]);
        empty.accept(&mut chain, h + 3, &[]);
        assert_eq!(
            step(&store, &chain, dir.path(), None)["results"][0]["queued_exact_bytes"],
            true
        );
        assert!(inbox.forget(digest).unwrap());
        for height in
            h + 4..=u32::try_from(store.reservations().unwrap()[&token].expiry_height).unwrap()
        {
            empty.accept(&mut chain, height, &[]);
        }
        assert_eq!(
            step(&store, &chain, dir.path(), None)["results"][0]["state"],
            "expired"
        );
        assert!(inbox.status(digest).unwrap().is_none());
        assert_eq!(store.checkpoint().unwrap(), cp);
        assert_eq!(store.reservations().unwrap()[&token].inputs, claims);
        assert_eq!(
            store.reservations().unwrap()[&token].expose_transaction(),
            Some(raw.as_slice())
        );
    }
}

#[test]
fn rebroadcast_cli_authentication_pins_recovery_and_retired_destinations_fail_closed() {
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
    store
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
    drop(Inbox::create(dir.path(), "local", profile, [11; 32]).unwrap());
    let before = wallet_vault(dir.path());
    let values = args(dir.path(), cp, profile);
    for checkpoint in [None, Some(pin)] {
        let mut values = values.clone();
        if let Some(pin) = checkpoint {
            values.extend(["--checkpoint".into(), hex(&pin).into()]);
        }
        let mut out = Vec::new();
        crate::execute(
            Command::parse(values).unwrap(),
            &mut credentials(),
            &mut out,
        )
        .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(result["results"][0]["state"], "unsigned");
        assert_eq!(result["network_started"], false);
    }
    for flag in ["--wallet-id", "--profile", "--node-public-key"] {
        let mut bad = values.clone();
        let at = bad.iter().position(|v| v == flag).unwrap() + 1;
        bad[at] = hex(&vec![0; if flag == "--wallet-id" { 16 } else { 32 }]).into();
        let mut out = Vec::new();
        assert!(
            crate::execute(Command::parse(bad).unwrap(), &mut credentials(), &mut out).is_err()
        );
        assert!(out.is_empty());
    }
    let mut bad = values.clone();
    bad.extend(["--checkpoint".into(), hex(&[0; 32]).into()]);
    assert!(
        crate::execute(
            Command::parse(bad).unwrap(),
            &mut credentials(),
            &mut Vec::new()
        )
        .is_err()
    );
    let mut wrong = credentials().into_inner();
    wrong[2] ^= 1;
    assert!(
        crate::execute(
            Command::parse(values.clone()).unwrap(),
            &mut Cursor::new(wrong),
            &mut Vec::new()
        )
        .is_err()
    );
    let store = open_wallet(dir.path(), cp);
    let wallet_root = WalletDirectory::open(dir.path()).unwrap();
    store
        .backup(&wallet_root, "saved", &password(PASSWORD).unwrap())
        .unwrap();
    let recovered = WalletStore::recover(
        &wallet_root,
        "saved",
        &password(PASSWORD).unwrap(),
        cp,
        &wallet_root,
        "restored",
        &password(PASSWORD).unwrap(),
    )
    .unwrap();
    let chain = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        production(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    assert!(matches!(
        api::step(
            &recovered,
            &chain,
            destination(dir.path(), [11; 32]),
            None,
            || {}
        ),
        Err(Error::RecoveryLocked)
    ));
    drop(recovered);
    drop(chain);
    drop(store);
    drop(inbox(dir.path(), profile).rotate("next").unwrap());
    assert!(
        crate::execute(
            Command::parse(values).unwrap(),
            &mut credentials(),
            &mut Vec::new()
        )
        .is_err()
    );
    assert_eq!(wallet_vault(dir.path()), before);
}

#[test]
fn rebroadcast_crash_worker() {
    let Some(path) = std::env::var_os("MONAR_REBROADCAST_CRASH_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let cp: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("pins.json")).unwrap()).unwrap();
    let cp = WalletCheckpoint {
        wallet_id: id(cp["id"].as_str().unwrap()).unwrap(),
        network: Network::Main,
        revision: cp["revision"].as_u64().unwrap(),
    };
    let store = open_wallet(path, cp);
    let chain = DurableChain::open(
        &path.join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    if std::env::var("MONAR_REBROADCAST_CRASH_PHASE").unwrap() == "before" {
        std::process::exit(97);
    }
    api::step(&store, &chain, destination(path, [11; 32]), None, || {
        std::process::exit(98)
    })
    .unwrap();
    panic!("expected a signed publication");
}

#[test]
fn abrupt_exit_and_failed_receipt_preserve_exact_signatures_claims_and_idempotent_retry() {
    let dir = private_dir();
    let (mut chain, mut model) = source(dir.path(), false);
    let profile = chain.profile_id().unwrap();
    let mut store = wallet(dir.path());
    let shield = intent(&store, &chain, false, true, 7);
    let shield = make(&mut store, &chain, &shield).unwrap();
    model.accept(
        &mut chain,
        3,
        &[decode(shield["transaction_hex"].as_str().unwrap())],
    );
    let doc = intent(&store, &chain, true, false, 8);
    make(&mut store, &chain, &doc).unwrap();
    let inputs = inventory(&store, &chain);
    let input = inputs["transparent"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["amount_atoms"] == "9" && p["reserved"] == false)
        .unwrap();
    let mut doc = doc;
    doc["funding"] = serde_json::json!({"pool":"transparent","inputs":[{
        "transaction":input["transaction"],"index":input["index"]}]});
    doc["payments"][0]["amount_atoms"] = "1".into();
    doc["change"] = "transparent".into();
    make(&mut store, &chain, &doc).unwrap();
    let cp = store.checkpoint().unwrap();
    let bytes: Vec<_> = store
        .reservations()
        .unwrap()
        .values()
        .filter(|r| {
            !chain
                .chain()
                .unwrap()
                .ledger()
                .contains_transaction(&r.transaction.unwrap())
        })
        .map(|r| r.expose_transaction().unwrap().to_vec())
        .collect();
    assert_eq!(bytes.len(), 2);
    fs::write(
        dir.path().join("pins.json"),
        serde_json::to_vec(&serde_json::json!({"id":hex(&cp.wallet_id),"revision":cp.revision}))
            .unwrap(),
    )
    .unwrap();
    drop(store);
    drop(chain);
    let before = wallet_vault(dir.path());
    drop(Inbox::create(dir.path(), "local", profile, [11; 32]).unwrap());
    for (phase, code, count) in [("before", 97, 0), ("after-first", 98, 1)] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "balance::tests::construction::rebroadcast::rebroadcast_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_REBROADCAST_CRASH_DIR", dir.path())
            .env("MONAR_REBROADCAST_CRASH_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(code));
        let local = inbox(dir.path(), profile);
        assert_eq!(
            bytes
                .iter()
                .filter(|b| local
                    .status(monario_node::submission::digest(b))
                    .unwrap()
                    .is_some())
                .count(),
            count
        );
    }
    let store = open_wallet(dir.path(), cp);
    let chain = DurableChain::open(
        &dir.path().join("chain.sqlite"),
        config(),
        root(),
        V6Verifier,
        u64::MAX / 2,
    )
    .unwrap();
    let result = step(&store, &chain, dir.path(), None);
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(report(&result, &mut Broken), Err(Error::Output));
    assert_eq!(step(&store, &chain, dir.path(), None), result);
    assert_eq!(store.checkpoint().unwrap(), cp);
    assert!(bytes.iter().all(|raw| {
        store
            .reservations()
            .unwrap()
            .values()
            .any(|r| r.expose_transaction() == Some(raw.as_slice()))
    }));
    drop(store);
    assert_eq!(wallet_vault(dir.path()), before);
}

//! Prune is offline and never creates genesis or starts networking.
use super::*;

fn values(action: &str, root: &Path, cp: Checkpoint) -> Vec<String> {
    let mut values = args(action, root, cp);
    values.extend(["--manifest".into(), "node.json".into()]);
    values
}

fn run(args: Vec<String>) -> Result<serde_json::Value, Error> {
    let mut out = Vec::new();
    execute(
        parse(args),
        &mut Cursor::new(frame(OLD)),
        &mut out,
        &Arc::new(AtomicBool::new(true)),
    )?;
    Ok(serde_json::from_slice(&out).unwrap())
}

#[test]
fn prune_requires_bounded_arguments_and_an_existing_retained_tail() {
    let dir = private_tempdir();
    let cp = chain_fixture(dir.path());
    // Both bounds are required.
    assert!(
        Command::parse(
            values("prune", dir.path(), cp)
                .into_iter()
                .map(OsString::from)
        )
        .is_err()
    );
    // Values are decimal-only and bounded.
    for bad in ["", "-1", "1.5", "0x10", "99999999999999999999999999"] {
        let mut args = values("prune", dir.path(), cp);
        args.extend([
            "--below".into(),
            bad.into(),
            "--keep-blocks".into(),
            "1".into(),
        ]);
        assert!(Command::parse(args.into_iter().map(OsString::from)).is_err());
    }
    // Network activation is not part of an offline prune.
    let mut networked = values("prune", dir.path(), cp);
    networked.extend([
        "--below".into(),
        "1".into(),
        "--keep-blocks".into(),
        "1".into(),
        "--enable-network".into(),
        String::new(),
    ]);
    assert!(Command::parse(networked.into_iter().map(OsString::from)).is_err());
    // The synthetic empty root metadata has no body to prune.
    let mut empty = values("prune", dir.path(), cp);
    empty.extend([
        "--below".into(),
        "0".into(),
        "--keep-blocks".into(),
        "1".into(),
    ]);
    assert_eq!(run(empty), Err(Error::Arguments));
    let mut shallow = values("prune", dir.path(), cp);
    shallow.extend([
        "--below".into(),
        "1".into(),
        "--keep-blocks".into(),
        "1".into(),
    ]);
    assert_eq!(run(shallow).err(), Some(Error::Arguments));
}

#[test]
fn checkpoint_prune_requires_a_bounded_keep_and_never_starts_networking() {
    let dir = private_tempdir();
    let cp = chain_fixture(dir.path());
    // The flag is required and decimal-only.
    assert!(
        Command::parse(
            values("checkpoint-prune", dir.path(), cp)
                .into_iter()
                .map(OsString::from)
        )
        .is_err()
    );
    for bad in ["", "-1", "1.5", "0x10", "99999999999999999999999999"] {
        let mut args = values("checkpoint-prune", dir.path(), cp);
        args.extend(["--keep".into(), bad.into()]);
        assert!(Command::parse(args.into_iter().map(OsString::from)).is_err());
    }
    // The keep bound is enforced by the storage layer (1..=1024).
    for bad in ["0", "1025"] {
        let mut args = values("checkpoint-prune", dir.path(), cp);
        args.extend(["--keep".into(), bad.into()]);
        assert_eq!(run(args).err(), Some(Error::Arguments));
    }
    let mut good = values("checkpoint-prune", dir.path(), cp);
    good.extend(["--keep".into(), "2".into()]);
    let receipt = run(good).unwrap();
    assert_eq!(receipt["operation"], "checkpoint-prune");
    assert_eq!(receipt["generations_removed"], "0");
    assert_eq!(receipt["network_started"], false);
}
